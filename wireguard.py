from pathlib import Path
import subprocess, time, socket, winreg, ctypes
from constants import (
    CONFIG_DIR, CONFIG_NAME, SERVICE_NAME, WG_PROGDATA, WG_EXE, WG_CLI, DEBUG_MODE,
    DEFAULT_STEALTH_PORT
)
from network import (
    run, _ps, _make_si,
    add_dns_leak_block, remove_dns_leak_block,
    add_kill_switch, remove_kill_switch,
    enable_ipv6_on_non_wg_adapters,
    add_wpad_block, remove_wpad_block,
    block_physical_immediately,
)
from metadata import SERVER_METADATA
from utils import read_registry, write_registry
import atexit as _atexit


def _emergency_firewall_cleanup():
    """
    atexit handler: remove all Shuriken firewall rules if the process exits
    unexpectedly. Without this, stale rules block all traffic on next launch.

    Includes remove_split_tunnel() so that split-tunnel Allow rules don't
    survive a crash and leak traffic outside the VPN on the next session.
    """
    try:
        remove_kill_switch()
        remove_dns_leak_block()
        remove_wpad_block()
        enable_ipv6_on_non_wg_adapters()
        from network import remove_split_tunnel
        remove_split_tunnel()
    except Exception:
        pass

_atexit.register(_emergency_firewall_cleanup)

# ── WireGuard config helpers ──────────────────────────────────────────────────

def validate_config_has_dns(conf_path: Path) -> bool:
    """Ensure .conf has a DNS = line to prevent DoH leaks."""
    try:
        text = conf_path.read_text(encoding="utf-8", errors="ignore")
        return any(
            line.strip().lower().startswith("dns") and "=" in line
            for line in text.splitlines()
        )
    except Exception:
        return False

def copy_conf_to_progdata(src: Path) -> Path:
    """
    Securely copy a WireGuard config to ProgramData.
    Applies stealth port 443 rewrite when enabled via registry.
    """
    try:
        src_resolved = src.resolve(strict=True)
    except FileNotFoundError:
        raise ValueError(f"Source config does not exist: {src}")
    except Exception as e:
        raise ValueError(f"Cannot resolve source path: {src}") from e

    try:
        config_dir_resolved = CONFIG_DIR.resolve(strict=True)
    except Exception as e:
        raise RuntimeError("CONFIG_DIR is not accessible") from e

    if config_dir_resolved not in src_resolved.parents:
        raise ValueError(
            f"Config file must be inside CONFIG_DIR.\n"
            f"CONFIG_DIR: {config_dir_resolved}\n"
            f"Rejected:   {src_resolved}"
        )

    WG_PROGDATA.mkdir(parents=True, exist_ok=True)
    dst = WG_PROGDATA / CONFIG_NAME

    text  = src_resolved.read_text(encoding="utf-8", errors="ignore")
    lines = [ln.rstrip("\n") for ln in text.splitlines()]

    # Read stealth setting from HKLM so an unprivileged user cannot force port
    # 443 by writing to their own HKCU hive. Falls back to HKCU for dev use.
    stealth_enabled = False
    try:
        for hive, hive_name in [
            (winreg.HKEY_LOCAL_MACHINE, "HKLM"),
            (winreg.HKEY_CURRENT_USER,  "HKCU"),
        ]:
            try:
                key = winreg.OpenKey(hive, r"Software\Shuriken", 0, winreg.KEY_READ)
                value, _ = winreg.QueryValueEx(key, "StealthPort")
                winreg.CloseKey(key)
                stealth_enabled = bool(value)
                if DEBUG_MODE:
                    print(f"[DEBUG] Stealth mode from {hive_name} = {stealth_enabled}")
                break
            except FileNotFoundError:
                continue
    except Exception:
        pass

    new_lines = []
    for ln in lines:
        if ln.strip().lower().startswith("endpoint") and stealth_enabled and ":" in ln:
            if DEBUG_MODE:
                print("[DEBUG] Applying stealth port 443")
            kv_sep   = ln.index("=")
            key_part = ln[:kv_sep + 1]
            val_part = ln[kv_sep + 1:].strip()
            if val_part:
                host = val_part.rsplit(":", 1)[0]
                new_lines.append(f"{key_part} {host}:{DEFAULT_STEALTH_PORT}")
            else:
                new_lines.append(ln)
        else:
            new_lines.append(ln)

    new_text = "\n".join(new_lines)
    if not new_text.endswith("\n"):
        new_text += "\n"

    dst.write_text(new_text, encoding="utf-8")

    # Harden permissions — config contains WireGuard private keys.
    try:
        subprocess.run(
            ["icacls", str(dst),
             "/inheritance:r",
             "/grant:r", "SYSTEM:(F)",
             "/grant:r", "Administrators:(F)"],
            capture_output=True, timeout=10,
        )
    except Exception as e:
        if DEBUG_MODE:
            print(f"[DEBUG] icacls hardening failed (non-fatal): {e}")

    return dst

# ── Service control ───────────────────────────────────────────────────────────

def service_install(cfg: Path):
    return run([str(WG_EXE), "/installtunnelservice", str(cfg)])

def service_uninstall(name: str):
    return run([str(WG_EXE), "/uninstalltunnelservice", name])

def wg_active_interfaces() -> set[str]:
    names: set[str] = set()
    try:
        if WG_CLI.exists():
            code, out, _ = run([str(WG_CLI), "show", "interfaces"])
            if code == 0 and out:
                for n in out.strip().replace("\n", " ").split():
                    n = n.strip()
                    if n:
                        names.add(n.lower())
    except Exception:
        pass
    return names

def is_vpn_up() -> bool:
    # Delegate to wg_active_interfaces() — avoids a redundant subprocess call.
    if not WG_CLI or not WG_CLI.exists():
        return False
    return SERVICE_NAME.lower() in wg_active_interfaces()

def is_handshake_ok(min_age_seconds: float = 180.0) -> bool:
    """
    Return True only if WireGuard has completed a successful handshake with
    the peer within the last `min_age_seconds` seconds.

    `wg show` reports the latest handshake timestamp per peer. A handshake of
    0 seconds ago or up to ~180 s (3 min) ago means the tunnel is genuinely
    exchanging traffic. A handshake that is very old (or absent) means the
    tunnel adapter exists but no cryptographic session has been established —
    which is exactly what happens when stealth port 443 is enabled but the
    server doesn't actually listen on 443.
    """
    if not WG_CLI or not WG_CLI.exists():
        return False
    try:
        code, out, _ = run([str(WG_CLI), "show", SERVICE_NAME, "latest-handshakes"])
        if code != 0 or not out.strip():
            return False
        # Output: "<peer_pubkey>\t<unix_timestamp>"
        for line in out.strip().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                try:
                    ts = int(parts[-1])
                    if ts == 0:
                        # Never had a handshake
                        return False
                    age = time.time() - ts
                    if age < min_age_seconds:
                        return True
                except ValueError:
                    pass
    except Exception:
        pass
    return False

def probe_server_reachable(conf_path: Path, timeout: float = 4.0) -> tuple[bool, str]:
    """
    UDP-ping the server's WireGuard endpoint port before installing the tunnel.
    WireGuard uses UDP, so we can't do a TCP handshake like the stealth probe —
    instead we send a small UDP datagram and check whether the host at least
    routes (i.e. we don't get ICMP port-unreachable back immediately, and DNS
    resolves). Returns (True, "") if the host looks reachable, or
    (False, reason) with a human-readable message if it clearly isn't.

    This is a best-effort check: UDP is connectionless so a clean-looking result
    doesn't guarantee the WireGuard service is running. The handshake check that
    runs after tunnel install is the definitive gate. This probe exists to catch
    the obvious cases early (DNS failure, host completely offline) and give a
    fast, clear error instead of making the user wait 25+ seconds.
    """
    try:
        text = conf_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return True, ""

    host = None
    port = 51820  # WireGuard default; will be overridden from conf
    for line in text.splitlines():
        s = line.strip().lower()
        if s.startswith("endpoint") and "=" in s:
            val = line.split("=", 1)[1].strip()
            # handles host:port and [ipv6]:port
            parts = val.rsplit(":", 1)
            host = parts[0].strip("[]")
            if len(parts) == 2:
                try:
                    port = int(parts[1])
                except ValueError:
                    pass
            break

    if not host:
        return True, ""  # no endpoint in conf — let normal flow handle it

    # Step 1: DNS / address resolution
    try:
        resolved = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
        if not resolved:
            raise OSError("No addresses returned")
    except OSError as e:
        return False, (
            f"Cannot resolve server address '{host}'.\n\n"
            f"Check your internet connection or DNS settings.\n\n"
            f"(Detail: {e})"
        )

    # Step 2: UDP reachability — send a tiny datagram and check for instant ICMP refusal
    addr_info = resolved[0]
    af, socktype, proto, _canonname, sockaddr = addr_info
    try:
        with socket.socket(af, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.connect(sockaddr)
            sock.send(b"\x00" * 4)   # tiny dummy payload
            # If we get here without an immediate OS error the route exists
    except ConnectionRefusedError:
        # ICMP port-unreachable came back immediately — host is up but port rejected
        return False, (
            f"Server '{host}' rejected the connection on port {port}.\n\n"
            "The WireGuard service may not be running on this server.\n"
            "Try a different server or contact support."
        )
    except OSError:
        # Could be a routing error or firewall block on our side — not definitive,
        # let the tunnel attempt proceed and the handshake check be the real gate
        pass
    except Exception:
        pass

    if DEBUG_MODE:
        print(f"[PROBE] UDP probe to {host}:{port} — route looks viable")
    return True, ""

def validate_stealth_port_reachable(conf_path: Path, timeout: float = 5.0) -> tuple[bool, str]:
    """
    When stealth port 443 is active, TCP-probe the server's endpoint on port 443
    BEFORE installing the tunnel. Returns (True, "") if reachable, or
    (False, human_readable_reason) if not.

    This prevents the silent hang where WireGuard creates a tunnel adapter but
    the server never responds on 443, leaving the user with broken internet and
    an unstoppable "Connecting to internet..." loop.
    """
    try:
        text = conf_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return True, ""  # can't read conf — let normal flow handle it

    host = None
    for line in text.splitlines():
        s = line.strip().lower()
        if s.startswith("endpoint") and "=" in s:
            val = line.split("=", 1)[1].strip()
            # strip port — handles both host:port and [ipv6]:port
            host = val.rsplit(":", 1)[0].strip("[]")
            break

    if not host:
        return True, ""  # no endpoint found — can't probe, proceed normally

    try:
        with socket.create_connection((host, DEFAULT_STEALTH_PORT), timeout=timeout):
            if DEBUG_MODE:
                print(f"[STEALTH] TCP probe {host}:443 succeeded")
            return True, ""
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        msg = (
            f"Stealth port 443 is enabled but the server\n"
            f"'{host}' does not appear to accept connections on port 443.\n\n"
            f"Either disable stealth port in Settings, or choose a server\n"
            f"that supports port 443.\n\n"
            f"(Technical detail: {e})"
        )
        if DEBUG_MODE:
            print(f"[STEALTH] TCP probe {host}:443 FAILED: {e}")
        return False, msg

# ── Network repair ────────────────────────────────────────────────────────────

def repair_network_stack_if_stuck():
    """Full network-stack repair when the tunnel gets wedged."""
    print(f"[DEBUG] Repairing network due to error at {time.time():.0f}")
    si, cf = _make_si()
    try:
        result = subprocess.run(
            ["netsh", "interface", "show", "interface"],
            capture_output=True, text=True, timeout=3,
            startupinfo=si, creationflags=cf
        )
        if "connected" not in result.stdout.lower():
            return
        can_reach = False
        try:
            with socket.create_connection(("10.0.0.1", 53), timeout=2.5):
                can_reach = True
        except (socket.timeout, OSError, ConnectionRefusedError):
            pass
        if can_reach:
            return

        _reset_network_basics(si, cf)

        saved = read_registry()
        if saved:
            try:
                cfg = copy_conf_to_progdata(saved)
                subprocess.run(
                    [str(WG_EXE), "/installtunnelservice", str(cfg)],
                    capture_output=True, text=True, timeout=8,
                    startupinfo=si, creationflags=cf
                )
            except Exception:
                pass
        try:
            test_dns = subprocess.run(
                ["nslookup", "cloudflare.com", "10.0.0.1"],
                capture_output=True, text=True, timeout=5,
                startupinfo=si, creationflags=cf
            )
            if test_dns.returncode != 0:
                try:
                    with socket.create_connection(("10.0.0.1", 53), timeout=2.5):
                        pass
                except Exception:
                    pass
        except Exception:
            pass
        time.sleep(2)
    except Exception:
        pass

def run_adapter_repair_sequence():
    """Lighter repair: wipe firewall rules, flush DHCP/DNS, sleep."""
    si, cf = _make_si()
    try:
        _ps("Get-NetFirewallRule -DisplayName 'Shuriken*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -Confirm:$false")
    except Exception:
        pass
    _reset_network_basics(si, cf)

def _reset_network_basics(si, cf) -> None:
    """
    Shared repair steps used by both repair_network_stack_if_stuck and
    run_adapter_repair_sequence: teardown WireGuard services, reset DNS,
    re-enable TCP/IP bindings, flush DHCP, and sleep briefly.
    """
    cmds = [
        [str(WG_EXE), "/uninstalltunnelservice", SERVICE_NAME],
        [str(WG_EXE), "/uninstallmanagerservice"],
        ["ipconfig", "/release"],
        ["ipconfig", "/renew"],
        ["ipconfig", "/flushdns"],
    ]
    for cmd in cmds:
        try:
            subprocess.run(cmd, startupinfo=si, creationflags=cf,
                           capture_output=True, timeout=12)
        except Exception as e:
            if DEBUG_MODE:
                print(f"[SafeRepair] Failed: {cmd} → {e}")

    for adapter_name in ["Ethernet", "Wi-Fi", "WiFi", "LAN"]:
        try:
            subprocess.run(
                ["netsh", "interface", "ip", "set", "dns",
                 f"name={adapter_name}", "dhcp"],
                capture_output=True, text=True, timeout=4,
                startupinfo=si, creationflags=cf
            )
        except Exception:
            continue

    try:
        subprocess.run(
            ["net", "start", "dnscache"],
            capture_output=True, text=True, timeout=5,
            startupinfo=si, creationflags=cf
        )
    except Exception:
        pass

    try:
        subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-NetAdapter | ForEach-Object { "
             "Enable-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip "
             "  -Confirm:$false -ErrorAction SilentlyContinue; "
             "Enable-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6 "
             "  -Confirm:$false -ErrorAction SilentlyContinue }"],
            capture_output=True, text=True, timeout=10,
            startupinfo=si, creationflags=cf
        )
    except Exception:
        pass

    time.sleep(2)

def cleanup_stale_wireguard_service():
    """
    Remove any stuck WireGuard tunnel service before reconnecting.
    """
    _quick_kill_service()

# ── Registry helpers ──────────────────────────────────────────────────────────

def service_registry_exists(name: str) -> bool:
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WireGuard\Tunnels", 0, winreg.KEY_READ
        ) as key:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(key, i)
                    if sub.lower() == name.lower():
                        return True
                    i += 1
                except OSError:
                    break
    except OSError:
        pass
    return False

# ── Network profile helpers ───────────────────────────────────────────────────

def purge_stale_network_profiles():
    """
    Delete all Shuriken-named WireGuard NetworkList profile entries from the
    registry. Windows appends " 2", " 3" etc. when it sees what it thinks is a
    new network. Deleting before tunnel-up forces Windows to create a fresh
    profile with the bare service name.

    Guard: only delete profiles whose Category is 0 (Public / unidentified) AND
    whose Name starts with SERVICE_NAME. This prevents a timing race during
    NLA re-evaluation from accidentally deleting a real Wi-Fi network profile
    (e.g. "Shibuya Ku") that briefly shares a registry slot.
    """
    profiles_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"
    deleted = []
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, profiles_path, 0,
            winreg.KEY_READ | winreg.KEY_WRITE
        ) as profiles_key:
            subkeys = []
            i = 0
            while True:
                try:
                    subkeys.append(winreg.EnumKey(profiles_key, i))
                    i += 1
                except OSError:
                    break

            for subkey_name in subkeys:
                try:
                    with winreg.OpenKey(profiles_key, subkey_name, 0, winreg.KEY_READ) as sk:
                        try:
                            profile_name, _ = winreg.QueryValueEx(sk, "ProfileName")
                        except OSError:
                            continue

                        # Only touch profiles whose name starts with our service name
                        if not (isinstance(profile_name, str)
                                and profile_name.startswith(SERVICE_NAME)):
                            continue

                        # Extra guard: WireGuard tunnel profiles are always
                        # Category 0 (Public/unidentified). Real user Wi-Fi networks
                        # are typically Category 1 (Private) or 2 (Domain). Skip
                        # anything that looks like a real network profile.
                        try:
                            category, _ = winreg.QueryValueEx(sk, "Category")
                            if category != 0:
                                if DEBUG_MODE:
                                    print(f"[PROFILE] Skipping '{profile_name}' "
                                          f"— Category={category} (not a tunnel profile)")
                                continue
                        except OSError:
                            pass  # No Category key — safe to proceed

                    winreg.DeleteKey(profiles_key, subkey_name)
                    deleted.append(profile_name)
                    if DEBUG_MODE:
                        print(f"[PROFILE] Deleted stale profile: '{profile_name}' ({subkey_name})")
                except Exception as e:
                    if DEBUG_MODE:
                        print(f"[PROFILE] Could not process subkey '{subkey_name}': {e}")

    except PermissionError:
        if DEBUG_MODE:
            print("[PROFILE] Skipping profile purge — insufficient privileges")
    except Exception as e:
        if DEBUG_MODE:
            print(f"[PROFILE] purge_stale_network_profiles failed: {e}")

    if DEBUG_MODE and deleted:
        print(f"[PROFILE] Purged {len(deleted)} stale profile(s): {deleted}")

def _fix_numbered_profiles():
    """
    Rename any 'ShurikenVPN 2', 'ShurikenVPN 14', etc. profile entries back
    to the bare service name. Called post-connect by both vpn_up_nogui and
    switch_server_nogui.

    Sleep briefly first: Windows NLA (Network Location Awareness) re-evaluates
    ALL active connections when a new tunnel adapter appears. Touching the
    registry while NLA is mid-scan can cause it to reassign profile GUIDs for
    unrelated adapters (e.g. rename "Shibuya Ku" → "Network 2"). Waiting 2 s
    gives NLA time to settle before we make any writes.
    """
    time.sleep(2.0)   # let NLA settle before touching NetworkList registry

    profiles_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles"
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, profiles_path, 0,
            winreg.KEY_READ | winreg.KEY_WRITE
        ) as profiles_key:
            subkeys = []
            i = 0
            while True:
                try:
                    subkeys.append(winreg.EnumKey(profiles_key, i))
                    i += 1
                except OSError:
                    break
            for subkey_name in subkeys:
                try:
                    with winreg.OpenKey(
                        profiles_key, subkey_name, 0,
                        winreg.KEY_READ | winreg.KEY_WRITE
                    ) as sk:
                        try:
                            profile_name, _ = winreg.QueryValueEx(sk, "ProfileName")
                        except OSError:
                            continue
                        if (isinstance(profile_name, str)
                                and profile_name.startswith(SERVICE_NAME)
                                and profile_name != SERVICE_NAME):
                            # Same Category guard as purge_stale_network_profiles:
                            # only rename tunnel (Category 0) profiles.
                            try:
                                category, _ = winreg.QueryValueEx(sk, "Category")
                                if category != 0:
                                    if DEBUG_MODE:
                                        print(f"[PROFILE] Skipping rename of '{profile_name}' "
                                              f"— Category={category}")
                                    continue
                            except OSError:
                                pass
                            winreg.SetValueEx(sk, "ProfileName", 0, winreg.REG_SZ, SERVICE_NAME)
                            if DEBUG_MODE:
                                print(f"[PROFILE] Renamed '{profile_name}' → '{SERVICE_NAME}'")
                except Exception as e:
                    if DEBUG_MODE:
                        print(f"[PROFILE] Could not fix subkey '{subkey_name}': {e}")
    except Exception as e:
        if DEBUG_MODE:
            print(f"[PROFILE] Post-connect profile fix failed: {e}")

# ── Tunnel teardown helpers ───────────────────────────────────────────────────

def _quick_kill_service():
    """Fire the uninstall request and kill WireGuard processes without waiting."""
    si, cf = _make_si()
    try:
        subprocess.run(
            [str(WG_EXE), "/uninstalltunnelservice", SERVICE_NAME],
            capture_output=True, timeout=4, startupinfo=si, creationflags=cf
        )
    except Exception:
        pass
    for proc in ["wireguard.exe", "wg.exe"]:
        try:
            subprocess.run(
                ["taskkill", "/F", "/IM", proc],
                capture_output=True, timeout=3,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )
        except Exception:
            pass

def _graceful_uninstall(name: str, timeout_s: float = 12.0) -> bool:
    """
    Graceful tunnel teardown for server switches.
    Uses /uninstalltunnelservice only — does NOT kill wireguard.exe.
    Killing wireguard.exe prevents it from restarting quickly as a service.
    """
    si, cf = _make_si()
    try:
        subprocess.run(
            [str(WG_EXE), "/uninstalltunnelservice", name],
            capture_output=True, timeout=6, startupinfo=si, creationflags=cf
        )
    except Exception:
        pass

    t0 = time.time()
    name_lower = name.lower()
    while time.time() - t0 < timeout_s:
        if name_lower not in wg_active_interfaces() and not service_registry_exists(name):
            time.sleep(0.4)
            return True
        time.sleep(0.3)

    return False

def uninstall_and_wait(name: str, timeout_s: float = 25.0) -> bool:
    """
    Aggressive WireGuard tunnel cleanup.
    Returns True if the tunnel is fully gone from interface and registry.
    """
    name_lower = name.lower()
    print(f"[UNINSTALL] Starting aggressive cleanup for '{name}'")

    # Phase 1: Repeated uninstall attempts
    for attempt in range(5):
        code, out, err = service_uninstall(name)
        msg = out or err or ""
        print(f"[UNINSTALL] Attempt {attempt+1}: exit={code}, msg={msg.strip()}")
        if code == 0 or "not installed" in msg.lower() or "does not exist" in msg.lower():
            print("[UNINSTALL] Uninstall reported success or already gone")
            break
        time.sleep(0.8)

    # Phase 2: Force-kill WireGuard processes
    for proc in ["wireguard.exe", "wg.exe"]:
        try:
            subprocess.run(
                ["taskkill", "/F", "/IM", proc],
                creationflags=subprocess.CREATE_NO_WINDOW,
                timeout=6, capture_output=True
            )
            print(f"[UNINSTALL] Killed {proc}")
        except Exception:
            pass

    try:
        subprocess.run(
            ["sc", "stop", name],
            creationflags=subprocess.CREATE_NO_WINDOW,
            timeout=8, capture_output=True
        )
        print("[UNINSTALL] sc stop attempted")
    except Exception:
        pass

    time.sleep(1.0)

    # Phase 3: Poll until gone
    t_start = time.time()
    while time.time() - t_start < timeout_s:
        active     = name_lower in wg_active_interfaces()
        reg_exists = service_registry_exists(name)
        if not active and not reg_exists:
            print("[UNINSTALL] Clean: no active interface + no registry entry")
            time.sleep(0.6)
            return True
        print(f"[UNINSTALL] Still present → active={active}, reg={reg_exists}")
        time.sleep(0.5)

    # Phase 4: Nuclear — direct registry deletion (requires admin)
    try:
        base_key = r"SOFTWARE\WireGuard\Tunnels"
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, base_key, 0, winreg.KEY_ALL_ACCESS
        ) as key:
            try:
                winreg.DeleteKey(key, name)
                print(f"[UNINSTALL] Deleted registry key: {base_key}\\{name}")
            except FileNotFoundError:
                pass
            except OSError as e:
                print(f"[UNINSTALL] Registry delete failed: {e}")
    except Exception as e:
        print(f"[UNINSTALL] Could not open registry for deletion: {e}")

    time.sleep(1.2)
    final_active = name_lower in wg_active_interfaces()
    final_reg    = service_registry_exists(name)
    success      = not final_active and not final_reg
    print(f"[UNINSTALL] Final result: success={success} (active={final_active}, reg={final_reg})")
    return success

def install_with_retry(cfg: Path, retries: int = 10, base_delay: float = 0.5) -> tuple[bool, str]:
    delay = base_delay
    last_out = last_err = ""
    for attempt in range(retries):
        code, last_out, last_err = service_install(cfg)
        if code == 0:
            return True, ""
        msg = (last_err or last_out or "").lower()
        if "already installed" in msg or "already exists" in msg:
            _graceful_uninstall(SERVICE_NAME, timeout_s=6.0)
        if DEBUG_MODE:
            print(f"[install_with_retry] Attempt {attempt + 1} failed: {last_err or last_out}")
        time.sleep(delay)
        delay = min(delay * 2, 8.0)
    return False, (last_err or last_out or "Failed to install tunnel service after retries.")

# ── Adapter rename helper ─────────────────────────────────────────────────────

def _rename_wg_adapter() -> bool:
    """
    Attempt up to 5 times to rename the WireGuard adapter to SERVICE_NAME.
    Returns True if the adapter ends up correctly named.
    """
    for rename_attempt in range(1, 6):
        if DEBUG_MODE:
            print(f"[DEBUG] Rename attempt {rename_attempt}/5...")

        ps_command = (
            r"Get-NetAdapter | Where-Object { "
            r"    ($_.Name -eq '" + SERVICE_NAME + r"') -or "
            r"    ($_.InterfaceDescription -like '*WireGuard*') "
            r"} | Select-Object -First 1 -ExpandProperty Name"
        )
        code, out, _ = _ps(ps_command)
        current_name = out.strip() if code == 0 and out.strip() else ""

        if not current_name:
            if DEBUG_MODE:
                print("[DEBUG] No matching adapter found for rename")
            return False

        if current_name == SERVICE_NAME:
            if DEBUG_MODE:
                print(f"[DEBUG] Adapter already correctly named '{SERVICE_NAME}'")
            return True

        safe_current = current_name.replace("'", "''").replace('"', '""')
        rename_ps = (
            f"Rename-NetAdapter -Name '{safe_current}' "
            f"-NewName '{SERVICE_NAME}' -Confirm:$false -ErrorAction SilentlyContinue"
        )
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", "powershell.exe",
                f'-NoProfile -Command "{rename_ps}"',
                None, 0
            )
            if DEBUG_MODE:
                print(f"[DEBUG] Rename requested: '{current_name}' → '{SERVICE_NAME}' (attempt {rename_attempt})")
        except Exception as e:
            if DEBUG_MODE:
                print(f"[DEBUG] ShellExecuteW failed on attempt {rename_attempt}: {e}")

        time.sleep(1.2)

        code, out, _ = _ps(
            f"Get-NetAdapter -Name '{SERVICE_NAME}' -ErrorAction SilentlyContinue "
            "| Select -Expand Name"
        )
        if code == 0 and out.strip() == SERVICE_NAME:
            if DEBUG_MODE:
                print(f"[DEBUG] Rename successful after attempt {rename_attempt}")
            return True

    return False

# ── Config scanning ───────────────────────────────────────────────────────────

def pretty_name_for(filename: str) -> str:
    return SERVER_METADATA.get(filename, {"name": filename}).get("name", filename)

def list_conf_files() -> list[Path]:
    search_roots: list[Path] = []
    try:
        if CONFIG_DIR.exists():
            search_roots.append(CONFIG_DIR)
    except Exception:
        pass
    seen  = set()
    found: list[Path] = []
    for root in search_roots:
        try:
            for p in root.glob("*.conf"):
                if p.name.lower() == CONFIG_NAME.lower():
                    continue
                key = (p.name.lower(), str(p.parent).lower())
                if key not in seen:
                    seen.add(key)
                    found.append(p)
        except Exception:
            continue
    return sorted(found, key=lambda p: p.name.lower())

# ── No-GUI VPN operations ─────────────────────────────────────────────────────

def _read_stealth_enabled() -> bool:
    """Return True if stealth port 443 is currently enabled in the registry."""
    try:
        for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            try:
                key = winreg.OpenKey(hive, r"Software\Shuriken", 0, winreg.KEY_READ)
                value, _ = winreg.QueryValueEx(key, "StealthPort")
                winreg.CloseKey(key)
                return bool(value)
            except FileNotFoundError:
                continue
    except Exception:
        pass
    return False

def vpn_up_nogui() -> tuple[bool, str | None, Path | None]:
    saved = read_registry()
    if not (saved and saved.is_file()):
        return False, "Please select a server from the list first.", None
    try:
        CONFIG_DIR.resolve(strict=True)
    except Exception:
        return False, "CONFIG_DIR is missing. Please reinstall application.", None

    # ── Stealth port pre-flight check ────────────────────────────────────────
    if _read_stealth_enabled():
        reachable, reason = validate_stealth_port_reachable(saved)
        if not reachable:
            return False, reason, None

    # ── General server reachability probe ────────────────────────────────────
    # Quick DNS + UDP check before installing the tunnel. Catches a completely
    # dead or unreachable server early and gives a clear error immediately,
    # rather than making the user wait 25+ seconds for the handshake to time out.
    reachable, reason = probe_server_reachable(saved)
    if not reachable:
        return False, reason, None

    try:
        cfg = copy_conf_to_progdata(saved)
    except Exception as e:
        return False, str(e), None

    add_dns_leak_block()
    add_kill_switch()
    add_wpad_block()
    purge_stale_network_profiles()

    ok, msg = install_with_retry(cfg)
    if not ok:
        remove_dns_leak_block()
        remove_kill_switch()
        return False, msg, None

    if DEBUG_MODE:
        print(f"[DEBUG] Waiting up to 40s for interface '{SERVICE_NAME}'...")

    t0 = time.time()
    tunnel_detected_time = None

    while time.time() - t0 < 40.0:
        if is_vpn_up():
            if tunnel_detected_time is None:
                tunnel_detected_time = time.time()
                if DEBUG_MODE:
                    print(f"[DEBUG] Tunnel detected — giving Windows 2s to settle")

            if time.time() - tunnel_detected_time < 2.0:
                time.sleep(0.3)
                continue

            # ── Handshake confirmation ────────────────────────────────────
            # The adapter being present does NOT mean the server responded.
            # Poll for up to 25 s — WireGuard retries every 5 s, so this
            # gives the server five full retry windows before giving up.
            handshake_deadline = time.time() + 25.0
            handshake_ok = False
            if DEBUG_MODE:
                print("[DEBUG] Waiting for WireGuard handshake confirmation...")
            while time.time() < handshake_deadline:
                if is_handshake_ok():
                    handshake_ok = True
                    break
                time.sleep(0.5)

            if not handshake_ok:
                if DEBUG_MODE:
                    print("[DEBUG] No handshake — tearing down stuck tunnel")
                _quick_kill_service()
                remove_dns_leak_block()
                remove_kill_switch()
                remove_wpad_block()
                uninstall_and_wait(SERVICE_NAME, timeout_s=8.0)
                stealth_hint = (
                    "\n\nNote: Stealth port 443 is enabled. If this server does not "
                    "support port 443, disable it in Settings."
                ) if _read_stealth_enabled() else ""
                return False, (
                    "Connected to the server but no response was received.\n\n"
                    "The server may be online but the WireGuard service is not "
                    "running, or a firewall is blocking UDP traffic between "
                    "you and the server.\n\n"
                    "Try a different server or check your local firewall settings."
                    + stealth_hint
                ), None

            remove_dns_leak_block()

            renamed = _rename_wg_adapter()
            if DEBUG_MODE:
                print("[DEBUG] Post-connect profile name cleanup")
            _fix_numbered_profiles()

            if not renamed and DEBUG_MODE:
                print("[DEBUG] Rename did not succeed after 5 attempts")

            return True, None, saved

        time.sleep(0.2)

    remove_dns_leak_block()
    remove_kill_switch()
    return False, (
        "The WireGuard tunnel did not start within 40 seconds.\n\n"
        "This usually means WireGuard is already running another tunnel "
        "or the service failed to install. Try disconnecting any active "
        "VPN and connecting again."
    ), None

def vpn_down_nogui() -> tuple[bool, str | None]:
    _quick_kill_service()
    remove_kill_switch()
    remove_dns_leak_block()
    remove_wpad_block()
    enable_ipv6_on_non_wg_adapters()
    success = uninstall_and_wait(SERVICE_NAME, timeout_s=8.0)
    if success:
        return True, None
    return False, "Tunnel service did not fully stop (still visible in wg show)"

def switch_server_nogui(new_conf: Path) -> tuple[bool, str | None]:
    """
    Switch to a new WireGuard server config while already connected.
    The watchdog must be stopped (with join) in Shuriken.pyw before this runs
    so no auto-reconnect can race the install.
    """
    write_registry(new_conf)

    # Stealth port pre-flight — same guard as vpn_up_nogui
    if _read_stealth_enabled():
        reachable, reason = validate_stealth_port_reachable(new_conf)
        if not reachable:
            return False, reason

    # General reachability probe
    reachable, reason = probe_server_reachable(new_conf)
    if not reachable:
        return False, reason

    try:
        cfg = copy_conf_to_progdata(new_conf)
    except Exception as e:
        return False, str(e)

    if DEBUG_MODE:
        print(f"[switch] Starting switch to {new_conf.name}")

    # Block physical immediately — prevents leaks during teardown window
    block_physical_immediately()
    add_dns_leak_block()
    add_kill_switch()

    if is_vpn_up():
        if DEBUG_MODE:
            print("[switch] Tearing down old tunnel...")
        _graceful_uninstall(SERVICE_NAME, timeout_s=15.0)
        if DEBUG_MODE:
            print("[switch] Old tunnel down")

    purge_stale_network_profiles()

    if DEBUG_MODE:
        print(f"[switch] Installing {cfg.name}...")
    ok, msg = install_with_retry(cfg)
    if not ok:
        if DEBUG_MODE:
            print(f"[switch] Install FAILED: {msg}")
        remove_dns_leak_block()
        remove_kill_switch()
        return False, (msg or "Failed to install tunnel after switch.")

    if DEBUG_MODE:
        print("[switch] Installed. Waiting up to 40s...")

    t0          = time.time()
    detected_at = None

    while time.time() - t0 < 40.0:
        up = is_vpn_up()
        if DEBUG_MODE:
            print(f"[switch] t={time.time()-t0:.1f}s up={up}")
        if up:
            if detected_at is None:
                detected_at = time.time()
            if time.time() - detected_at >= 2.0:
                remove_dns_leak_block()
                add_wpad_block()
                if DEBUG_MODE:
                    print("[DEBUG] Post-connect profile name cleanup")
                _fix_numbered_profiles()
                if DEBUG_MODE:
                    print(f"[switch] Done in {time.time()-t0:.1f}s")
                return True, None
        time.sleep(0.5)

    if DEBUG_MODE:
        print("[switch] TIMEOUT after 40s")
    remove_dns_leak_block()
    remove_kill_switch()
    return False, "Switched but interface did not come up within 40 seconds."
