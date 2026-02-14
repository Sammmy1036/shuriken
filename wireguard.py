from pathlib import Path
import subprocess, time, socket, winreg, ctypes
from constants import (
    CONFIG_DIR, CONFIG_NAME, SERVICE_NAME, WG_PROGDATA, WG_EXE, WG_CLI, DEBUG_MODE,
    STEALTH_PORT_ENABLED, DEFAULT_STEALTH_PORT   # ← ADD THIS LINE
)
from network import run, _ps, add_dns_leak_block, remove_dns_leak_block, add_kill_switch, remove_kill_switch, enable_ipv6_on_non_wg_adapters
from metadata import SERVER_METADATA
from utils import read_registry, write_registry

# -------------------------- WireGuard helpers -------------------
def validate_config_has_dns(conf_path: Path) -> bool:
    """Ensure .conf has DNS = line to prevent DoH leaks."""
    try:
        text = conf_path.read_text(encoding="utf-8", errors="ignore")
        lines = [line.strip() for line in text.splitlines()]
        for line in lines:
            if line.lower().startswith("dns") and "=" in line:
                return True
        return False
    except Exception:
        return False

def copy_conf_to_progdata(src: Path) -> Path:
    """
    Securely copy a WireGuard config to ProgramData.
    Now supports stealth port 443 when enabled.
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

    text = src_resolved.read_text(encoding="utf-8", errors="ignore")
    lines = [ln.rstrip("\n") for ln in text.splitlines()]

    stealth_enabled = False
    try:
        import winreg
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Shuriken", 0, winreg.KEY_READ)
        value, _ = winreg.QueryValueEx(key, "StealthPort")
        stealth_enabled = bool(value)
        winreg.CloseKey(key)
        print(f"[DEBUG] Stealth mode from registry = {stealth_enabled}")
    except Exception:
        pass

    new_lines = []
    for ln in lines:
        s = ln.strip().lower()
        if s.startswith("endpoint"):
            if stealth_enabled:
                print("Applying stealth port 443")
                if ":" in ln:
                    host = ln.rsplit(":", 1)[0].strip()
                    new_lines.append(f"{host}:{DEFAULT_STEALTH_PORT}")
                else:
                    new_lines.append(ln)
            else:
                new_lines.append(ln)
            continue
        new_lines.append(ln)

    new_text = "\n".join(new_lines)
    if not new_text.endswith("\n"):
        new_text += "\n"

    dst.write_text(new_text, encoding="utf-8")
    return dst

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
    if not WG_CLI or not WG_CLI.exists():
        return False
    try:
        code, out, _ = run([str(WG_CLI), "show", "interfaces"])
        if code == 0 and out:
            interfaces = out.strip().lower()
            return SERVICE_NAME.lower() in interfaces
    except Exception:
        pass
    return False

def repair_network_stack_if_stuck():
    print(f"[DEBUG] Repairing network due to error at {time.time():.0f}")
    try:
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        cf = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        result = subprocess.run(
            ["netsh", "interface", "show", "interface"],
            capture_output=True, text=True, timeout=3,
            startupinfo=si, creationflags=cf
        )
        if "connected" not in result.stdout.lower():
            return  
        can_reach = False
        try:
            with socket.create_connection(("10.0.0.1", 53), timeoute=2.5):
                can_reach = True
        except (socket.timeout, OSError, ConnectionRefusedError):
            can_reach = False
        if can_reach:
            return
        try:
            subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-NetFirewallRule | Where-Object { $_.DisplayName -like 'Shuriken*' } "
                 "| Remove-NetFirewallRule -Confirm:$false -ErrorAction SilentlyContinue"],
                capture_output=True, text=True, timeout=10,
                startupinfo=si, creationflags=cf
            )
        except Exception:
            pass
        for name in ["Ethernet", "Wi-Fi", "WiFi", "LAN"]:
            try:
                subprocess.run(
                    ["netsh", "interface", "ip", "set", "dns", f"name={name}", "dhcp"],
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
                 "Enable-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip -Confirm:$false -ErrorAction SilentlyContinue; "
                 "Enable-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6 -Confirm:$false -ErrorAction SilentlyContinue }"],
                capture_output=True, text=True, timeout=10,
                startupinfo=si, creationflags=cf
            )
        except Exception:
            pass
        try:
            subprocess.run(
                [str(WG_EXE), "/uninstalltunnelservice", SERVICE_NAME],
                capture_output=True, text=True, timeout=8,
                startupinfo=si, creationflags=cf
            )
        except Exception:
            pass
        try:
            subprocess.run(
                [str(WG_EXE), "/uninstallmanagerservice"],
                capture_output=True, text=True, timeout=6,
                startupinfo=si, creationflags=cf
            )
        except Exception:
            pass
        time.sleep(1.0)
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
                    with socket.create_connection(("10.0.0.1", 53), timeoute=2.5):
                        pass
                except:
                    pass
        except Exception:
            pass
        time.sleep(2)
    except Exception:
        pass

def run_adapter_repair_sequence():
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    cf = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    cmds = [
        [str(WG_EXE), "/uninstalltunnelservice", SERVICE_NAME],
        [str(WG_EXE), "/uninstallmanagerservice"],
        ["ipconfig", "/release"],
        ["ipconfig", "/renew"],
        ["ipconfig", "/flushdns"],
    ]
    try:
        _ps("Get-NetFirewallRule -DisplayName 'Shuriken*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -Confirm:$false")
    except:
        pass
    for cmd in cmds:
        try:
            subprocess.run(cmd, startupinfo=si, creationflags=cf, capture_output=True, timeout=12)
        except Exception as e:
            if DEBUG_MODE:
                print(f"[SafeRepair] Failed: {cmd} → {e}")
    time.sleep(2)

def cleanup_stale_wireguard_service():
    """Remove any stuck WireGuard tunnel service before reconnecting."""
    try:
        si = subprocess.STARTUPINFO()
        si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        cf = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        subprocess.run(
            [str(WG_EXE), "/uninstalltunnelservice", SERVICE_NAME],
            capture_output=True, text=True, timeout=5,
            startupinfo=si, creationflags=cf
        )
    except Exception:
        pass

def service_registry_exists(name: str) -> bool:
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WireGuard\Tunnels", 0, winreg.KEY_READ)
        i = 0
        while True:
            sub = winreg.EnumKey(key, i)
            if sub.lower() == name.lower():
                winreg.CloseKey(key)
                return True
            i += 1
    except OSError:
        pass
    return False

def uninstall_and_wait(name: str, timeout_s: float = 25.0) -> bool:
    """
    Aggressive WireGuard tunnel cleanup.
    Returns True if tunnel appears fully gone (interface + registry).
    """
    name_lower = name.lower()
    print(f"[UNINSTALL] Starting aggressive cleanup for '{name}'")

    # Phase 1: Repeated uninstall attempts
    for attempt in range(5):  # more attempts
        code, out, err = service_uninstall(name)
        msg = out or err or ""
        print(f"[UNINSTALL] Attempt {attempt+1}: exit={code}, msg={msg.strip()}")
        if code == 0 or "not installed" in msg.lower() or "does not exist" in msg.lower():
            print("[UNINSTALL] Uninstall reported success or already gone")
            break
        time.sleep(0.8)

    # Phase 2: Force-kill anything WireGuard-related
    for proc in ["wireguard.exe", "wireguard.exe"]:
        try:
            subprocess.run(
                ["taskkill", "/F", "/IM", proc],
                creationflags=subprocess.CREATE_NO_WINDOW,
                timeout=6,
                capture_output=True
            )
            print(f"[UNINSTALL] Killed {proc}")
        except:
            pass

    try:
        subprocess.run(
            ["sc", "stop", name],
            creationflags=subprocess.CREATE_NO_WINDOW,
            timeout=8,
            capture_output=True
        )
        print("[UNINSTALL] sc stop attempted")
    except:
        pass

    time.sleep(1.0)

    # Phase 3: Wait and poll multiple signals
    t_start = time.time()
    while time.time() - t_start < timeout_s:
        active = name_lower in wg_active_interfaces()
        reg_exists = service_registry_exists(name)

        if not active and not reg_exists:
            print("[UNINSTALL] Clean: no active interface + no registry entry")
            time.sleep(0.6)  # small grace
            return True

        print(f"[UNINSTALL] Still present → active={active}, reg={reg_exists}")
        time.sleep(0.5)

    # Phase 4: Nuclear — direct registry deletion (requires admin!)
    try:
        base_key = r"SOFTWARE\WireGuard\Tunnels"
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, base_key, 0, winreg.KEY_ALL_ACCESS
        ) as key:
            try:
                winreg.DeleteKey(key, name)
                print(f"[UNINSTALL] Deleted registry key: {base_key}\\{name}")
            except FileNotFoundError:
                pass  # already gone
            except OSError as e:
                print(f"[UNINSTALL] Registry delete failed: {e}")
    except Exception as e:
        print(f"[UNINSTALL] Could not open registry for deletion: {e}")

    # Final check
    time.sleep(1.2)
    final_active = name_lower in wg_active_interfaces()
    final_reg = service_registry_exists(name)
    success = not final_active and not final_reg

    print(f"[UNINSTALL] Final result: success={success} (active={final_active}, reg={final_reg})")
    return success

def install_with_retry(cfg: Path, retries: int = 10, base_delay: float = 0.5) -> tuple[bool, str]:
    delay = base_delay
    for attempt in range(retries):
        code, out, err = service_install(cfg)
        if code == 0:
            return True, ""
        msg = (err or out or "").lower()
        if "already installed" in msg or "already exists" in msg:
            uninstall_and_wait(SERVICE_NAME, timeout_s=5.0)
            time.sleep(delay)
            delay = min(delay * 2, 8.0)
            continue
        if DEBUG_MODE:
            print(f"[install_with_retry] Attempt {attempt + 1} failed: {err or out}")
        time.sleep(delay)
        delay = min(delay * 2, 8.0)

    code, out, err = service_install(cfg)
    return (code == 0, (err or out or "Failed to install tunnel service after retries."))

# -------------------------- Config scanning ----------------------
def pretty_name_for(filename: str) -> str:
    return SERVER_METADATA.get(filename, {"name": filename}).get("name", filename)

def list_conf_files() -> list[Path]:
    search_roots: list[Path] = []
    try:
        if CONFIG_DIR.exists():
            search_roots.append(CONFIG_DIR)
    except Exception:
        pass
    seen = set()
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

# -------------------------- NO-GUI ops ---------------------------
def vpn_up_nogui() -> tuple[bool, str | None, Path | None]:
    saved = read_registry()
    if not (saved and saved.is_file()):
        return False, "Please select a server from the list first.", None
    try:
        CONFIG_DIR.resolve(strict=True)
    except Exception:
        return False, "CONFIG_DIR is missing. Please reinstall application.", None
    if CONFIG_DIR not in saved.parents:
        return False, f"Selected config is outside allowed folder: {saved}. Please reinstall application.", None
    try:
        cfg = copy_conf_to_progdata(saved)
    except Exception as e:
        return False, str(e), None

    # --- Apply DNS leak block + full kill switch before tunnel install ---
    add_dns_leak_block()
    add_kill_switch()

    ok, msg = install_with_retry(cfg)
    if not ok:
        remove_dns_leak_block()
        remove_kill_switch()
        return False, msg, None

    if DEBUG_MODE:
        print(f"[DEBUG] Waiting up to 40s for interface '{SERVICE_NAME}'...")

    t0 = time.time()
    timeout = 40.0
    tunnel_detected_time = None

    while time.time() - t0 < timeout:
        if is_vpn_up():
            if tunnel_detected_time is None:
                tunnel_detected_time = time.time()
                if DEBUG_MODE:
                    print(f"[DEBUG] Tunnel detected at {tunnel_detected_time:.1f}s — giving Windows 2s to settle before rename")

            # Give Windows ~2 seconds after first detection to fully create/register the adapter
            if time.time() - tunnel_detected_time < 2.0:
                time.sleep(0.3)
                continue

            # Tunnel is up: remove only DNS block ---
            remove_dns_leak_block()
            # Kill switch stays active to protect if the tunnel drops later

            # ── Improved rename: retry multiple times with better targeting ──
            renamed = False
            for rename_attempt in range(1, 6):
                if DEBUG_MODE:
                    print(f"[DEBUG] Rename attempt {rename_attempt}/5...")

                # Prefer exact name match first, fallback to any WireGuard adapter
                ps_command = (
                    r"Get-NetAdapter | Where-Object { "
                    r"    ($_.Name -eq '" + SERVICE_NAME + r"') -or "
                    r"    ($_.InterfaceDescription -like '*WireGuard*') "
                    r"} | Select-Object -First 1 -ExpandProperty Name"
                )
                code, out, err = _ps(ps_command)
                current_name = out.strip() if code == 0 and out.strip() else ""

                if not current_name:
                    if DEBUG_MODE:
                        print("[DEBUG] No matching adapter found for rename")
                    break

                if current_name == SERVICE_NAME:
                    if DEBUG_MODE:
                        print(f"[DEBUG] Adapter already correctly named '{SERVICE_NAME}'")
                    renamed = True
                    break

                # Build rename command
                safe_current = current_name.replace("'", "''").replace('"', '""')
                rename_ps = (
                    f"Rename-NetAdapter -Name '{safe_current}' "
                    f"-NewName '{SERVICE_NAME}' -Confirm:$false -ErrorAction SilentlyContinue"
                )

                try:
                    ctypes.windll.shell32.ShellExecuteW(
                        None, "runas",
                        "powershell.exe",
                        f'-NoProfile -Command "{rename_ps}"',
                        None,
                        0  # SW_HIDE
                    )
                    if DEBUG_MODE:
                        print(f"[DEBUG] Rename requested for '{current_name}' → '{SERVICE_NAME}' (attempt {rename_attempt})")
                except Exception as e:
                    if DEBUG_MODE:
                        print(f"[DEBUG] ShellExecuteW failed on attempt {rename_attempt}: {e}")

                time.sleep(1.2)  # give time for rename to apply

                # Quick re-check
                code, out, _ = _ps(f"Get-NetAdapter -Name '{SERVICE_NAME}' -ErrorAction SilentlyContinue | Select -Expand Name")
                if code == 0 and out.strip() == SERVICE_NAME:
                    if DEBUG_MODE:
                        print(f"[DEBUG] Rename successful after attempt {rename_attempt}")
                    renamed = True
                    break

            # ── Fix persistent numbered profile name (UI display) via registry ──
            if DEBUG_MODE:
                print("[DEBUG] Fixing NetworkList profile name to remove numbering")

            profile_fix_ps = (
                r"$wgAdapter = Get-NetAdapter | Where-Object { $_.Name -eq '" + SERVICE_NAME + r"' -or $_.InterfaceDescription -like '*WireGuard*' } | Select-Object -First 1;"
                r"if ($wgAdapter) {"
                r"  $profilesPath = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles';"
                r"  Get-ChildItem $profilesPath -ErrorAction SilentlyContinue | ForEach-Object {"
                r"    $profile = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue;"
                r"    if ($profile.ProfileName -like '*Shuriken*' -and ($profile.Guid -ne $null)) {"
                r"      Set-ItemProperty -Path $_.PSPath -Name 'ProfileName' -Value '" + SERVICE_NAME + r"' -Force -ErrorAction SilentlyContinue;"
                r"      Write-Output \"Updated profile $($profile.ProfileName) to " + SERVICE_NAME + r"\";"
                r"    }"
                r"  }"
                r"} else { Write-Output 'No WireGuard adapter found for profile fix' }"
            )

            try:
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas",
                    "powershell.exe",
                    f'-NoProfile -ExecutionPolicy Bypass -Command "{profile_fix_ps}"',
                    None,
                    0  # SW_HIDE
                )
                if DEBUG_MODE:
                    print("[DEBUG] Profile name reset requested (elevated PowerShell)")
                time.sleep(2.0)  # Allow registry + UI to settle
            except Exception as e:
                if DEBUG_MODE:
                    print(f"[DEBUG] Profile fix launch failed: {e}")

            if not renamed and DEBUG_MODE:
                print("[DEBUG] Rename did not succeed after 5 attempts — number may still appear")

            return True, None, saved

        time.sleep(0.2)

    remove_dns_leak_block()
    remove_kill_switch()
    return False, "Tunnel failed to start within 40 seconds.", None

def vpn_down_nogui() -> tuple[bool, str | None]:
    success = uninstall_and_wait(SERVICE_NAME, timeout_s=15.0)
    remove_kill_switch()
    remove_dns_leak_block()
    enable_ipv6_on_non_wg_adapters()
    if success:
        return True, None
    else:
        return False, "Tunnel service did not fully stop (still visible in wg show)"

def switch_server_nogui(new_conf: Path) -> tuple[bool, str | None]:
    # Switch WireGuard server safely while keeping firewall protection
    write_registry(new_conf)
    cfg = copy_conf_to_progdata(new_conf)

    # Apply DNS leak block + full kill switch during server switch
    add_dns_leak_block()
    add_kill_switch()

    try:
        if is_vpn_up():
            uninstall_and_wait(SERVICE_NAME, timeout_s=8.0)
        ok, msg = install_with_retry(cfg)
        if not ok:
            remove_dns_leak_block()
            remove_kill_switch()
            return False, (msg or "Failed to install after switch.")
        t0 = time.time()
        while time.time() - t0 < 5.0:
            if is_vpn_up():
                # --- Success: remove only DNS block, keep kill switch active ---
                remove_dns_leak_block()
                return True, None
            time.sleep(0.1)

        # --- Timed out waiting for tunnel ---
        remove_dns_leak_block()
        remove_kill_switch()
        return False, "Switched but interface not detected."

    finally:
        remove_dns_leak_block()