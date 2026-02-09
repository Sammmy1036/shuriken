from pathlib import Path
import subprocess, time, socket, winreg
from constants import CONFIG_DIR, CONFIG_NAME, SERVICE_NAME, WG_PROGDATA, WG_EXE, WG_CLI, DEBUG_MODE
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
    - Resolves symlinks/hardlinks
    - Enforces strict containment in CONFIG_DIR
    - Prevents arbitrary file read
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
            f"Rejected:   {src_resolved}\n"
            f"Parent:     {src_resolved.parent}"
        )
    WG_PROGDATA.mkdir(parents=True, exist_ok=True)
    dst = WG_PROGDATA / CONFIG_NAME
    text = src_resolved.read_text(encoding="utf-8", errors="ignore")
    lines = [ln.rstrip("\n") for ln in text.splitlines()]
    new_lines = []
    for ln in lines:
        s = ln.strip()
        if s.lower().startswith("endpoint"):
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

def uninstall_and_wait(name: str, timeout_s: float = 15.0) -> bool:
    for attempt in range(3):
        code, out, err = service_uninstall(name)
        if code == 0:
            print(f"[UNINSTALL] Attempt {attempt+1} succeeded (exit 0)")
        t0 = time.time()
        while time.time() - t0 < timeout_s:
            if (name.lower() not in wg_active_interfaces() and
                not service_registry_exists(name)):
                return True
            time.sleep(0.3)
        if attempt == 2:
            try:
                subprocess.run(["taskkill", "/F", "/IM", "wireguard.exe"], 
                               creationflags=CREATE_NO_WINDOW, timeout=5)
                subprocess.run(["sc", "stop", name], creationflags=CREATE_NO_WINDOW, timeout=5)
                time.sleep(1)
            except:
                pass
    return name.lower() not in wg_active_interfaces() and not service_registry_exists(name)

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
    while time.time() - t0 < timeout:
        if is_vpn_up():
            # Tunnel is up: remove only DNS block ---
            remove_dns_leak_block()
            # Kill switch stays active to protect if the tunnel drops later
            try:
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas",
                    "powershell.exe",
                    '-Command "Get-NetAdapter | Where-Object {$_.InterfaceDescription -like \'*WireGuard*\'} | '
                    'Rename-NetAdapter -NewName \'Shuriken\' -Confirm:$false -ErrorAction SilentlyContinue"',
                    None,
                    0
                )
                if DEBUG_MODE:
                    print("[DEBUG] Adapter rename requested silently via elevated PowerShell")
            except Exception as e:
                if DEBUG_MODE:
                    print(f"[DEBUG] Silent rename failed (non-critical): {e}")
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