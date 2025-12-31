# Shuriken v1.0.0.0 by Sammmy1036

__version__ = "1.0.0.0"

import os, sys, time, threading, subprocess, winreg, ctypes, win32con, win32gui, json, atexit, random, ssl
import tkinter as tk
import customtkinter as ctk
import ctypes.wintypes as wintypes                  
import urllib.request
from customtkinter import CTkScrollableFrame, CTkFrame, CTkEntry, CTkLabel, CTkButton, CTkImage
from tkinter import messagebox, ttk
from pathlib import Path
from PIL import Image as PILImage
from PIL import ImageTk

try:
    import pythoncom
    import win32com.client
    _HAVE_WMI = True
except Exception:
    _HAVE_WMI = False
    pythoncom = None
    win32com = None

ERROR_ALREADY_EXISTS = 183

def acquire_mutex(name: str = "ShurikenInstanceLock") -> bool:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    handle = kernel32.CreateMutexW(None, wintypes.BOOL(True), name)
    last_err = ctypes.get_last_error()
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())

    if last_err == ERROR_ALREADY_EXISTS:
        kernel32.CloseHandle(handle)
        return False
    return True

# -------------------------- Tray / Pillow --------------------------
try:
    import pystray
    from PIL import Image, ImageDraw
    try:
        import win32api
        _HAVE_PYWIN32 = True
    except Exception:
        _HAVE_PYWIN32 = False
except Exception:
    pystray = None
    Image = None
    ImageDraw = None
    _HAVE_PYWIN32 = False

try:
    from PIL import Image as PILImage
    from PIL import ImageTk
    _HAVE_PIL_IMAGETK = True
except Exception:
    PILImage = None
    ImageTk = None
    _HAVE_PIL_IMAGETK = False

def safe_messagebox(kind, title, message, parent=None):
    from tkinter import messagebox
    import tkinter as tk

    if parent is None:
        parent = tk._default_root
        if parent is None:
            return

    if kind == "info":
        messagebox.showinfo(title, message, parent=parent)
    elif kind == "warn":
        messagebox.showwarning(title, message, parent=parent)
    elif kind == "error":
        messagebox.showerror(title, message, parent=parent)
    else:
        messagebox.showinfo(title, message, parent=parent)

# -------------------------- Paths --------------------------------
def setup_runtime_paths():
    """
    Determine runtime directories for icons, configs, etc.
    Always prioritizes a 'Config' folder next to the .exe,
    but falls back safely if the app is installed in a protected location.
    """
    global APP_DIR, BUNDLED_BASE_DIR, ICON_PATH, CONFIG_DIR

    frozen = getattr(sys, "frozen", False)

    try:
        if frozen:
            # Running as packaged EXE
            APP_DIR = Path(sys.executable).parent
            BUNDLED_BASE_DIR = Path(getattr(sys, "_MEIPASS", APP_DIR))
        else:
            # Running from source
            APP_DIR = Path(__file__).resolve().parent
            BUNDLED_BASE_DIR = APP_DIR

        # --- Icon path resolution ---
        ICON_PATH = BUNDLED_BASE_DIR / "Icons" / "PG.ico"
        if not ICON_PATH.exists():
            ICON_PATH = APP_DIR / "Icons" / "PG.ico"

        # --- Prefer Config folder next to the executable ---
        external_config = APP_DIR / "Config"
        if external_config.exists():
            CONFIG_DIR = external_config
        else:
            try:
                external_config.mkdir(parents=True, exist_ok=True)
                CONFIG_DIR = external_config
            except Exception:
                # Always fall back instead of crashing
                fallback = Path(os.environ.get("APPDATA", ".")) / "Shuriken" / "Config"
                try:
                    fallback.mkdir(parents=True, exist_ok=True)
                except Exception:
                    fallback = Path(os.environ.get("TEMP", ".")) / "Shuriken_Config"
                    fallback.mkdir(parents=True, exist_ok=True)
                CONFIG_DIR = fallback

    except Exception as e:
        # As a final safety net: fallback to TEMP so GUI can still start
        CONFIG_DIR = Path(os.environ.get("TEMP", ".")) / "Shuriken_Config"
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        print("setup_runtime_paths() failed, using TEMP:", e, CONFIG_DIR)

setup_runtime_paths()

DEBUG_MODE = True

APP_NAME     = "Shuriken"
CONFIG_NAME  = "Shuriken.conf"
SERVICE_NAME = Path(CONFIG_NAME).stem
REG_PATH     = r"Software\Shuriken"
REG_VAL      = "LastConfig"

ASSETS_DIR = BUNDLED_BASE_DIR / "assets"
if not ASSETS_DIR.exists():
    ASSETS_DIR = APP_DIR / "assets"

LOCKED_OVERLAY_PATH = ASSETS_DIR / "locked.png"
UNLOCKED_OVERLAY_PATH = ASSETS_DIR / "unlocked.png"

# --- Flags for all Countries
FLAGS_DIR = BUNDLED_BASE_DIR / "flags"
if not FLAGS_DIR.exists():
    FLAGS_DIR = APP_DIR / "flags"
FLAG_CACHE = {}  # Cache loaded ImageTk photos to avoid garbage collection issues

# --- Custom Theme
THEME_PATH = APP_DIR / "shuriken_theme.json"
if not THEME_PATH.exists():
    THEME_PATH = BUNDLED_BASE_DIR / "shuriken_theme.json"

# --- Persistent Connection State ---
APPDATA = Path(os.environ.get("APPDATA", ""))
STATE_DIR = APPDATA / "Shuriken"

# ----------------------------------------------------------------------
#  Persistent connection-state file (AppData)
# ----------------------------------------------------------------------
# --- Safe WireGuard path handling (works even if not installed) ---
def get_wg_paths():
    progdata = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "WireGuard"

    # Check both Program Files directories
    wg_dir = Path(r"C:\Program Files\WireGuard")
    if not wg_dir.exists():
        wg_dir = Path(r"C:\Program Files (x86)\WireGuard")

    # Main executables
    wg_exe = wg_dir / "wireguard.exe"
    wg_cli = wg_dir / "wg.exe"

    # Fallbacks if somehow not found
    if not wg_exe.exists() and (wg_dir / "Data" / "wireguard.exe").exists():
        wg_exe = wg_dir / "Data" / "wireguard.exe"
    if not wg_cli.exists() and (wg_dir / "Data" / "wg.exe").exists():
        wg_cli = wg_dir / "Data" / "wg.exe"

    return progdata, wg_dir, wg_exe, wg_cli

WG_PROGDATA, WG_DIR, WG_EXE, WG_CLI = get_wg_paths()

# -------------------------- Helpers -------------------------------
def run(cmd: list[str]) -> tuple[int, str, str]:
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    creationflags = 0
    if hasattr(subprocess, "CREATE_NO_WINDOW"):
        creationflags |= subprocess.CREATE_NO_WINDOW

    p = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        startupinfo=startupinfo,
        creationflags=creationflags,
    )
    out, err = p.communicate()
    return p.returncode, out, err

def _ps(cmd: str) -> tuple[int, str, str]:
    return run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd])


def disable_ipv6_on_non_wg_adapters():
    """BLOCK ALL IPv6 traffic on non-WireGuard adapters using firewall."""
    try:
        cmd = (
            "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Name -notlike '*WireGuard*' } "
            "| ForEach-Object { "
            "  $name = $_.Name; "
            "  New-NetFirewallRule -DisplayName \"Shuriken Block IPv6 on `$name\" "
            "  -Direction Outbound -Action Block -Protocol Any "
            "  -LocalAddress Any -RemoteAddress Any "
            "  -InterfaceAlias `$name -Profile Any -Enabled True "
            "  -ErrorAction SilentlyContinue | Out-Null; "
            "  New-NetFirewallRule -DisplayName \"Shuriken Block IPv6 on `$name\" "
            "  -Direction Inbound -Action Block -Protocol Any "
            "  -LocalAddress Any -RemoteAddress Any "
            "  -InterfaceAlias `$name -Profile Any -Enabled True "
            "  -ErrorAction SilentlyContinue | Out-Null "
            "} "
            "Get-NetFirewallRule -DisplayName 'Shuriken Block IPv6 on *' -ErrorAction SilentlyContinue | Out-Null"
        )
        _ps(cmd)
    except Exception:
        pass


def enable_ipv6_on_non_wg_adapters():
    """REMOVE all Shuriken IPv6 firewall block rules."""
    try:
        _ps("Get-NetFirewallRule -DisplayName 'Shuriken Block IPv6 on *' "
            "-ErrorAction SilentlyContinue | Remove-NetFirewallRule -Confirm:$false")
    except Exception:
        pass

atexit.register(enable_ipv6_on_non_wg_adapters)

# -------------------------- DNS leak block -----------------------
_DNS_BLOCK_RULES: list[str] = []

def _list_non_wg_adapters() -> list[str]:
    """Get list of active network adapters excluding WireGuard/tunnel ones."""
    code, out, _ = _ps(
        r"(Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -ExpandProperty Name) -join '`n'"
    )
    aliases = []
    if code == 0 and out:
        for name in out.splitlines():
            n = name.strip().lower()
            if n and "wireguard" not in n and "tunnel" not in n and "wg" not in n:
                aliases.append(name.strip())
    return aliases

def add_dns_leak_block():
    """Block DNS (53, 853) and DoH (443) on non-WireGuard interfaces, allow Windows Update."""
    remove_dns_leak_block()  # Clean slate
    aliases = _list_non_wg_adapters()
    if not aliases:
        return

    cmds = []
    names = []

    # === 1. Block standard DNS + DoT ===
    dns_ports = [
        ("TCP", 53),
        ("UDP", 53),
        ("TCP", 853),
        ("UDP", 853),
    ]

    for alias in aliases:
        safe_alias = alias.replace("'", "''").replace("`", "``").replace("$", "`$")
        for proto, port in dns_ports:
            rule_name = f"Shuriken DNS Block {proto} {port} on {alias}"
            safe_name = rule_name.replace("'", "''")

            check_cmd = f"Get-NetFirewallRule -DisplayName '{safe_name}' -ErrorAction SilentlyContinue"
            code, out, _ = _ps(check_cmd)
            if code == 0 and out.strip():
                continue

            names.append(rule_name)
            cmds.append(
                f"New-NetFirewallRule -DisplayName '{safe_name}' "
                f"-Direction Outbound -Protocol {proto} -RemotePort {port} "
                f"-Action Block -Profile Any -Enabled True "
                f"-InterfaceAlias '{safe_alias}' -ErrorAction SilentlyContinue | Out-Null"
            )

    # === 2. Block ALL TCP 443 (DoH) on non-WG interfaces ===
    for alias in aliases:
        safe_alias = alias.replace("'", "''").replace("`", "``").replace("$", "`$")
        rule_name = f"Shuriken Block DoH 443 on {alias}"
        safe_name = rule_name.replace("'", "''")

        check_cmd = f"Get-NetFirewallRule -DisplayName '{safe_name}' -ErrorAction SilentlyContinue"
        code, out, _ = _ps(check_cmd)
        if code == 0 and out.strip():
            continue

        names.append(rule_name)
        cmds.append(
            f"New-NetFirewallRule -DisplayName '{safe_name}' "
            f"-Direction Outbound -Protocol TCP -RemotePort 443 "
            f"-Action Block -Profile Any -Enabled True "
            f"-InterfaceAlias '{safe_alias}' -ErrorAction SilentlyContinue | Out-Null"
        )

    # === 3. ALLOW Windows Update domains (EXCEPTION) ===
    update_domains = [
        "www.microsoft.com",
        "*.microsoft.com",
        "*.msftconnecttest.com",
        "*.msftncsi.com",
        "settings-win.data.microsoft.com",
        "*.wdcp.microsoft.com",
        "*.dl.delivery.mp.microsoft.com",        
        "windowsupdate.microsoft.com",
        "*.windowsupdate.microsoft.com",
        "update.microsoft.com",
        "*.update.microsoft.com",
        "download.windowsupdate.com",
        "*.download.windowsupdate.com",
        "wustat.windows.com",
        "delivery.mp.microsoft.com",
        "*.delivery.mp.microsoft.com",
        "storeedgefd.dsx.mp.microsoft.com",
    ]

    for domain in update_domains:
        safe_domain = domain.replace("'", "''")
        rule_name = f"Shuriken Allow Update {domain}"
        safe_name = rule_name.replace("'", "''")

        check_cmd = f"Get-NetFirewallRule -DisplayName '{safe_name}' -ErrorAction SilentlyContinue"
        code, out, _ = _ps(check_cmd)
        if code == 0 and out.strip():
            continue

        names.append(rule_name)
        cmds.append(
            f"New-NetFirewallRule -DisplayName '{safe_name}' "
            f"-Direction Outbound -Protocol TCP -RemotePort 443 "
            f"-Action Allow -Profile Any -Enabled True "
            f"-RemoteAddress '{safe_domain}' -ErrorAction SilentlyContinue | Out-Null"
        )

    if cmds:
        _ps("; ".join(cmds))
        _DNS_BLOCK_RULES[:] = names

def remove_dns_leak_block():
    """Remove all Shuriken DNS + DoH block rules."""
    if _DNS_BLOCK_RULES:
        rm_cmds = [
            f"Get-NetFirewallRule -DisplayName '{rn.replace("'", "''")}' "
            "-ErrorAction SilentlyContinue | "
            "Remove-NetFirewallRule -Confirm:$false -ErrorAction SilentlyContinue | Out-Null"
            for rn in _DNS_BLOCK_RULES
        ]
        _ps("; ".join(rm_cmds))
        _DNS_BLOCK_RULES.clear()
    else:
        _ps(
            "Get-NetFirewallRule -DisplayName 'Shuriken*' "
            "-ErrorAction SilentlyContinue | "
            "Remove-NetFirewallRule -Confirm:$false -ErrorAction SilentlyContinue | Out-Null"
        )

# -------------------------- Full Kill Switch --------------------
_KILLSWITCH_RULES: list[str] = []

def add_kill_switch():
    """
    Enforce a full kill switch: block all outbound traffic on non-WireGuard
    interfaces, allowing only traffic through WireGuard tunnels.
    """
    remove_kill_switch()  # <<< ALWAYS start completely clean — this fixes the bug
    aliases = _list_non_wg_adapters()
    if not aliases:
        return

    cmds = []
    names: list[str] = []

    # Block all outbound traffic on non-WireGuard interfaces
    for alias in aliases:
        safe = alias.replace("'", "''").replace('`', '``').replace('$', '`$')
        rn = f"Shuriken KillSwitch Block {alias}"
        rn_safe = rn.replace("'", "''")

        names.append(rn)  # <<< Always add to cache
        cmds.append(
            f"New-NetFirewallRule -DisplayName '{rn_safe}' -Direction Outbound "
            f"-Action Block -Enabled True -Profile Any -InterfaceAlias '{safe}' | Out-Null"
        )

    # Allow traffic through WireGuard interface(s)
    rn_allow = "Shuriken KillSwitch Allow WireGuard"
    safe_allow = rn_allow.replace("'", "''")

    names.append(rn_allow)  # <<< Always add allow rule to cache too
    cmds.append(
        f"New-NetFirewallRule -DisplayName '{safe_allow}' -Direction Outbound "
        f"-Action Allow -Enabled True -Profile Any -InterfaceAlias 'WireGuard*' | Out-Null"
    )

    if cmds:
        _ps("; ".join(cmds))
        _KILLSWITCH_RULES[:] = names  # Cache is always complete


def remove_kill_switch():
    """Delete every Shuriken kill-switch rule."""
    if _KILLSWITCH_RULES:
        rm_cmds = [
            f"Get-NetFirewallRule -DisplayName '{rn.replace("'", "''")}' "
            "-ErrorAction SilentlyContinue | Remove-NetFirewallRule -Confirm:$false | Out-Null"
            for rn in _KILLSWITCH_RULES
        ]
        _ps("; ".join(rm_cmds))
        _KILLSWITCH_RULES.clear()

    # Extra safety: broad catch-all for any stray Shuriken kill-switch rules
    _ps(
        "Get-NetFirewallRule -DisplayName 'Shuriken KillSwitch*' "
        "-ErrorAction SilentlyContinue | Remove-NetFirewallRule -Confirm:$false | Out-Null"
    )

# -------------------------- Admin / Registry --------------------
def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def read_registry() -> Path | None:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_READ) as k:
            val, _ = winreg.QueryValueEx(k, REG_VAL)
            p = Path(val)

            # --- FULL SECURITY VALIDATION ---
            try:
                config_dir_resolved = CONFIG_DIR.resolve(strict=True)
            except Exception:
                return None  # CONFIG_DIR broken → reject all

            try:
                resolved = p.resolve(strict=True)  # Must exist + follow symlinks
            except FileNotFoundError:
                return None
            except Exception:
                return None  # Invalid path, symlink loop, etc.

            # Must be strictly inside CONFIG_DIR
            if config_dir_resolved not in resolved.parents and resolved != config_dir_resolved:
                return None

            # Optional: auto-correct legacy paths (only if safe)
            if not resolved.exists():
                candidate = config_dir_resolved / p.name
                if candidate.exists() and candidate.resolve(strict=True) == candidate:
                    write_registry(candidate)
                    return candidate

            return resolved

    except FileNotFoundError:
        return None
    except Exception:
        return None

def write_registry(p: Path) -> None:
    k = winreg.CreateKey(winreg.HKEY_CURRENT_USER, REG_PATH)
    winreg.SetValueEx(k, REG_VAL, 0, winreg.REG_SZ, str(p))
    winreg.CloseKey(k)

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

    # --- Resolve CONFIG_DIR ---
    try:
        config_dir_resolved = CONFIG_DIR.resolve(strict=True)
    except Exception as e:
        raise RuntimeError("CONFIG_DIR is not accessible") from e

    # --- Enforce strict containment ---
    if config_dir_resolved not in src_resolved.parents:
        raise ValueError(
            f"Config file must be inside CONFIG_DIR.\n"
            f"CONFIG_DIR: {config_dir_resolved}\n"
            f"Rejected:   {src_resolved}\n"
            f"Parent:     {src_resolved.parent}"
        )

    # --- Copy and sanitize ---
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

def reset_firewall_if_blocked():
    try: _ps("Get-NetFirewallRule -DisplayName 'Shuriken*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -Confirm:$false")
    except: pass

def repair_network_stack_if_stuck():
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

        ping = subprocess.run(
            ["ping", "-n", "1", "1.1.1.1"],
            capture_output=True, text=True, timeout=3,
            startupinfo=si, creationflags=cf
        )
        if ping.returncode == 0:
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
                ["nslookup", "cloudflare.com"],
                capture_output=True, text=True, timeout=5,
                startupinfo=si, creationflags=cf
            )
            if test_dns.returncode != 0:
                subprocess.run(
                    ["ping", "-n", "1", "8.8.8.8"],
                    capture_output=True, text=True, timeout=3,
                    startupinfo=si, creationflags=cf
                )
        except Exception:
            pass

        time.sleep(2)

    except Exception:
        pass

class AdapterWatcher:
    """
    Monitors a list of physical adapters (Wi-Fi, Ethernet, …) and runs a
    repair routine the moment any of them transitions from Disabled → Enabled.
    """
    # ---------- CONFIG ----------
    ADAPTERS = ["Wi-Fi", "Ethernet"]
    POLL_SECONDS = 1.0
    # --------------------------------

    def __init__(self, repair_callback):
        self.repair_callback = repair_callback
        self._stop_event = threading.Event()
        self._thread = None
        self._states = {}

    # ---- WMI helper ---------------------------------------------------
    @staticmethod
    def _adapter_enabled(name: str) -> bool | None:
        """Return True=Enabled, False=Disabled, None=not found."""
        if not _HAVE_WMI:
            return None
        try:
            pythoncom.CoInitialize()
            wmi = win32com.client.GetObject(r"winmgmts:\\.\root\cimv2")
            query = f"SELECT NetConnectionStatus FROM Win32_NetworkAdapter WHERE NetConnectionID = '{name}'"
            results = wmi.ExecQuery(query)
            if results.Count == 0:
                return None
            code = results.ItemIndex(0).NetConnectionStatus

            # Wi-Fi specific codes
            if name == "Wi-Fi":
                return code in {2, 5, 7}          # Connected / Connecting / Authenticating
            # Ethernet
            return code == 2                     # Connected
        except Exception:
            return None
        finally:
            pythoncom.CoUninitialize()

    # ---- Logging ------------------------------------------------------
    @staticmethod
    def _log(msg: str):
        if DEBUG_MODE:
            from datetime import datetime
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            line = f"[AdapterWatcher] {ts} {msg}\n"
            try:
                with open("Shuriken_Log.txt", "a", encoding="utf-8") as f:
                    f.write(line)
            except Exception:
                pass
            print(line.strip())

    # ---- Main loop ----------------------------------------------------
    def _run(self):
        self._log(f"Started monitoring: {', '.join(self.ADAPTERS)}")

        # initialise states
        for name in self.ADAPTERS:
            self._states[name] = self._adapter_enabled(name)

        while not self._stop_event.is_set():
            for name in self.ADAPTERS:
                cur = self._adapter_enabled(name)
                prev = self._states.get(name)

                # Adapter appeared → was disabled before
                if cur is True and prev is False:
                    self._log(f"{name} RE-ENABLED → running repair")
                    self.repair_callback()

                # Keep state up-to-date (including None → not present)
                self._states[name] = cur

            time.sleep(self.POLL_SECONDS)

    # ---- Public API ---------------------------------------------------
    def start(self):
        if self._thread is None or not self._thread.is_alive():
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
            self._log("Thread started")

    def stop(self):
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        self._log("Thread stopped")

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

def uninstall_and_wait(name: str, timeout_s: float = 10.0) -> None:
    for _ in range(2):
        service_uninstall(name)
        t0 = time.time()
        while time.time() - t0 < timeout_s:
            if name.lower() not in wg_active_interfaces() and not service_registry_exists(name):
                return
            time.sleep(0.1)
    service_uninstall(name)
    t0 = time.time()
    while time.time() - t0 < timeout_s:
        if name.lower() not in wg_active_interfaces() and not service_registry_exists(name):
            return
        time.sleep(0.2)

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
SERVER_METADATA = {
    "Shuriken-CA.conf": {"city": "Los Angeles", "state": "CA", "country": "US", "name": "Shuriken-CA"},
}

# WILL LATER ADD THE BELOW TO BE IN A SEPARATE TAB FOR SHURIKEN SO IT WILL READ THE USERS OWN CONFIGS 
USER_SERVER_METADATA = {
   '''Make a User.json file so the user can edit their own servers info'''
   '''"###": {"City": "###", "state": "###", "country": "###", "name": "###"},'''
    "wg-CA-FREE-1.conf":  {"city": "Toronto", "state": "ON", "country": "CA", "name": "Toronto-1"},
    "wg-CA-FREE-2.conf":  {"city": "Toronto", "state": "ON", "country": "CA", "name": "Toronto-2"},
    "wg-CA-FREE-3.conf":  {"city": "Toronto", "state": "ON", "country": "CA", "name": "Toronto-3"},
    "wg-CA-FREE-4.conf":  {"city": "Toronto", "state": "ON", "country": "CA", "name": "Toronto-4"},
    "wg-CA-FREE-5.conf":  {"city": "Toronto", "state": "ON", "country": "CA", "name": "Toronto-5"},
    "wg-CA-FREE-6.conf":  {"city": "Toronto", "state": "ON", "country": "CA", "name": "Toronto-6"},
    "wg-CA-FREE-7.conf":  {"city": "Toronto", "state": "ON", "country": "CA", "name": "Toronto-7"},
    "wg-CA-FREE-8.conf":  {"city": "Toronto", "state": "ON", "country": "CA", "name": "Toronto-8"},
    "wg-CA-FREE-13.conf": {"city": "Vancouver", "state": "BC", "country": "CA", "name": "Vancouver-13"},
    "wg-CH-FREE-4.conf":  {"city": "Zurich", "state": "", "country": "CH", "name": "Zurich-4"},
    "wg-CH-FREE-8.conf":  {"city": "Zurich", "state": "", "country": "CH", "name": "Zurich-8"},
    "wg-JP-FREE-3.conf":  {"city": "Osaka", "state": "", "country": "JP", "name": "Osaka-3"},
    "wg-JP-FREE-18.conf": {"city": "Tokyo", "state": "", "country": "JP", "name": "Tokyo-18"},
    "wg-JP-FREE-19.conf": {"city": "Tokyo", "state": "", "country": "JP", "name": "Tokyo-19"},
    "wg-JP-FREE-26.conf": {"city": "Tokyo", "state": "", "country": "JP", "name": "Tokyo-26"},
    "wg-JP-FREE-27.conf": {"city": "Tokyo", "state": "", "country": "JP", "name": "Tokyo-27"},
    "wg-JP-FREE-28.conf": {"city": "Tokyo", "state": "", "country": "JP", "name": "Tokyo-28"},
    "wg-JP-FREE-29.conf": {"city": "Tokyo", "state": "", "country": "JP", "name": "Tokyo-29"},
    "wg-JP-FREE-30.conf": {"city": "Tokyo", "state": "", "country": "JP", "name": "Tokyo-30"},
    "wg-JP-FREE-31.conf": {"city": "Tokyo", "state": "", "country": "JP", "name": "Tokyo-31"},
    "wg-MX-FREE-4.conf":  {"city": "Mexico City", "state": "", "country": "MX", "name": "MX-4"},
    "wg-NL-FREE-2.conf":  {"city": "Amsterdam", "state": "", "country": "NL", "name": "Amsterdam-2"},
    "wg-NO-FREE-7.conf":  {"city": "Oslo", "state": "", "country": "NO", "name": "Oslo-7"},
    "wg-NO-FREE-8.conf":  {"city": "Oslo", "state": "", "country": "NO", "name": "Oslo-8"},
    "wg-NO-FREE-9.conf":  {"city": "Oslo", "state": "", "country": "NO", "name": "Oslo-9"},
    "wg-PL-FREE-2.conf":  {"city": "Warsaw", "state": "", "country": "PL", "name": "Warsaw-2"},
    "wg-PL-FREE-17.conf": {"city": "Warsaw", "state": "", "country": "PL", "name": "Warsaw-17"},
    "wg-RO-FREE-21.conf": {"city": "Bucharest", "state": "", "country": "RO", "name": "Bucharest-21"},
    "wg-RO-FREE-27.conf": {"city": "Bucharest", "state": "", "country": "RO", "name": "Bucharest-27"},
    "wg-RO-FREE-28.conf": {"city": "Bucharest", "state": "", "country": "RO", "name": "Bucharest-28"},
    "wg-SG-FREE-4.conf":  {"city": "Singapore", "state": "", "country": "SG", "name": "SG-4"},
    "wg-SG-FREE-7.conf":  {"city": "Singapore", "state": "", "country": "SG", "name": "SG-7"},
    "wg-US-FREE-1.conf":  {"city": "Los Angeles", "state": "CA", "country": "US", "name": "LA-1"},
    "wg-US-FREE-2.conf":  {"city": "Los Angeles", "state": "CA", "country": "US", "name": "LA-2"},
    "wg-US-FREE-3.conf":  {"city": "Miami", "state": "FL", "country": "US", "name": "Miami-3"},
    "wg-US-FREE-4.conf":  {"city": "Los Angeles", "state": "CA", "country": "US", "name": "LA-4"},
    "wg-US-FREE-5.conf":  {"city": "Seattle", "state": "WA", "country": "US", "name": "Seattle-5"},
    "wg-US-FREE-6.conf":  {"city": "Dallas", "state": "TX", "country": "US", "name": "Dallas-6"},
    "wg-US-FREE-27.conf": {"city": "Seattle", "state": "WA", "country": "US", "name": "Seattle-27"},
    "wg-US-FREE-36.conf": {"city": "San Jose", "state": "CA", "country": "US", "name": "SanJose-36"},
    "wg-US-FREE-38.conf": {"city": "Atlanta", "state": "GA", "country": "US", "name": "Atlanta-38"},
    "wg-US-FREE-51.conf": {"city": "Miami", "state": "FL", "country": "US", "name": "Miami-51"},
    "wg-US-FREE-57.conf": {"city": "New York", "state": "NY", "country": "US", "name": "NY-57"},
    "wg-US-FREE-58.conf": {"city": "New York", "state": "NY", "country": "US", "name": "NY-58"},
    "wg-US-FREE-60.conf": {"city": "Los Angeles", "state": "CA", "country": "US", "name": "LA-60"},
    "wg-US-FREE-66.conf": {"city": "Los Angeles", "state": "CA", "country": "US", "name": "LA-66"},
}

# --- Smart Search Synonyms / Abbreviations ---
SEARCH_SYNONYMS = {
    # Cities
    "la": "los angeles",
    "nyc": "new york",
    "ny": "new york",
    "sj": "san jose",
    "sf": "san francisco",

    # States/Provinces
    "alabama": "al",
    "ala": "al",
    "alaska": "ak",
    "arizona": "az",
    "ariz": "az",
    "arkansas": "ar",
    "ark": "ar",
    "california": "ca",
    "calif": "ca",
    "cal": "ca",
    "colorado": "co",
    "colo": "co",
    "col": "co",
    "connecticut": "ct",
    "conn": "ct",
    "delaware": "de",
    "del": "de",
    "florida": "fl",
    "fla": "fl",
    "georgia": "ga",
    "ga": "ga",
    "hawaii": "hi",
    "idaho": "id",
    "id": "id",
    "illinois": "il",
    "ill": "il",
    "indiana": "in",
    "ind": "in",
    "iowa": "ia",
    "kansas": "ks",
    "kan": "ks",
    "kans": "ks",
    "kentucky": "ky",
    "ken": "ky",
    "louisiana": "la",
    "la": "la",
    "maine": "me",
    "maryland": "md",
    "md": "md",
    "massachusetts": "ma",
    "mass": "ma",
    "michigan": "mi",
    "mich": "mi",
    "minnesota": "mn",
    "minn": "mn",
    "mississippi": "ms",
    "miss": "ms",
    "missouri": "mo",
    "mo": "mo",
    "montana": "mt",
    "mont": "mt",
    "nebraska": "ne",
    "nebr": "ne",
    "nevada": "nv",
    "nev": "nv",
    "new hampshire": "nh",
    "n h": "nh",
    "new jersey": "nj",
    "n j": "nj",
    "new mexico": "nm",
    "n mex": "nm",
    "new york": "ny",
    "n y": "ny",
    "north carolina": "nc",
    "n c": "nc",
    "north dakota": "nd",
    "n dak": "nd",
    "ohio": "oh",
    "oklahoma": "ok",
    "okla": "ok",
    "oregon": "or",
    "ore": "or",
    "pennsylvania": "pa",
    "penn": "pa",
    "pa": "pa",
    "rhode island": "ri",
    "r i": "ri",
    "south carolina": "sc",
    "s c": "sc",
    "south dakota": "sd",
    "s dak": "sd",
    "tennessee": "tn",
    "tenn": "tn",
    "texas": "tx",
    "tex": "tx",
    "utah": "ut",
    "vermont": "vt",
    "vt": "vt",
    "virginia": "va",
    "va": "va",
    "washington": "wa",
    "wash": "wa",
    "west virginia": "wv",
    "w va": "wv",
    "w virg": "wv",
    "wisconsin": "wi",
    "wis": "wi",
    "wisc": "wi",
    "wyoming": "wy",
    "wyo": "wy",

    # Canadian Provinces/Territories
    "alberta": "ab",
    "alta": "ab",
    "british columbia": "bc",
    "b c": "bc",
    "manitoba": "mb",
    "man": "mb",
    "new brunswick": "nb",
    "n b": "nb",
    "newfoundland and labrador": "nl",
    "newfoundland": "nl",
    "labrador": "nl",
    "nf": "nl",
    "nova scotia": "ns",
    "n s": "ns",
    "nunavut": "nu",
    "northwest territories": "nt",
    "n w t": "nt",
    "ontario": "on",
    "ont": "on",
    "prince edward island": "pe",
    "p e i": "pe",
    "quebec": "qc",
    "que": "qc",
    "saskatchewan": "sk",
    "sask": "sk",
    "yukon": "yt",
    "y t": "yt",
    "yukon territory": "yt",

    # Countries
    "afghanistan": "af",
    "albania": "al",
    "algeria": "dz",
    "american samoa": "as",
    "andorra": "ad",
    "angola": "ao",
    "anguilla": "ai",
    "antarctica": "aq",
    "antigua and barbuda": "ag",
    "argentina": "ar",
    "armenia": "am",
    "aruba": "aw",
    "australia": "au",
    "aussie": "au",
    "austria": "at",
    "azerbaijan": "az",
    "bahamas": "bs",
    "bahrain": "bh",
    "bangladesh": "bd",
    "barbados": "bb",
    "belarus": "by",
    "belgium": "be",
    "belize": "bz",
    "benin": "bj",
    "bermuda": "bm",
    "bhutan": "bt",
    "bolivia": "bo",
    "bosnia and herzegovina": "ba",
    "botswana": "bw",
    "bouvet island": "bv",
    "brazil": "br",
    "british indian ocean territory": "io",
    "brunei": "bn",
    "bulgaria": "bg",
    "burkina faso": "bf",
    "burundi": "bi",
    "cabo verde": "cv",
    "cape verde": "cv",
    "cambodia": "kh",
    "cameroon": "cm",
    "canada": "ca",
    "cayman islands": "ky",
    "central african republic": "cf",
    "chad": "td",
    "chile": "cl",
    "china": "cn",
    "christmas island": "cx",
    "cocos islands": "cc",
    "colombia": "co",
    "comoros": "km",
    "congo": "cg",
    "democratic republic of the congo": "cd",
    "dr congo": "cd",
    "cook islands": "ck",
    "costa rica": "cr",
    "croatia": "hr",
    "cuba": "cu",
    "curacao": "cw",
    "cyprus": "cy",
    "czechia": "cz",
    "czech republic": "cz",
    "denmark": "dk",
    "djibouti": "dj",
    "dominica": "dm",
    "dominican republic": "do",
    "ecuador": "ec",
    "egypt": "eg",
    "el salvador": "sv",
    "equatorial guinea": "gq",
    "eritrea": "er",
    "estonia": "ee",
    "eswatini": "sz",
    "swaziland": "sz",
    "ethiopia": "et",
    "falkland islands": "fk",
    "faroe islands": "fo",
    "fiji": "fj",
    "finland": "fi",
    "france": "fr",
    "french guiana": "gf",
    "french polynesia": "pf",
    "french southern territories": "tf",
    "gabon": "ga",
    "gambia": "gm",
    "georgia": "ge",
    "germany": "de",
    "ghana": "gh",
    "gibraltar": "gi",
    "great britain": "gb",
    "greece": "gr",
    "greenland": "gl",
    "grenada": "gd",
    "guadeloupe": "gp",
    "guam": "gu",
    "guatemala": "gt",
    "guernsey": "gg",
    "guinea": "gn",
    "guinea bissau": "gw",
    "guyana": "gy",
    "haiti": "ht",
    "heard island and mcdonald islands": "hm",
    "honduras": "hn",
    "hong kong": "hk",
    "hungary": "hu",
    "iceland": "is",
    "india": "in",
    "indonesia": "id",
    "iran": "ir",
    "iraq": "iq",
    "ireland": "ie",
    "isle of man": "im",
    "israel": "il",
    "italy": "it",
    "ivory coast": "ci",
    "cote d'ivoire": "ci",
    "jamaica": "jm",
    "japan": "jp",
    "jersey": "je",
    "jordan": "jo",
    "kazakhstan": "kz",
    "kenya": "ke",
    "kiribati": "ki",
    "korea": "kr",
    "south korea": "kr",
    "republic of korea": "kr",
    "north korea": "kp",
    "dprk": "kp",
    "kuwait": "kw",
    "kyrgyzstan": "kg",
    "laos": "la",
    "latvia": "lv",
    "lebanon": "lb",
    "lesotho": "ls",
    "liberia": "lr",
    "libya": "ly",
    "liechtenstein": "li",
    "lithuania": "lt",
    "luxembourg": "lu",
    "macao": "mo",
    "madagascar": "mg",
    "malawi": "mw",
    "malaysia": "my",
    "maldives": "mv",
    "mali": "ml",
    "malta": "mt",
    "marshall islands": "mh",
    "martinique": "mq",
    "mauritania": "mr",
    "mauritius": "mu",
    "mayotte": "yt",
    "mexico": "mx",
    "micronesia": "fm",
    "moldova": "md",
    "monaco": "mc",
    "mongolia": "mn",
    "montenegro": "me",
    "montserrat": "ms",
    "morocco": "ma",
    "mozambique": "mz",
    "myanmar": "mm",
    "burma": "mm",
    "namibia": "na",
    "nauru": "nr",
    "nepal": "np",
    "netherlands": "nl",
    "holland": "nl",
    "dutch": "nl",
    "new caledonia": "nc",
    "new zealand": "nz",
    "nicaragua": "ni",
    "niger": "ne",
    "nigeria": "ng",
    "niue": "nu",
    "norfolk island": "nf",
    "northern mariana islands": "mp",
    "norway": "no",
    "oman": "om",
    "pakistan": "pk",
    "palau": "pw",
    "palestine": "ps",
    "panama": "pa",
    "papua new guinea": "pg",
    "paraguay": "py",
    "peru": "pe",
    "philippines": "ph",
    "pitcairn": "pn",
    "poland": "pl",
    "portugal": "pt",
    "puerto rico": "pr",
    "qatar": "qa",
    "reunion": "re",
    "romania": "ro",
    "russia": "ru",
    "russian federation": "ru",
    "rwanda": "rw",
    "saint barthelemy": "bl",
    "saint helena": "sh",
    "saint kitts and nevis": "kn",
    "saint lucia": "lc",
    "saint martin": "mf",
    "saint pierre and miquelon": "pm",
    "saint vincent and the grenadines": "vc",
    "samoa": "ws",
    "san marino": "sm",
    "sao tome and principe": "st",
    "saudi arabia": "sa",
    "senegal": "sn",
    "serbia": "rs",
    "seychelles": "sc",
    "sierra leone": "sl",
    "singapore": "sg",
    "sint maarten": "sx",
    "slovakia": "sk",
    "slovenia": "si",
    "solomon islands": "sb",
    "somalia": "so",
    "south africa": "za",
    "south georgia and the south sandwich islands": "gs",
    "south sudan": "ss",
    "spain": "es",
    "sri lanka": "lk",
    "sudan": "sd",
    "suriname": "sr",
    "svalbard and jan mayen": "sj",
    "sweden": "se",
    "switzerland": "ch",
    "swiss": "ch",
    "syria": "sy",
    "taiwan": "tw",
    "tajikistan": "tj",
    "tanzania": "tz",
    "thailand": "th",
    "timor leste": "tl",
    "east timor": "tl",
    "togo": "tg",
    "tokelau": "tk",
    "tonga": "to",
    "trinidad and tobago": "tt",
    "tunisia": "tn",
    "turkey": "tr",
    "turkmenistan": "tm",
    "turks and caicos islands": "tc",
    "tuvalu": "tv",
    "uganda": "ug",
    "ukraine": "ua",
    "united arab emirates": "ae",
    "uae": "ae",
    "emirates": "ae",
    "united kingdom": "gb",
    "uk": "gb",
    "britain": "gb",
    "england": "gb",
    "united states": "us",
    "usa": "us",
    "america": "us",
    "united states of america": "us",
    "us virgin islands": "vi",
    "uruguay": "uy",
    "uzbekistan": "uz",
    "vanuatu": "vu",
    "vatican city": "va",
    "holy see": "va",
    "venezuela": "ve",
    "vietnam": "vn",
    "wallis and futuna": "wf",
    "western sahara": "eh",
    "yemen": "ye",
    "zambia": "zm",
    "zimbabwe": "zw",
}

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
            # --- Tunnel is up: remove only DNS block ---
            remove_dns_leak_block()
            # NOTE: Kill switch stays active to protect if the tunnel drops later
            return True, None, saved
        time.sleep(0.2)

    # --- Timed out waiting for interface; cleanup all protections ---
    remove_dns_leak_block()
    remove_kill_switch()
    return False, "Tunnel failed to start within 40 seconds.", None

def vpn_down_nogui() -> tuple[bool, str | None]:
    uninstall_and_wait(SERVICE_NAME, timeout_s=8.0)
    remove_kill_switch()
    remove_dns_leak_block()
    enable_ipv6_on_non_wg_adapters()
    return (False if is_vpn_up() else True), (None if not is_vpn_up() else "Interface still present")

def switch_server_nogui(new_conf: Path) -> tuple[bool, str | None]:
    """Switch WireGuard server safely while keeping firewall protection."""
    write_registry(new_conf)
    cfg = copy_conf_to_progdata(new_conf)

    # --- Apply DNS leak block + full kill switch during server switch ---
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
        # --- Ensure cleanup on any unexpected error ---
        remove_dns_leak_block()
        # Keep kill switch active intentionally — protection should remain

# -------------------------- Tray icons ---------------------------
def _load_base_icon(size: int):
    """Load ICO at closest native size to avoid resizing blur."""
    if ICON_PATH is None or not ICON_PATH.exists() or Image is None:
        return None

    try:
        with Image.open(ICON_PATH) as ico:
            # Get all available sizes in the ICO
            ico_sizes = ico.info.get('sizes', [(16,16), (32,32), (48,48), (64,64), (128,128), (256,256)])
            # Pick the closest larger-or-equal size
            best_size = max((s for s in ico_sizes if s[0] >= size), key=lambda s: s[0], default=(256,256))
            ico.load()  # Ensure loaded
            img = ico.resize((size, size), PILImage.LANCZOS if size < best_size[0] else PILImage.NEAREST)
            return img.convert("RGB")
    except Exception:
        # Fallback: standard resize
        try:
            img = Image.open(ICON_PATH).convert("RGBA")
            return img.resize((size, size), PILImage.LANCZOS).convert("RGB")
        except Exception:
            return None

def _add_corner_png_overlay(base_img, overlay_path: Path):
    if base_img is None or Image is None:
        return base_img

    try:
        overlay = Image.open(overlay_path).convert("RGBA")
    except Exception as e:
        print(f"Overlay load failed: {e}")
        return base_img

    img = base_img.copy().convert("RGBA")
    w, h = img.size

    frac = 0.50
    pad_frac = 0.04 

    d = max(int(min(w, h) * frac), 6) 
    pad = int(min(w, h) * pad_frac)

    overlay_resized = overlay.resize((d, d), PILImage.LANCZOS)

    x = w - pad - d
    y = pad

    img.paste(overlay_resized, (x, y), overlay_resized)

    return img.convert("RGB")

def get_tray_images():
    if Image is None:
        return None, None

    small_sz = 20
    big_sz   = 32

    base_s = _load_base_icon(small_sz)
    base_b = _load_base_icon(big_sz)

    if base_s is None or base_b is None:
        return None, None

    # Green locked.png in corner
    green_locked_s = _add_corner_png_overlay(base_s, LOCKED_OVERLAY_PATH)
    green_locked_b = _add_corner_png_overlay(base_b, LOCKED_OVERLAY_PATH)

    # Red unlocked.png in corner
    red_unlocked_s = _add_corner_png_overlay(base_s, UNLOCKED_OVERLAY_PATH)
    red_unlocked_b = _add_corner_png_overlay(base_b, UNLOCKED_OVERLAY_PATH)

    return (green_locked_s, green_locked_b), (red_unlocked_s, red_unlocked_b)

# -------------------------- UI -----------------------------------
class App:
    def force_refresh_tray_icon(self):
        if not self.tray_icon:
            return
        try:
            self.tray_icon.visible = False
            self.root.after(100, lambda: setattr(self.tray_icon, "visible", True))
        except Exception:
            pass

    def __init__(self, root: tk.Tk):
        self.root = root
        self._ip_detect_stop = threading.Event()
        self.root.title("Shuriken")
        self.root.geometry("1000x620")
        self.root.resizable(False, False)
        self.set_window_icon()
        self.center_on_screen()
        self.secure_connected = False
        self.in_progress = False
        self.tray_icon = None
        self.tray_imgs = None
        self.window_hidden = False
        self._last_tray_online = None
        self._last_hidden_state = None
        self._global_anim_stop = False
        self.ip_detection_complete = False
        self.secure_connected = False
        # Connection tracking
        self.ip_check_thread = None
        self._adapter_watcher = AdapterWatcher(repair_callback=run_adapter_repair_sequence)
        # Configure main window grid for 2-column layout (no more right column)
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=0)  # Left sidebar: fixed width
        self.root.grid_columnconfigure(1, weight=1)  # Center/main area: expands to fill space

        # Load button images from assets folder (size reduced for floating buttons)
        self.killswitch_img = CTkImage(light_image=PILImage.open(ASSETS_DIR / "killswitch.png"),
                                      dark_image=PILImage.open(ASSETS_DIR / "killswitch.png"),
                                      size=(36, 36))
        self.splittunnel_img = CTkImage(light_image=PILImage.open(ASSETS_DIR / "splittunneling.png"),
                                        dark_image=PILImage.open(ASSETS_DIR / "splittunneling.png"),
                                        size=(36, 36))
        self.tor_img = CTkImage(light_image=PILImage.open(ASSETS_DIR / "tor.png"),
                                dark_image=PILImage.open(ASSETS_DIR / "tor.png"),
                                size=(36, 36))
        self.settings_img = CTkImage(light_image=PILImage.open(ASSETS_DIR / "settings.png"),
                                     dark_image=PILImage.open(ASSETS_DIR / "settings.png"),
                                     size=(36, 36))

        # ===================== CENTER MAIN FRAME (for overlay) =====================
        self.main_frame = ctk.CTkFrame(self.root, corner_radius=0, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nswe")

        # ===================== OVERLAY BUTTONS ON THE RIGHT EDGE (with labels) =====================
        self.overlay_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.overlay_frame.place(relx=1.0, x=-40, rely=0.5, anchor="e")  # Slightly more space for labels

        # Helper function to create a button + label pair
        def create_feature_button(image, command, label_text):
            frame = ctk.CTkFrame(self.overlay_frame, fg_color="transparent")
            frame.pack(pady=12)  # Vertical spacing between features

            btn = ctk.CTkButton(
                frame,
                text="",
                image=image,
                width=52,
                height=52,
                corner_radius=20,
                fg_color="#1f1f1f",
                hover_color="#3a3a3a",
                command=command
            )
            btn.pack()

            label = ctk.CTkLabel(
                frame,
                text=label_text,
                font=ctk.CTkFont(family="Segoe UI", size=11, weight="normal"),
                text_color="#BBBBBB"
            )
            label.pack(pady=(4, 0))

            return frame

        # Create the four features with labels
        create_feature_button(self.killswitch_img, self.open_killswitch, "Kill Switch")
        create_feature_button(self.splittunnel_img, self.open_splittunneling, "Split Tunneling")
        create_feature_button(self.tor_img, self.launch_tor_browser, "Tor Browser")
        create_feature_button(self.settings_img, self.open_settings, "Settings")

        # ===================== LEFT SIDEBAR (Server List) =====================
        self.server_buttons = {}
        self.left_sidebar = CTkFrame(self.root, width=280, corner_radius=0)
        self.left_sidebar.grid(row=0, column=0, sticky="nswe")
        self.left_sidebar.grid_propagate(False)
        title_label = CTkLabel(self.left_sidebar, text="Servers", font=("Segoe UI", 16, "bold"), pady=15)
        title_label.pack()
        self.search_var = tk.StringVar()
        self.search_entry = CTkEntry(
            self.left_sidebar,
            textvariable=self.search_var,
            placeholder_text="Search for a Server",
            height=40,
            corner_radius=12,
            font=("Segoe UI", 12)
        )
        self.search_entry.pack(fill="x", padx=15, pady=(0, 10))
        icon_path = ASSETS_DIR / "search_icon.png" # Or your exact path
        if icon_path.exists():
            search_img = CTkImage(light_image=PILImage.open(icon_path),
                                  dark_image=PILImage.open(icon_path),
                                  size=(22, 22)) # 20-24 works best
        else:
            search_img = None
        if search_img:
            search_icon_label = CTkLabel(
                self.search_entry, # Parent is the entry itself!
                image=search_img,
                text="",
                fg_color="transparent"
            )
            search_icon_label.place(relx=0, rely=0.5, anchor="w", x=190) # Your exact desired position
            search_icon_label.configure(takefocus=0) # Prevent label from taking focus
            # When clicking the icon, give focus to the entry and let the click pass through naturally
            def on_icon_click(event):
                self.search_entry.focus_set()
                # Do NOT generate synthetic events or block propagation - just give focus
            search_icon_label.bind("<Button-1>", on_icon_click)
        # Live search
        self.search_var.trace_add("write", lambda *_: self.load_server_list())
        # Scrollable server list
        self.server_scrollable_frame = CTkScrollableFrame(self.left_sidebar, width=210)
        self.server_scrollable_frame.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        # Initial load
        self.load_server_list()

        # ===================== MAIN CONTENT AREA =====================
        self.main_content = CTkFrame(self.main_frame, corner_radius=0, fg_color="transparent")
        self.main_content.pack(fill="both", expand=True, padx=30, pady=30)  # Use pack instead of grid

        # ----- Header / logo -----
        self.logo_img = None
        if _HAVE_PIL_IMAGETK and ICON_PATH.exists():
            try:
                pil = PILImage.open(ICON_PATH)
                max_w = 72
                ratio = min(1.0, max_w / pil.width)
                if ratio < 1.0:
                    pil = pil.resize((int(pil.width * ratio), int(pil.height * ratio)), PILImage.LANCZOS)
                self.logo_img = ImageTk.PhotoImage(pil)
            except Exception:
                pass

        if self.logo_img:
            ctk.CTkLabel(self.main_content, image=self.logo_img, text="").pack(pady=(10, 2))

        self.header = ctk.CTkLabel(self.main_content, text="Shuriken", font=("Segoe UI", 16, "bold"))
        self.header.pack(pady=(8, 8))

        self.status = ctk.CTkLabel(self.main_content, text="Disconnected", font=("Segoe UI", 10, "bold"))

        # ----- MAIN CONNECT / DISCONNECT BUTTON -----
        self.btn = ctk.CTkButton(
            self.main_content,
            text="Connect",
            command=self.toggle,
            font=("Segoe UI", 16, "bold"),
            width=200,
            height=60,
            corner_radius=12,
            fg_color="#2E7D32",
            hover_color="#43A047",
            text_color="white",
            border_width=2,
            border_color="#1B5E20",
        )
        self.btn.pack(pady=30)

        # ----- Transient status label (below the button) -----
        self.transient_status = ctk.CTkLabel(
            self.main_content,
            text="",
            font=("Segoe UI", 14),
            text_color="#AAAAAA"
        )
        self.transient_status.pack(pady=(10, 30))

        # ----- Bottom Info Panel (Protected/Unprotected clearly above the info) -----
        bottom_frame = ctk.CTkFrame(self.main_content, fg_color="transparent")
        bottom_frame.pack(side="bottom", fill="x", pady=(40, 20), padx=40)

        # === Large Protected/Unprotected status (full width, on top) ===
        self.protection_status = ctk.CTkLabel(
            bottom_frame,
            text="🔓 Unprotected",
            font=ctk.CTkFont(family="Arial", size=32, weight="bold"),
            text_color="#f44336",
            anchor="w",
            justify="left"
        )
        self.protection_status.pack(anchor="w", pady=(0, 20), padx=20)

        # Sub-frame for the three info labels (horizontal row)
        info_subframe = ctk.CTkFrame(bottom_frame, fg_color="transparent")
        info_subframe.pack(fill="x", padx=20)

        info_subframe.grid_columnconfigure(0, weight=1)
        info_subframe.grid_columnconfigure(1, weight=1)
        info_subframe.grid_columnconfigure(2, weight=1)

        info_font = ctk.CTkFont(family="Segoe UI", size=13, weight="normal")
        info_color = "#DADADA"

        # Current IP label
        self.ip_var = tk.StringVar(value="Your IP Address:\nDetecting...")
        self.ip_label = ctk.CTkLabel(
            info_subframe,
            textvariable=self.ip_var,
            font=info_font,
            text_color=info_color,
            anchor="w",
            justify="left"
        )
        self.ip_label.grid(row=0, column=0, sticky="w")

        # Location label
        self.location_var = tk.StringVar(value="Location:\nDetecting...")
        self.location_label = ctk.CTkLabel(
            info_subframe,
            textvariable=self.location_var,
            font=info_font,
            text_color=info_color,
            anchor="center",
            justify="center"
        )
        self.location_label.grid(row=0, column=1, sticky="ew", padx=20)

        # Provider label
        self.provider_var = tk.StringVar(value="Provider:\nDetecting...")
        self.provider_label = ctk.CTkLabel(
            info_subframe,
            textvariable=self.provider_var,
            font=info_font,
            text_color=info_color,
            anchor="e",
            justify="right"
        )
        self.provider_label.grid(row=0, column=2, sticky="e", padx=(20, 0))

        separator = ctk.CTkFrame(self.main_content, height=1, fg_color="#333333")
        separator.pack(side="bottom", fill="x", pady=(0, 20), padx=40)
        separator.lower()

        # ----- Final UI setup -----
        self.refresh_status()
        self.init_tray()
        if self.tray_icon:
            try:
                self.tray_icon.icon = self.tray_image_for_state(online)
            except Exception:
                pass
        # Load servers into the sidebar
        self.load_server_list()

        # --- Startup: ALWAYS pessimistic ---
        self.transient_status.configure(text="Checking connection status…")
        self.protection_status.configure(text="🔓 Unprotected", text_color="#f44336")
        self.btn.configure(text="Connect")
        self.location_var.set("Location:\nDetecting...")

        # If WireGuard *might* be running, VERIFY before trusting it
        if is_vpn_up():
            self.protection_status.configure(text="🔒 Protected", text_color="#00FF00")
            self.transient_status.configure(text="Connection Secure & Encrypted")
            self.btn.configure(text="Disconnect")
            self.transient_status.configure(text="Checking Connection status...")
            self.secure_connected = True
            self.fetch_and_display_ip("VPN", continuous=True)
        else:
            self.transient_status.configure(text="Secure your online activity by connecting to VPN")
            self.fetch_and_display_ip("Local", continuous=False)

        self.overlay_frame.lift()

    def open_killswitch(self):
        messagebox.showinfo(
            "Kill Switch",
            "Full Kill Switch is already built-in and active when connected!\n\n"
            "Blocks all internet traffic if the VPN connection drops unexpectedly.",
            parent=self.root
        )

    def open_splittunneling(self):
        messagebox.showinfo(
            "Split Tunneling",
            "Split Tunneling is not yet implemented.\n\n"
            "Your current setup uses a full tunnel with kill switch protection.",
            parent=self.root
        )

    def launch_tor_browser(self):
        # Tor Browser will always be bundled in Resources/tor-windows (on Windows) or Resources/tor-linux (on Linux)
        resources_dir = BUNDLED_BASE_DIR / "Resources"  
        if not resources_dir.exists():
            resources_dir = APP_DIR / "Resources"  

        if sys.platform.startswith("win"):
            tor_root = resources_dir / "tor-windows"
            firefox_exe = tor_root / "Browser" / "firefox.exe"
        else:  # Assume Linux (or other Unix-like)
            tor_root = resources_dir / "tor-linux"
            firefox_exe = tor_root / "Browser" / "firefox"  # No .exe on Linux

        if not tor_root.exists() or not tor_root.is_dir():
            messagebox.showerror(
                "Tor Browser Not Found",
                "Official Tor Browser folder not found!\n\n"
                f"Expected location: {resources_dir}\n"
                "Inside it:\n"
                " - tor-windows/ (extracted Windows Tor Browser)\n"
                " - tor-linux/   (extracted Linux Tor Browser)\n\n"
                f"Download latest stable (15.0.3 as of Dec 2025) from https://www.torproject.org/download/\n"
                "Extract and place the full folder here.",
                parent=self.root
            )
            return

        if not firefox_exe.exists():
            messagebox.showerror(
                "Tor Browser Error",
                f"firefox executable not found at:\n{firefox_exe}\n\n"
                "Make sure you extracted the full official Tor Browser bundle correctly into the platform folder.",
                parent=self.root
            )
            return

        if not getattr(self, "secure_connected", False):
            if not messagebox.askyesno(
                "Shuriken",
                "For maximum privacy, it's recommended to use Tor over an active VPN.\n\n"
                "This hides Tor usage from your ISP and adds an extra layer of protection.\n\n"
                "Launch Official Tor Browser anyway?",
                icon="warning",
                parent=self.root
            ):
                return  # User canceled

        try:
            # Launch detached, no console window (Windows-friendly)
            creationflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0

            subprocess.Popen(
                [str(firefox_exe)],
                cwd=str(tor_root),  # Critical: Run from the Tor Browser root folder
                creationflags=creationflags
            )

        except Exception as e:
            messagebox.showerror(
                "Launch Failed",
                f"Could not start Official Tor Browser:\n\n{e}",
                parent=self.root
            )

    def open_settings(self):
        settings_win = ctk.CTkToplevel(self.root)
        settings_win.title("Shuriken Settings")
        settings_win.geometry("500x400")
        settings_win.resizable(False, False)
        settings_win.grab_set()                          # Modal window

        # Center on parent
        settings_win.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - (500 // 2)
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - (400 // 2)
        settings_win.geometry(f"+{x}+{y}")

        ctk.CTkLabel(
            settings_win,
            text="Advanced Settings",
            font=ctk.CTkFont(size=20, weight="bold")
        ).pack(pady=30)

        ctk.CTkLabel(
            settings_win,
            text="More options coming soon...",
            text_color="gray"
        ).pack(pady=10)

    # ------------------------------------------------------------------
    #  Internet Connectivity Monitor (runs ONLY when VPN is secure)
    # ------------------------------------------------------------------
    def start_internet_monitor(self):
        if hasattr(self, "_internet_monitor_thread") and self._internet_monitor_thread.is_alive():
            return
        self._internet_stop = threading.Event()
        self._internet_monitor_thread = threading.Thread(
            target=self._internet_monitor_loop, daemon=True
        )
        self._internet_monitor_thread.start()

    def stop_internet_monitor(self):
        if hasattr(self, "_internet_stop"):
            self._internet_stop.set()
        if hasattr(self, "_internet_monitor_thread") and self._internet_monitor_thread.is_alive():
            self._internet_monitor_thread.join(timeout=1)

    def _internet_monitor_loop(self):
        was_online = None
        while not self._internet_stop.is_set():
            if not self.secure_connected:
                time.sleep(2)
                continue

            online = self._is_online()
            was_online = online
            time.sleep(2)

    def _is_online(self):
        try:
            result = subprocess.run(
                ["ping", "-n" if platform.system().lower() == "windows" else "-c", "1", "1.1.1.1"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    # ---------- Icon helpers ----------
    def set_window_icon(self):
        if _HAVE_PIL_IMAGETK and ICON_PATH.exists(): 
            try:
                pil = PILImage.open(ICON_PATH).resize((32, 32), PILImage.LANCZOS)
                img = ImageTk.PhotoImage(pil)
                self.root.iconphoto(True, img)
                self._iconphoto_ref = img
            except Exception as e:
                print("Icon load fallback failed:", e)
        else:
            try:
                if ICON_PATH.exists():
                    self.root.iconbitmap(default=str(ICON_PATH))
            except Exception:
                pass

    def center_on_screen(self):
        self.root.update_idletasks()
        w, h = self.root.winfo_width(), self.root.winfo_height()
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        x, y = (sw - w) // 2, (sh - h) // 2
        self.root.geometry(f"{w}x{h}+{x}+{y}")

    # ---------- Dropdown ----------
    def display_for_path(self, p: Path | None) -> str:
        return "(none)" if not p else pretty_name_for(p.name)

    def get_available_servers(self) -> list[Path]:
        """Return list of available server configs using your existing logic."""
        return list_conf_files()  # Reuses your robust function
    def _get_flag(self, country: str):
        from datetime import datetime

        country_normalized = country.strip().upper()

        if DEBUG_MODE:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            def log(msg: str):
                try:
                    with open("Shuriken_Log.txt", "a", encoding="utf-8") as f:
                        f.write(f"[FLAG DEBUG] {ts} {msg}\n")
                except Exception:
                    pass

        # Quick fallback if prerequisites missing (Pillow or flags folder)
        if PILImage is None or not FLAGS_DIR.exists():
            if DEBUG_MODE:
                if not hasattr(self, "_flag_prereq_warning_logged"):
                    self._flag_prereq_warning_logged = True
                    log("Pillow or FLAGS_DIR missing — using emoji fallbacks only")
                    log(f"FLAGS_DIR: {FLAGS_DIR} (exists: {FLAGS_DIR.exists()})")
                    log(f"Pillow available: {PILImage is not None}")

            mapping = {
                "JP": "🇯🇵",
                "US": "🇺🇸", "UNITED STATES": "🇺🇸",
                "GERMANY": "🇩🇪",
                "FRANCE": "🇫🇷",
                "UK": "🇬🇧", "UNITED KINGDOM": "🇬🇧",
                "NL": "🇳🇱",
                "CA": "🇨🇦",
                "SG": "🇸🇬",
                "CH": "🇨🇭",
                "SWEDEN": "🇸🇪",
                "AUSTRALIA": "🇦🇺",
                "SOUTH KOREA": "🇰🇷",
                "INDIA": "🇮🇳",
            }
            emoji = mapping.get(country_normalized, "🌐")
            FLAG_CACHE[country_normalized] = emoji
            if DEBUG_MODE and emoji == "🌐":
                log(f"FLAG MISSING: '{country}' → '{country_normalized}' → No image, no custom emoji → using generic 🌐")
            return emoji

        # Cache hit — silent success
        if country_normalized in FLAG_CACHE:
            return FLAG_CACHE[country_normalized]

        # Try to find and load the flag file
        candidates = [
            f"{country_normalized}.png",
            f"{country_normalized}.jpg",
            f"{country_normalized.lower()}.png",
            f"{country_normalized.lower()}.jpg",
            f"{country_normalized[:2].lower()}.png",  # e.g., "us.png"
        ]

        flag_path = None
        for cand in candidates:
            p = FLAGS_DIR / cand
            if p.exists() and p.is_file():
                flag_path = p
                break

        if flag_path:
            try:
                pil_img = PILImage.open(flag_path).convert("RGBA")
                ctk_img = CTkImage(
                    light_image=pil_img,
                    dark_image=pil_img,
                    size=(32, 24)
                )
                FLAG_CACHE[country_normalized] = ctk_img
                return ctk_img
            except Exception as e:
                if DEBUG_MODE:
                    log(f"FLAG LOAD FAILED: '{country}' → '{country_normalized}'")
                    log(f"  Found file: {flag_path}")
                    log(f"  Error: {e}")
        else:
            if DEBUG_MODE:
                # Only log when a flag is actually missing
                log(f"FLAG MISSING: '{country}' → normalized: '{country_normalized}'")
                log(f"  Searched in: {FLAGS_DIR}")
                log(f"  Tried filenames: {', '.join(candidates)}")

                # One-time summary of available flags (only when first miss occurs)
                if not hasattr(self, "_flag_missing_summary_logged"):
                    self._flag_missing_summary_logged = True
                    try:
                        all_flags = [p.name for p in FLAGS_DIR.iterdir() 
                                   if p.is_file() and p.suffix.lower() in {'.png', '.jpg'}]
                        all_flags.sort()
                        log(f"  Total flag files available: {len(all_flags)}")
                        samples = all_flags[:15]
                        extra = " ..." if len(all_flags) > 15 else ""
                        log(f"  Sample available flags: {', '.join(samples)}{extra}")
                    except Exception as e:
                        log(f"  Error scanning FLAGS_DIR: {e}")

        # Final emoji fallback
        mapping = {
            "JP": "🇯🇵",
            "US": "🇺🇸", "UNITED STATES": "🇺🇸",
            "GERMANY": "🇩🇪",
            "FRANCE": "🇫🇷",
            "UK": "🇬🇧", "UNITED KINGDOM": "🇬🇧",
            "NL": "🇳🇱",
            "CA": "🇨🇦",
            "SG": "🇸🇬",
            "CH": "🇨🇭",
            "SWEDEN": "🇸🇪",
            "AUSTRALIA": "🇦🇺",
            "SOUTH KOREA": "🇰🇷",
            "INDIA": "🇮🇳",
        }
        emoji = mapping.get(country_normalized, "🌐")
        FLAG_CACHE[country_normalized] = emoji

        if DEBUG_MODE and emoji == "🌐":
            log(f"  → Fell back to generic 🌐 (no custom emoji defined)")

        return emoji

    def load_server_list(self):
        """Refresh the left sidebar with all available servers (with smart search)."""
        for widget in self.server_scrollable_frame.winfo_children():
            widget.destroy()
        self.server_buttons.clear()

        servers = self.get_available_servers()
        if not servers:
            no_srv = CTkLabel(
                self.server_scrollable_frame,
                text="No .conf files found in Config folder",
                text_color="#888888",
                font=("Segoe UI", 12)
            )
            no_srv.pack(pady=30)
            return

        # --- Smart Search Preparation ---
        raw_query = self.search_var.get().strip()
        query_lower = raw_query.lower()

        # Known state/province and city abbreviation keys (to avoid treating them as countries)
        state_province_keys = {
            "alabama", "ala", "alaska", "arizona", "ariz", "arkansas", "ark", "california", "calif", "cal",
            "colorado", "colo", "col", "connecticut", "conn", "delaware", "del", "florida", "fla", "georgia",
            "ga", "hawaii", "idaho", "id", "illinois", "ill", "indiana", "ind", "iowa", "kansas", "kan", "kans",
            "kentucky", "ky", "ken", "louisiana", "la", "maine", "maryland", "md", "massachusetts", "mass",
            "michigan", "mich", "minnesota", "minn", "mississippi", "ms", "miss", "missouri", "mo", "montana",
            "mt", "mont", "nebraska", "nebr", "nevada", "nv", "nev", "new hampshire", "n h", "new jersey", "n j",
            "new mexico", "n mex", "new york", "n y", "north carolina", "n c", "north dakota", "n dak", "ohio",
            "oklahoma", "okla", "oregon", "or", "ore", "pennsylvania", "penn", "pa", "rhode island", "r i",
            "south carolina", "s c", "south dakota", "s dak", "tennessee", "tn", "tenn", "texas", "tx", "tex",
            "utah", "vermont", "vt", "virginia", "va", "washington", "wash", "west virginia", "wv", "w va",
            "w virg", "wisconsin", "wi", "wis", "wisc", "wyoming", "wyo",
            "alberta", "alta", "british columbia", "b c", "manitoba", "man", "new brunswick", "n b",
            "newfoundland and labrador", "newfoundland", "labrador", "nf", "nova scotia", "n s", "nunavut",
            "northwest territories", "n w t", "ontario", "ont", "prince edward island", "p e i", "quebec", "que",
            "saskatchewan", "sask", "yukon", "yt", "y t", "yukon territory",
        }

        city_keys = {"la", "nyc", "ny", "sj", "sf"}

        # Anything in SEARCH_SYNONYMS that is not a state/province or city key is a country key
        country_keys = set(SEARCH_SYNONYMS.keys()) - state_province_keys - city_keys

        current_config = read_registry()

        # === Current Server Banner at Top ===
        if current_config and current_config in servers:
            meta = SERVER_METADATA.get(
                current_config.name,
                {"city": "Unknown", "state": "", "country": "Unknown", "name": current_config.stem}
            )
            flag = self._get_flag(meta["country"])
            location = meta["city"]
            if meta.get("state"):
                location += f", {meta['state']}"
            location += f", {meta['country']}"

            current_row = CTkFrame(self.server_scrollable_frame, fg_color=("#0d47a1", "#0d47a1"), height=50)
            current_row.pack(fill="x", pady=(0, 12), padx=8)
            current_row.pack_propagate(False)

            flag_lbl = CTkLabel(current_row, text="", image=flag, width=40, height=30)
            flag_lbl.pack(side="left", padx=12)

            CTkLabel(
                current_row,
                text="● Current Server",
                font=("Segoe UI", 11, "bold"),
                text_color="white"
            ).pack(side="top", anchor="w", padx=(0, 10))

            CTkLabel(
                current_row,
                text=f"{location}",
                font=("Segoe UI", 12),
                text_color="#bbdefb",
                anchor="w"
            ).pack(side="bottom", anchor="w", padx=(0, 10))

        # === List All Servers ===
        for conf_path in servers:
            meta = SERVER_METADATA.get(
                conf_path.name,
                {"city": "Unknown", "state": "", "country": "Unknown", "name": conf_path.stem}
            )

            city_norm = meta["city"].lower()
            state_norm = meta.get("state", "").lower()
            country_norm = meta["country"].lower()
            name_norm = meta["name"].lower()

            searchable_tokens = {city_norm, state_norm, country_norm, name_norm}
            if state_norm:
                searchable_tokens.add(f"{city_norm}, {state_norm}")

            searchable_text = " ".join([city_norm, state_norm, country_norm, name_norm])

            # --- Smart Matching Logic ---
            if raw_query:
                matched = False

                # 1. Exact full phrase match in synonyms (e.g. "united states", "south korea")
                if query_lower in SEARCH_SYNONYMS:
                    synonym = SEARCH_SYNONYMS[query_lower].lower()
                    if query_lower in country_keys and synonym == country_norm:
                        matched = True
                    elif query_lower not in country_keys and (
                        synonym == state_norm or synonym in city_norm or synonym in name_norm
                    ):
                        matched = True

                # 2. Partial prefix match on country names (e.g. "united" → "united states")
                if not matched:
                    for key in country_keys:
                        if key.startswith(query_lower):
                            synonym = SEARCH_SYNONYMS[key].lower()
                            if synonym == country_norm:
                                matched = True
                                break

                # 3. Word-by-word fallback for flexibility
                if not matched:
                    words = [w.lower() for w in raw_query.split()]
                    for word in words:
                        if word in SEARCH_SYNONYMS:
                            syn = SEARCH_SYNONYMS[word].lower()
                            if word in country_keys and syn == country_norm:
                                matched = True
                                break
                            elif word not in country_keys and (
                                syn == state_norm or syn in city_norm or syn in name_norm
                            ):
                                matched = True
                                break

                        if word in searchable_tokens or word in searchable_text:
                            matched = True
                            break

                # 4. Final loose substring fallback
                if not matched and query_lower in searchable_text:
                    matched = True

                if not matched:
                    continue

            # Display text (visible in button)
            location = meta["city"]
            if meta.get("state"):
                location += f", {meta['state']}"
            location += f", {meta['country']}"
            full_text = location

            # Flag - kept exactly as in your original code
            flag = self._get_flag(meta["country"])

            # Row frame
            row = CTkFrame(self.server_scrollable_frame, fg_color="transparent")
            row.pack(fill="x", pady=2, padx=8)

            # Flag icon
            CTkLabel(row, text="", image=flag, width=36, height=28).pack(side="left", padx=(8, 12))

            # Server button
            btn = CTkButton(
                row,
                text=full_text,
                anchor="w",
                fg_color="transparent",
                hover_color=("#2f2f2f", "#333333"),
                height=44,
                font=("Segoe UI", 13),
                width=100,
                command=lambda p=conf_path: self.select_server(p)
            )
            btn.pack(fill="x", expand=True)

            # Highlight current server
            if conf_path == current_config:
                btn.configure(fg_color=("#1f538d", "#144870"))

            self.server_buttons[conf_path] = btn

    def select_server(self, conf_path: Path):
        """Handle server selection from sidebar."""
        if not validate_config_has_dns(conf_path):
            safe_messagebox("error", "Invalid Config", f"Missing DNS in {conf_path.name}", parent=self.root)
            return

        write_registry(conf_path)

        # Highlight
        for path, btn in self.server_buttons.items():
            if btn:
                btn.configure(fg_color=("#1f538d", "#144870") if path == conf_path else "transparent")

        if is_vpn_up():
            self.switch_server(conf_path)
        else:
            meta = SERVER_METADATA.get(conf_path.name, {"name": conf_path.stem})
            safe_messagebox("info", "Shuriken", f"Default Server Set To: {meta.get('name')}", parent=self.root)

        self.load_server_list()  # Refresh to update current banner

    # ---------- UI helpers ----------
    def set_busy(self, btn: ctk.CTkButton, text: str):
        self.in_progress = True
        btn.configure(state="disabled", text=text)
        self.root.configure(cursor="watch")
        self.root.update_idletasks()

    def clear_busy(self, btn: ctk.CTkButton, text: str, fg_color: str | None = None):
        self.in_progress = False
        btn.configure(state="normal", text=text)
        if fg_color is not None:
            if fg_color.lower() in ["#f44336", "#d32f2f", "#c62828"]:
                hover = "#e53935"
            else:
                hover = "#43a047"
            btn.configure(fg_color=fg_color, hover_color=hover, text_color="white")
        self.root.configure(cursor="")

    def run_async(self, task, done):
        def wrapper():
            try:
                result = task()
            except Exception as e:
                result = (False, str(e), None)
            self.root.after(0, lambda: done(*result))
        threading.Thread(target=wrapper, daemon=True).start()

    def animate_status(self, base_text: str, fg_color: str, stop_event: threading.Event):
        """Continuously update the status label with animated dots."""
        if self._global_anim_stop:
            return

        dots = 0
        while not stop_event.is_set():
            dots = (dots + 1) % 4
            text = base_text + ("." * dots)
            self.root.after(0, lambda t=text, c=fg_color: self.transient_status.configure(text=t))
            time.sleep(0.35)  # adjust speed of animation

    # ---------- IP Detection ----------
    def fetch_and_display_ip(self, state: str = "Local", continuous: bool = False, timeout_sec: int = 30):
        """
        Fetch public IP until it changes (for VPN mode) or timeout.
        In VPN mode: continuously shows "Detecting..." and retries until real IP change is confirmed.
        """
        if continuous and hasattr(self, '_ip_detect_stop'):
            self._ip_detect_stop.set()  # Cancel previous
        if continuous:
            self._ip_detect_stop = threading.Event()

        start_time = time.time()
        if not continuous:
            timeout_sec = 10

        last_ip = getattr(self, '_last_detected_ip', None)  # Remember last known public IP

        def task():
            nonlocal last_ip
            ip_changed = False

            try:
                while (continuous and not self._ip_detect_stop.is_set()) or not continuous:
                    # Timeout only applies to one-shot (local) checks
                    if not continuous and time.time() - start_time > timeout_sec:
                        break

                    ip = None
                    provider = "Unknown"
                    country = "Unknown"

                    # --- Multiple fallback IP services ---
                    ip_services = [
                        "https://api.ipify.org",
                        "https://ifconfig.co/plain",
                        "https://icanhazip.com",
                        "https://checkip.amazonaws.com",
                    ]
                    for service in ip_services:
                        try:
                            with urllib.request.urlopen(service, timeout=8) as resp:
                                raw_ip = resp.read().decode('utf-8').strip()
                                if '.' in raw_ip and raw_ip.replace('.', '').isdigit():
                                    parts = raw_ip.split('.')
                                    if len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts):
                                        ip = raw_ip
                                        break
                        except Exception as e:
                            if DEBUG_MODE:
                                print(f"[DEBUG] IP service {service} failed: {e}")
                            continue

                    # --- SUCCESS: Real IP change detected ---
                    if ip and ip != last_ip:
                        ip_changed = True
                        try:
                            geo_url = f"http://ip-api.com/json/{ip}?fields=isp,org,asname,country"
                            with urllib.request.urlopen(geo_url, timeout=8) as resp:
                                data = json.load(resp)
                                asname = data.get("asname", "").strip()
                                isp = data.get("isp", "").strip()
                                org = data.get("org", "").strip()
                                country = data.get("country", "").strip() or "Unknown"
                                provider_mapping = {
                                    "CDNEXT": "Datacamp Limited",
                                    "HETZNER-CLOUD3-AS": "Hetzner Online",
                                    "ORACLE-BMC-31898": "Oracle Cloud Infrastructure",
                                    "ATT-INTERNET4": "AT&T",
                                }
                                raw_provider = asname or isp or org or "Unknown"
                                provider = provider_mapping.get(raw_provider, raw_provider)
                        except Exception as e:
                            if DEBUG_MODE:
                                print(f"[DEBUG] Geo lookup failed for {ip}: {e}")

                        self.root.after(0, lambda ip=ip, provider=provider, country=country: (
                            self.ip_var.set(f"Your IP Address:\n{ip} ({state})"),
                            self.provider_var.set(f"Provider:\n{provider}"),
                            self.location_var.set(f"Location:\n{country}"),
                            self.protection_status.configure(text="🔒 Protected", text_color="#00FF00"),
                            self.transient_status.configure(text="Connection Secure & Encrypted"),
                            self.clear_busy(self.btn, "Disconnect", "#f44336") if state == "VPN" else None,
                        ))
                        last_ip = ip
                        self._last_detected_ip = ip  # Persist for future checks
                        if continuous:
                            self._ip_detect_stop.set()
                        return

                    # --- No IP change yet ---
                    # Update last_ip so we can detect future changes
                    if ip:
                        last_ip = ip

                    # In VPN mode: keep detecting indefinitely (until change or cancel)
                    if state == "VPN":
                        self.root.after(0, lambda: (
                            self.ip_var.set("Your IP Address:\nDetecting..."),
                            self.provider_var.set("Provider:\nDetecting..."),
                            self.location_var.set("Location:\nDetecting..."),
                            self.protection_status.configure(text="⏳ Establishing", text_color="#FFFF00"),
                            self.transient_status.configure(text="Tunnel active. Connecting to internet..."),
                            self.clear_busy(self.btn, "Disconnect", "#f44336"),
                        ))
                        if continuous:
                            time.sleep(3)
                            continue
                        else:
                            return

                    # One-shot local check: failed to get IP
                    if not continuous:
                        self.root.after(0, lambda: (
                            self.ip_var.set("Your IP Address:\nFailed to detect"),
                            self.provider_var.set("Provider:\nFailed to detect"),
                            self.location_var.set("Location:\nFailed to detect"),
                            self.protection_status.configure(text="🔓 Unprotected", text_color="#f44336"),
                        ))
                        return

                # Only reached for non-continuous (local) timeout — already handled above

            finally:
                if hasattr(self, "_status_stop_event"):
                    self._status_stop_event.set()
                if continuous and hasattr(self, "_ip_detect_stop"):
                    self._ip_detect_stop.set()

        threading.Thread(target=task, daemon=True).start()

    # ---------- Tray ----------
    def init_tray(self):
        self.tray_imgs = get_tray_images()
        self._tray_img_green = self.tray_imgs[0][0] if self.tray_imgs else None
        self._tray_img_red   = self.tray_imgs[1][0] if self.tray_imgs else None

        if pystray is None or Image is None or not _HAVE_PYWIN32:
            messagebox.showwarning(
                "Tray Unavailable",
                "Tray requires: pystray, Pillow, pywin32.\n\n"
                "Install: pip install pystray pillow pywin32\n\n"
                "Closing the window will minimize application to the taskbar.",
                parent=self.root)
            self.root.protocol("WM_DELETE_WINDOW", lambda: self.root.iconify())
            return

        self.tray_icon = pystray.Icon(APP_NAME)

        def setup(icon):
            icon.icon   = self.tray_image_for_state(is_vpn_up())
            icon.title  = APP_NAME
            icon.menu   = self.build_tray_menu()
            icon.visible = True
            icon.on_activate = lambda _: self.root.after(0, self.show_from_tray)

        try:
            self.tray_icon.run_detached(setup)
            atexit.register(lambda: self.tray_icon.stop())
            self._last_tray_online = is_vpn_up()
            self._last_hidden_state = self.window_hidden
            self.root.protocol("WM_DELETE_WINDOW", self.hide_to_tray)
        except Exception as e:
            messagebox.showwarning(
                "Tray Error",
                f"Could not start tray icon: {e}",
                parent=self.root)
            self.root.protocol("WM_DELETE_WINDOW", lambda: self.root.iconify())

    def tray_image_for_state(self, online: bool):
        if not self.tray_imgs:
            return None
        (g_s, _), (r_s, _) = self.tray_imgs
        return g_s if online else r_s

    def build_tray_menu(self):
        def on_toggle(_): self.root.after(0, self.toggle)
        def on_showhide(_): self.root.after(0, self.toggle_window_visibility)
        def on_exit(_): self.root.after(0, self.exit_app)

        return pystray.Menu(
            pystray.MenuItem(lambda _: f"Status: {'Connected' if is_vpn_up() else 'Disconnected'}", None, enabled=False),
            pystray.MenuItem(lambda _: "Show Window" if self.window_hidden else "Hide Window", on_showhide, default=True),
            pystray.MenuItem(lambda _: "Disconnect VPN" if is_vpn_up() else "Connect VPN", on_toggle),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit", on_exit),
        )

    def _update_tray_if_needed(self):
        if not self.tray_icon:
            return
        try:
            online = is_vpn_up() and getattr(self, "secure_connected", False)
            hidden = self.window_hidden

            changed_online = (online != self._last_tray_online)
            changed_hidden = (hidden != self._last_hidden_state)

            if changed_online:
                self.tray_icon.icon = self.tray_image_for_state(online)

            if changed_online or changed_hidden:
                self.tray_icon.menu = self.build_tray_menu()
                try:
                    self.tray_icon.update_menu()
                except Exception:
                    pass

            self._last_tray_online = online
            self._last_hidden_state = hidden

        except Exception:
            pass

    def hide_to_tray(self):
        self.window_hidden = True
        self.root.withdraw()
        self._update_tray_if_needed()

    def show_from_tray(self):
        self.window_hidden = False
        self.root.deiconify()
        self.root.lift()
        self.root.attributes('-topmost', True)
        self.root.after(50, lambda: self.root.attributes('-topmost', False))
        self.root.focus_force()
        self._update_tray_if_needed()

    def toggle_window_visibility(self):
        if self.window_hidden:
            self.show_from_tray()
        else:
            self.hide_to_tray()

    def exit_app(self):
        try:
            if self.tray_icon:
                self.tray_icon.stop()
        except Exception:
            pass

        # --- Stop any ongoing IP detection threads safely ---
        if hasattr(self, '_ip_detect_stop'):
            self._ip_detect_stop.set()

        # Gracefully stop background IP check thread if running
        if hasattr(self, 'ip_check_thread') and self.ip_check_thread and self.ip_check_thread.is_alive():
            try:
                self.ip_check_thread.join(timeout=1)
            except Exception:
                pass

        # --- Stop watchdog safely before exit ---
        if hasattr(self, "_watchdog_stop"):
            try:
                self._watchdog_stop.set()
            except Exception:
                pass
        self._adapter_watcher.stop()
        self.stop_internet_monitor()

        # Destroy main window cleanly
        try:
            self.root.destroy()
        except Exception:
            pass

    # ---------- Status poll ----------
    def refresh_status(self):
        """Periodically refresh the VPN status label and button."""
        stop_event = getattr(self, "_status_stop_event", None)
        is_animating = False

        # Determine if an animation is currently running
        if isinstance(stop_event, threading.Event):
            is_animating = not stop_event.is_set()

        # Only refresh when not in progress and no animation is active
        if not self.in_progress and not is_animating:
            if is_vpn_up():
                self.btn.configure(text="Disconnect")
                # Do not update tray to green here; wait until connection is confirmed secure
            else:
                self.transient_status.configure(text="Secure your online activity by connecting to Shuriken VPN")
                self.protection_status.configure(text="🔓 Unprotected", text_color="#f44336")
                self.btn.configure(text="Connect")
                self._update_tray_if_needed()  # Only update tray for disconnected state

        # Schedule next refresh
        self.root.after(1000, self.refresh_status)

    # ---------- VPN Watchdog ----------
    def start_vpn_watchdog(self):
        """Start a background thread that monitors WireGuard and handles unexpected drops."""
        if hasattr(self, "_watchdog_thread") and self._watchdog_thread.is_alive():
            return  # Already running

        self._watchdog_stop = threading.Event()
        self._watchdog_thread = threading.Thread(target=self._vpn_watchdog_loop, daemon=True)
        self._watchdog_thread.start()

        self._adapter_watcher.start()

    def stop_vpn_watchdog(self):
        """Stop the background watchdog thread."""
        if hasattr(self, "_watchdog_stop"):
            self._watchdog_stop.set()

            self._adapter_watcher.stop()

    def _vpn_watchdog_loop(self):
        """Continuously monitor the VPN state and react to unexpected drops or wake events."""
        import subprocess
        from subprocess import SW_HIDE, CREATE_NO_WINDOW

        was_up = is_vpn_up()
        network_was_up = True
        last_check = time.time()
        # --- Prepare hidden startup configuration ---
        si = subprocess.STARTUPINFO()
        si.dwFlags = subprocess.STARTF_USESHOWWINDOW | subprocess.STARTF_USESTDHANDLES  # Optional: helps with pipes
        si.wShowWindow = SW_HIDE  # Explicitly hide (SW_HIDE = 0)
        cf = CREATE_NO_WINDOW  # Preferred if available (Python 3.7+)

        # Helper to run PowerShell commands completely hidden
        def run_ps_command(ps_command):
            full_cmd = [
                "powershell.exe",
                "-WindowStyle", "Hidden",
                "-ExecutionPolicy", "Bypass",
                "-Command", ps_command
            ]
            try:
                result = subprocess.run(
                    full_cmd,
                    capture_output=True,
                    text=True,
                    timeout=15,
                    startupinfo=si,
                    creationflags=cf
                )
                # Optional logging (uncomment for debugging)
                # print(f"PS: {ps_command}\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}")
                return result.returncode == 0
            except Exception:
                return False

        # Helper to wait for a stable physical network with valid IP
        def wait_for_valid_ip(max_attempts=25, delay=3):
            for attempt in range(max_attempts):
                try:
                    result = subprocess.run(
                        ["ipconfig"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        startupinfo=si,
                        creationflags=cf
                    )
                    output = result.stdout.lower()
                    if ("ipv4 address" in output and 
                        "169." not in output and 
                        "media disconnected" not in output):
                        return True
                except Exception:
                    pass
                time.sleep(delay)
            return False

        while not getattr(self, "_watchdog_stop", threading.Event()).is_set():
            now_up = is_vpn_up()
            network_up = False
            # --- Detect physical network availability (Ethernet/Wi-Fi) ---
            try:
                result = subprocess.run(
                    ["netsh", "interface", "show", "interface"],
                    capture_output=True, text=True, timeout=5,
                    startupinfo=si, creationflags=cf
                )
                for line in result.stdout.lower().splitlines():
                    if "connected" in line and not any(v in line for v in ("wireguard", "wg", "tunnel", "virtual")):
                        network_up = True
                        break
            except Exception:
                pass
            # --- Detect system wake from sleep ---
            now = time.time()
            slept = (now - last_check) > 30
            last_check = now
            if slept:
                self.root.after(0, lambda: self.transient_status.configure(
                    text="Killswitch Active... Reconfiguring Network… Please wait..."
                ))
                # Wait for network stack to stabilize before repairs
                if wait_for_valid_ip():
                    run_ps_command("Get-NetFirewallRule -DisplayName 'Shuriken*' | Remove-NetFirewallRule -Confirm:$false -ErrorAction SilentlyContinue")
                    time.sleep(3)
                    run_ps_command("ipconfig /release *")
                    time.sleep(2)
                    run_ps_command("ipconfig /renew *")
                    run_ps_command("ipconfig /flushdns")

                    cleanup_stale_wireguard_service()

                    time.sleep(5)

                    if not is_vpn_up():
                        self.root.after(0, lambda: (
                            self.transient_status.configure(text="Resuming VPN after sleep…"),
                            self._attempt_auto_reconnect()
                        ))
                else:
                    self.root.after(0, lambda: self.transient_status.configure(
                        text="Network unstable after wake — will retry later"
                    ))
                self.root.after(4000, self.force_refresh_tray_icon)
            # --- Detect adapter restored after manual disable/enable ---
            if not network_was_up and network_up:
                self.root.after(0, lambda: self.transient_status.configure(
                    text="Adapter re-enabled — verifying network integrity…"
                ))
                if wait_for_valid_ip(max_attempts=15):
                    cleanup_stale_wireguard_service()
                    run_ps_command("Get-NetFirewallRule -DisplayName 'Shuriken*' | Remove-NetFirewallRule -Confirm:$false")
                    run_ps_command("ipconfig /release")
                    time.sleep(2)
                    run_ps_command("ipconfig /renew")
                    run_ps_command("ipconfig /flushdns")
                    if not is_vpn_up():
                        self.root.after(0, lambda: self.transient_status.configure(
                            text="Reconnecting VPN…"
                        ))
                        time.sleep(2)
                        self.root.after(0, self._attempt_auto_reconnect)
            # --- Detect VPN drop while kill switch active ---
            if was_up and not now_up and network_up:
                self.root.after(0, lambda: self.transient_status.configure(
                    text="VPN Connection Lost! Kill Switch Active!"
                ))
                self.root.after(0, lambda: self._update_tray_if_needed())
                if getattr(self, "auto_reconnect", True):
                    time.sleep(5)
                    if not is_vpn_up():
                        self.root.after(0, lambda: (
                            self.transient_status.configure(text="Reconnecting..."),
                            self._attempt_auto_reconnect()
                        ))
            if not was_up and now_up:
                self.root.after(0, lambda: (
                    self.transient_status.configure(text="Reconnected Securely"),
                    self.btn.configure(text="Disconnect"),
                    setattr(self, "secure_connected", True)
                ))
                self.root.after(1200, self.force_refresh_tray_icon)
                self.root.after(1500, lambda: self.fetch_and_display_ip("VPN", continuous=True))
               
            was_up = now_up
            network_was_up = network_up
            time.sleep(3)

    def _attempt_auto_reconnect(self):
        """Attempt to reconnect automatically using last known config."""
        if self.in_progress or is_vpn_up():
            return

        saved = read_registry()
        if not saved or not saved.is_file():
            self.transient_status.configure(text="Reconnect Failed! No Config Found!")
            return

        self.transient_status.configure(text="Reconnecting…")
        self.set_busy(self.btn, "Reconnecting…")

        def task():
            return vpn_up_nogui()

        def done(ok, err, src=None):
            if ok:
                self.transient_status.configure(text="Reconnected Securely")
                self.clear_busy(self.btn, "Disconnect")
                self.secure_connected = True
                self._update_tray_if_needed()
                self.fetch_and_display_ip("VPN", continuous=True)
            else:
                self.transient_status.configure(text="Reconnect Failed")
                self.clear_busy(self.btn, "Reconnect")
                if err:
                    messagebox.showerror("Reconnect Failed", err, parent=self.root)
                self._update_tray_if_needed()

        self.run_async(task, done)

    # ---------- Actions ----------
    def toggle(self):
        print("Toggle method called successfully!")
        if self.btn.cget("text") == "Connect":
            self.transient_status.configure(text="Connecting")
            self.set_busy(self.btn, "Connecting…")

            # --- Stop any existing watchdog before reconnecting ---
            self.stop_vpn_watchdog()

            # --- Start animated status dots for Connecting ---
            self._status_stop_event = threading.Event()
            threading.Thread(
                target=self.animate_status,
                args=("Connecting", "#009688", self._status_stop_event),
                daemon=True
            ).start()

            def task():
                return vpn_up_nogui()

            def done(ok, err, src=None):
                # Stop "Connecting..." animation regardless of outcome
                if hasattr(self, "_status_stop_event"):
                    self._status_stop_event.set()

                if ok:
                    if src:
                        write_registry(src)

                    # Step 1: connected to WireGuard service
                    self.transient_status.configure(text="Connected to WireGuard Service")

                    # --- Step 2: start Routing IP animation after short delay ---
                    def start_routing_animation():
                        if hasattr(self, "_status_stop_event"):
                            self._status_stop_event.set()

                        if getattr(self, "ip_detection_complete", False):
                            self.protection_status.configure(text="🔒 Protected", text_color="#00FF00")
                            self.transient_status.configure(text="")
                            return

                        self._status_stop_event = threading.Event()
                        threading.Thread(
                            target=self.animate_status,
                            args=("Routing IP", "#FFA000", self._status_stop_event),
                            daemon=True
                        ).start()

                    # Let "Connected to WireGuard Service" show briefly before Routing IP
                    self.root.after(100, start_routing_animation)

                    # --- NEW: Use consolidated function with continuous retry ---
                    # This will:
                    # - Retry every 3s until VPN IP is detected
                    # - Update IP, Provider, and Country labels
                    # - Stop the "Routing IP" animation automatically on success
                    self.fetch_and_display_ip("VPN", continuous=True)

                    # Start watchdog and internet monitor now that tunnel is up
                    self.start_vpn_watchdog()
                    self.start_internet_monitor()

                    # Optional: mark as secure early (tray icon, etc.)
                    self.secure_connected = True
                    self.clear_busy(self.btn, "Disconnect", "#f44336")
                    self._update_tray_if_needed()

                else:
                    self.transient_status.configure(text="Secure your online activity by connecting to VPN")
                    self.protection_status.configure(text="🔓 Unprotected", text_color="#f44336")
                    self.clear_busy(self.btn, "Connect", "#4CAF50")
                    self.secure_connected = False
                    if err:
                        messagebox.showerror("Shuriken", err, parent=self.root)
                    self._update_tray_if_needed()

            self.run_async(task, done)

        else:
            # ------------------- DISCONNECT -------------------
            self.transient_status.configure(text="Disconnecting…")
            self.set_busy(self.btn, "Disconnecting…")

            # Stop any ongoing status animation
            if hasattr(self, "_status_stop_event"):
                self._status_stop_event.set()

            self._status_stop_event = threading.Event()
            threading.Thread(
                target=self.animate_status,
                args=("Disconnecting", "#ff6f00", self._status_stop_event),
                daemon=True
            ).start()

            def task():
                self.stop_vpn_watchdog()
                ok, err = vpn_down_nogui()
                return ok, err, None

            def done(ok, err, _):
                if hasattr(self, "_status_stop_event"):
                    self._status_stop_event.set()
                self.transient_status.configure(text="Secure your online activity by connecting to VPN")
                self.protection_status.configure(text="🔓 Unprotected", text_color="#f44336")
                self.clear_busy(self.btn, "Connect", "#4CAF50")

                self.secure_connected = False
                self._update_tray_if_needed()

                # --- Stop watchdog when disconnecting ---
                self.stop_vpn_watchdog()
                self.stop_internet_monitor()

                # Show local IP again (one-shot is perfect here)
                self.fetch_and_display_ip("Local", continuous=False)
                self.location_var.set("Location:\nDetecting...")

                if not ok and err:
                    messagebox.showerror("Disconnect Failed", err, parent=self.root)
                self._update_tray_if_needed()

            self.run_async(task, done)

    def switch_server(self, new_conf: Path):
        if not new_conf.is_file():
            messagebox.showerror(
                "Shuriken",
                f"The selected config was not found:\n{new_conf}",
                parent=self.root,
            )
            return

        # ---- SECURE PATH VALIDATION (unchanged) ----
        try:
            config_dir_resolved = CONFIG_DIR.resolve(strict=True)
            new_conf_resolved = new_conf.resolve(strict=True)
        except FileNotFoundError:
            messagebox.showerror(
                "Shuriken",
                f"Config file does not exist:\n{new_conf}",
                parent=self.root,
            )
            return
        except Exception as e:
            messagebox.showerror(
                "Shuriken",
                f"Cannot resolve config path (symlink/perm issue):\n{new_conf}\n\n{e}",
                parent=self.root,
            )
            return

        if (config_dir_resolved not in new_conf_resolved.parents and
            new_conf_resolved != config_dir_resolved):
            messagebox.showerror(
                "Shuriken",
                f"Config must be inside the Config folder.\n\n"
                f"Allowed : {config_dir_resolved}\n"
                f"Rejected: {new_conf_resolved}",
                parent=self.root,
            )
            return

        if not validate_config_has_dns(new_conf):
            messagebox.showerror(
                "Shuriken",
                f"Config is missing DNS setting:\n{new_conf.name}\n\n"
                "Add this line under [Interface]:\n"
                "DNS = 10.0.0.1",
                parent=self.root,
            )
            return

        # --- Stop watchdog before switching ---
        self.stop_vpn_watchdog()

        # --- Start animated Connecting dots ---
        if hasattr(self, "_status_stop_event"):
            self._status_stop_event.set()
        self._status_stop_event = threading.Event()
        threading.Thread(
            target=self.animate_status,
            args=("Connecting", "#009688", self._status_stop_event),
            daemon=True,
        ).start()

        def task():
            ok, err = switch_server_nogui(new_conf)
            return ok, err, new_conf

        def done(ok, err, conf):
            # Always stop the "Connecting" animation
            if hasattr(self, "_status_stop_event"):
                self._status_stop_event.set()

            if ok:
                # Write the new config to registry and update server label
                if conf:
                    write_registry(conf)

                # Brief "Connected to WireGuard Service" message
                self.transient_status.configure(text="Connected to WireGuard Service")
  
                def start_routing_animation():
                    if hasattr(self, "_status_stop_event"):
                        self._status_stop_event.set()
                    if getattr(self, "ip_detection_complete", False):
                        self.protection_status.configure(text="🔒 Protected", text_color="#00FF00")
                        self.transient_status.configure(text="")
                        return
                    self._status_stop_event = threading.Event()
                    threading.Thread(
                        target=self.animate_status,
                        args=("Routing IP", "#FFA000", self._status_stop_event),
                        daemon=True
                    ).start()

                self.root.after(100, start_routing_animation)

                # Use the same consolidated continuous retry logic as in toggle()
                self.fetch_and_display_ip("VPN", continuous=True)

                # Restart watchdog now that the new tunnel is coming up
                self.start_vpn_watchdog()

                # Update tray and mark as secure
                self.secure_connected = True
                self._update_tray_if_needed()

            else:
                # Failure case
                self.transient_status.configure(text="Secure your online activity by connecting to VPN")
                self.protection_status.configure(text="🔓 Unprotected", text_color="#f44336")
                if err:
                    messagebox.showerror("Shuriken", err, parent=self.root)
                self._update_tray_if_needed()

        self.run_async(task, done)

def safe_run_main():
    """Run main() and log everything to Shuriken_Log.txt when DEBUG_MODE is enabled."""
    if DEBUG_MODE:
        from datetime import datetime
        ts = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        try:
            with open("Shuriken_Log.txt", "a", encoding="utf-8") as f:
                f.write(f"{ts} === Shuriken Started ===\n")
        except Exception:
            pass
    try:
        main()
    except Exception:
        import traceback
        if DEBUG_MODE:
            from datetime import datetime
            ts = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
            err = traceback.format_exc()
            try:
                with open("Shuriken_Log.txt", "a", encoding="utf-8") as f:
                    f.write(f"{ts} UNHANDLED EXCEPTION:\n{err}\n")
            except Exception:
                pass
            print("UNHANDLED EXCEPTION:", err)
        else:
            print("Error during execution (see Shuriken_Log.txt for details if enabled)")

# -------------------------- MAIN ---------------------------------
def main():
    import traceback

# === CLEAR LOG FILE AT STARTUP ===
    if DEBUG_MODE:
        try:
            from datetime import datetime
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open("Shuriken_Log.txt", "w", encoding="utf-8") as f:  # "w" = overwrite
                f.write(f"[{ts}] Shuriken v{__version__} initialized!\n")
            print("Log file cleared and new session started.")
        except Exception as e:
            print(f"Could not clear log file: {e}")
    # ==================================

    def dbg(msg):
        if DEBUG_MODE:
            from datetime import datetime
            ts = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
            try:
                with open("Shuriken_Log.txt", "a", encoding="utf-8") as f:
                    f.write(f"{ts} {msg}\n")
            except Exception:
                pass
    try:
        root = ctk.CTk()
        ctk.set_appearance_mode("dark")
        if THEME_PATH.exists():
            try:
                ctk.set_default_color_theme(str(THEME_PATH))
            except Exception as e:
                if DEBUG_MODE:
                    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    dbg(f"Failed to load custom theme ({e}), falling back to built-in")
                ctk.set_default_color_theme("dark-blue")
        else:
            if DEBUG_MODE:
                dbg(f"shuriken_theme.json not found, using built-in dark-blue theme")
            ctk.set_default_color_theme("dark-blue")
        try:
            if ICON_PATH.exists():
                root.iconbitmap(str(ICON_PATH.resolve()))
            else:
                dbg("Icon file not found")
        except Exception as e:
            dbg(f"Icon load failed: {e}")

        if not is_admin():
            result = messagebox.askyesno(
                "Shuriken",
                "Admin Rights Required.\n\n"
                "DNS leak protection requires Administrator privileges.\n\n"
                "Run as Administrator for full privacy protection?\n\n"
                "Click 'No' to continue with reduced security.",
                icon="warning"
            )
            if not result:
                safe_messagebox("info", "Shuriken", "Running with limited DNS protection.")
            else:
                # Relaunch as admin
                try:
                    ctypes.windll.shell32.ShellExecuteW(
                        None, "runas", sys.executable, " ".join(sys.argv), None, 1
                    )
                except Exception:
                    pass
                return

        # --- Single-instance protection (Windows Named Mutex) ---
        if not acquire_mutex("Global\\ShurikenInstanceLock"):
            messagebox.showwarning("Shuriken", "Shuriken is already running.")
            return

        # --- Resolve WireGuard paths dynamically (safe for missing installs) ---
        WG_PROGDATA, WG_DIR, WG_EXE, WG_CLI = get_wg_paths()

        # Base path for bundled resources when packaged (PyInstaller _MEIPASS)
        msi_path = (BUNDLED_BASE_DIR / "Resources" / "wireguard-amd64-0.5.3.msi").resolve()
        log_path = Path(os.environ.get("TEMP", ".")) / "Shuriken_installer.log"

        app = App(root)
        root.after(0, app.center_on_screen)
        root.deiconify()

        root.mainloop()
        dbg("Mainloop exited normally")

    except Exception:
        if DEBUG_MODE:
            from datetime import datetime
            ts = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
            with open("Shuriken_Log.txt", "a", encoding="utf-8") as f:
                f.write(f"{ts} EXCEPTION:\n" + traceback.format_exc() + "\n")

if __name__ == "__main__":
    safe_run_main()