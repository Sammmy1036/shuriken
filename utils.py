import ctypes, threading, time, sys, winreg
import ctypes.wintypes as wintypes
from pathlib import Path
from constants import REG_PATH, REG_VAL, CONFIG_DIR, DEBUG_MODE
try:
    import pythoncom
    import win32com.client
    _HAVE_WMI = True
except ImportError:
    _HAVE_WMI = False
    pythoncom = None
    win32com = None
DEBUG_MODE = True
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
            try:
                config_dir_resolved = CONFIG_DIR.resolve(strict=True)
            except Exception:
                return None
            try:
                resolved = p.resolve(strict=True)
            except FileNotFoundError:
                return None
            except Exception:
                return None
            # Must be strictly inside CONFIG_DIR
            if config_dir_resolved not in resolved.parents and resolved != config_dir_resolved:
                return None
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
        if getattr(sys.modules[__name__], "DEBUG_MODE", False):
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
        self._log(f"[UTILS]Started monitoring: {', '.join(self.ADAPTERS)}")

        # initialise states
        for name in self.ADAPTERS:
            self._states[name] = self._adapter_enabled(name)

        while not self._stop_event.is_set():
            for name in self.ADAPTERS:
                cur = self._adapter_enabled(name)
                prev = self._states.get(name)

                # Adapter appeared → was disabled before
                if cur is True and prev is False:
                    self._log(f"[UTILS]{name} re-enabled. Running adapater repair.")
                    self.repair_callback()

                # Keep state up-to-date (including None → not present)
                self._states[name] = cur

            time.sleep(self.POLL_SECONDS)

    # ---- Public API ---------------------------------------------------
    def start(self):
        if self._thread is None or not self._thread.is_alive():
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()
            self._log(f"[UTILS]Thread started")

    def stop(self):
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        self._log(f"[UTILS]Thread stopped")