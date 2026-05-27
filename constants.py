import sys
import os
from pathlib import Path

DEFAULT_STEALTH_PORT = 443

# -------------------------- Paths --------------------------------
def setup_runtime_paths():
    global APP_DIR, BUNDLED_BASE_DIR, ICON_PATH, CONFIG_DIR
    frozen = getattr(sys, "frozen", False)
    try:
        if frozen:
            APP_DIR = Path(sys.executable).parent
            BUNDLED_BASE_DIR = Path(getattr(sys, "_MEIPASS", APP_DIR))
        else:
            APP_DIR = Path(__file__).resolve().parent
            BUNDLED_BASE_DIR = APP_DIR

        ICON_PATH = BUNDLED_BASE_DIR / "assets" / "shuriken.ico"
        if not ICON_PATH.exists():
            ICON_PATH = APP_DIR / "assets" / "shuriken.ico"

        external_config = APP_DIR / "Config"
        if external_config.exists():
            CONFIG_DIR = external_config
        else:
            try:
                external_config.mkdir(parents=True, exist_ok=True)
                CONFIG_DIR = external_config
            except Exception:
                fallback = Path(os.environ.get("APPDATA", ".")) / "Shuriken" / "Config"
                try:
                    fallback.mkdir(parents=True, exist_ok=True)
                except Exception:
                    fallback = Path(os.environ.get("TEMP", ".")) / "Shuriken_Config"
                    fallback.mkdir(parents=True, exist_ok=True)
                CONFIG_DIR = fallback

    except Exception as e:
        _temp = Path(os.environ.get("TEMP", "."))
        APP_DIR          = _temp
        BUNDLED_BASE_DIR = _temp
        ICON_PATH        = _temp / "assets" / "shuriken.ico"
        CONFIG_DIR       = _temp / "Shuriken_Config"
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        print("setup_runtime_paths() failed, using TEMP:", e, CONFIG_DIR)

def get_wg_paths():
    progdata = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "WireGuard"

    wg_dir = Path(r"C:\Program Files\WireGuard")
    if not wg_dir.exists():
        wg_dir = Path(r"C:\Program Files (x86)\WireGuard")

    wg_exe = wg_dir / "wireguard.exe"
    wg_cli = wg_dir / "wg.exe"

    if not wg_exe.exists() and (wg_dir / "Data" / "wireguard.exe").exists():
        wg_exe = wg_dir / "Data" / "wireguard.exe"
    if not wg_cli.exists() and (wg_dir / "Data" / "wg.exe").exists():
        wg_cli = wg_dir / "Data" / "wg.exe"

    return progdata, wg_dir, wg_exe, wg_cli

# Run both path setups once at import time
setup_runtime_paths()
WG_PROGDATA, WG_DIR, WG_EXE, WG_CLI = get_wg_paths()

DEBUG_MODE   = False
APP_NAME     = "Shuriken VPN"
CONFIG_NAME  = "ShurikenVPN.conf"
SERVICE_NAME = Path(CONFIG_NAME).stem
REG_PATH     = r"Software\Shuriken"
REG_VAL      = "LastConfig"

ASSETS_DIR = BUNDLED_BASE_DIR / "assets"
if not ASSETS_DIR.exists():
    ASSETS_DIR = APP_DIR / "assets"

LOCKED_OVERLAY_PATH   = ASSETS_DIR / "locked.png"
UNLOCKED_OVERLAY_PATH = ASSETS_DIR / "unlocked.png"

FLAGS_DIR = BUNDLED_BASE_DIR / "flags"
if not FLAGS_DIR.exists():
    FLAGS_DIR = APP_DIR / "flags"

THEME_PATH = APP_DIR / "shuriken_theme.json"
if not THEME_PATH.exists():
    THEME_PATH = BUNDLED_BASE_DIR / "shuriken_theme.json"

APPDATA    = Path(os.environ.get("APPDATA", ""))
STATE_DIR  = APPDATA / "Shuriken"
