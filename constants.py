import sys
import os
from pathlib import Path

# -------------------------- Paths --------------------------------
def setup_runtime_paths():
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
DEBUG_MODE   = True
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