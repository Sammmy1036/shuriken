# Shuriken VPN v1.0.0.0 by Sammmy1036

__version__ = "1.0.0.0"

import os, sys, time, threading, subprocess, socket, winreg, ctypes, win32con, win32gui, json, atexit, random, ssl
import tkinter as tk
import customtkinter as ctk
import ctypes.wintypes as wintypes
import urllib.request
import platform, requests
from customtkinter import CTkScrollableFrame, CTkFrame, CTkEntry, CTkLabel, CTkButton, CTkImage
from tkinter import messagebox, ttk
from pathlib import Path
from PIL import Image as PILImage
from PIL import ImageTk
from difflib import SequenceMatcher
from subprocess import SW_HIDE, CREATE_NO_WINDOW
from metadata import SERVER_METADATA, USER_SERVER_METADATA, CITY_SYNONYMS, STATE_SYNONYMS, COUNTRY_SYNONYMS
from network import (
    _ps, _list_non_wg_adapters, _make_si,
    add_dns_leak_block, remove_dns_leak_block, run,
    add_kill_switch, remove_kill_switch,
    disable_ipv6_on_non_wg_adapters, enable_ipv6_on_non_wg_adapters,
    reset_firewall_if_blocked, add_wpad_block, remove_wpad_block,
    apply_split_tunnel, remove_split_tunnel,
)
from utils import (
    acquire_mutex, safe_messagebox, is_admin, read_registry, write_registry,
    AdapterWatcher,
    _HAVE_WMI, pythoncom, win32com,
)
from constants import (
    setup_runtime_paths, get_wg_paths, APP_DIR, BUNDLED_BASE_DIR, ICON_PATH, CONFIG_DIR,
    APP_NAME, CONFIG_NAME, SERVICE_NAME, REG_PATH, REG_VAL, ASSETS_DIR,
    LOCKED_OVERLAY_PATH, UNLOCKED_OVERLAY_PATH, FLAGS_DIR, THEME_PATH,
    STATE_DIR, WG_PROGDATA, WG_DIR, WG_EXE, WG_CLI, DEBUG_MODE,
    DEFAULT_STEALTH_PORT
)
from wireguard import (
    validate_config_has_dns, copy_conf_to_progdata, is_vpn_up, is_handshake_ok,
    vpn_up_nogui, vpn_down_nogui, switch_server_nogui,
    pretty_name_for, list_conf_files,
    repair_network_stack_if_stuck, run_adapter_repair_sequence,
    cleanup_stale_wireguard_service,
)

# FLAG_CACHE holds Tkinter ImageTk objects and must live here (UI layer),
# not in constants.py which has no Tkinter dependency.
FLAG_CACHE: dict = {}

# ── Split tunnel persistence ──────────────────────────────────────────────────
_SPLIT_TUNNEL_JSON = STATE_DIR / "split_tunnel_apps.json"

def _load_split_tunnel_apps() -> list[str]:
    """Load the persisted split tunnel app list. Returns [] on any error."""
    try:
        if _SPLIT_TUNNEL_JSON.exists():
            data = json.loads(_SPLIT_TUNNEL_JSON.read_text(encoding="utf-8"))
            if isinstance(data, list):
                # Filter out paths that no longer exist on disk
                return [p for p in data if isinstance(p, str) and Path(p).exists()]
    except Exception:
        pass
    return []

def _save_split_tunnel_apps(paths: list[str]) -> None:
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        _SPLIT_TUNNEL_JSON.write_text(
            json.dumps(paths, indent=2), encoding="utf-8"
        )
    except Exception as e:
        if DEBUG_MODE:
            print(f"[SPLIT] Save failed: {e}")

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
    pystray    = None
    Image      = None
    ImageDraw  = None
    _HAVE_PYWIN32 = False

try:
    from PIL import Image as PILImage
    from PIL import ImageTk
    _HAVE_PIL_IMAGETK = True
except Exception:
    PILImage          = None
    ImageTk           = None
    _HAVE_PIL_IMAGETK = False

# -------------------------- Tray icons ---------------------------
def _load_base_icon(size: int) -> PILImage.Image | None:
    if ICON_PATH is None or not ICON_PATH.exists():
        return None
    try:
        with PILImage.open(ICON_PATH) as ico:
            ico_sizes = ico.info.get('sizes', [(size, size) for size in [16, 32, 48, 64, 128, 256]])
            best_size = max(
                (s for s in ico_sizes if s[0] >= size),
                key=lambda s: s[0],
                default=max(ico_sizes, key=lambda s: s[0], default=(256, 256))
            )
            ico.load()
            resized = ico.resize((size, size), PILImage.LANCZOS)
            return resized.convert("RGBA")
    except Exception as e:
        print(f"Base icon load failed for size {size}: {e}")
        try:
            img = PILImage.open(ICON_PATH).convert("RGBA")
            return img.resize((size, size), PILImage.LANCZOS)
        except Exception:
            return None

def _add_corner_png_overlay(base_img: PILImage.Image | None, overlay_path: Path) -> PILImage.Image | None:
    if base_img is None:
        return None
    try:
        overlay = PILImage.open(overlay_path).convert("RGBA")
    except Exception as e:
        print(f"Overlay load failed ({overlay_path}): {e}")
        return base_img

    img    = base_img.copy()
    w, h   = img.size
    frac   = 0.50
    pad_frac = 0.04
    d      = max(int(min(w, h) * frac), 8)
    pad    = int(min(w, h) * pad_frac)

    overlay_resized = overlay.resize((d, d), PILImage.LANCZOS)
    x = w - pad - d
    y = pad
    img.paste(overlay_resized, (x, y), overlay_resized)
    return img

def get_tray_images():
    if PILImage is None:
        return None, None

    sizes       = [24, 40, 48, 64, 96]
    green_locked  = {}
    red_unlocked  = {}

    for sz in sizes:
        base = _load_base_icon(sz)
        if base is None:
            continue
        green_locked[sz]  = _add_corner_png_overlay(base, LOCKED_OVERLAY_PATH)
        red_unlocked[sz]  = _add_corner_png_overlay(base, UNLOCKED_OVERLAY_PATH)

    if not green_locked or not red_unlocked:
        return None, None
    largest_sz = max(sizes)
    return (
        green_locked[largest_sz],
        green_locked
    ), (
        red_unlocked[largest_sz],
        red_unlocked
    )

# -------------------------- UI -----------------------------------
class App:
    ECHOIP_URL = "https://shuriken-vpn3.ddnsgeek.com/json"

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
        self.root.title("Shuriken VPN")
        self.root.geometry("1000x620")
        self.root.resizable(False, False)
        self.set_window_icon()
        self.center_on_screen()
        # Core state
        self.secure_connected   = False
        self.in_progress        = False
        self.window_hidden      = False
        # Tray and icon state
        self.tray_icon          = None
        self.tray_imgs          = None
        self._last_tray_online  = is_vpn_up()
        self._last_hidden_state = self.window_hidden
        # Animation and IP detection
        self._global_anim_stop      = False
        self.ip_detection_complete  = False
        self.ip_check_thread        = None
        self._ip_detection_running  = False
        self._status_stop_event     = threading.Event()
        self._status_stop_event.set()

        self.auto_reconnect = True

        def _adapter_repair_callback():
            try:
                from network import _ps
                _ps("Get-NetFirewallRule -DisplayName 'Shuriken*' "
                    "-ErrorAction SilentlyContinue | "
                    "Remove-NetFirewallRule -Confirm:$false -ErrorAction SilentlyContinue | Out-Null")
            except Exception:
                pass
            si, cf = _make_si()
            for cmd in [["ipconfig", "/release"], ["ipconfig", "/renew"], ["ipconfig", "/flushdns"]]:
                try:
                    subprocess.run(cmd, capture_output=True, timeout=10,
                                   startupinfo=si, creationflags=cf)
                except Exception:
                    pass
            self._adapter_restored_pending = True

        self._adapter_watcher = AdapterWatcher(repair_callback=_adapter_repair_callback)

        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=0)
        self.root.grid_columnconfigure(1, weight=1)

        self.killswitch_img = CTkImage(light_image=PILImage.open(ASSETS_DIR / "killswitch.png"),
                                       dark_image=PILImage.open(ASSETS_DIR / "killswitch.png"),
                                       size=(50, 50))
        self.splittunnel_img = CTkImage(light_image=PILImage.open(ASSETS_DIR / "splittunneling.png"),
                                         dark_image=PILImage.open(ASSETS_DIR / "splittunneling.png"),
                                         size=(50, 50))
        self.tor_img = CTkImage(light_image=PILImage.open(ASSETS_DIR / "tor.png"),
                                dark_image=PILImage.open(ASSETS_DIR / "tor.png"),
                                size=(50, 50))
        self.settings_img = CTkImage(light_image=PILImage.open(ASSETS_DIR / "settings.png"),
                                     dark_image=PILImage.open(ASSETS_DIR / "settings.png"),
                                     size=(50, 50))

        # ===================== CENTER MAIN FRAME =====================
        self.main_frame = ctk.CTkFrame(self.root, corner_radius=0, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nswe")

        # ===================== OVERLAY BUTTONS =====================
        self.overlay_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.overlay_frame.place(relx=1.04, x=-40, rely=0.45, anchor="e")

        def create_feature_button(image, command, label_text):
            frame = ctk.CTkFrame(self.overlay_frame, fg_color="transparent")
            frame.pack(pady=12)
            btn = ctk.CTkButton(
                frame, text="", image=image, width=64, height=64,
                corner_radius=20, fg_color="#2D2D2D", hover_color="#333333",
                command=command
            )
            btn.pack()
            label = ctk.CTkLabel(
                frame, text=label_text,
                font=ctk.CTkFont(family="AniMe Vision - MB_EN", size=11, weight="normal"),
                text_color="#BBBBBB"
            )
            label.pack(pady=(4, 0))
            return frame

        create_feature_button(self.killswitch_img,  self.open_killswitch,    "Kill Switch")
        create_feature_button(self.splittunnel_img, self.open_splittunneling, "Split Tunneling")
        create_feature_button(self.tor_img,         self.launch_tor_browser,  "Tor Browser")
        create_feature_button(self.settings_img,    self.open_settings,       "Settings")

        # ===================== LEFT SIDEBAR =====================
        self.server_buttons = {}
        self.left_sidebar   = CTkFrame(self.root, width=280, corner_radius=0)
        self.left_sidebar.grid(row=0, column=0, sticky="nswe")
        self.left_sidebar.grid_propagate(False)
        CTkLabel(self.left_sidebar, text="Servers",
                 font=("AniMe Vision - MB_EN", 16, "bold"), pady=15).pack()

        self.search_entry = CTkEntry(
            self.left_sidebar,
            placeholder_text="Search for a Server",
            height=40, corner_radius=12, font=("Segoe UI", 12)
        )
        self.search_entry.pack(fill="x", padx=15, pady=(0, 10))

        icon_path = ASSETS_DIR / "search_icon.png"
        if icon_path.exists():
            search_img = CTkImage(light_image=PILImage.open(icon_path),
                                  dark_image=PILImage.open(icon_path),
                                  size=(27, 27))
        else:
            search_img = None
        if search_img:
            search_icon_label = CTkLabel(
                self.search_entry, image=search_img, text="", fg_color="transparent"
            )
            search_icon_label.place(relx=0, rely=0.5, anchor="w", x=190)
            search_icon_label.configure(takefocus=0)
            search_icon_label.bind("<Button-1>", lambda _: self.search_entry.focus_set())

        self.search_entry.bind("<KeyRelease>", lambda _: self.load_server_list())
        self.server_scrollable_frame = CTkScrollableFrame(self.left_sidebar, width=210)
        self.server_scrollable_frame.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        self.load_server_list()

        # ===================== MAIN CONTENT AREA =====================
        self.main_content = CTkFrame(self.main_frame, corner_radius=0, fg_color="transparent")
        self.main_content.pack(fill="both", expand=True, padx=30, pady=30)

        self.logo_img = None
        if ICON_PATH.exists():
            try:
                pil_img  = PILImage.open(ICON_PATH).convert("RGBA")
                max_width = 100
                if pil_img.width > max_width:
                    ratio    = min(1.0, max_width / pil_img.width)
                    new_size = (max_width, int(pil_img.height * ratio))
                    pil_img  = pil_img.resize(new_size, PILImage.Resampling.LANCZOS)
                self.logo_img = ctk.CTkImage(
                    light_image=pil_img, dark_image=pil_img,
                    size=(pil_img.width, pil_img.height)
                )
            except Exception as e:
                print(f"Logo loading failed: {e}")

        if self.logo_img:
            ctk.CTkLabel(self.main_content, image=self.logo_img, text="").pack(pady=(10, 2))

        self.header = ctk.CTkLabel(self.main_content, text="Shuriken VPN",
                                   font=("AniMe Vision - MB_EN", 16))
        self.header.pack(pady=(8, 8))

        self.status = ctk.CTkLabel(self.main_content, text="Disconnected",
                                   font=("Segoe UI", 10, "bold"))

        self.btn = ctk.CTkButton(
            self.main_content, text="Connect", command=self.toggle,
            font=("AniMe Vision - MB_EN", 16), width=200, height=60,
            corner_radius=12, fg_color="#2E7D32", hover_color="#43A047",
            text_color="white", border_width=2, border_color="#1B5E20",
        )
        self.btn.pack(pady=30)

        self.transient_status = ctk.CTkLabel(
            self.main_content, text="", font=("Segoe UI", 14), text_color="#AAAAAA"
        )
        self.transient_status.pack(pady=(10, 30))

        bottom_frame = ctk.CTkFrame(self.main_content, fg_color="transparent")
        bottom_frame.pack(side="bottom", fill="x", pady=(40, 20), padx=40)

        self.protection_status = ctk.CTkLabel(
            bottom_frame, text="Unprotected",
            font=ctk.CTkFont(family="AniMe Vision - MB_EN", size=25),
            text_color="#f44336", anchor="w", justify="left"
        )
        self.protection_status.pack(anchor="w", pady=(0, 20), padx=20)

        info_subframe = ctk.CTkFrame(bottom_frame, fg_color="transparent")
        info_subframe.pack(fill="x", padx=20)
        info_subframe.grid_columnconfigure(0, weight=1)
        info_subframe.grid_columnconfigure(1, weight=1)
        info_subframe.grid_columnconfigure(2, weight=1)

        info_font  = ctk.CTkFont(family="Segoe UI", size=13, weight="normal")
        info_color = "#DADADA"

        self.ip_var = tk.StringVar(value="Your IP Address:\nDetecting...")
        self.ip_label = ctk.CTkLabel(
            info_subframe, textvariable=self.ip_var,
            font=info_font, text_color=info_color, anchor="w", justify="left"
        )
        self.ip_label.grid(row=0, column=0, sticky="w")

        self.location_var = tk.StringVar(value="Location:\nDetecting...")
        self.location_label = ctk.CTkLabel(
            info_subframe, textvariable=self.location_var,
            font=info_font, text_color=info_color, anchor="center", justify="center"
        )
        self.location_label.grid(row=0, column=1, sticky="ew", padx=20)

        self.provider_var = tk.StringVar(value="Provider:\nDetecting...")
        self.provider_label = ctk.CTkLabel(
            info_subframe, textvariable=self.provider_var,
            font=info_font, text_color=info_color, anchor="e", justify="right"
        )
        self.provider_label.grid(row=0, column=2, sticky="e", padx=(20, 0))

        separator = ctk.CTkFrame(self.main_content, height=1, fg_color="#333333")
        separator.pack(side="bottom", fill="x", pady=(0, 20), padx=40)
        separator.lower()

        self.refresh_status()
        self.init_tray()
        if self.tray_icon:
            try:
                self.tray_icon.icon = self.tray_image_for_state(is_vpn_up())
            except Exception:
                pass
        self.load_server_list()
        self.transient_status.configure(text="Checking connection status…")
        self.protection_status.configure(text="Detecting", text_color="#FFFF00")
        self.btn.configure(text="Connect")
        self.location_var.set("Location:\nDetecting...")
        if is_vpn_up():
            self.protection_status.configure(text="Protected", text_color="#00FF00")
            print("Protected Label Update 1")
            self.transient_status.configure(text="Connection Secure & Encrypted")
            self.btn.configure(text="Disconnect")
            self.secure_connected = True
            self.fetch_and_display_ip("VPN", continuous=True)
        else:
            self.transient_status.configure(
                text="Secure your online activity by connecting to Shuriken VPN"
            )
            self.fetch_and_display_ip("Local", continuous=False)

        self.overlay_frame.lift()

    def open_killswitch(self):
        messagebox.showinfo(
            "Shuriken VPN",
            "Full Kill Switch is already built-in and active when connected!\n\n"
            "Blocks all internet traffic if the VPN connection drops unexpectedly.",
            parent=self.root
        )

    def open_splittunneling(self):
        SW, SH = 560, 520
        win = ctk.CTkToplevel(self.root)
        win.title("Shuriken VPN")
        win.resizable(False, False)
        win.grab_set()

        # ── Center over main window ──────────────────────────────────────────
        self.root.update_idletasks()
        x = self.root.winfo_rootx() + (self.root.winfo_width()  - SW) // 2
        y = self.root.winfo_rooty() + (self.root.winfo_height() - SH) // 2
        win.geometry(f"{SW}x{SH}+{x}+{y}")

        # ── Icon (deferred so CTk doesn't overwrite it) ──────────────────────
        def _apply_icon():
            if _HAVE_PIL_IMAGETK and ICON_PATH.exists():
                try:
                    pil = PILImage.open(ICON_PATH).resize((32, 32), PILImage.LANCZOS)
                    img = ImageTk.PhotoImage(pil)
                    win.iconphoto(False, img)
                    win._icon_ref = img
                    return
                except Exception:
                    pass
            if ICON_PATH.exists():
                try:
                    win.iconbitmap(str(ICON_PATH))
                except Exception:
                    pass
        win.after(201, _apply_icon)

        # ── Logo + title ─────────────────────────────────────────────────────
        if self.logo_img:
            ctk.CTkLabel(win, image=self.logo_img, text="").pack(pady=(18, 0))
        ctk.CTkLabel(win, text="Split Tunneling",
                     font=ctk.CTkFont(size=20, weight="bold")).pack(pady=(8, 0))
        ctk.CTkLabel(
            win,
            text="Apps listed below bypass the VPN and use your real network.",
            font=ctk.CTkFont(size=12),
            text_color="#AAAAAA"
        ).pack(pady=(2, 12))

        # ── Scrollable app list ───────────────────────────────────────────────
        list_frame = ctk.CTkScrollableFrame(win, width=500, height=220)
        list_frame.pack(fill="x", padx=20)

        # In-memory working copy — edits apply immediately when connected
        app_paths: list[str] = _load_split_tunnel_apps()

        def _refresh_list():
            for w in list_frame.winfo_children():
                w.destroy()
            if not app_paths:
                ctk.CTkLabel(
                    list_frame,
                    text="No apps added yet. Click 'Add Application' below.",
                    text_color="#666666", font=ctk.CTkFont(size=12)
                ).pack(pady=20)
                return
            for idx, path in enumerate(app_paths):
                row = ctk.CTkFrame(list_frame, fg_color="#1e1e1e", corner_radius=8)
                row.pack(fill="x", pady=3, padx=4)

                # App icon from exe (best effort)
                icon_label = ctk.CTkLabel(row, text="", width=28)
                icon_label.pack(side="left", padx=(10, 6), pady=6)
                try:
                    import win32ui, win32con, win32api
                    import struct
                    large, small = win32gui.ExtractIconEx(path, 0)
                    if large:
                        hdc  = win32ui.CreateDCFromHandle(win32gui.GetDC(0))
                        hbmp = win32ui.CreateBitmap()
                        hbmp.CreateCompatibleBitmap(hdc, 32, 32)
                        hdc2 = hdc.CreateCompatibleDC()
                        hdc2.SelectObject(hbmp)
                        win32gui.DrawIconEx(hdc2.GetSafeHdc(), 0, 0, large[0], 32, 32, 0, 0, win32con.DI_NORMAL)
                        bmp_info = hbmp.GetInfo()
                        bmp_str  = hbmp.GetBitmapBits(True)
                        pil_icon = PILImage.frombuffer(
                            "RGBA", (bmp_info["bmWidth"], bmp_info["bmHeight"]),
                            bmp_str, "raw", "BGRA", 0, 1
                        )
                        ctk_icon = ctk.CTkImage(light_image=pil_icon, dark_image=pil_icon, size=(24, 24))
                        icon_label.configure(image=ctk_icon)
                        icon_label._img_ref = ctk_icon   # prevent GC
                        for h in large + small:
                            try: win32gui.DestroyIcon(h)
                            except Exception: pass
                except Exception:
                    pass  # icon extraction failed — blank space is fine

                name = Path(path).name
                ctk.CTkLabel(
                    row, text=name, font=ctk.CTkFont(size=13),
                    anchor="w", width=330
                ).pack(side="left", padx=(0, 8))
                ctk.CTkLabel(
                    row, text=str(Path(path).parent),
                    font=ctk.CTkFont(size=10), text_color="#666666",
                    anchor="w"
                ).pack(side="left", expand=True, fill="x")

                def _remove(i=idx):
                    del app_paths[i]
                    _save_split_tunnel_apps(app_paths)
                    if is_vpn_up():
                        apply_split_tunnel(app_paths)
                    _refresh_list()

                ctk.CTkButton(
                    row, text="✕", width=32, height=28,
                    fg_color="#3a1a1a", hover_color="#6b2020",
                    font=ctk.CTkFont(size=13), command=_remove
                ).pack(side="right", padx=8, pady=4)

        _refresh_list()

        # ── Status note ───────────────────────────────────────────────────────
        status_color = "#00CC44" if is_vpn_up() else "#888888"
        status_text  = (
            "VPN connected — changes apply immediately."
            if is_vpn_up() else
            "VPN not connected — changes saved and will apply on next connect."
        )
        status_label = ctk.CTkLabel(
            win, text=status_text,
            font=ctk.CTkFont(size=11), text_color=status_color
        )
        status_label.pack(pady=(10, 4))

        # ── Add Application button ────────────────────────────────────────────
        def _add_app():
            from tkinter import filedialog
            path = filedialog.askopenfilename(
                parent=win,
                title="Select Application",
                filetypes=[("Executable", "*.exe"), ("All files", "*.*")],
                initialdir=os.environ.get("ProgramFiles", r"C:\Program Files")
            )
            if not path:
                return
            path = str(Path(path))   # normalise slashes
            if path in app_paths:
                messagebox.showinfo(
                    "Already Added",
                    f"{Path(path).name} is already in the split tunnel list.",
                    parent=win
                )
                return
            app_paths.append(path)
            _save_split_tunnel_apps(app_paths)
            if is_vpn_up():
                apply_split_tunnel(app_paths)
            _refresh_list()

        btn_row = ctk.CTkFrame(win, fg_color="transparent")
        btn_row.pack(pady=(6, 16))
        ctk.CTkButton(
            btn_row, text="＋  Add Application",
            width=200, height=40, corner_radius=10,
            fg_color="#1a3a1a", hover_color="#2e7d32",
            font=ctk.CTkFont(size=14),
            command=_add_app
        ).pack(side="left", padx=8)
        ctk.CTkButton(
            btn_row, text="Clear All",
            width=110, height=40, corner_radius=10,
            fg_color="#3a1a1a", hover_color="#6b2020",
            font=ctk.CTkFont(size=13),
            command=lambda: (
                app_paths.clear(),
                _save_split_tunnel_apps(app_paths),
                remove_split_tunnel() if is_vpn_up() else None,
                _refresh_list()
            )
        ).pack(side="left", padx=8)

    def launch_tor_browser(self):
        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            base_dir = Path(sys._MEIPASS)
        else:
            base_dir = Path(os.path.dirname(os.path.abspath(__file__)))

        resources_dir = base_dir / "Resources"

        if sys.platform.startswith("win"):
            tor_root  = resources_dir / "tor-windows" / "Tor Browser"
            firefox_exe = tor_root / "Browser" / "firefox.exe"
        else:
            tor_root  = resources_dir / "tor-linux" / "Tor Browser"
            firefox_exe = tor_root / "Browser" / "firefox"

        if not tor_root.exists() or not tor_root.is_dir():
            messagebox.showerror(
                "Tor Browser Not Found",
                "Official Tor Browser folder not found in bundled resources!\n\n"
                f"Expected location: {tor_root}\n\n"
                "This usually means:\n"
                "• The --add-data path in PyInstaller doesn't match the expected structure, or\n"
                "• Case mismatch in folder names, or\n"
                "• The Tor Browser folder was not fully included.\n\n"
                "Current expected structure:\n"
                "Resources/tor-windows/Tor Browser/Browser/firefox.exe",
                parent=self.root
            )
            return

        if not firefox_exe.exists():
            messagebox.showerror(
                "Tor Browser Error",
                f"firefox executable not found at:\n{firefox_exe}\n\n"
                "The Tor Browser bundle appears incomplete.",
                parent=self.root
            )
            return

        if not getattr(self, "secure_connected", False):
            if not messagebox.askyesno(
                "Shuriken VPN",
                "For maximum privacy, it's recommended to use Tor over an active VPN.\n\n"
                "This hides Tor usage from your ISP and adds an extra layer of protection.\n\n"
                "Launch Official Tor Browser anyway?",
                icon="warning", parent=self.root
            ):
                return

        try:
            creationflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            subprocess.Popen([str(firefox_exe)], cwd=str(tor_root), creationflags=creationflags)
        except Exception as e:
            messagebox.showerror("Launch Failed", f"Could not start Official Tor Browser:\n\n{e}",
                                 parent=self.root)

    def open_settings(self):
        SW, SH = 500, 400
        settings_win = ctk.CTkToplevel(self.root)
        settings_win.title("Shuriken VPN")
        settings_win.resizable(False, False)
        settings_win.grab_set()

        # ── Center over the main window ──────────────────────────────────────
        self.root.update_idletasks()
        rx = self.root.winfo_rootx()
        ry = self.root.winfo_rooty()
        rw = self.root.winfo_width()
        rh = self.root.winfo_height()
        x  = rx + (rw - SW) // 2
        y  = ry + (rh - SH) // 2
        settings_win.geometry(f"{SW}x{SH}+{x}+{y}")

        # ── Apply the same icon as the main window ───────────────────────────
        # CTkToplevel re-applies the default CTk icon after __init__ finishes,
        # overwriting any iconphoto/iconbitmap set synchronously. Deferring
        # with after(201) fires after CTk's own internal icon setup is done.
        def _apply_icon():
            if _HAVE_PIL_IMAGETK and ICON_PATH.exists():
                try:
                    pil = PILImage.open(ICON_PATH).resize((32, 32), PILImage.LANCZOS)
                    img = ImageTk.PhotoImage(pil)
                    settings_win.iconphoto(False, img)
                    settings_win._icon_ref = img   # prevent garbage collection
                    return
                except Exception:
                    pass
            if ICON_PATH.exists():
                try:
                    settings_win.iconbitmap(str(ICON_PATH))
                except Exception:
                    pass

        settings_win.after(201, _apply_icon)

        # ── Shuriken logo ────────────────────────────────────────────────────
        if self.logo_img:
            ctk.CTkLabel(settings_win, image=self.logo_img, text="").pack(pady=(18, 0))

        ctk.CTkLabel(settings_win, text="Advanced Settings",
                     font=ctk.CTkFont(size=20, weight="bold")).pack(pady=(8, 20))

        _stealth_initial = False
        try:
            _sk = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Shuriken", 0, winreg.KEY_READ)
            _stealth_initial = bool(winreg.QueryValueEx(_sk, "StealthPort")[0])
            winreg.CloseKey(_sk)
        except Exception:
            pass
        stealth_var = tk.BooleanVar(value=_stealth_initial)

        def toggle_stealth():
            new_val = stealth_var.get()
            if DEBUG_MODE:
                print("Stealth port changed to:", new_val)
            try:
                key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Shuriken")
                winreg.SetValueEx(key, "StealthPort", 0, winreg.REG_DWORD, int(new_val))
                winreg.CloseKey(key)
            except Exception:
                pass

        ctk.CTkCheckBox(
            settings_win,
            text="Use stealth port 443 (better obfuscation against ISP DPI)",
            variable=stealth_var, command=toggle_stealth,
            border_width=2,
            border_color=("gray70", "gray50"),
            fg_color=("gray80", "gray30"),
            hover_color=("gray60", "gray40"),
            checkmark_color=("white", "black"),
            text_color=("black", "white"),
            text_color_disabled=("gray50", "gray60"),
            corner_radius=6
        ).pack(pady=10, padx=20, anchor="w")

        ctk.CTkLabel(settings_win, text="More options coming soon...", text_color="gray").pack(pady=20)

    # ------------------------------------------------------------------
    #  Internet Connectivity Monitor
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
                was_online = None
                time.sleep(2)
                continue
            online = self._is_online()
            if was_online is None:
                was_online = online
            elif online != was_online:
                was_online = online
            time.sleep(5)

    def _is_online(self):
        try:
            result = subprocess.run(
                ["ping", "-n", "1", "-w", "1000", self.vpn_server_ip],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW
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
        w, h   = self.root.winfo_width(), self.root.winfo_height()
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        self.root.geometry(f"{w}x{h}+{(sw - w) // 2}+{(sh - h) // 2}")

    # ---------- Dropdown ----------
    def display_for_path(self, p: Path | None) -> str:
        return "(none)" if not p else pretty_name_for(p.name)

    def get_available_servers(self) -> list[Path]:
        return list_conf_files()

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

        if country_normalized in FLAG_CACHE:
            cached = FLAG_CACHE[country_normalized]
            if isinstance(cached, CTkImage):
                return cached
            del FLAG_CACHE[country_normalized]

        if PILImage is None or not FLAGS_DIR.exists():
            if DEBUG_MODE:
                if not hasattr(self, "_flag_prereq_warning_logged"):
                    self._flag_prereq_warning_logged = True
                    log("Pillow or FLAGS_DIR missing — cannot load flag images")
            return None

        candidates = [
            f"{country_normalized}.png",
            f"{country_normalized}.jpg",
            f"{country_normalized.lower()}.png",
            f"{country_normalized.lower()}.jpg",
            f"{country_normalized[:2].lower()}.png",
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
                ctk_img = CTkImage(light_image=pil_img, dark_image=pil_img, size=(32, 24))
                FLAG_CACHE[country_normalized] = ctk_img
                return ctk_img
            except Exception as e:
                if DEBUG_MODE:
                    log(f"FLAG LOAD FAILED: '{country}' → '{country_normalized}': {e}")
                return None
        else:
            if DEBUG_MODE:
                log(f"FLAG MISSING: '{country}' → normalized: '{country_normalized}'")
            return None

    def _resolve_synonym(self, word: str, syn_dict: dict) -> list[str] | None:
        """Exact match first, then smart fuzzy fallback."""
        word_l = word.lower().strip()
        if word_l in syn_dict:
            val = syn_dict[word_l]
            return [t.lower() for t in val] if isinstance(val, list) else [str(val).lower()]

        best_ratio = 0.0
        best_val   = None
        for k, v in syn_dict.items():
            r = SequenceMatcher(None, word_l, k.lower()).ratio()
            if r > best_ratio:
                best_ratio = r
                best_val   = v

        if best_ratio >= 0.60:
            if isinstance(best_val, list):
                return [t.lower() for t in best_val]
            return [str(best_val).lower()]
        return None

    def load_server_list(self):
        """Refresh the left sidebar with all available servers (with smart search)."""
        for widget in self.server_scrollable_frame.winfo_children():
            widget.destroy()
        self.server_buttons.clear()
        servers = self.get_available_servers()
        if not servers:
            CTkLabel(
                self.server_scrollable_frame,
                text="No .conf files found in Config folder",
                text_color="#888888", font=("Segoe UI", 12)
            ).pack(pady=30)
            return

        raw_query      = self.search_entry.get().strip()
        query_lower    = raw_query.lower()
        current_config = read_registry()

        # === Current Server Banner ===
        if current_config and current_config in servers:
            meta     = SERVER_METADATA.get(
                current_config.name,
                {"city": "Unknown", "state": "", "country": "Unknown", "name": current_config.stem}
            )
            flag     = self._get_flag(meta["country"])
            location = meta["city"]
            if meta.get("state"):
                location += f", {meta['state']}"
            location += f", {meta['country']}"
            current_row = CTkFrame(self.server_scrollable_frame,
                                   fg_color=("#0d47a1", "#0d47a1"), height=50)
            current_row.pack(fill="x", pady=(0, 12), padx=8)
            current_row.pack_propagate(False)
            CTkLabel(current_row, text="", image=flag, width=40, height=30).pack(side="left", padx=12)
            CTkLabel(current_row, text="● Current Server",
                     font=("Segoe UI", 11, "bold"), text_color="white").pack(side="top", anchor="w", padx=(0, 10))
            CTkLabel(current_row, text=location,
                     font=("Segoe UI", 12), text_color="#bbdefb", anchor="w").pack(side="bottom", anchor="w", padx=(0, 10))

        # === Smart Search ===
        display_servers = servers
        if raw_query:
            scored = []
            q            = query_lower.strip()
            query_words  = q.split()
            city_target = state_target = country_target = None

            for word in [q] + query_words:
                if (city_target := self._resolve_synonym(word, CITY_SYNONYMS)) is not None:
                    break
                if (state_target := self._resolve_synonym(word, STATE_SYNONYMS)) is not None:
                    break
                if (country_target := self._resolve_synonym(word, COUNTRY_SYNONYMS)) is not None:
                    break

            for conf_path in servers:
                meta         = SERVER_METADATA.get(
                    conf_path.name,
                    {"city": "Unknown", "state": "", "country": "Unknown", "name": conf_path.stem}
                )
                city_norm    = meta["city"].lower()
                state_norm   = meta.get("state", "").lower()
                country_norm = meta["country"].lower()
                name_norm    = meta["name"].lower()

                parts = [city_norm, state_norm, country_norm, name_norm]
                if state_norm:
                    parts.extend([
                        f"{city_norm} {state_norm}",
                        f"{city_norm}, {state_norm}",
                        f"{city_norm} {state_norm} {country_norm}",
                    ])

                best_ratio = max(
                    (SequenceMatcher(None, q, part).ratio() for part in parts),
                    default=0.0
                )

                if city_target:
                    for tgt in city_target:
                        if tgt in (city_norm, name_norm):
                            best_ratio += 0.60
                            break
                if state_target:
                    for tgt in state_target:
                        if tgt == state_norm:
                            best_ratio += 0.65
                            break
                if country_target:
                    for tgt in country_target:
                        if tgt == country_norm:
                            best_ratio += 0.70
                            break

                if len(q) > 5 and q in (city_norm, state_norm, country_norm):
                    best_ratio += 0.12

                if best_ratio >= 0.45:
                    scored.append((best_ratio, conf_path, meta))

            scored.sort(reverse=True, key=lambda x: x[0])
            display_servers = [item[1] for item in scored]

        # === Display servers ===
        for conf_path in display_servers:
            meta     = SERVER_METADATA.get(
                conf_path.name,
                {"city": "Unknown", "state": "", "country": "Unknown", "name": conf_path.stem}
            )
            location = meta["city"]
            if meta.get("state"):
                location += f", {meta['state']}"
            location += f", {meta['country']}"
            flag = self._get_flag(meta["country"])
            row  = CTkFrame(self.server_scrollable_frame, fg_color="transparent")
            row.pack(fill="x", pady=2, padx=8)
            CTkLabel(row, text="", image=flag, width=36, height=28).pack(side="left", padx=(8, 12))
            btn = CTkButton(
                row, text=location, anchor="w",
                fg_color="transparent", hover_color=("#2f2f2f", "#333333"),
                height=44, font=("Segoe UI", 13), width=100,
                command=lambda p=conf_path: self.select_server(p)
            )
            btn.pack(fill="x", expand=True)
            if conf_path == current_config:
                btn.configure(fg_color=("#1f538d", "#144870"))
            self.server_buttons[conf_path] = btn

    def select_server(self, conf_path: Path):
        current_config = read_registry()
        if is_vpn_up() and current_config and current_config.resolve() == conf_path.resolve():
            return

        if not validate_config_has_dns(conf_path):
            safe_messagebox("error", "Invalid Config", f"Missing DNS in {conf_path.name}", parent=self.root)
            return

        write_registry(conf_path)

        for path, btn in self.server_buttons.items():
            if btn:
                btn.configure(fg_color=("#1f538d", "#144870") if path == conf_path else "transparent")

        if is_vpn_up():
            self.switch_server(conf_path)
        else:
            meta = SERVER_METADATA.get(conf_path.name, {"name": conf_path.stem})
            safe_messagebox("info", "Shuriken VPN", f"Default Server Set To: {meta.get('name')}", parent=self.root)

        self.load_server_list()

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
            hover = "#e53935" if fg_color.lower() in ["#f44336", "#d32f2f", "#c62828"] else "#43a047"
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
        if self._global_anim_stop:
            return
        dots = 0
        while not stop_event.is_set():
            dots = (dots + 1) % 4
            text = base_text + ("." * dots)
            self.root.after(0, lambda t=text, c=fg_color: self.transient_status.configure(text=t))
            time.sleep(0.35)

    def fetch_and_display_ip(self, state: str = "Local", continuous: bool = False, timeout_sec: int = 30):
        """
        Fetch public IP until it changes (VPN mode) or timeout.
        In VPN mode: continuously shows Detecting... and retries until real IP change is confirmed.
        """
        # Clear stale _ip_detection_running flag instead of silently dropping the fetch
        if continuous and getattr(self, '_ip_detection_running', False):
            print("[DEBUG] IP detection flag stale — clearing and proceeding")
            self._ip_detection_running = False
        if continuous:
            self._ip_detection_running = True
        if continuous and hasattr(self, '_ip_detect_stop'):
            self._ip_detect_stop.set()
        if continuous:
            self._ip_detect_stop = threading.Event()

        start_time = time.time()
        if not continuous:
            timeout_sec = 10

        last_ip = getattr(self, '_last_detected_ip', None)

        def get_ip_info():
            try:
                response = requests.get(self.ECHOIP_URL, timeout=8)
                response.raise_for_status()
                data = response.json()

                ip = data.get("ip")
                if not ip:
                    return None, None, None, None

                provider        = data.get("asn_org") or data.get("asn") or "Unknown"
                country         = data.get("country") or "Unknown"
                city            = data.get("city", "")
                location_parts  = [p for p in [city, country] if p and p != "Unknown"]
                display_location = ", ".join(location_parts) if location_parts else country

                if ip.startswith("10."):
                    try:
                        real_public_ip = socket.gethostbyname("shuriken-vpn3.ddnsgeek.com")
                        if real_public_ip != ip:
                            ip               = real_public_ip
                            provider         = "Datacamp Limited"
                            country          = "Switzerland"
                            display_location = "Zurich, Switzerland"
                    except socket.gaierror as e:
                        print(f"[DEBUG] DDNS fallback failed: {e}")
                        provider = "VPN"
                        country  = "VPN"

                return ip, provider, country, display_location

            except Exception as e:
                if DEBUG_MODE:
                    print(f"[DEBUG] echoip request failed: {e}")
                return None, None, None, None

        def update_ui_protected(ip, provider, country, display_location):
            self.root.after(0, lambda: (
                self.ip_var.set(f"Your IP Address:\n{ip} ({state})"),
                self.provider_var.set(f"Provider:\n{provider}"),
                self.location_var.set(f"Location:\n{display_location}"),
                self.protection_status.configure(text="Protected", text_color="#00FF00"),
                print("Protected Label Update 2"),
                self.transient_status.configure(text="Connection Secure & Encrypted"),
                self.clear_busy(self.btn, "Disconnect", "#f44336") if state == "VPN" else None,
                setattr(self, "secure_connected", True),
            ))

        def update_ui_ip(ip, provider, country, display_location, protected):
            self.root.after(0, lambda: (
                self.ip_var.set(f"Your IP Address:\n{ip} ({state})"),
                self.provider_var.set(f"Provider:\n{provider}"),
                self.location_var.set(f"Location:\n{display_location}"),
                self.protection_status.configure(
                    text="Protected" if protected else "Unprotected",
                    text_color="#00FF00" if protected else "#f44336"
                ),
                print("Protected Label Update IP" if protected else "Unprotected Label Update IP"),
            ))

        def update_ui_detecting():
            self.root.after(0, lambda: (
                self.ip_var.set("Your IP Address:\nDetecting..."),
                self.provider_var.set("Provider:\nDetecting..."),
                self.location_var.set("Location:\nDetecting..."),
                self.protection_status.configure(text="Establishing", text_color="#FFFF00"),
                self.transient_status.configure(text="Tunnel active. Connecting to internet..."),
                self.clear_busy(self.btn, "Disconnect", "#f44336"),
            ))

        def update_ui_unprotected():
            self.root.after(0, lambda: (
                self.ip_var.set("Your IP Address:\nNot connected"),
                self.provider_var.set("Provider:\n—"),
                self.location_var.set("Location:\n—"),
                self.protection_status.configure(text="Unprotected", text_color="#f44336"),
                print("Unprotected Label Updated 2"),
                self.transient_status.configure(text="VPN tunnel not active"),
            ))

        def update_ui_failed():
            self.root.after(0, lambda: (
                self.ip_var.set("Your IP Address:\nFailed to detect"),
                self.provider_var.set("Provider:\nFailed to detect"),
                self.location_var.set("Location:\nFailed to detect"),
                self.protection_status.configure(text="Unprotected", text_color="#f44336"),
                print("Unprotected Label Updated 4"),
            ))

        def task():
            nonlocal last_ip
            if state == "VPN" and not is_vpn_up():
                update_ui_unprotected()
                return

            try:
                while (continuous and not self._ip_detect_stop.is_set()) or not continuous:
                    if not continuous and time.time() - start_time > timeout_sec:
                        update_ui_failed()
                        return

                    ip, provider, country, display_location = get_ip_info()

                    if ip:
                        current_vpn_up = is_vpn_up()
                        if (state == "VPN" and not self.secure_connected
                                and ip != last_ip and current_vpn_up):
                            update_ui_protected(ip, provider, country, display_location)
                            if hasattr(self, "_status_stop_event"):
                                self._status_stop_event.set()
                            last_ip = ip
                            self._last_detected_ip = ip
                            print("[DEBUG] IP change confirmed. Stopping continuous IP check.")
                            break
                        else:
                            last_ip = ip
                            is_protected_now = (state == "VPN" and current_vpn_up and self.secure_connected)
                            update_ui_ip(ip, provider, country, display_location, is_protected_now)
                            if not continuous:
                                return
                            if self.secure_connected:
                                print("[DEBUG] Protected & stable. Stopping IP polling thread.")
                                break
                            time.sleep(3)
                            print(f"[DEBUG] Checking for real IP change at {time.time():.0f}")
                            continue
                    else:
                        if not continuous and time.time() - start_time > timeout_sec:
                            update_ui_failed()
                            return
                        if state == "VPN" and not self.secure_connected:
                            update_ui_detecting()
                        if continuous:
                            time.sleep(3)
                            print(f"[DEBUG] No IP this iteration at {time.time():.0f}")
                            continue
                        else:
                            return

            finally:
                if hasattr(self, "_status_stop_event"):
                    self._status_stop_event.set()
                if continuous and hasattr(self, "_ip_detect_stop"):
                    self._ip_detect_stop.set()
                if continuous:
                    self._ip_detection_running = False

        threading.Thread(target=task, daemon=True).start()

    # ---------- Tray ----------
    def init_tray(self):
        self.tray_imgs       = get_tray_images()
        self._tray_img_green = self.tray_imgs[0][0] if self.tray_imgs else None
        self._tray_img_red   = self.tray_imgs[1][0] if self.tray_imgs else None

        if pystray is None or Image is None or not _HAVE_PYWIN32:
            messagebox.showwarning(
                "Tray Unavailable",
                "Tray requires: pystray, Pillow, pywin32.\n\n"
                "Install: pip install pystray pillow pywin32\n\n"
                "Closing the window will minimize to the taskbar.",
                parent=self.root)
            self.root.protocol("WM_DELETE_WINDOW", lambda: self.root.iconify())
            return

        self.tray_icon = pystray.Icon(APP_NAME)

        def setup(icon):
            icon.icon       = self.tray_image_for_state(is_vpn_up())
            icon.title      = APP_NAME
            icon.menu       = self.build_tray_menu()
            icon.visible    = True
            icon.on_activate = lambda _: self.root.after(0, self.show_from_tray)

        try:
            self.tray_icon.run_detached(setup)
            atexit.register(lambda: self.tray_icon.stop())
            self._last_tray_online  = is_vpn_up()
            self._last_hidden_state = self.window_hidden
            self.root.protocol("WM_DELETE_WINDOW", self.hide_to_tray)
        except Exception as e:
            messagebox.showwarning("Tray Error", f"Could not start tray icon: {e}", parent=self.root)
            self.root.protocol("WM_DELETE_WINDOW", lambda: self.root.iconify())

    def tray_image_for_state(self, online: bool):
        if not self.tray_imgs:
            return None
        (g_s, _), (r_s, _) = self.tray_imgs
        return g_s if online else r_s

    def build_tray_menu(self):
        def on_toggle(_):   self.root.after(0, self.toggle)
        def on_showhide(_): self.root.after(0, self.toggle_window_visibility)
        def on_exit(_):     self.root.after(0, self.exit_app)

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

            self._last_tray_online  = online
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
        def dbg(msg):
            if DEBUG_MODE:
                from datetime import datetime
                ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                line = f"[EXIT DEBUG] {ts} {msg}\n"
                try:
                    with open("Shuriken_Log.txt", "a", encoding="utf-8") as f:
                        f.write(line)
                except Exception:
                    pass
                print(line.strip())

        dbg("1. exit_app() was actually called")
        try:
            if hasattr(self, 'tray_icon') and self.tray_icon:
                dbg("2. Attempting to hide & stop tray icon")
                self.tray_icon.visible = False
                self.tray_icon.stop()
                dbg("2b. tray_icon.stop() finished")
        except Exception as e:
            dbg(f"Tray cleanup failed: {e}")

        dbg("3. Signaling stop events")
        if hasattr(self, '_ip_detect_stop'):
            self._ip_detect_stop.set()
        if hasattr(self, '_watchdog_stop'):
            self._watchdog_stop.set()

        dbg("4. Joining IP check thread if alive")
        if hasattr(self, 'ip_check_thread') and self.ip_check_thread and self.ip_check_thread.is_alive():
            try:
                self.ip_check_thread.join(timeout=1.5)
            except Exception as e:
                dbg(f"IP join failed: {e}")

        dbg("5. Calling adapter_watcher.stop()")
        try:
            self._adapter_watcher.stop()
        except Exception as e:
            dbg(f"Adapter watcher stop failed: {e}")

        dbg("6. Calling stop_internet_monitor()")
        try:
            self.stop_internet_monitor()
        except Exception as e:
            dbg(f"Internet monitor stop failed: {e}")

        dbg("7. Calling root.destroy()")
        try:
            self.root.destroy()
        except Exception as e:
            dbg(f"destroy failed: {e}")

        dbg("8. End of exit_app")

    # ---------- Status poll ----------
    def refresh_status(self):
        """Periodically refresh the VPN status label and button."""
        stop_event   = getattr(self, "_status_stop_event", None)
        is_animating = False
        if isinstance(stop_event, threading.Event):
            is_animating = not stop_event.is_set()
        self.root.after(1000, self.refresh_status)

    # ---------- VPN Watchdog ----------
    def start_vpn_watchdog(self):
        if hasattr(self, "_watchdog_thread") and self._watchdog_thread.is_alive():
            return
        self._watchdog_stop   = threading.Event()
        self._watchdog_thread = threading.Thread(target=self._vpn_watchdog_loop, daemon=True)
        self._watchdog_thread.start()
        self._adapter_watcher.start()

    def stop_vpn_watchdog(self):
        if hasattr(self, "_watchdog_stop"):
            self._watchdog_stop.set()
        # Join so no auto-reconnect can race a server switch
        if hasattr(self, "_watchdog_thread") and self._watchdog_thread.is_alive():
            self._watchdog_thread.join(timeout=5.0)
        self._adapter_watcher.stop()

    def _vpn_watchdog_loop(self):
        """Continuously monitor the VPN state and react to unexpected drops or wake events."""
        was_up         = False
        network_was_up = True
        last_check     = time.time()
        si, cf         = _make_si()

        def run_ps_command(ps_command):
            full_cmd = [
                "powershell.exe", "-WindowStyle", "Hidden",
                "-ExecutionPolicy", "Bypass", "-Command", ps_command
            ]
            try:
                result = subprocess.run(
                    full_cmd, capture_output=True, text=True, timeout=15,
                    startupinfo=si, creationflags=cf
                )
                return result.returncode == 0
            except Exception:
                return False

        def wait_for_valid_ip(max_attempts=25, delay=3):
            for attempt in range(max_attempts):
                try:
                    result = subprocess.run(
                        ["ipconfig"], capture_output=True, text=True, timeout=10,
                        startupinfo=si, creationflags=cf
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
            now_up     = is_vpn_up()
            network_up = False

            try:
                result = subprocess.run(
                    ["netsh", "interface", "show", "interface"],
                    capture_output=True, text=True, timeout=2,
                    startupinfo=si, creationflags=cf
                )
                for line in result.stdout.lower().splitlines():
                    if "connected" in line and not any(v in line for v in ("wireguard", "wg", "tunnel", "virtual")):
                        network_up = True
                        break
            except Exception:
                pass

            now   = time.time()
            slept = (now - last_check) > 30
            last_check = now

            if slept:
                self.root.after(0, lambda: self.transient_status.configure(
                    text="Verifying Network Connection…"
                ))
                if wait_for_valid_ip():
                    run_ps_command("Get-NetFirewallRule -DisplayName 'Shuriken*' | Remove-NetFirewallRule -Confirm:$false")
                    cleanup_stale_wireguard_service()
                    run_ps_command("ipconfig /release")
                    time.sleep(2)
                    run_ps_command("ipconfig /renew")
                    run_ps_command("ipconfig /flushdns")
                    now_up = is_vpn_up()
                    if not now_up:
                        self.root.after(0, lambda: (
                            self.transient_status.configure(text="Resuming VPN after sleep…"),
                            self._attempt_auto_reconnect()
                        ))
                    else:
                        was_up = False
                        self.root.after(0, lambda: self.fetch_and_display_ip("VPN", continuous=True))
                        self.root.after(0, lambda: self.protection_status.configure(
                            text="Protected", text_color="#00FF00"
                        ))
                else:
                    self.root.after(0, lambda: self.transient_status.configure(
                        text="Resetting Connection..."
                    ))
                self.root.after(4000, self.force_refresh_tray_icon)

            adapter_pending = getattr(self, "_adapter_restored_pending", False)
            if adapter_pending:
                self._adapter_restored_pending = False
            if (not network_was_up and network_up) or adapter_pending:
                self.root.after(0, lambda: self.transient_status.configure(
                    text="Verifying Network Connection…"
                ))
                if wait_for_valid_ip(max_attempts=15):
                    now_up = is_vpn_up()
                    if not now_up:
                        self.root.after(0, lambda: self.transient_status.configure(text="Reconnecting…"))
                        time.sleep(2)
                        self.root.after(0, self._attempt_auto_reconnect)

            if was_up and not now_up and network_up:
                self.root.after(0, lambda: self.transient_status.configure(
                    text="VPN Connection Lost! Kill Switch Active!"
                ))
                self.root.after(0, lambda: self._update_tray_if_needed())
                # Don't auto-reconnect during a deliberate disconnect or server switch
                if getattr(self, "auto_reconnect", True) and not getattr(self, "_switching", False):
                    time.sleep(5)
                    now_up = is_vpn_up()
                    if not now_up:
                        self.root.after(0, lambda: (
                            self.transient_status.configure(text="Reconnecting..."),
                            self._attempt_auto_reconnect()
                        ))

            if not was_up and now_up:
                self.root.after(0, lambda: (
                    self.transient_status.configure(text="Connection Secure & Encrypted"),
                    self.btn.configure(text="Disconnect"),
                    setattr(self, "secure_connected", True)
                ))
                self.root.after(1200, self.force_refresh_tray_icon)
                self.root.after(1500, lambda: self.fetch_and_display_ip("VPN", continuous=True))

            was_up         = now_up
            network_was_up = network_up
            time.sleep(3)

    def _attempt_auto_reconnect(self):
        if getattr(self, "_switching", False):
            return
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
            self.stop_vpn_watchdog()

            self._status_stop_event = threading.Event()
            threading.Thread(
                target=self.animate_status,
                args=("Connecting", "#009688", self._status_stop_event),
                daemon=True
            ).start()

            def task():
                return vpn_up_nogui()

            def done(ok, err, src=None):
                if hasattr(self, "_status_stop_event"):
                    self._status_stop_event.set()

                if ok:
                    if src:
                        write_registry(src)

                    self.transient_status.configure(text="Connected to WireGuard Service")

                    _routing_stop = threading.Event()
                    self._routing_stop_event = _routing_stop

                    def _routing_thread():
                        MAX_ATTEMPTS = 15
                        for attempt in range(MAX_ATTEMPTS + 1):
                            if _routing_stop.is_set() or not is_vpn_up():
                                return
                            self.root.after(0, lambda a=attempt: self.transient_status.configure(
                                text=f"Establishing secure route... ({a + 1}/{MAX_ATTEMPTS})"
                            ))
                            try:
                                with urllib.request.urlopen(self.ECHOIP_URL, timeout=8) as resp:
                                    current_ip = resp.read().decode("utf-8").strip()
                                if current_ip:
                                    baseline_ip = getattr(self, "_last_detected_ip", None)
                                    if baseline_ip is None or current_ip != baseline_ip:
                                        self._last_detected_ip = current_ip
                                    def _mark_protected():
                                        self.protection_status.configure(text="Protected", text_color="#00FF00")
                                        print("Protected Label Update 3")
                                        self.transient_status.configure(text="Connection Secure & Encrypted")
                                        self.secure_connected = True
                                        self._update_tray_if_needed()
                                    self.root.after(0, _mark_protected)
                                    return
                            except Exception as e:
                                print(f"IP-check attempt {attempt + 1} failed: {e}")
                            if attempt < MAX_ATTEMPTS:
                                for _ in range(10):
                                    if _routing_stop.is_set():
                                        return
                                    time.sleep(0.5)

                        # All attempts exhausted and stop not requested — the tunnel
                        # is up but has no working internet (e.g. wrong port, server
                        # down). Do NOT silently flip to "Protected". Instead show a
                        # clear failure message so the user knows to disconnect.
                        if not _routing_stop.is_set():
                            print("[ROUTING] Max IP-check retries reached — tunnel has no internet")
                            def _mark_no_internet():
                                self.transient_status.configure(
                                    text="Tunnel active but no internet detected — click Disconnect"
                                )
                                self.protection_status.configure(text="No Internet", text_color="#FF9800")
                                # Do NOT set secure_connected = True
                                self._update_tray_if_needed()
                            self.root.after(0, _mark_no_internet)

                    threading.Thread(target=_routing_thread, daemon=True).start()

                    self.clear_busy(self.btn, "Disconnect", "#f44336")
                    self.fetch_and_display_ip("VPN", continuous=True)
                    self.start_vpn_watchdog()
                    self.start_internet_monitor()
                    # Apply any saved split tunnel rules now that kill switch is up
                    _st_apps = _load_split_tunnel_apps()
                    if _st_apps:
                        apply_split_tunnel(_st_apps)
                        if DEBUG_MODE:
                            print(f"[SPLIT] Auto-applied {len(_st_apps)} app(s) on connect")
                    self._update_tray_if_needed()

                else:
                    self.transient_status.configure(
                        text="Secure your online activity by connecting to Shuriken VPN"
                    )
                    self.protection_status.configure(text="Unprotected", text_color="#f44336")
                    print("Unprotected Label Updated 6")
                    self.clear_busy(self.btn, "Connect", "#4CAF50")
                    self.secure_connected = False
                    if err:
                        messagebox.showerror("Shuriken VPN", err, parent=self.root)
                    self._update_tray_if_needed()

            self.run_async(task, done)

        else:
            # ------------------- DISCONNECT -------------------
            # Cancel routing/status threads FIRST so they cannot flip
            # UI state back to "Protected" or "Establishing" after we start
            # the teardown. Also set _switching=True so the watchdog's
            # _attempt_auto_reconnect guard fires during teardown.
            self._switching = True
            if hasattr(self, "_routing_stop_event"):
                self._routing_stop_event.set()
            if hasattr(self, "_status_stop_event"):
                self._status_stop_event.set()
            if hasattr(self, "_ip_detect_stop"):
                self._ip_detect_stop.set()

            self.transient_status.configure(text="Disconnecting…")
            self.set_busy(self.btn, "Disconnecting…")

            self._status_stop_event = threading.Event()
            threading.Thread(
                target=self.animate_status,
                args=("Disconnecting", "#ff6f00", self._status_stop_event),
                daemon=True
            ).start()

            def task():
                # Stop the watchdog in the background thread (has a 5s join).
                # This must happen here — not on the main thread — so the UI
                # doesn't freeze while we wait.
                self.stop_vpn_watchdog()
                ok, err = vpn_down_nogui()
                return ok, err, None

            def done(ok, err, _):
                self._switching = False   # re-enable auto-reconnect
                if hasattr(self, "_status_stop_event"):
                    self._status_stop_event.set()

                if ok:
                    self.transient_status.configure(
                        text="Secure your online activity by connecting to Shuriken VPN"
                    )
                    self.protection_status.configure(text="Unprotected", text_color="#f44336")
                    print("Unprotected Label Updated 7")
                    self.clear_busy(self.btn, "Connect", "#4CAF50")
                    self.secure_connected = False
                else:
                    self.transient_status.configure(text="Disconnection failed. Tunnel still active")
                    self.clear_busy(self.btn, "Disconnect", "#f44336")
                    self.secure_connected = True
                    if err:
                        messagebox.showerror("Disconnection Failed", err, parent=self.root)

                self.stop_internet_monitor()
                remove_split_tunnel()
                self.fetch_and_display_ip("Local", continuous=False)
                self.location_var.set("Location:\nDetecting...")
                self._update_tray_if_needed()

            self.run_async(task, done)

    def switch_server(self, new_conf: Path):
        if not new_conf.is_file():
            messagebox.showerror(
                "Shuriken VPN",
                f"The selected config was not found:\n{new_conf}",
                parent=self.root,
            )
            return

        try:
            config_dir_resolved = CONFIG_DIR.resolve(strict=True)
            new_conf_resolved   = new_conf.resolve(strict=True)
        except FileNotFoundError:
            messagebox.showerror("Shuriken VPN", f"Config file does not exist:\n{new_conf}", parent=self.root)
            return
        except Exception as e:
            messagebox.showerror("Shuriken VPN",
                                 f"Cannot resolve config path (symlink/perm issue):\n{new_conf}\n\n{e}",
                                 parent=self.root)
            return

        if (config_dir_resolved not in new_conf_resolved.parents and
                new_conf_resolved != config_dir_resolved):
            messagebox.showerror(
                "Shuriken VPN",
                f"Config must be inside the Config folder.\n\n"
                f"Allowed : {config_dir_resolved}\n"
                f"Rejected: {new_conf_resolved}",
                parent=self.root,
            )
            return

        if not validate_config_has_dns(new_conf):
            messagebox.showerror(
                "Shuriken VPN",
                f"Config is missing DNS setting:\n{new_conf.name}\n\n"
                "Add this line under [Interface]:\nDNS = 10.0.0.1",
                parent=self.root,
            )
            return

        self.stop_vpn_watchdog()

        if hasattr(self, "_status_stop_event"):
            self._status_stop_event.set()

        self._status_stop_event = threading.Event()
        threading.Thread(
            target=self.animate_status,
            args=("Connecting", "#009688", self._status_stop_event),
            daemon=True,
        ).start()

        self._switching = True

        def task():
            ok, err = switch_server_nogui(new_conf)
            return ok, err, new_conf

        def done(ok, err, conf):
            self._switching = False
            if hasattr(self, "_status_stop_event"):
                self._status_stop_event.set()

            if ok:
                if conf:
                    write_registry(conf)

                self.transient_status.configure(text="Connected to WireGuard Service")

                if hasattr(self, "_ip_detect_stop"):
                    self._ip_detect_stop.set()
                if hasattr(self, "_routing_stop_event"):
                    self._routing_stop_event.set()

                self.secure_connected       = False
                self._last_detected_ip      = None
                self._ip_detection_running  = False

                _sw_stop = threading.Event()
                self._routing_stop_event = _sw_stop

                def _switch_routing_thread():
                    time.sleep(0.8)
                    for attempt in range(12):
                        if _sw_stop.is_set() or not is_vpn_up():
                            return
                        try:
                            with urllib.request.urlopen(self.ECHOIP_URL, timeout=6) as resp:
                                current_ip = resp.read().decode("utf-8").strip()
                            if current_ip and not current_ip.startswith(("10.", "100.64.", "192.168.", "172.")):
                                self._last_detected_ip = current_ip
                                if not _sw_stop.is_set():
                                    def _mark():
                                        self.protection_status.configure(text="Protected", text_color="#00FF00")
                                        print("Protected Label Update 4 - quick path")
                                        self.transient_status.configure(text="Connection Secure & Encrypted")
                                        self.secure_connected = True
                                        self._update_tray_if_needed()
                                        self.clear_busy(self.btn, "Disconnect", "#f44336")
                                        if hasattr(self, "_status_stop_event"):
                                            self._status_stop_event.set()
                                    self.root.after(0, _mark)
                                return
                        except Exception as e:
                            print(f"[switch_server] IP check attempt {attempt+1} failed: {e}")
                        for _ in range(int((0.9 if attempt < 2 else 1.4) * 2)):
                            if _sw_stop.is_set():
                                return
                            time.sleep(0.5)
                    print("[switch_server] IP check gave up after 12 attempts")

                threading.Thread(target=_switch_routing_thread, daemon=True).start()

                self.fetch_and_display_ip("VPN", continuous=True)
                self.start_vpn_watchdog()
                # Re-apply split tunnel rules — switch teardown removed all firewall rules
                _st_apps = _load_split_tunnel_apps()
                if _st_apps:
                    apply_split_tunnel(_st_apps)
                self._update_tray_if_needed()

            else:
                self.transient_status.configure(
                    text="Secure your online activity by connecting to Shuriken VPN"
                )
                self.protection_status.configure(text="Unprotected", text_color="#f44336")
                print("Unprotected Label Updated 8")
                if err:
                    messagebox.showerror("Shuriken VPN", err, parent=self.root)
                self._update_tray_if_needed()

        self.run_async(task, done)


def safe_run_main():
    """Run main() and log everything to Shuriken_Log.txt when DEBUG_MODE is enabled."""
    if DEBUG_MODE:
        from datetime import datetime
        ts = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        try:
            with open("Shuriken_Log.txt", "a", encoding="utf-8") as f:
                f.write(f"{ts} === Shuriken VPN Started ===\n")
        except Exception:
            pass
    try:
        main()
    except Exception:
        import traceback
        if DEBUG_MODE:
            from datetime import datetime
            ts  = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
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
    if DEBUG_MODE:
        try:
            from datetime import datetime
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open("Shuriken_Log.txt", "w", encoding="utf-8") as f:
                f.write(f"[{ts}] Shuriken VPN v{__version__} initialized!\n")
            print("Log file cleared and new session started.")
        except Exception as e:
            print(f"Could not clear log file: {e}")

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
        if ICON_PATH.exists():
            try:
                root.iconbitmap(default=str(ICON_PATH.resolve()))
                if DEBUG_MODE:
                    dbg("Applied icon via iconbitmap (multi-size .ico)")
                print("Applied icon via iconbitmap")
            except Exception as e1:
                if DEBUG_MODE:
                    dbg(f"iconbitmap failed: {e1}")
                print(f"iconbitmap failed: {e1}")
                try:
                    from PIL import Image, ImageTk
                    pil_img   = Image.open(ICON_PATH)
                    ico_sizes = getattr(pil_img, 'info', {}).get('sizes', [])
                    preferred = [(64, 64), (48, 48), (32, 32), (256, 256)]
                    selected_size = next((sz for sz in preferred if sz in ico_sizes), None)
                    if not selected_size and ico_sizes:
                        selected_size = max(ico_sizes, key=lambda s: s[0])
                    if selected_size:
                        pil_img.load()
                        resized = pil_img.resize(selected_size, Image.Resampling.LANCZOS).convert("RGBA")
                        photo   = ImageTk.PhotoImage(resized)
                        root.iconphoto(True, photo)
                        root._icon_ref = photo
                        if DEBUG_MODE:
                            dbg(f"Applied icon via iconphoto (size {selected_size})")
                        print(f"Applied icon via iconphoto (size {selected_size})")
                    else:
                        if DEBUG_MODE:
                            dbg("No usable size found in .ico file")
                        print("No usable size found in .ico")
                except Exception as e2:
                    if DEBUG_MODE:
                        dbg(f"iconphoto fallback also failed: {e2}")
                    print(f"iconphoto fallback failed: {e2}")
        else:
            if DEBUG_MODE:
                dbg("Icon file not found: " + str(ICON_PATH))
            print("Icon file not found")

        if THEME_PATH.exists():
            try:
                ctk.set_default_color_theme(str(THEME_PATH))
            except Exception as e:
                if DEBUG_MODE:
                    dbg(f"Failed to load custom theme ({e}), falling back to built-in")
                ctk.set_default_color_theme("dark-blue")
        else:
            if DEBUG_MODE:
                dbg("shuriken_theme.json not found, using built-in dark-blue theme")
            ctk.set_default_color_theme("dark-blue")

        if not is_admin():
            result = messagebox.askyesno(
                "Shuriken VPN",
                "Admin Rights Required.\n\n"
                "DNS leak protection requires Administrator privileges.\n\n"
                "Run as Administrator for full privacy protection?\n\n"
                "Click 'No' to continue with reduced security.",
                icon="warning"
            )
            if not result:
                safe_messagebox("info", "Shuriken VPN", "Running with limited DNS protection.")
            else:
                try:
                    ctypes.windll.shell32.ShellExecuteW(
                        None, "runas", sys.executable, " ".join(sys.argv), None, 1
                    )
                except Exception:
                    pass
                return

        if not acquire_mutex("Global\\ShurikenInstanceLock"):
            messagebox.showwarning("Shuriken VPN", "Shuriken is already running.")
            return

        WG_PROGDATA, WG_DIR, WG_EXE, WG_CLI = get_wg_paths()
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
