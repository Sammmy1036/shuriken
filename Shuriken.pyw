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
from network import (_ps, _list_non_wg_adapters, add_dns_leak_block, remove_dns_leak_block, run,
add_kill_switch, remove_kill_switch, disable_ipv6_on_non_wg_adapters, enable_ipv6_on_non_wg_adapters,
reset_firewall_if_blocked)
from utils import (acquire_mutex, safe_messagebox, is_admin, read_registry, write_registry, AdapterWatcher)
from constants import (
    setup_runtime_paths, get_wg_paths, APP_DIR, BUNDLED_BASE_DIR, ICON_PATH, CONFIG_DIR,
    APP_NAME, CONFIG_NAME, SERVICE_NAME, REG_PATH, REG_VAL, ASSETS_DIR,
    LOCKED_OVERLAY_PATH, UNLOCKED_OVERLAY_PATH, FLAGS_DIR, FLAG_CACHE, THEME_PATH,
    STATE_DIR, WG_PROGDATA, WG_DIR, WG_EXE, WG_CLI, DEBUG_MODE,
    STEALTH_PORT_ENABLED, DEFAULT_STEALTH_PORT
)
from wireguard import (validate_config_has_dns, copy_conf_to_progdata, is_vpn_up, vpn_up_nogui, vpn_down_nogui,
switch_server_nogui, pretty_name_for, list_conf_files, repair_network_stack_if_stuck, run_adapter_repair_sequence,
cleanup_stale_wireguard_service)
try:
    import pythoncom
    import win32com.client
    _HAVE_WMI = True
except Exception:
    _HAVE_WMI = False
    pythoncom = None
    win32com = None

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

# -------------------------- Tray icons ---------------------------
def _load_base_icon(size: int) -> PILImage.Image | None:
    if ICON_PATH is None or not ICON_PATH.exists():
        return None
    try:
        with PILImage.open(ICON_PATH) as ico:
            # ico_sizes might not exist if not ICO; fallback to common sizes
            ico_sizes = ico.info.get('sizes', [(size, size) for size in [16, 32, 48, 64, 128, 256]])
            # Pick largest available >= requested size, or biggest overall
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
            # Fallback: load as regular image
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

    img = base_img.copy()  # Already RGBA
    w, h = img.size
    frac = 0.50       # Overlay size fraction
    pad_frac = 0.04   # Padding from edge
    d = max(int(min(w, h) * frac), 8)  # Min 8px to avoid tiny overlays
    pad = int(min(w, h) * pad_frac)

    overlay_resized = overlay.resize((d, d), PILImage.LANCZOS)
    x = w - pad - d
    y = pad
    img.paste(overlay_resized, (x, y), overlay_resized)  # Use mask=overlay itself for alpha

    return img  # Keep as RGBA

def get_tray_images():
    if PILImage is None:
        return None, None

    # Recommended sizes for modern high-DPI Windows tray (effective pixels often 20–48 px)
    sizes = [24, 40, 48, 64, 96]  # Start with these; add 32 or 96 if needed
    green_locked = {}
    red_unlocked = {}

    for sz in sizes:
        base = _load_base_icon(sz)
        if base is None:
            continue

        green_locked[sz] = _add_corner_png_overlay(base, LOCKED_OVERLAY_PATH)
        red_unlocked[sz] = _add_corner_png_overlay(base, UNLOCKED_OVERLAY_PATH)

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

    ECHOIP_URL = "http://45.149.154.247:9090/json"  # Change to whatever server is hosting IPASNGeoLoc 

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
        self.root.title("Shuriken VPN") # Window Title of Application
        self.root.geometry("1000x620")
        self.root.resizable(False, False)
        self.set_window_icon()
        self.center_on_screen()
        # Core state
        self.secure_connected = False
        self.in_progress = False
        self.window_hidden = False
        # Tray and icon state
        self.tray_icon = None
        self.tray_imgs = None
        self._last_tray_online = is_vpn_up()
        self._last_hidden_state = self.window_hidden
        # Animation and IP detection
        self._global_anim_stop = False
        self.ip_detection_complete = False
        self.ip_check_thread = None
        self._ip_detection_running = False
        self._status_stop_event = threading.Event()
        self._status_stop_event.set()

        self.auto_reconnect = True
        # Adapter watcher
        self._adapter_watcher = AdapterWatcher(repair_callback=run_adapter_repair_sequence)
        # Configure main window grid for 2-column layout (no more right column)
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=0)  # Left sidebar: fixed width
        self.root.grid_columnconfigure(1, weight=1)  # Center/main area: expands to fill space

        # Load button images from assets folder (size reduced for floating buttons)
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

        # ===================== CENTER MAIN FRAME (for overlay) =====================
        self.main_frame = ctk.CTkFrame(self.root, corner_radius=0, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nswe")

        # ===================== OVERLAY BUTTONS ON THE RIGHT EDGE (with labels) =====================
        self.overlay_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.overlay_frame.place(relx=1.04, x=-40, rely=0.45, anchor="e")  # Slightly more space for labels

        def create_feature_button(image, command, label_text):
            frame = ctk.CTkFrame(self.overlay_frame, fg_color="transparent")
            frame.pack(pady=12)  # Vertical spacing between features

            btn = ctk.CTkButton(
                frame,
                text="",
                image=image,
                width=64,
                height=64,
                corner_radius=20,
                fg_color="#2D2D2D",
                hover_color="#333333",
                command=command
            )
            btn.pack()

            label = ctk.CTkLabel(
                frame,
                text=label_text,
                font=ctk.CTkFont(family="AniMe Vision - MB_EN", size=11, weight="normal"),
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
        title_label = CTkLabel(self.left_sidebar, text="Servers", font=("AniMe Vision - MB_EN", 16, "bold"), pady=15)
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
        icon_path = ASSETS_DIR / "search_icon.png"
        if icon_path.exists():
            search_img = CTkImage(light_image=PILImage.open(icon_path),
                                  dark_image=PILImage.open(icon_path),
                                  size=(27, 27))
        else:
            search_img = None
        if search_img:
            search_icon_label = CTkLabel(
                self.search_entry,
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
        if ICON_PATH.exists():
            try:
                pil_img = PILImage.open(ICON_PATH).convert("RGBA")
                max_width = 100
                if pil_img.width > max_width:
                    ratio = min(1.0, max_w / pil_img.width)
                    new_size = (max_width, int(pil_img.height * ratio))
                    pil = pil_img.resize(new_size, PILImage.Resampling.LANCZOS)
                self.logo_img = ctk.CTkImage(light_image=pil_img, dark_image=pil_img, size=(pil_img.width, pil_img.height))
            except Exception as e:
                print(f"Logo loading failed: {e}")

        if self.logo_img:
            ctk.CTkLabel(self.main_content, image=self.logo_img, text="").pack(pady=(10, 2))
        # Main page Shuriken VPN text
        self.header = ctk.CTkLabel(self.main_content, text="Shuriken VPN", font=("AniMe Vision - MB_EN", 16))
        self.header.pack(pady=(8, 8))

        self.status = ctk.CTkLabel(self.main_content, text="Disconnected", font=("Segoe UI", 10, "bold"))

        # ----- MAIN CONNECT / DISCONNECT BUTTON -----
        self.btn = ctk.CTkButton(
            self.main_content,
            text="Connect",
            command=self.toggle,
            font=("AniMe Vision - MB_EN", 16),
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

        bottom_frame = ctk.CTkFrame(self.main_content, fg_color="transparent")
        bottom_frame.pack(side="bottom", fill="x", pady=(40, 20), padx=40)

        self.protection_status = ctk.CTkLabel(
            bottom_frame,
            text="Unprotected",
            font=ctk.CTkFont(family="AniMe Vision - MB_EN", size=25),
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
                online = is_vpn_up()
                self.tray_icon.icon = self.tray_image_for_state(online)
            except Exception:
                pass
        self.load_server_list()
        self.transient_status.configure(text="Checking connection status…")
        self.protection_status.configure(text="Detecting", text_color="#FFFF00")
        self.btn.configure(text="Connect")
        self.location_var.set("Location:\nDetecting...")
        if is_vpn_up():
            self.protection_status.configure(text="Protected", text_color="#00FF00")
            print(f"Protected Label Update 1")
            self.transient_status.configure(text="Connection Secure & Encrypted")
            self.btn.configure(text="Disconnect")
            self.secure_connected = True
            self.fetch_and_display_ip("VPN", continuous=True)
        else:
            self.transient_status.configure(text="Secure your online activity by connecting to Shuriken VPN")
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
        messagebox.showinfo(
            "Shuriken VPN",
            "Split Tunneling is not yet implemented.\n\n"
            "Your current setup uses a full tunnel with kill switch protection.",
            parent=self.root
        )

    def launch_tor_browser(self):
        # Determine the correct base directory (works in both dev and PyInstaller one-file mode)
        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            # Running as PyInstaller one-file or one-dir bundle → use the temp extraction folder
            base_dir = Path(sys._MEIPASS)
        else:
            # Running from source (development)
            base_dir = Path(os.path.dirname(os.path.abspath(__file__)))  # or replace with your APP_DIR / BUNDLED_BASE_DIR logic if needed

        resources_dir = base_dir / "Resources"

        if sys.platform.startswith("win"):
            tor_root = resources_dir / "tor-windows" / "Tor Browser"
            firefox_exe = tor_root / "Browser" / "firefox.exe"
        else:
            # Optional: add linux/mac support later if needed
            tor_root = resources_dir / "tor-linux" / "Tor Browser"  # adjust structure if different on other platforms
            firefox_exe = tor_root / "Browser" / "firefox"

        if not tor_root.exists() or not tor_root.is_dir():
            messagebox.showerror(
                "Tor Browser Not Found",
                "Official Tor Browser folder not found in bundled resources!\n\n"
                f"Expected location: {tor_root}\n\n"
                "This usually means:\n"
                "• The --add-data path in PyInstaller doesn't match the expected structure, or\n"
                "• Case mismatch in folder names (Windows is case-insensitive, but Python .exists() is case-sensitive), or\n"
                "• The Tor Browser folder was not fully included.\n\n"
                "Current expected structure:\n"
                "Resources/tor-windows/Tor Browser/Browser/firefox.exe\n\n"
                "Check your PyInstaller command includes something like:\n"
                "--add-data \"path/to/Resources;Resources\"",
                parent=self.root
            )
            return

        if not firefox_exe.exists():
            messagebox.showerror(
                "Tor Browser Error",
                f"firefox executable not found at:\n{firefox_exe}\n\n"
                "The Tor Browser bundle appears incomplete or the folder names don't match exactly.\n\n"
                "Expected full path:\n"
                f"{resources_dir / 'tor-windows' / 'Tor Browser' / 'Browser' / 'firefox.exe'}",
                parent=self.root
            )
            return

        if not getattr(self, "secure_connected", False):
            if not messagebox.askyesno(
                "Shuriken VPN",
                "For maximum privacy, it's recommended to use Tor over an active VPN.\n\n"
                "This hides Tor usage from your ISP and adds an extra layer of protection.\n\n"
                "Launch Official Tor Browser anyway?",
                icon="warning",
                parent=self.root
            ):
                return

        try:
            creationflags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            subprocess.Popen(
                [str(firefox_exe)],
                cwd=str(tor_root),               # ← This must point to the "Tor Browser" folder (contains Browser/)
                creationflags=creationflags,
                # stdout=subprocess.DEVNULL,     # optional
                # stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            messagebox.showerror(
                "Launch Failed",
                f"Could not start Official Tor Browser:\n\n{str(e)}",
                parent=self.root
            )

    def open_settings(self):
        settings_win = ctk.CTkToplevel(self.root)
        settings_win.title("Shuriken VPN")
        settings_win.geometry("500x400")
        settings_win.resizable(False, False)
        settings_win.grab_set()
        ctk.CTkLabel(settings_win, text="Advanced Settings", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=30)
        
        stealth_var = tk.BooleanVar(value=STEALTH_PORT_ENABLED)

        def toggle_stealth():
            global STEALTH_PORT_ENABLED
            STEALTH_PORT_ENABLED = stealth_var.get()
            print("STEALTH_PORT_ENABLED port changed to:", STEALTH_PORT_ENABLED)
            try:
                import winreg
                key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, r"Software\Shuriken")
                winreg.SetValueEx(key, "StealthPort", 0, winreg.REG_DWORD, int(STEALTH_PORT_ENABLED))
                winreg.CloseKey(key)
            except:
                pass

        ctk.CTkCheckBox(
            settings_win,
            text="Use stealth port 443 (better obfuscation against ISP DPI)",
            variable=stealth_var,
            command=toggle_stealth,
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
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
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
        w, h = self.root.winfo_width(), self.root.winfo_height()
        sw, sh = self.root.winfo_screenwidth(), self.root.winfo_screenheight()
        x, y = (sw - w) // 2, (sh - h) // 2
        self.root.geometry(f"{w}x{h}+{x}+{y}")

    # ---------- Dropdown ----------
    def display_for_path(self, p: Path | None) -> str:
        return "(none)" if not p else pretty_name_for(p.name)

    def get_available_servers(self) -> list[Path]:
        """Return list of available server configs using your existing logic."""
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
                    log(f"FLAGS_DIR: {FLAGS_DIR} (exists: {FLAGS_DIR.exists()})")
                    log(f"Pillow available: {PILImage is not None}")
            return None

        candidates = [
            f"{country_normalized}.png",
            f"{country_normalized}.jpg",
            f"{country_normalized.lower()}.png",
            f"{country_normalized.lower()}.jpg",
            f"{country_normalized[:2].lower()}.png", # e.g., "us.png"
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
                    log(f" Found file: {flag_path}")
                    log(f" Error: {e}")
                return None
        else:
            if DEBUG_MODE:
                log(f"FLAG MISSING: '{country}' → normalized: '{country_normalized}'")
                log(f" Searched in: {FLAGS_DIR}")
                log(f" Tried filenames: {', '.join(candidates)}")
                if not hasattr(self, "_flag_missing_summary_logged"):
                    self._flag_missing_summary_logged = True
                    try:
                        all_flags = [p.name for p in FLAGS_DIR.iterdir()
                                   if p.is_file() and p.suffix.lower() in {'.png', '.jpg'}]
                        all_flags.sort()
                        log(f" Total flag files available: {len(all_flags)}")
                        samples = all_flags[:15]
                        extra = " ..." if len(all_flags) > 15 else ""
                        log(f" Sample available flags: {', '.join(samples)}{extra}")
                    except Exception as e:
                        log(f" Error scanning FLAGS_DIR: {e}")
            return None

    def _resolve_synonym(self, word: str, syn_dict: dict) -> list[str] | None:
        """Exact match first, then smart fuzzy fallback. No more manual prefixes needed."""
        word_l = word.lower().strip()
        if word_l in syn_dict:
            val = syn_dict[word_l]
            return [t.lower() for t in val] if isinstance(val, list) else [str(val).lower()]

        # Fuzzy fallback — catches "cali", "nether", "mexi", "switz", etc.
        best_ratio = 0.0
        best_val = None
        for k, v in syn_dict.items():
            r = SequenceMatcher(None, word_l, k.lower()).ratio()
            if r > best_ratio:
                best_ratio = r
                best_val = v

        if best_ratio >= 0.60:  # 0.60 catches "cali" (0.615), "nether" (0.75), "mexi" etc.
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

        # === List All Servers with Smart Matching ===
        display_servers = servers
        if raw_query:
            scored = []
            q = query_lower.strip()
            query_words = q.split()

            city_target = state_target = country_target = None

            # --- Synonym resolution with fuzzy fallback ---
            for word in [q] + query_words:
                # City first (highest priority)
                if (city_target := self._resolve_synonym(word, CITY_SYNONYMS)) is not None:
                    break
                # State next
                if (state_target := self._resolve_synonym(word, STATE_SYNONYMS)) is not None:
                    break
                # Country last
                if (country_target := self._resolve_synonym(word, COUNTRY_SYNONYMS)) is not None:
                    break

            # --- Score each server ---
            for conf_path in servers:
                meta = SERVER_METADATA.get(
                    conf_path.name,
                    {"city": "Unknown", "state": "", "country": "Unknown", "name": conf_path.stem}
                )
                city_norm = meta["city"].lower()
                state_norm = meta.get("state", "").lower()
                country_norm = meta["country"].lower()
                name_norm = meta["name"].lower()

                # Build searchable pieces
                parts = [city_norm, state_norm, country_norm, name_norm]
                if state_norm:
                    parts.extend([
                        f"{city_norm} {state_norm}",
                        f"{city_norm}, {state_norm}",
                        f"{city_norm} {state_norm} {country_norm}"
                    ])

                # Fuzzy baseline score
                best_ratio = max(
                    (SequenceMatcher(None, q, part).ratio() for part in parts),
                    default=0.0
                )

                # Synonym boosts (supports multiple targets per code)
                if city_target:
                    for tgt in city_target:
                        if tgt in (city_norm, name_norm):
                            best_ratio += 0.60
                            break  # don't over-boost the same server
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

                # Bonus for longer exact matches
                if len(q) > 5 and q in (city_norm, state_norm, country_norm):
                    best_ratio += 0.12

                # Keep reasonably good matches
                if best_ratio >= 0.45:
                    scored.append((best_ratio, conf_path, meta))

            # Sort best → worst
            scored.sort(reverse=True, key=lambda x: x[0])
            display_servers = [item[1] for item in scored]

        # === Display the (filtered/sorted) servers ===
        for conf_path in display_servers:
            meta = SERVER_METADATA.get(
                conf_path.name,
                {"city": "Unknown", "state": "", "country": "Unknown", "name": conf_path.stem}
            )
            location = meta["city"]
            if meta.get("state"):
                location += f", {meta['state']}"
            location += f", {meta['country']}"
            full_text = location
            flag = self._get_flag(meta["country"])
            row = CTkFrame(self.server_scrollable_frame, fg_color="transparent")
            row.pack(fill="x", pady=2, padx=8)
            CTkLabel(row, text="", image=flag, width=36, height=28).pack(side="left", padx=(8, 12))
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

    def fetch_and_display_ip(self, state: str = "Local", continuous: bool = False, timeout_sec: int = 30):
        """
        Fetch public IP until it changes (for VPN mode) or timeout.
        In VPN mode: continuously shows "Detecting..." and retries until real IP change is confirmed.
        """
        # Prevent starting duplicate continuous detection threads
        if continuous and getattr(self, '_ip_detection_running', False):
            print("[DEBUG] IP detection already active — skipping duplicate start")
            return
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
                    return None, None, None

                # Provider: asn_org is usually the clean ISP/provider name
                provider = data.get("asn_org") or data.get("asn") or "Unknown"

                # Location
                country = data.get("country") or "Unknown"

                if ip.startswith("10."):
                    try:
                        real_public_ip = socket.gethostbyname("shuriken-vpn.ddnsgeek.com")
                        if real_public_ip != ip: 
                            ip = real_public_ip
                            provider = "JogCorp SAS"
                            country = "The Netherlands"
                    except socket.gaierror as e:
                        print(f"[DEBUG] DDNS fallback failed: {e}")
                        provider = "VPN"
                        country = "VPN"

                return ip, provider, country

            except Exception as e:
                if DEBUG_MODE:
                    print(f"[DEBUG] echoip request failed: {e}")
                return None, None, None

        def update_ui_protected(ip, provider, country):
            self.root.after(0, lambda: (
                self.ip_var.set(f"Your IP Address:\n{ip} ({state})"),
                self.provider_var.set(f"Provider:\n{provider}"),
                self.location_var.set(f"Location:\n{country}"),
                self.protection_status.configure(text="Protected", text_color="#00FF00"),
                print("Protected Label Update 2"),
                self.transient_status.configure(text="Connection Secure & Encrypted"),
                self.clear_busy(self.btn, "Disconnect", "#f44336") if state == "VPN" else None,
                setattr(self, "secure_connected", True),
            ))

        def update_ui_ip(ip, provider, country, protected):
            self.root.after(0, lambda: (
                self.ip_var.set(f"Your IP Address:\n{ip} ({state})"),
                self.provider_var.set(f"Provider:\n{provider}"),
                self.location_var.set(f"Location:\n{country}"),
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
                print(f"Unprotected Label Updated 2"),
                self.transient_status.configure(text="VPN tunnel not active"),
            ))

        def update_ui_failed():
            self.root.after(0, lambda: (
                self.ip_var.set("Your IP Address:\nFailed to detect"),
                self.provider_var.set("Provider:\nFailed to detect"),
                self.location_var.set("Location:\nFailed to detect"),
                self.protection_status.configure(text="Unprotected", text_color="#f44336"),
                print(f"Unprotected Label Updated 4"),
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

                    ip, provider, country = get_ip_info()

                    if ip:
                        current_vpn_up = is_vpn_up()

                        # Case 1: VPN mode + transition to protected + real IP change
                        if (state == "VPN" and
                            not self.secure_connected and
                            ip != last_ip and
                            current_vpn_up):
                            update_ui_protected(ip, provider, country)
                            if hasattr(self, "_status_stop_event"):
                                self._status_stop_event.set()
                            last_ip = ip
                            self._last_detected_ip = ip
                            print("[DEBUG] IP change confirmed. Stopping continuous IP check.")
                            break

                        # Case 2: normal / ongoing update
                        else:
                            last_ip = ip
                            is_protected_now = (state == "VPN" and current_vpn_up and self.secure_connected)
                            update_ui_ip(ip, provider, country, is_protected_now)
                            if not continuous:
                                return
                            if self.secure_connected:
                                print("[DEBUG] Protected & stable. Stopping IP polling thread.")
                                break
                            time.sleep(3)
                            print(f"[DEBUG] Checking for real IP change at {time.time():.0f}")
                            continue

                    # No IP fetched this time
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
                    self._ip_detection_running = False  # allow future starts

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
        """Gracefully shut down — with logging for debugging."""
        def dbg(msg):
            if DEBUG_MODE:
                from datetime import datetime
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                line = f"[EXIT DEBUG] {ts} {msg}\n"
                try:
                    with open("Shuriken_Log.txt", "a", encoding="utf-8") as f:
                        f.write(line)
                except:
                    pass
                print(line.strip())  # still show in console too

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
                dbg("4b. IP thread joined or timed out")
            except Exception as e:
                dbg(f"IP join failed: {e}")

        dbg("5. Calling adapter_watcher.stop()")
        try:
            self._adapter_watcher.stop()
            dbg("5b. adapter_watcher.stop() returned")
        except Exception as e:
            dbg(f"Adapter watcher stop failed: {e}")

        dbg("6. Calling stop_internet_monitor()")
        try:
            self.stop_internet_monitor()
            dbg("6b. internet monitor stop returned")
        except Exception as e:
            dbg(f"Internet monitor stop failed: {e}")

        dbg("7. Calling root.destroy()")
        try:
            self.root.destroy()
            dbg("7b. root.destroy() returned")
        except Exception as e:
            dbg(f"destroy failed: {e}")

        dbg("8. End of exit_app — if process still alive, check non-daemon threads")

    # ---------- Status poll ----------
    def refresh_status(self):
        """Periodically refresh the VPN status label and button."""
        stop_event = getattr(self, "_status_stop_event", None)
        is_animating = False

        # Determine if an animation is currently running
        if isinstance(stop_event, threading.Event):
            is_animating = not stop_event.is_set()

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
        was_up = False
        network_was_up = True
        last_check = time.time()
        si = subprocess.STARTUPINFO()
        si.dwFlags = subprocess.STARTF_USESHOWWINDOW | subprocess.STARTF_USESTDHANDLES
        si.wShowWindow = SW_HIDE # Explicitly hide (SW_HIDE = 0)
        cf = CREATE_NO_WINDOW # Preferred if available (Python 3.7+)
        
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
            # Core VPN state check — now using reliable WireGuard detection
            now_up = is_vpn_up()
            network_up = False
            
            # --- Detect physical network availability (Ethernet/Wi-Fi) ---
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
            
            # --- Detect system wake from sleep ---
            now = time.time()
            slept = (now - last_check) > 30
            last_check = now
            
            if slept:
                self.root.after(0, lambda: self.transient_status.configure(
                    text="Verifying Network Connection…"
                ))
                
                # Wait for network stack to stabilize before repairs
                if wait_for_valid_ip():
                    run_ps_command("Get-NetFirewallRule -DisplayName 'Shuriken*' | Remove-NetFirewallRule -Confirm:$false")
                    cleanup_stale_wireguard_service()
                    run_ps_command("ipconfig /release")
                    time.sleep(2)
                    run_ps_command("ipconfig /renew")
                    run_ps_command("ipconfig /flushdns")
                    
                    # After repair → check real VPN state
                    now_up = is_vpn_up()
                    
                    if not now_up:
                        self.root.after(0, lambda: (
                            self.transient_status.configure(text="Resuming VPN after sleep…"),
                            self._attempt_auto_reconnect()
                        ))
                    else:
                        # Tunnel survived sleep → force connected UI state
                        was_up = False  # ← this tricks the transition block below into firing
                        self.root.after(0, lambda: self.fetch_and_display_ip("VPN", continuous=True))
                        self.root.after(0, lambda: self.protection_status.configure(
                            text="Protected", text_color="#00FF00"
                        ))
                
                else:
                    self.root.after(0, lambda: self.transient_status.configure(
                        text="Resetting Connection..."
                    ))
                
                self.root.after(4000, self.force_refresh_tray_icon)
            
            # --- Detect adapter restored after manual disable/enable ---
            if not network_was_up and network_up:
                self.root.after(0, lambda: self.transient_status.configure(
                    text="Verifying Network Connection…"
                ))
                if wait_for_valid_ip(max_attempts=15):
                    cleanup_stale_wireguard_service()
                    run_ps_command("Get-NetFirewallRule -DisplayName 'Shuriken*' | Remove-NetFirewallRule -Confirm:$false")
                    run_ps_command("ipconfig /release")
                    time.sleep(2)
                    run_ps_command("ipconfig /renew")
                    run_ps_command("ipconfig /flushdns")
                    
                    # After repair → check real VPN state
                    now_up = is_vpn_up()
                    if not now_up:
                        self.root.after(0, lambda: self.transient_status.configure(
                            text="Reconnecting…"
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
                    now_up = is_vpn_up() # re-check after short delay
                    if not now_up:
                        self.root.after(0, lambda: (
                            self.transient_status.configure(text="Reconnecting..."),
                            self._attempt_auto_reconnect()
                        ))
            
            # --- Normal connection established (or forced after survived sleep) ---
            if not was_up and now_up:
                self.root.after(0, lambda: (
                    self.transient_status.configure(text="Connection Secure & Encrypted"),
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
                if hasattr(self, "_status_stop_event"):
                    self._status_stop_event.set()

                if ok:
                    if src:
                        write_registry(src)

                    # Step 1: WireGuard tunnel is up
                    self.transient_status.configure(text="Connected to WireGuard Service")

                    # Step 2: Wait for routed internet connectivity
                    def maybe_start_routing(attempt=0):
                        MAX_ATTEMPTS = 15          # ~7–8 seconds total
                        if not is_vpn_up():
                            return

                        try:
                            with urllib.request.urlopen(self.ECHOIP_URL, timeout=8) as resp:
                                current_ip = resp.read().decode("utf-8").strip()
                        except Exception as e:
                            print(f"IP-check attempt {attempt} failed: {e}")
                            if attempt < MAX_ATTEMPTS:
                                # Still trying → show progress
                                self.root.after(0, lambda: self.transient_status.configure(
                                    text=f"Establishing secure route... ({attempt + 1}/{MAX_ATTEMPTS})"
                                ))
                                self.root.after(500, lambda: maybe_start_routing(attempt + 1))
                                return
                            else:
                                # Max retries reached → assume it's working (tunnel is up)
                                print("Max IP-check retries reached → forcing 'Connected'")
                                current_ip = None                     # we don't have the IP but that's ok

                        # ── Success path (either real IP or forced after max retries) ──
                        baseline_ip = getattr(self, "_last_detected_ip", None)
                        if current_ip and (baseline_ip is None or current_ip != baseline_ip):
                            self._last_detected_ip = current_ip

                        self.root.after(0, lambda: (
                            self.protection_status.configure(
                                text="Protected",
                                text_color="#00FF00"
                            ),
                            print("Protected Label Update 3"),
                            self.transient_status.configure(
                                text="Connection Secure & Encrypted"
                            ),
                            self._update_tray_if_needed()
                        ))

                    self.root.after(100, maybe_start_routing)

                    self.fetch_and_display_ip("VPN", continuous=True)
                    self.start_vpn_watchdog()
                    self.start_internet_monitor()

                    self.secure_connected = True
                    self.clear_busy(self.btn, "Disconnect", "#f44336")
                    self._update_tray_if_needed()

                else:
                    self.transient_status.configure(
                        text="Secure your online activity by connecting to Shuriken VPN"
                    )
                    self.protection_status.configure(
                        text="Unprotected",
                        text_color="#f44336"
                    )
                    print("Unprotected Label Updated 6")
                    self.clear_busy(self.btn, "Connect", "#4CAF50")
                    self.secure_connected = False
                    if err:
                        messagebox.showerror("Shuriken VPN", err, parent=self.root)
                    self._update_tray_if_needed()

            self.run_async(task, done)

        else:
            # ------------------- DISCONNECT -------------------
            self.transient_status.configure(text="Disconnecting…")
            self.set_busy(self.btn, "Disconnecting…")

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

                if ok:
                    self.transient_status.configure(
                        text="Secure your online activity by connecting to Shuriken VPN"
                    )
                    self.protection_status.configure(
                        text="Unprotected",
                        text_color="#f44336"
                    )
                    print("Unprotected Label Updated 7")
                    self.clear_busy(self.btn, "Connect", "#4CAF50")
                    self.secure_connected = False
                else:
                    self.transient_status.configure(
                        text="Disconnection failed. Tunnel still active"
                    )
                    self.clear_busy(self.btn, "Disconnect", "#f44336")
                    self.secure_connected = True
                    if err:
                        messagebox.showerror(
                            "Disconnection Failed",
                            err,
                            parent=self.root
                        )

                self._update_tray_if_needed()
                self.stop_vpn_watchdog()
                self.stop_internet_monitor()
                self.fetch_and_display_ip("Local", continuous=False)
                self.location_var.set("Location:\nDetecting...")
                if not ok and err:
                    messagebox.showerror("Disconnect Failed", err, parent=self.root)
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

        # ---- SECURE PATH VALIDATION (unchanged) ----
        try:
            config_dir_resolved = CONFIG_DIR.resolve(strict=True)
            new_conf_resolved = new_conf.resolve(strict=True)
        except FileNotFoundError:
            messagebox.showerror(
                "Shuriken VPN",
                f"Config file does not exist:\n{new_conf}",
                parent=self.root,
            )
            return
        except Exception as e:
            messagebox.showerror(
                "Shuriken VPN",
                f"Cannot resolve config path (symlink/perm issue):\n{new_conf}\n\n{e}",
                parent=self.root,
            )
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
                "Add this line under [Interface]:\n"
                "DNS = 10.0.0.1",
                parent=self.root,
            )
            return

        self.stop_vpn_watchdog()

        # Stop any previous animation
        if hasattr(self, "_status_stop_event"):
            self._status_stop_event.set()

        # Start "Connecting..." animation
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
            if hasattr(self, "_status_stop_event"):
                self._status_stop_event.set()

            if ok:
                if conf:
                    write_registry(conf)

                self.transient_status.configure(text="Connected to WireGuard Service")

                def maybe_start_routing():
                    """Try to detect real public IP quickly — if successful, skip animation"""
                    if not is_vpn_up():
                        return

                    current_ip = None
                    for attempt in range(4):  # more retries
                        try:
                            with urllib.request.urlopen(self.ECHOIP_URL, timeout=6) as resp:
                                current_ip = resp.read().decode('utf-8').strip()
                            # Consider it real if it's not obviously private/local
                            if current_ip and not current_ip.startswith(("10.", "100.64.", "192.168.", "172.")):
                                break
                        except Exception:
                            time.sleep(0.9 if attempt < 2 else 1.4)

                    baseline_ip = getattr(self, '_last_detected_ip', None)
                    if current_ip and not current_ip.startswith(("10.", "100.64.", "192.168.", "172.")):
                        self.root.after(0, lambda: (
                            self.protection_status.configure(text="Protected", text_color="#00FF00"),
                            print(f"Protected Label Update 4 - quick path"),
                            self.transient_status.configure(text="Connection Secure & Encrypted"),
                            setattr(self, "secure_connected", True),
                            self._update_tray_if_needed(),
                            self.clear_busy(self.btn, "Disconnect", "#f44336"),
                            # Most important: STOP the animation!
                            self._status_stop_event.set() if hasattr(self, "_status_stop_event") else None
                        ))
                        self._last_detected_ip = current_ip
                        return

                    # If quick check failed → animation continues until IP poller finishes
                    print("[switch_server] Quick IP check failed → keeping 'Routing IP...' animation")

                # Give WireGuard + routing table a realistic chance to settle
                self.root.after(800, maybe_start_routing)   # was 400 — increased

                # Start the background IP confirmation/polling
                self.fetch_and_display_ip("VPN", continuous=True)

                self.start_vpn_watchdog()
                self._update_tray_if_needed()

            else:
                self.transient_status.configure(text="Secure your online activity by connecting to Shuriken VPN")
                self.protection_status.configure(text="Unprotected", text_color="#f44336")
                print(f"Unprotected Label Updated 8")
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
    if DEBUG_MODE:
        try:
            from datetime import datetime
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open("Shuriken_Log.txt", "w", encoding="utf-8") as f:  # "w" = overwrite
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
                    pil_img = Image.open(ICON_PATH)

                    ico_sizes = getattr(pil_img, 'info', {}).get('sizes', [])
                    preferred = [(64,64), (48,48), (32,32), (256,256)]
                    selected_size = None

                    for sz in preferred:
                        if sz in ico_sizes:
                            selected_size = sz
                            break

                    if not selected_size and ico_sizes:
                        selected_size = max(ico_sizes, key=lambda s: s[0])

                    if selected_size:
                        pil_img.load()
                        resized = pil_img.resize(selected_size, Image.Resampling.LANCZOS).convert("RGBA")
                        photo = ImageTk.PhotoImage(resized)
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
                    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    dbg(f"Failed to load custom theme ({e}), falling back to built-in")
                ctk.set_default_color_theme("dark-blue")
        else:
            if DEBUG_MODE:
                dbg(f"shuriken_theme.json not found, using built-in dark-blue theme")
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