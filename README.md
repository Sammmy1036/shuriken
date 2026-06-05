<div align="center">
<img src="assets/shuriken.png" alt="Alt text" width="200"/>
</div>

# Shuriken VPN

**Shuriken** is a fast, lightweight, and highly secure **WireGuard-based VPN client** for Windows, focused on maximum privacy and reliability.  
Built for users who want strong leak protection, automatic reconnection, split tunneling, and a clean modern interface without bloat.

---

## Overview

Shuriken is a Windows VPN client that uses **official WireGuard** under the hood while layering a comprehensive set of privacy and reliability protections on top:

- Full kill switch with pre-switch gap protection
- DNS, DoH, DoT, and WPAD/proxy leak blocking
- Skype & Teams SNI/DNS leak suppression
- Automatic reconnect after sleep, adapter changes, or crashes
- Split tunneling per-app VPN bypass
- Stealth port 443 mode — evades ISP deep packet inspection
- Smart server selection with fuzzy search
- Built-in official Tor Browser (Tor-over-VPN recommended)
- IP address and geolocation display via self-hosted EchoIP / GeoLite2

---

## Features

- **Full Kill Switch** — Blocks all outbound internet on physical adapters the moment the VPN drops. A pre-switch kill switch also fires instantly during server switches to close the teardown/reestablishment gap.
- **DNS Leak Protection** — Blocks ports 53 (TCP/UDP), 853 (DoT), and DoH (443) on all non-WireGuard adapters while connected.
- **WPAD / Proxy Leak Suppression** — Disables the WinHTTP auto-proxy service and blocks NetBIOS ports 137/138 during active sessions.
- **Skype & Teams Leak Suppression** — Null-routes Microsoft Skype and Teams IP ranges and firewall-blocks those processes to prevent direct TLS/SNI leaks that bypass DNS entirely.
- **Split Tunneling** — Designate specific applications to bypass the VPN and use your regular connection. Rules apply immediately while connected and persist across sessions.
- **Stealth Port 443** — Optionally rewrites the WireGuard endpoint port to 443 to evade ISP deep packet inspection. Pre-flight TCP probe ensures the server supports 443 before installing the tunnel.
- **Smart Reconnect** — Survives sleep, Wi-Fi adapter re-enables, network resets, and unexpected crashes. Adapter state is monitored and repair sequences run automatically.
- **Handshake Verification** — Confirms a successful WireGuard cryptographic handshake (not just adapter presence) before marking the connection as established. Tears down and reports failure cleanly if no handshake occurs within 25 seconds.
- **Fuzzy Server Search** — Search by city, state, country name, or common abbreviations. Handles typos and partial matches.
- **IP & Geolocation Display** — Shows your current public IP, network provider (ASN), and approximate location via a self-hosted [EchoIP](https://github.com/mpolden/echoip) instance backed by [GeoLite2](https://www.maxmind.com) data. All lookups are ephemeral — nothing is logged or stored.
- **Tray Icon with Status Overlay** — Green lock = Protected, Red lock = Unprotected. Reflects live connection state.
- **Official Tor Browser Integration** — Launch Tor Browser directly from the UI. Shuriken recommends connecting to the VPN first to hide Tor usage from your ISP (Tor-over-VPN).
- **Auto Network Repair** — Detects stuck adapters, stale WireGuard services, and broken DNS caches, and runs a repair sequence automatically.
- **Emergency Firewall Cleanup** — All Shuriken-created firewall rules and routing changes are cleaned up on exit, even on unexpected crash, via an `atexit` handler registered at startup.

---

## Bundled Components

| Component | Version | License |
|-----------|---------|---------|
| WireGuard for Windows | 1.1 (amd64) | GPL v3 |
| Tor Browser | Latest bundled | GPL v3 |

> WireGuard® is a registered trademark of Jason A. Donenfeld.  
> Tor Browser is developed by the Tor Project, Inc.  
> GeoLite2 data is created by MaxMind.

---

## Requirements

- **Windows 10 / 11** (64-bit)
- **Administrator rights** — required for firewall rules, DNS protection, and WireGuard service management
- WireGuard is **bundled** — no separate installation required

---

## Privacy & Transparency

Shuriken is an **open-source client**. The code is public and can be audited.  
It does **not** collect, phone home, or log any user activity.

### Client-side

- No telemetry, analytics, or crash reporting of any kind
- No storage of connection history, IPs, or timestamps
- Kill switch and DNS leak protection enforced locally via Windows Firewall
- All WireGuard keys and configs stay on your machine (in the `Config/` folder and `%PROGRAMDATA%\WireGuard\` during active sessions only)
- The only registry key written is `HKCU\Software\Shuriken` — stores your last-used server selection and optional stealth port setting
- Split tunnel app list stored locally at `%APPDATA%\Shuriken\split_tunnel_apps.json`
- IP lookups (for the IP display in the UI) are made to a self-hosted EchoIP endpoint over HTTPS, are ephemeral, and return only your public IP, city, country, and ASN for on-screen display — nothing is logged or forwarded

### Server-side (public Shuriken endpoints)

We operate a small fleet of public WireGuard servers with a strict operational design aimed at eliminating any possibility of user-identifiable logging.

**No-logs operational policy**

- No storage of: traffic content, DNS queries, source IPs, connection times, bandwidth per user, or any linking metadata
- DNS handled via an internal AdGuard Home instance with query logging **disabled**
- The only data processed is ephemeral encrypted tunnel traffic — nothing is persisted to disk

**RAM-only / diskless server architecture**

- Servers boot from read-only images (netboot / squashfs)
- All runtime state (WireGuard keys, configs, logs) lives in `tmpfs` / ramdisk
- `/var/log`, `/var/lib/wireguard`, `/etc/wireguard` → mounted as `tmpfs` or redirected to `/dev/null`
- **Power cycle or reboot = everything disappears**

**Data disclosure policy**

No user data is sold or provided to any third party or government agency. The only exception is a valid court order served upon the author in the applicable jurisdiction. Any such requests, to the extent they can be published, will be disclosed in the transparency log below.

### Transparency log

| Date | Event |
|------|-------|
| 2026-06-01 | Routine reboot of all public nodes. Verified `tmpfs` mounts and confirmed no persistent WireGuard-related files post-reboot. |
| 2026-05-27 | Updates to GeoLite2 City Data for IPs in California Region of the United States of America. |
| 2026-05-01 | Routine reboot of all public nodes. Verified `tmpfs` mounts and confirmed no persistent WireGuard-related files post-reboot. |
| 2026-04-01 | Routine reboot of all public nodes. Verified `tmpfs` mounts and confirmed no persistent WireGuard-related files post-reboot. |
| 2026-03-01 | Routine reboot of all public nodes. Verified `tmpfs` mounts and confirmed no persistent WireGuard-related files post-reboot. |
| 2026-02-01 | Routine reboot of all public nodes. Verified `tmpfs` mounts and confirmed no persistent WireGuard-related files post-reboot. |
| 2026-01-01 | Routine reboot of all public nodes. Verified `tmpfs` mounts and confirmed no persistent WireGuard-related files post-reboot. |

We publish any future compelled data requests in this section.

### Audit invitation

The client is open source. Feel free to audit, build from source, or run your own servers.  
Server provisioning code is public so the RAM-disk setup can be independently verified.  
Questions → open an issue.

---

## Setup Guide

### Option 1: Run from Source (Recommended for testing)

```bash
git clone https://github.com/sammmy1036/shuriken.git
cd shuriken

# Recommended: create a virtual environment
python -m venv venv
venv\Scripts\activate

pip install -r requirements.txt
python Shuriken.pyw
```

> **Note:** Run as Administrator for full kill switch and DNS leak protection. The app will prompt you on launch if not elevated.

### Option 2: Run the Pre-built Executable

Download the latest release from the [Releases](https://github.com/sammmy1036/shuriken/releases) page. Not posted to releases yet.  
Run `ShurikenVPN.exe` to setup the application.  
WireGuard and Tor Browser are bundled and no separate installs are needed.

---

## Configuration

Place your WireGuard `.conf` files in the `Config/` folder next to the application (or `%APPDATA%\Shuriken\Config\` as a fallback).  
Shuriken will auto-detect them and display them in the server list.

Server display names, flags, and city/country metadata for known Shuriken servers are defined in `metadata.py`. Custom `.conf` files dropped into the Config folder will also appear in the list using the filename as the display name.

---

## What Shuriken Modifies on Your System

Shuriken is transparent about every system change it makes:

| What | When | Cleaned up? |
|------|------|-------------|
| Windows Firewall rules (prefixed `Shuriken *`) | On connect | ✅ On disconnect / exit / crash |
| DNS settings on physical adapters | On connect | ✅ On disconnect |
| WireGuard tunnel service | On connect | ✅ On disconnect |
| WinHTTP WPAD auto-proxy service (disabled) | On connect | ✅ On disconnect |
| Null routes for private DNS IPs & Teams/Skype ranges | On connect | ✅ On disconnect |
| Registry key `HKCU\Software\Shuriken` | On first use | Persists (stores server selection & settings only) |
| `%APPDATA%\Shuriken\split_tunnel_apps.json` | When split tunnel is configured | Persists (user-managed) |

Shuriken does **not** reset Windows Firewall globally, touch Winsock, modify the TCP/IP stack, or interfere with antivirus or Group Policy settings.

---

## License

- **ShurikenVPN client code** — Free for personal, non-commercial use. See [LICENSE.md](LICENSE.md).
- **WireGuard** — GNU General Public License v3
- **Tor Browser** — GNU General Public License v3
- **GeoLite2** — [MaxMind GeoLite2 End User License Agreement](https://www.maxmind.com/en/geolite2/eula)
