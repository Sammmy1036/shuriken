# Shuriken VPN

**Shuriken** is a fast, lightweight, and highly secure **WireGuard based VPN client** for Windows, focused on maximum privacy and reliability.

Built for users who want strong leak protection, automatic reconnection, and a clean modern interface without bloat.

## Overview

Shuriken is a VPN client that uses **official WireGuard** under the hood while adding military grade protections:
- Full Kill Switch
- DNS + DoH/DoT leak blocking
- Automatic reconnect after sleep, adapter changes, or crashes
- Smart server selection with fuzzy search
- Built-in official Tor Browser launcher

## Features

- **Full Kill Switch** – Blocks all internet if VPN drops
- **DNS Leak Protection** – Blocks port 53, 853 and DoH (443)
- **Smart Reconnect** – Survives sleep, Wi-Fi changes, network resets
- **Fuzzy Server Search** – Search by city, country, airport code (e.g. "la", "tokyo", "ams")
- **Tray Icon with Status Overlay** – Green = Protected, Red = Unprotected
- **Official Tor Browser Integration** (Recommended: Tor over VPN)
- **Auto Network Repair** – Fixes stuck adapters and DNS cache issues

## Requirements

- **Windows 10 / 11** (64-bit)
- **Administrator rights** (required for firewall rules & DNS protection)
- **WireGuard** installed (MSI will be auto-detected or bundled)

## Privacy & Transparency

Shuriken is an **open-source client** — the code is public and can be audited.  
It does **not** collect, phone home, or log any user activity on your device.

### Client-side (your computer)
- No telemetry, no analytics, no crash reporting
- No storage of connection history, IPs, or timestamps
- DNS leak protection and kill-switch are enforced locally via Windows Firewall
- All WireGuard keys & configs stay on your machine (in the `Config/` folder)

### Server-side (public Shuriken endpoints)
We operate (or strongly endorse) a small fleet of public WireGuard servers with a strict operational design aimed at minimizing any possibility of user-identifiable logging:

**No-logs operational policy**
- No storage of: traffic content, DNS queries, source IPs, connection times, bandwidth per user, or any linking metadata
- DNS is handled via an internal AdGuard Home instance with query logging **disabled**
- The only data processed is ephemeral encrypted tunnel traffic — nothing is persisted to disk

**RAM-only / diskless server architecture**
- Servers boot from read-only images (netboot / squashfs)
- All runtime state (WireGuard keys, configs, logs) lives in tmpfs / ramdisk
- /var/log, /var/lib/wireguard, /etc/wireguard → mounted as tmpfs or redirected to /dev/null
- **Power cycle / reboot = everything disappears**

Server bootstrap & hardening scripts (Ansible / Packer) are public here:  
→ [github.com/yourusername/shuriken-infra] (create this repo if it doesn't exist yet)

### Transparency log (warrant canary style)
- **2026-02-01** — Routine reboot of all public nodes. Verified tmpfs mounts and no persistent WireGuard-related files post-reboot.
- **2026-01-15** — Zero data requests / subpoenas received that could be actioned.
- **2025-12-20** — Enforced tmpfs mounts on logging and config directories in bootstrap image.

We publish any future compelled data requests (that we can legally disclose) in this section.

### Audit invitation
The client is open source — feel free to audit, build from source, or run your own servers.  
Server provisioning code is public so the RAM-disk setup can be independently verified.

Questions → open an issue.

## Setup Guide

### Option 1: Run from Source (Recommended for testing)

```bash
git clone https://github.com/yourusername/shuriken.git
cd shuriken

# Recommended: Create virtual environment
python -m venv venv
venv\Scripts\activate

pip install -r requirements.txt
python Shuriken.py

