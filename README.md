# Shuriken VPN

**Shuriken** is a fast, lightweight, and highly secure **WireGuard-based VPN client** for Windows, focused on maximum privacy and reliability.

Built for users who want strong leak protection, automatic reconnection, and a clean modern interface without bloat.

![Shuriken Banner](https://via.placeholder.com/800x200/1a1a1a/00ff9f?text=Shuriken+VPN) <!-- Replace with real screenshot later -->

## Overview

Shuriken is a custom-designed VPN client that uses **official WireGuard** under the hood while adding enterprise-grade protections:
- Full Kill Switch (no leaks even on disconnect)
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
- **Clean Dark UI** using CustomTkinter
- **Portable-ready** (works when packaged with PyInstaller)

## Requirements

- **Windows 10 / 11** (64-bit)
- **Administrator rights** (required for firewall rules & DNS protection)
- **WireGuard** installed (MSI will be auto-detected or bundled)

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
