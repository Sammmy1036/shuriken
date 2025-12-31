# 🛡️ Shuriken VPN v1.0.0.0  

Shuriken VPN is a lightweight Windows VPN management tool designed to provide a secure and automated experience for WireGuard configurations — offering simplified control, automatic IP detection, and DNS leak protection.

---

## 🚀 Features
- One-click VPN connection management  
- Built-in kill-switch and DNS leak protection  
- Automatic IPv6 leak prevention  
- Real-time connection status and tray integration  
- Compatible with any VPN `.conf` files. It is recommended to use free or premium ProtonVPN files or `.conf` files you trust!

---

## ⚙️ Requirements
- **Windows 10 / 11 (64-bit)**
- **Administrator privileges** (Required for firewall and adapter control)
- **WireGuard** (Automatically installed by Shuriken installer)

## ⚙️ Optional
- **ProtonVPN** Free or Premium Account (Recommended for trusted `.conf` files!)

---

## 🧩 Setup Guide

### Step 1 — Create a ProtonVPN Account  
Sign up for a free account here:  
👉 [https://protonvpn.com/](https://protonvpn.com/)

### Step 2 — Log in to Your Proton Account  
Use your ProtonVPN credentials to access the dashboard.

### Step 3 — Download WireGuard Configurations  
1. Go to **Menu → Downloads**.  
2. Scroll down and select **Platform: Windows**.  
3. Under *Configuration Files*, choose the **NAT-PMP (Port Forwarding)** option.  
4. For each server region you want, click **Create** → **Download** to save the `.conf` file.

### Step 4 — Add Config Files to Shuriken  
Move all downloaded `.conf` files into the Shuriken Config folder

Default Path: C:\Program Files\Shuriken\Config
