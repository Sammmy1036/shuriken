# ShurikenVPN — License Agreement, Security Overview & Disclaimer

**Version 1.0.0.0** — © 2026 ShurikenVPN  
**Software Name:** ShurikenVPN  
**License Type:** Free for personal, non-commercial use

## 1. Introduction

This License Agreement (“Agreement”) governs your use of the ShurikenVPN application (“Software”).  
By downloading, installing, or using the Software, you acknowledge that you have read, understood, and agreed to be bound by these terms.

## 2. No Affiliation

The Software is not affiliated, associated, authorized, endorsed by, or in any way officially connected with WireGuard® or any subsidiaries or affiliates of related entities.

WireGuard® is a registered trademark of Jason A. Donenfeld.

All names, trademarks, and brands are the property of their respective owners.

## 3. User Responsibility & Prohibition of Illegal Use

You are solely responsible for all activities performed using the Software.

**Illegal activities of any kind are strictly prohibited.** The Software must not be used for any unlawful purpose, including but not limited to hacking, fraud, distribution of illegal content, or any violation of applicable laws.

The creator of this Software accepts no liability and bears no responsibility for:

- Any illegal use or misuse
- Legal, financial, or operational consequences
- Misconfigurations caused by user-supplied configuration files
- Loss of connectivity, data, or privacy arising from user choices

You are fully responsible for verifying the trustworthiness and safety of any configuration files you choose to use.

## 4. Third-Party Requirements

The Software interacts with and/or bundles third-party technologies and services required for operation, including:

- WireGuard protocol (bundled — for tunnel creation)
- Tor Browser (bundled — for optional onion routing / privacy features)

You are responsible for reviewing the corresponding Terms of Service, Licenses, and Privacy Policies for:

- WireGuard
- Tor Project / Tor Browser
- Any other third-party components or services used via custom configurations

No guarantee of compatibility with third-party services is provided.

## 5. Data & Privacy Policy

ShurikenVPN collects **no personal data** and performs **no logging** of:

- User activity
- IP addresses
- Connection metadata
- DNS requests
- Configuration details

The Software **does not** transmit, store, upload, share, or send any user data or metadata to **third parties** under any circumstances, including during normal operation, IP validation, configuration import, error handling, or update checks.

All operations that involve external communication (such as IP checking) are performed ephemerally and do not include tracking parameters, API keys, persistent identifiers, or any form of telemetry.

### 5.1 Server-Side & Infrastructure Privacy (User Responsibility)

ShurikenVPN is a purely **client-side** application in terms of user tracking and telemetry. Any logging policy (or lack thereof) on the VPN endpoint, DDNS provider, or DNS resolver is determined **solely** by the configuration and infrastructure selected or provided.

Users who self-host components remain fully responsible for configuring and verifying those components in accordance with their own no-logging requirements.

## 6. Security Overview

ShurikenVPN follows a strict security boundary to ensure predictable, safe behavior.

### 6.1 What the Software Does Modify

To maintain tunnel stability, leak protection, and network integrity, ShurikenVPN does modify:

- Firewall rules created only by ShurikenVPN
- DNS settings on common adapters (Ethernet / Wi-Fi / LAN)
- IPv4/IPv6 adapter bindings
- The WireGuard tunnel service (install/uninstall operations)

### 6.2 What the Software Does Not Modify

ShurikenVPN explicitly does **NOT**:

- Reset Windows Firewall globally
- Reset Winsock
- Reset the TCP/IP stack
- Modify antivirus or third-party firewall rules
- Override Group Policy settings
- Interfere with unrelated network interfaces
- Modify the content of user-supplied configuration files (when applicable)

### 6.3 Leak Protection

ShurikenVPN implements:

- Outbound kill-switch enforcement
- DNS leak blocking (53/853/443)
- DoH leak prevention on non-VPN interfaces
- External IP validation over HTTPS with strict certificate validation; performed ephemerally in memory only — no results are logged, stored to disk, or transmitted to the developer or any other party

## 7. What ShurikenVPN Does NOT Do

To avoid misunderstanding, the Software does not:

- Monitor browsing activity or network traffic
- Collect user analytics or telemetry
- Upload or transmit any data to external services without user-initiated purpose
- Override OS-level protections or enterprise networking policies

## 8. User Disclaimer & Liability Statement

The Software relies on configuration files and infrastructure that can alter routing, DNS behavior, and network paths.

By using ShurikenVPN, you acknowledge and accept:

### 8.1 User Risk Acceptance

You accept all risks associated with:

- Using untrusted or malicious servers
- Incorrect routing rules or AllowedIPs in your configuration
- Tunnel behavior defined by your configuration
- DNS settings defined in your configuration
- Any breach, privacy leak, or misconfiguration caused by chosen settings

### 8.2 Developer Liability

The creator of the Software shall not be held liable for:

- Damages, losses, or security incidents
- Performance issues caused by VPN servers or infrastructure
- Legal or regulatory consequences arising from usage (including any illegal use)
- Network outages caused by configuration files or servers
- Misuse of the Software or violations of third-party terms

You assume complete responsibility for ensuring your configurations and usage are safe, legal, and appropriate.

## 9. Warranty Disclaimer

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO:

- MERCHANTABILITY
- FITNESS FOR A PARTICULAR PURPOSE
- NON-INFRINGEMENT

IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DAMAGES, CLAIMS, OR OTHER LIABILITY ARISING FROM THE SOFTWARE OR ITS USE.

## 10. Liability Disclaimer

The creator of ShurikenVPN shall not be held liable for:

- Violations of third-party licenses or terms
- Misuse, illegal use, or prohibited use
- Security breaches, privacy leaks, or data loss
- Network downtime or performance issues
- Actions taken by government or legal authorities
- Damages caused by servers, files, or services

## 11. Governing Law

This Agreement is governed by the laws of the author’s jurisdiction, without regard to conflict-of-law principles.

## 12. GNU General Public License (GPL) Notice

This Software incorporates or builds upon components licensed under the GNU General Public License (GPL).

The full text of the GNU GPL v2 is provided below.

---

**GNU GENERAL PUBLIC LICENSE**  
Version 2, June 1991  
© 1989, 1991 Free Software Foundation, Inc.

(The full GPLv2 text continues unchanged and must remain verbatim.)

---

**END OF LICENSE FILE**