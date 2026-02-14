import subprocess, time, socket, atexit, os, sys, ctypes
from pathlib import Path
from typing import List
from constants import DEBUG_MODE

_DNS_BLOCK_RULES: list[str] = []
_KILLSWITCH_RULES: list[str] = []

def run(cmd: list[str]) -> tuple[int, str, str]:
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    creationflags = 0
    if hasattr(subprocess, "CREATE_NO_WINDOW"):
        creationflags |= subprocess.CREATE_NO_WINDOW

    p = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        startupinfo=startupinfo,
        creationflags=creationflags,
    )
    out, err = p.communicate()
    return p.returncode, out, err

def _ps(cmd: str) -> tuple[int, str, str]:
    return run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd])

def _list_non_wg_adapters() -> list[str]:
    """Get list of active network adapters excluding WireGuard/tunnel ones."""
    code, out, _ = _ps(
        r"(Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -ExpandProperty Name) -join '`n'"
    )
    aliases = []
    if code == 0 and out:
        for name in out.splitlines():
            n = name.strip().lower()
            if n and "wireguard" not in n and "tunnel" not in n and "wg" not in n:
                aliases.append(name.strip())
    return aliases

def add_dns_leak_block():
    """Block DNS (53, 853) and DoH (443) on non-WireGuard interfaces, allow Windows Update."""
    remove_dns_leak_block()  # Clean slate
    aliases = _list_non_wg_adapters()
    if not aliases:
        return

    cmds = []
    names = []

    # === 1. Block standard DNS + DoT ===
    dns_ports = [
        ("TCP", 53),
        ("UDP", 53),
        ("TCP", 853),
        ("UDP", 853),
    ]

    for alias in aliases:
        safe_alias = alias.replace("'", "''").replace("`", "``").replace("$", "`$")
        for proto, port in dns_ports:
            rule_name = f"Shuriken DNS Block {proto} {port} on {alias}"
            safe_name = rule_name.replace("'", "''")

            check_cmd = f"Get-NetFirewallRule -DisplayName '{safe_name}' -ErrorAction SilentlyContinue"
            code, out, _ = _ps(check_cmd)
            if code == 0 and out.strip():
                continue

            names.append(rule_name)
            cmds.append(
                f"New-NetFirewallRule -DisplayName '{safe_name}' "
                f"-Direction Outbound -Protocol {proto} -RemotePort {port} "
                f"-Action Block -Profile Any -Enabled True "
                f"-InterfaceAlias '{safe_alias}' -ErrorAction SilentlyContinue | Out-Null"
            )

    # === 2. Block ALL TCP 443 (DoH) on non-WG interfaces ===
    for alias in aliases:
        safe_alias = alias.replace("'", "''").replace("`", "``").replace("$", "`$")
        rule_name = f"Shuriken Block DoH 443 on {alias}"
        safe_name = rule_name.replace("'", "''")

        check_cmd = f"Get-NetFirewallRule -DisplayName '{safe_name}' -ErrorAction SilentlyContinue"
        code, out, _ = _ps(check_cmd)
        if code == 0 and out.strip():
            continue

        names.append(rule_name)
        cmds.append(
            f"New-NetFirewallRule -DisplayName '{safe_name}' "
            f"-Direction Outbound -Protocol TCP -RemotePort 443 "
            f"-Action Block -Profile Any -Enabled True "
            f"-InterfaceAlias '{safe_alias}' -ErrorAction SilentlyContinue | Out-Null"
        )

    # === 3. ALLOW Windows Update domains (EXCEPTION) ===
    update_domains = [
        "www.microsoft.com",
        "*.microsoft.com",
        "*.msftconnecttest.com",
        "*.msftncsi.com",
        "settings-win.data.microsoft.com",
        "*.wdcp.microsoft.com",
        "*.dl.delivery.mp.microsoft.com",        
        "windowsupdate.microsoft.com",
        "*.windowsupdate.microsoft.com",
        "update.microsoft.com",
        "*.update.microsoft.com",
        "download.windowsupdate.com",
        "*.download.windowsupdate.com",
        "wustat.windows.com",
        "delivery.mp.microsoft.com",
        "*.delivery.mp.microsoft.com",
        "storeedgefd.dsx.mp.microsoft.com",
    ]

    for domain in update_domains:
        safe_domain = domain.replace("'", "''")
        rule_name = f"Shuriken Allow Update {domain}"
        safe_name = rule_name.replace("'", "''")

        check_cmd = f"Get-NetFirewallRule -DisplayName '{safe_name}' -ErrorAction SilentlyContinue"
        code, out, _ = _ps(check_cmd)
        if code == 0 and out.strip():
            continue

        names.append(rule_name)
        cmds.append(
            f"New-NetFirewallRule -DisplayName '{safe_name}' "
            f"-Direction Outbound -Protocol TCP -RemotePort 443 "
            f"-Action Allow -Profile Any -Enabled True "
            f"-RemoteAddress '{safe_domain}' -ErrorAction SilentlyContinue | Out-Null"
        )

    if cmds:
        _ps("; ".join(cmds))
        _DNS_BLOCK_RULES[:] = names

def remove_dns_leak_block():
    """Remove all Shuriken DNS + DoH block rules."""
    if _DNS_BLOCK_RULES:
        rm_cmds = [
            f"Get-NetFirewallRule -DisplayName '{rn.replace("'", "''")}' "
            "-ErrorAction SilentlyContinue | "
            "Remove-NetFirewallRule -Confirm:$false -ErrorAction SilentlyContinue | Out-Null"
            for rn in _DNS_BLOCK_RULES
        ]
        _ps("; ".join(rm_cmds))
        _DNS_BLOCK_RULES.clear()
    else:
        _ps(
            "Get-NetFirewallRule -DisplayName 'Shuriken*' "
            "-ErrorAction SilentlyContinue | "
            "Remove-NetFirewallRule -Confirm:$false -ErrorAction SilentlyContinue | Out-Null"
        )

# -------------------------- Full Kill Switch --------------------
def add_kill_switch():
    """
    Enforce a full kill switch: block all outbound traffic on non-WireGuard
    interfaces, allowing only traffic through WireGuard tunnels.
    """
    remove_kill_switch()  # ensure no duplicates
    aliases = _list_non_wg_adapters()
    if not aliases:
        return
    cmds = []
    names: list[str] = []

    # Block all outbound traffic on non-WireGuard interfaces
    for alias in aliases:
        safe = alias.replace("'", "''").replace('`', '``').replace('$', '`$')
        rn = f"Shuriken KillSwitch Block {alias}"
        rn_safe = rn.replace("'", "''")

        check_cmd = f"Get-NetFirewallRule -DisplayName '{rn_safe}' -ErrorAction SilentlyContinue"
        code, out, _ = _ps(check_cmd)
        if code == 0 and out.strip():
            continue

        names.append(rn)
        cmds.append(
            f"New-NetFirewallRule -DisplayName '{rn_safe}' -Direction Outbound "
            f"-Action Block -Enabled True -Profile Any -InterfaceAlias '{safe}' | Out-Null"
        )

    # Allow traffic through WireGuard interface(s)
    rn_allow = "Shuriken KillSwitch Allow WireGuard"
    safe_allow = rn_allow.replace("'", "''")

    check_cmd = f"Get-NetFirewallRule -DisplayName '{safe_allow}' -ErrorAction SilentlyContinue"
    code, out, _ = _ps(check_cmd)
    if code != 0 or not out.strip():
        cmds.append(
            f"New-NetFirewallRule -DisplayName '{safe_allow}' -Direction Outbound "
            f"-Action Allow -Enabled True -Profile Any -InterfaceAlias 'WireGuard*' | Out-Null"
        )
        names.append(rn_allow)

    if cmds:
        _ps("; ".join(cmds))
        _KILLSWITCH_RULES[:] = names

def remove_kill_switch():
    """Delete every Shuriken kill-switch rule, cached or not."""
    if _KILLSWITCH_RULES:
        rm_cmds = [
            f"Get-NetFirewallRule -DisplayName '{rn.replace("'", "''")}' "
            "-ErrorAction SilentlyContinue | Remove-NetFirewallRule -Confirm:$false | Out-Null"
            for rn in _KILLSWITCH_RULES
        ]
        _ps("; ".join(rm_cmds))
        _KILLSWITCH_RULES.clear()

    # Catch-all for any stray rule
    _ps(
        "Get-NetFirewallRule | Where-Object { $_.DisplayName -like '*Shuriken DNS Block*' } "
        "-ErrorAction SilentlyContinue | "
        "Remove-NetFirewallRule -Confirm:$false | Out-Null"
    )

# -------------------------- Helpers -------------------------------
def disable_ipv6_on_non_wg_adapters():
    """BLOCK ALL IPv6 traffic on non-WireGuard adapters using firewall."""
    try:
        cmd = (
            "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Name -notlike '*WireGuard*' } "
            "| ForEach-Object { "
            "  $name = $_.Name; "
            "  New-NetFirewallRule -DisplayName \"Shuriken Block IPv6 on `$name\" "
            "  -Direction Outbound -Action Block -Protocol Any "
            "  -LocalAddress Any -RemoteAddress Any "
            "  -InterfaceAlias `$name -Profile Any -Enabled True "
            "  -ErrorAction SilentlyContinue | Out-Null; "
            "  New-NetFirewallRule -DisplayName \"Shuriken Block IPv6 on `$name\" "
            "  -Direction Inbound -Action Block -Protocol Any "
            "  -LocalAddress Any -RemoteAddress Any "
            "  -InterfaceAlias `$name -Profile Any -Enabled True "
            "  -ErrorAction SilentlyContinue | Out-Null "
            "} "
            "Get-NetFirewallRule -DisplayName 'Shuriken Block IPv6 on *' -ErrorAction SilentlyContinue | Out-Null"
        )
        _ps(cmd)
    except Exception:
        pass

def enable_ipv6_on_non_wg_adapters():
    """REMOVE all Shuriken IPv6 firewall block rules."""
    try:
        _ps("Get-NetFirewallRule -DisplayName 'Shuriken Block IPv6 on *' "
            "-ErrorAction SilentlyContinue | Remove-NetFirewallRule -Confirm:$false")
    except Exception:
        pass

atexit.register(enable_ipv6_on_non_wg_adapters)

def reset_firewall_if_blocked():
    print(f"[NETWORK] Removing Shuriken Firewall settings due to block at {time.time():.0f}")
    try: _ps("Get-NetFirewallRule -DisplayName 'Shuriken*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -Confirm:$false")
    except: pass