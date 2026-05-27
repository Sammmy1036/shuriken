import subprocess, time, socket, atexit, os, sys, ctypes, ipaddress
from pathlib import Path
from typing import List
from constants import DEBUG_MODE

_DNS_BLOCK_RULES:  list[str] = []
_KILLSWITCH_RULES: list[str] = []
_WPAD_BLOCK_RULES: list[str] = []
_NULL_ROUTES:      list[str] = []
_SPLIT_TUNNEL_RULES: list[str] = []   # firewall rule names added for split tunnel apps

# Microsoft Skype/Teams IP ranges that bypass DNS entirely with cached IPs.
# Must be null-routed at the routing layer to stop direct TLS/SNI leaks.
_SKYPE_IP_RANGES = [
    "13.107.64.0/18",
    "52.112.0.0/14",
    "52.120.0.0/14",
    "172.202.0.0/16",
    "40.96.0.0/13",
    "40.104.0.0/15",
]

# Process-level firewall block targets — moved to module scope so they are
# clearly visible as configuration, not buried in a function body.
_PROCESS_BLOCK_APPS = [
    ("Skype",    r"%ProgramFiles(x86)%\Microsoft\Skype for Desktop\Skype.exe"),
    ("SkypeApp", r"%SystemRoot%\SystemApps\Microsoft.SkypeApp_kzf8qxf38zg5c\SkypeApp.exe"),
    ("Teams",    r"%LocalAppData%\Microsoft\Teams\current\Teams.exe"),
    ("TeamsNew", r"%ProgramFiles%\WindowsApps\MSTeams_23306.3005.2679.3221_x64__8wekyb3d8bbwe\ms-teams.exe"),
    ("OneDrive", r"%LocalAppData%\Microsoft\OneDrive\OneDrive.exe"),
]

# ── Core subprocess helpers ───────────────────────────────────────────────────

def _make_si() -> tuple[subprocess.STARTUPINFO, int]:
    """Return a STARTUPINFO + creationflags pair that suppresses console windows."""
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    return si, getattr(subprocess, "CREATE_NO_WINDOW", 0)

def run(cmd: list[str]) -> tuple[int, str, str]:
    si, cf = _make_si()
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         text=True, startupinfo=si, creationflags=cf)
    out, err = p.communicate()
    return p.returncode, out, err

def _ps(cmd: str) -> tuple[int, str, str]:
    return run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", cmd])

def _ps_batched(cmds: list[str], batch_size: int = 8) -> None:
    """Run a list of PowerShell statements in batches to avoid command-length limits."""
    for i in range(0, len(cmds), batch_size):
        _ps("; ".join(cmds[i:i + batch_size]))

def _list_non_wg_adapters() -> list[str]:
    """Return names of Up adapters that are not WireGuard/tunnel interfaces."""
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

def _safe_ps_name(name: str) -> str:
    """Escape a network adapter name for embedding in a PowerShell single-quoted string."""
    return name.replace("'", "''").replace("`", "``").replace("$", "`$")

# ── DNS leak block ────────────────────────────────────────────────────────────

def add_dns_leak_block():
    """Block DNS port 53 and DoT port 853 on all non-WireGuard interfaces."""
    remove_dns_leak_block()
    aliases = _list_non_wg_adapters()
    if not aliases:
        return
    cmds, names = [], []
    for alias in aliases:
        safe = _safe_ps_name(alias)
        for proto, port in [("TCP", 53), ("UDP", 53), ("TCP", 853), ("UDP", 853)]:
            rn = f"Shuriken DNS Block {proto} {port} on {alias}"
            names.append(rn)
            cmds.append(
                f"New-NetFirewallRule -DisplayName '{rn.replace(chr(39), chr(39)*2)}' "
                f"-Direction Outbound -Protocol {proto} -RemotePort {port} "
                f"-Action Block -Profile Any -Enabled True "
                f"-InterfaceAlias '{safe}' -ErrorAction SilentlyContinue | Out-Null"
            )
    if cmds:
        _ps_batched(cmds)
        _DNS_BLOCK_RULES[:] = names

def remove_dns_leak_block():
    """Remove all Shuriken DNS block rules."""
    if _DNS_BLOCK_RULES:
        _ps("; ".join(
            f"Get-NetFirewallRule -DisplayName '{rn.replace(chr(39), chr(39)*2)}' "
            "-ErrorAction SilentlyContinue | "
            "Remove-NetFirewallRule -Confirm:$false -ErrorAction SilentlyContinue | Out-Null"
            for rn in _DNS_BLOCK_RULES
        ))
        _DNS_BLOCK_RULES.clear()
    else:
        _ps(
            "Get-NetFirewallRule -DisplayName 'Shuriken DNS Block*' "
            "-ErrorAction SilentlyContinue | "
            "Remove-NetFirewallRule -Confirm:$false -ErrorAction SilentlyContinue | Out-Null"
        )

# ── Kill switch ───────────────────────────────────────────────────────────────

def add_kill_switch():
    """Block all outbound on physical interfaces; allow WireGuard tunnel only."""
    remove_kill_switch()
    aliases = _list_non_wg_adapters()
    if not aliases:
        return
    cmds, names = [], []
    for alias in aliases:
        safe = _safe_ps_name(alias)
        rn = f"Shuriken KillSwitch Block {alias}"
        names.append(rn)
        cmds.append(
            f"New-NetFirewallRule -DisplayName '{rn.replace(chr(39), chr(39)*2)}' "
            f"-Direction Outbound -Action Block -Enabled True -Profile Any "
            f"-InterfaceAlias '{safe}' -ErrorAction SilentlyContinue | Out-Null"
        )
    rn_allow = "Shuriken KillSwitch Allow WireGuard"
    names.append(rn_allow)
    cmds.append(
        f"New-NetFirewallRule -DisplayName '{rn_allow}' -Direction Outbound "
        f"-Action Allow -Enabled True -Profile Any -InterfaceAlias 'WireGuard*' "
        f"-ErrorAction SilentlyContinue | Out-Null"
    )
    if cmds:
        _ps_batched(cmds)
        _KILLSWITCH_RULES[:] = names

def remove_kill_switch():
    """Remove all Shuriken kill-switch rules."""
    if _KILLSWITCH_RULES:
        _ps("; ".join(
            f"Get-NetFirewallRule -DisplayName '{rn.replace(chr(39), chr(39)*2)}' "
            "-ErrorAction SilentlyContinue | Remove-NetFirewallRule -Confirm:$false | Out-Null"
            for rn in _KILLSWITCH_RULES
        ))
        _KILLSWITCH_RULES.clear()
    else:
        _ps(
            "Get-NetFirewallRule | Where-Object { $_.DisplayName -like 'Shuriken KillSwitch*' } "
            "-ErrorAction SilentlyContinue | Remove-NetFirewallRule -Confirm:$false | Out-Null"
        )

def block_physical_immediately() -> None:
    """
    Single PS pipeline that blocks ALL outbound on physical interfaces in ~50ms.
    Called before any slower rule-building loop so DNS/WPAD cannot escape
    during the gap between teardown and permanent rules landing.
    """
    _ps(
        "Get-NetFirewallRule -DisplayName 'Shuriken KillSwitch PreSwitch*' "
        "  -ErrorAction SilentlyContinue | Remove-NetFirewallRule -Confirm:$false | Out-Null; "
        "$a = Get-NetAdapter | Where-Object { "
        "  $_.Status -eq 'Up' -and $_.Name -notlike '*WireGuard*' "
        "  -and $_.Name -notlike '*tunnel*' -and $_.Name -notlike '*wg*' }; "
        "foreach ($x in $a) { "
        "  New-NetFirewallRule -DisplayName \"Shuriken KillSwitch PreSwitch $($x.Name)\" "
        "    -Direction Outbound -Action Block -Enabled True -Profile Any "
        "    -InterfaceAlias $x.Name -ErrorAction SilentlyContinue | Out-Null; "
        "  New-NetFirewallRule -DisplayName \"Shuriken KillSwitch PreSwitch DNS UDP $($x.Name)\" "
        "    -Direction Outbound -Protocol UDP -RemotePort 53 -Action Block "
        "    -Enabled True -Profile Any "
        "    -InterfaceAlias $x.Name -ErrorAction SilentlyContinue | Out-Null; "
        "  New-NetFirewallRule -DisplayName \"Shuriken KillSwitch PreSwitch DNS TCP $($x.Name)\" "
        "    -Direction Outbound -Protocol TCP -RemotePort 53 -Action Block "
        "    -Enabled True -Profile Any "
        "    -InterfaceAlias $x.Name -ErrorAction SilentlyContinue | Out-Null }"
    )

# ── IPv6 helpers ──────────────────────────────────────────────────────────────

def disable_ipv6_on_non_wg_adapters():
    """Block all IPv6 traffic on non-WireGuard adapters via firewall."""
    try:
        _ps(
            "Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.Name -notlike '*WireGuard*' } "
            "| ForEach-Object { "
            "  $name = $_.Name; "
            "  New-NetFirewallRule -DisplayName \"Shuriken Block IPv6 on `$name\" "
            "    -Direction Outbound -Action Block -Protocol Any "
            "    -InterfaceAlias `$name -Profile Any -Enabled True "
            "    -ErrorAction SilentlyContinue | Out-Null; "
            "  New-NetFirewallRule -DisplayName \"Shuriken Block IPv6 on `$name\" "
            "    -Direction Inbound -Action Block -Protocol Any "
            "    -InterfaceAlias `$name -Profile Any -Enabled True "
            "    -ErrorAction SilentlyContinue | Out-Null }"
        )
    except Exception:
        pass

def enable_ipv6_on_non_wg_adapters():
    """Remove all Shuriken IPv6 firewall block rules."""
    try:
        _ps(
            "Get-NetFirewallRule -DisplayName 'Shuriken Block IPv6 on *' "
            "-ErrorAction SilentlyContinue | Remove-NetFirewallRule -Confirm:$false"
        )
    except Exception:
        pass

atexit.register(enable_ipv6_on_non_wg_adapters)

def reset_firewall_if_blocked():
    print(f"[NETWORK] Removing Shuriken Firewall settings due to block at {time.time():.0f}")
    try:
        _ps(
            "Get-NetFirewallRule -DisplayName 'Shuriken*' "
            "-ErrorAction SilentlyContinue | Remove-NetFirewallRule -Confirm:$false"
        )
    except Exception:
        pass

# ── WPAD / system DNS leak suppression ───────────────────────────────────────

def _is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def _get_all_physical_dns_servers() -> list[str]:
    """
    Return all private DNS server IPs on physical interfaces.
    Public DNS (8.8.8.8 etc.) excluded — those route through the VPN correctly.
    """
    servers: list[str] = []
    try:
        code, out, _ = _ps(
            "$dns = @(); "
            "Get-NetAdapter | Where-Object { "
            "  $_.Status -eq 'Up' -and $_.Name -notlike '*WireGuard*' "
            "  -and $_.Name -notlike '*tunnel*' -and $_.Name -notlike '*wg*' "
            "} | ForEach-Object { "
            "  $cfg = Get-DnsClientServerAddress -InterfaceIndex $_.ifIndex "
            "    -AddressFamily IPv4 -ErrorAction SilentlyContinue; "
            "  if ($cfg) { $dns += $cfg.ServerAddresses } "
            "}; $dns | Sort-Object -Unique"
        )
        if code == 0 and out.strip():
            for line in out.strip().splitlines():
                ip = line.strip()
                if ip and ip.count(".") == 3 and _is_private_ip(ip):
                    servers.append(ip)
    except Exception:
        pass
    # Also add default gateway — routers often act as DNS proxy
    try:
        code, out, _ = _ps(
            "(Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway} "
            "| Select-Object -ExpandProperty IPv4DefaultGateway).NextHop"
        )
        if code == 0 and out.strip():
            for line in out.strip().splitlines():
                ip = line.strip()
                if ip and ip.count(".") == 3 and _is_private_ip(ip) and ip not in servers:
                    servers.append(ip)
    except Exception:
        pass
    if DEBUG_MODE:
        print(f"[LEAK] Physical DNS servers to null-route: {servers}")
    return servers

def _add_null_routes(dns_servers: list[str]) -> None:
    """Null-route each private DNS server IP to loopback."""
    si, cf = _make_si()
    for ip in dns_servers:
        if ip in _NULL_ROUTES:
            continue
        try:
            r = subprocess.run(
                ["route", "add", ip, "mask", "255.255.255.255", "127.0.0.1", "metric", "1"],
                capture_output=True, text=True, creationflags=cf
            )
            if r.returncode == 0:
                _NULL_ROUTES.append(ip)
                if DEBUG_MODE:
                    print(f"[LEAK] Null route added for {ip}")
        except Exception as e:
            if DEBUG_MODE:
                print(f"[LEAK] Null route error for {ip}: {e}")

def _remove_null_routes() -> None:
    si, cf = _make_si()
    for ip in list(_NULL_ROUTES):
        try:
            subprocess.run(["route", "delete", ip], capture_output=True, creationflags=cf)
        except Exception:
            pass
    _NULL_ROUTES.clear()

def _add_ip_range_null_routes(ranges: list[str]) -> None:
    """
    Null-route specific IP ranges to loopback.
    Used for Skype/Teams ranges that bypass DNS with cached IPs.
    """
    si, cf = _make_si()
    for cidr in ranges:
        try:
            net = ipaddress.IPv4Network(cidr, strict=False)
            network = str(net.network_address)
            mask = str(net.netmask)
            result = subprocess.run(
                ["route", "add", network, "mask", mask, "127.0.0.1", "metric", "1"],
                capture_output=True, text=True, creationflags=cf
            )
            if result.returncode == 0:
                _NULL_ROUTES.append(network)
                if DEBUG_MODE:
                    print(f"[LEAK] IP range null-route added: {cidr}")
            else:
                if DEBUG_MODE:
                    print(f"[LEAK] IP range null-route failed for {cidr}: {result.stderr.strip()}")
        except Exception as e:
            if DEBUG_MODE:
                print(f"[LEAK] IP range null-route error for {cidr}: {e}")

def _remove_ip_range_null_routes() -> None:
    """Remove IP range null-routes added by _add_ip_range_null_routes."""
    si, cf = _make_si()
    for cidr in _SKYPE_IP_RANGES:
        try:
            net = ipaddress.IPv4Network(cidr, strict=False)
            subprocess.run(
                ["route", "delete", str(net.network_address)],
                capture_output=True, creationflags=cf
            )
        except Exception:
            pass

def add_wpad_block() -> None:
    """
    Multi-layer suppression of Windows system-level and app-level DNS/SNI leaks.

    Layer 1 — DNS server null routes: black-holes all private DNS server IPs.
    Layer 2 — IP range null routes: black-holes Microsoft Skype/Teams IP ranges.
    Layer 3 — Process firewall blocks: blocks Skype/Teams/OneDrive executables.
    Layer 4 — Port firewall blocks: UDP/TCP 53 + NetBIOS 137/138.
    Layer 5 — Disable WinHTTP WPAD service + flush DNS cache.
    """
    remove_wpad_block()

    dns_servers = _get_all_physical_dns_servers()
    if dns_servers:
        _add_null_routes(dns_servers)
    elif DEBUG_MODE:
        print("[LEAK] No private DNS servers detected to null-route")

    _add_ip_range_null_routes(_SKYPE_IP_RANGES)

    aliases = _list_non_wg_adapters()
    cmds, names = [], []

    for app_label, program_path in _PROCESS_BLOCK_APPS:
        for alias in aliases:
            safe_alias = _safe_ps_name(alias)
            rn = f"Shuriken App Block {app_label} on {alias}"
            names.append(rn)
            cmds.append(
                f"$p = [Environment]::ExpandEnvironmentVariables('{program_path}'); "
                f"if (Test-Path $p) {{ "
                f"New-NetFirewallRule -DisplayName '{rn.replace(chr(39), chr(39)*2)}' "
                f"-Direction Outbound -Action Block -Enabled True -Profile Any "
                f"-Program $p -InterfaceAlias '{safe_alias}' "
                f"-ErrorAction SilentlyContinue | Out-Null }}"
            )

    for alias in aliases:
        safe = _safe_ps_name(alias)
        for proto, port in [("UDP", 53), ("TCP", 53), ("UDP", 137), ("UDP", 138)]:
            rn = f"Shuriken WPAD Block {proto} {port} on {alias}"
            names.append(rn)
            cmds.append(
                f"New-NetFirewallRule -DisplayName '{rn.replace(chr(39), chr(39)*2)}' "
                f"-Direction Outbound -Protocol {proto} -RemotePort {port} "
                f"-Action Block -Profile Any -Enabled True "
                f"-InterfaceAlias '{safe}' -ErrorAction SilentlyContinue | Out-Null"
            )

    if cmds:
        _ps_batched(cmds)
        _WPAD_BLOCK_RULES[:] = names

    _ps(
        r"Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc' "
        r"  -Name Start -Value 4 -ErrorAction SilentlyContinue; "
        "Stop-Service -Name WinHttpAutoProxySvc -Force -ErrorAction SilentlyContinue; "
        "Clear-DnsClientCache -ErrorAction SilentlyContinue"
    )

def remove_wpad_block() -> None:
    """Reverse all layers of add_wpad_block."""
    _remove_null_routes()
    _remove_ip_range_null_routes()
    if _WPAD_BLOCK_RULES:
        _ps("; ".join(
            f"Get-NetFirewallRule -DisplayName '{rn.replace(chr(39), chr(39)*2)}' "
            "-ErrorAction SilentlyContinue | Remove-NetFirewallRule -Confirm:$false | Out-Null"
            for rn in _WPAD_BLOCK_RULES
        ))
        _WPAD_BLOCK_RULES.clear()
    else:
        _ps(
            "Get-NetFirewallRule -DisplayName 'Shuriken WPAD Block*' "
            "-ErrorAction SilentlyContinue | "
            "Remove-NetFirewallRule -Confirm:$false | Out-Null"
        )
    _ps(
        r"Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc' "
        r"  -Name Start -Value 3 -ErrorAction SilentlyContinue; "
        "Clear-DnsClientCache -ErrorAction SilentlyContinue"
    )

atexit.register(remove_wpad_block)

# ── Split tunneling ───────────────────────────────────────────────────────────

def apply_split_tunnel(exe_paths: list[str]) -> None:
    """
    Allow a specific list of executables to bypass the VPN kill switch and
    send traffic directly over the physical network interface.

    How it works: the kill switch adds a broad outbound Block rule on every
    physical adapter. Windows Firewall evaluates Allow rules before Block rules
    when both match the same interface and both have the same weight — so adding
    a per-program Allow rule on physical interfaces lets that program's traffic
    pass through while everything else stays blocked and routed via WireGuard.

    Called whenever the connected state changes or the user edits the app list
    while connected.
    """
    remove_split_tunnel()
    if not exe_paths:
        return

    aliases = _list_non_wg_adapters()
    if not aliases:
        if DEBUG_MODE:
            print("[SPLIT] No physical adapters found — nothing to allow")
        return

    cmds, names = [], []
    for exe in exe_paths:
        # Normalise to a plain Windows path string
        exe_path = str(Path(exe))
        label    = Path(exe).stem  # e.g. "chrome" from "chrome.exe"
        for alias in aliases:
            safe  = _safe_ps_name(alias)
            rn    = f"Shuriken SplitTunnel Allow {label} on {alias}"
            names.append(rn)
            safe_rn = rn.replace("'", "''")
            # Outbound Allow for this program on this physical adapter.
            # Because Windows evaluates Allow before Block at the same priority
            # tier, this punches a hole through the kill switch for this exe only.
            cmds.append(
                f"New-NetFirewallRule -DisplayName '{safe_rn}' "
                f"-Direction Outbound -Action Allow -Enabled True -Profile Any "
                f"-Program '{exe_path.replace(chr(39), chr(39)*2)}' "
                f"-InterfaceAlias '{safe}' "
                f"-ErrorAction SilentlyContinue | Out-Null"
            )
            # Also allow inbound replies so the app can actually receive data
            rn_in   = f"Shuriken SplitTunnel Allow {label} In on {alias}"
            names.append(rn_in)
            safe_rn_in = rn_in.replace("'", "''")
            cmds.append(
                f"New-NetFirewallRule -DisplayName '{safe_rn_in}' "
                f"-Direction Inbound -Action Allow -Enabled True -Profile Any "
                f"-Program '{exe_path.replace(chr(39), chr(39)*2)}' "
                f"-InterfaceAlias '{safe}' "
                f"-ErrorAction SilentlyContinue | Out-Null"
            )

    if cmds:
        _ps_batched(cmds)
        _SPLIT_TUNNEL_RULES[:] = names
        if DEBUG_MODE:
            print(f"[SPLIT] Applied {len(exe_paths)} app(s), {len(names)} rules")

def remove_split_tunnel() -> None:
    """Remove all Shuriken split tunnel firewall rules."""
    if _SPLIT_TUNNEL_RULES:
        _ps("; ".join(
            f"Get-NetFirewallRule -DisplayName '{rn.replace(chr(39), chr(39)*2)}' "
            "-ErrorAction SilentlyContinue | Remove-NetFirewallRule -Confirm:$false | Out-Null"
            for rn in _SPLIT_TUNNEL_RULES
        ))
        _SPLIT_TUNNEL_RULES.clear()
        if DEBUG_MODE:
            print("[SPLIT] Rules removed")
    else:
        # Wildcard fallback for any rules left by a previous session
        _ps(
            "Get-NetFirewallRule -DisplayName 'Shuriken SplitTunnel*' "
            "-ErrorAction SilentlyContinue | Remove-NetFirewallRule -Confirm:$false | Out-Null"
        )

atexit.register(remove_split_tunnel)
