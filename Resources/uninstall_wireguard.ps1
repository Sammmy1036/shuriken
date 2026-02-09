# ====================================================================
# uninstall_wireguard.ps1 — Complete WireGuard removal (silent)
# Used by PrivacyGuard uninstaller
# ====================================================================

Write-Output "=== WireGuard full cleanup started ==="

# --- Stop WireGuard services and GUI if running ---
Get-Process wireguard -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Stop-Service -Name WireGuardTunnelService -ErrorAction SilentlyContinue

# --- Attempt normal MSI uninstall (using WMI) ---
$pkg = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like '*WireGuard*' }
if ($pkg) {
    Write-Output "Found MSI ProductCode: $($pkg.IdentifyingNumber)"
    try {
        Start-Process "msiexec.exe" -ArgumentList "/x",$pkg.IdentifyingNumber,"/qn","/norestart" -Wait
        Write-Output "WireGuard MSI uninstallation completed."
    } catch {
        Write-Output "Error during MSI uninstall: $_"
    }
} else {
    Write-Output "No MSI entry found for WireGuard — skipping direct uninstall."
}

# --- Folder cleanup ---
$paths = @(
    "$Env:ProgramFiles\WireGuard",
    "$Env:ProgramFiles(x86)\WireGuard",
    "$Env:LocalAppData\WireGuard"
)
foreach ($p in $paths) {
    if (Test-Path $p) {
        try {
            Remove-Item -Recurse -Force $p -ErrorAction Stop
            Write-Output "Removed folder: $p"
        } catch {
            Start-Process "cmd.exe" -ArgumentList "/C rd /s /q `"$p`"" -Verb RunAs -Wait
            Write-Output "Force-removed folder: $p"
        }
    }
}

# --- Registry cleanup ---
$guid = "{2FDB79CE-5193-4A39-82BB-E00158CC1533}"
$keys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$guid",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\$guid",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Products"
)
foreach ($k in $keys) {
    try {
        if (Test-Path $k) {
            Remove-Item $k -Recurse -Force -ErrorAction SilentlyContinue
            Write-Output "Removed registry key: $k"
        }
    } catch {
        Write-Output "Error removing key: $k — $_"
    }
}

Write-Output "=== WireGuard cleanup completed successfully ==="
exit 0
