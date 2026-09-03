param(
    [string]$InstallDir = "$env:ProgramData\MiraProtect",
    [switch]$PreserveLogs
)

$ErrorActionPreference = "Stop"
$TaskName = "Mira Protect Endpoint Agent"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this uninstaller from an elevated PowerShell session."
}

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

[Environment]::SetEnvironmentVariable("MIRA_AGENT_CONFIG", $null, "Machine")
[Environment]::SetEnvironmentVariable("MIRA_AGENT_TOKEN", $null, "Machine")

if (Test-Path $InstallDir) {
    if ($PreserveLogs) {
        Get-ChildItem -Path $InstallDir -Force | Where-Object { $_.Name -ne "logs" } | Remove-Item -Recurse -Force
    }
    else {
        Remove-Item -Path $InstallDir -Recurse -Force
    }
}

Write-Host "Mira Protect endpoint agent removed." -ForegroundColor Green
