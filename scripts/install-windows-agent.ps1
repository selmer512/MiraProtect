param(
    [Parameter(Mandatory = $true)]
    [string]$ControlPlaneUrl,

    [ValidateSet("monitor", "guard", "enforce")]
    [string]$Mode = "monitor",

    [string]$Token = "",

    [string]$InstallDir = "$env:ProgramData\MiraProtect",

    [string]$AgentBinary = "",

    [string]$RepoRoot = ""
)

$ErrorActionPreference = "Stop"
$TaskName = "Mira Protect Endpoint Agent"

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this installer from an elevated PowerShell session."
    }
}

function Resolve-AgentExecutable {
    param([string]$RequestedBinary, [string]$Root)

    if ($RequestedBinary) {
        $resolved = (Resolve-Path $RequestedBinary).Path
        return $resolved
    }

    $scriptDir = Split-Path -Parent $MyInvocation.ScriptName
    $bundled = Join-Path $scriptDir "MiraProtectAgent.exe"
    if (Test-Path $bundled) {
        return (Resolve-Path $bundled).Path
    }

    if (-not $Root) {
        $Root = (Resolve-Path (Join-Path $scriptDir "..")).Path
    }

    $python = Get-Command python -ErrorAction SilentlyContinue
    if (-not $python) {
        throw "MiraProtectAgent.exe was not supplied and Python was not found. Use the Windows endpoint artifact from GitHub Actions or provide Python 3.12+."
    }

    $venv = Join-Path $InstallDir "venv"
    & $python.Source -m venv $venv
    $venvPython = Join-Path $venv "Scripts\python.exe"
    & $venvPython -m pip install --upgrade pip
    & $venvPython -m pip install $Root
    return (Join-Path $venv "Scripts\mira-protect-agent.exe")
}

Assert-Administrator

New-Item -Path $InstallDir -ItemType Directory -Force | Out-Null
$LogDir = Join-Path $InstallDir "logs"
New-Item -Path $LogDir -ItemType Directory -Force | Out-Null

$SourceExecutable = Resolve-AgentExecutable -RequestedBinary $AgentBinary -Root $RepoRoot
$InstalledExecutable = Join-Path $InstallDir "MiraProtectAgent.exe"

if ($SourceExecutable -ne $InstalledExecutable) {
    Copy-Item -Path $SourceExecutable -Destination $InstalledExecutable -Force
}

$ConfigPath = Join-Path $InstallDir "agent-config.json"
$config = @{
    control_plane_url = $ControlPlaneUrl.TrimEnd('/')
    mode = $Mode
    poll_seconds = 2.0
    heartbeat_seconds = 60.0
    request_timeout_seconds = 5.0
    fail_closed = $false
    hash_executables = $true
    max_hash_bytes = 104857600
}
$config | ConvertTo-Json -Depth 5 | Set-Content -Path $ConfigPath -Encoding UTF8

[Environment]::SetEnvironmentVariable("MIRA_AGENT_CONFIG", $ConfigPath, "Machine")
if ($Token) {
    [Environment]::SetEnvironmentVariable("MIRA_AGENT_TOKEN", $Token, "Machine")
}

$RunnerPath = Join-Path $InstallDir "run-agent.ps1"
$LogPath = Join-Path $LogDir "agent.log"
$runner = @"
`$ErrorActionPreference = "Continue"
`$env:MIRA_AGENT_CONFIG = "$ConfigPath"
`$machineToken = [Environment]::GetEnvironmentVariable("MIRA_AGENT_TOKEN", "Machine")
if (`$machineToken) { `$env:MIRA_AGENT_TOKEN = `$machineToken }
if (Test-Path "$LogPath") {
    `$item = Get-Item "$LogPath"
    if (`$item.Length -gt 20971520) {
        Move-Item "$LogPath" "$LogPath.1" -Force
    }
}
& "$InstalledExecutable" *>> "$LogPath"
"@
$runner | Set-Content -Path $RunnerPath -Encoding UTF8

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

$action = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$RunnerPath`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount 5 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal `
    -Description "Mira Protect managed endpoint AI telemetry and process enforcement agent" | Out-Null

Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 2

$task = Get-ScheduledTask -TaskName $TaskName
Write-Host "Mira Protect endpoint agent installed." -ForegroundColor Green
Write-Host "Mode:          $Mode"
Write-Host "Control plane: $ControlPlaneUrl"
Write-Host "Install path:  $InstallDir"
Write-Host "Task state:    $($task.State)"
Write-Host "Agent log:     $LogPath"
Write-Host ""
Write-Host "Recommended rollout: monitor -> guard -> enforce after validating detections and allow/deny policy."
