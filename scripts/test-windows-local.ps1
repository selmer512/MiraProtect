param(
    [int]$Port = 18081,
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$TestRoot = Join-Path $RepoRoot ".mira-test-windows"
$BuildRoot = Join-Path $RepoRoot ".build\windows"
$VenvScripts = Join-Path $BuildRoot "venv\Scripts"
$AgentExe = Join-Path $RepoRoot "dist\windows\MiraProtectAgent.exe"
$ServerExe = Join-Path $VenvScripts "mira-protect-server.exe"
$CliExe = Join-Path $VenvScripts "mira-protect.exe"
$ControlPlaneUrl = "http://127.0.0.1:$Port"
$Token = "mira-windows-local-test-token-change-me"
$ReportPath = Join-Path $TestRoot "validation-report.json"

$serverProcess = $null
$agentProcess = $null
$targetProcess = $null

function Stop-TestProcess {
    param($Process)
    if ($null -ne $Process) {
        try {
            if (-not $Process.HasExited) {
                Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
            }
        }
        catch {}
    }
}

function Wait-ForCondition {
    param(
        [scriptblock]$Condition,
        [int]$Attempts = 60,
        [int]$DelayMilliseconds = 250,
        [string]$FailureMessage = "Condition did not become true."
    )

    for ($i = 0; $i -lt $Attempts; $i++) {
        if (& $Condition) {
            return
        }
        Start-Sleep -Milliseconds $DelayMilliseconds
    }
    throw $FailureMessage
}

if (-not $SkipBuild) {
    Write-Host "Building and validating the Windows endpoint..." -ForegroundColor Cyan
    & (Join-Path $RepoRoot "scripts\build-windows-agent.ps1")
    if ($LASTEXITCODE -ne 0) {
        throw "Windows build failed with exit code $LASTEXITCODE."
    }
}

foreach ($required in @($AgentExe, $ServerExe, $CliExe)) {
    if (-not (Test-Path $required)) {
        throw "Required test component was not found: $required"
    }
}

Remove-Item $TestRoot -Recurse -Force -ErrorAction SilentlyContinue
New-Item -Path $TestRoot -ItemType Directory -Force | Out-Null

$dbPath = (Join-Path $TestRoot "mira.db").Replace("\", "/")
$serverOut = Join-Path $TestRoot "server.out.log"
$serverErr = Join-Path $TestRoot "server.err.log"
$agentOut = Join-Path $TestRoot "agent.out.log"
$agentErr = Join-Path $TestRoot "agent.err.log"
$targetOut = Join-Path $TestRoot "target.out.log"
$targetErr = Join-Path $TestRoot "target.err.log"

$previous = @{
    MIRA_DATABASE_URL = $env:MIRA_DATABASE_URL
    MIRA_CONTROL_PLANE_URL = $env:MIRA_CONTROL_PLANE_URL
    MIRA_ENDPOINT_TOKEN = $env:MIRA_ENDPOINT_TOKEN
    MIRA_AGENT_TOKEN = $env:MIRA_AGENT_TOKEN
    MIRA_AGENT_MODE = $env:MIRA_AGENT_MODE
    MIRA_POLL_SECONDS = $env:MIRA_POLL_SECONDS
    MIRA_HEARTBEAT_SECONDS = $env:MIRA_HEARTBEAT_SECONDS
    MIRA_REQUEST_TIMEOUT_SECONDS = $env:MIRA_REQUEST_TIMEOUT_SECONDS
    MIRA_FAIL_CLOSED = $env:MIRA_FAIL_CLOSED
    MIRA_ENABLE_TEST_CONTROLS = $env:MIRA_ENABLE_TEST_CONTROLS
}

try {
    $env:MIRA_DATABASE_URL = "sqlite+pysqlite:///$dbPath"
    $env:MIRA_CONTROL_PLANE_URL = $ControlPlaneUrl
    $env:MIRA_ENDPOINT_TOKEN = $Token
    $env:MIRA_AGENT_TOKEN = $Token
    $env:MIRA_AGENT_MODE = "enforce"
    $env:MIRA_POLL_SECONDS = "0.35"
    $env:MIRA_HEARTBEAT_SECONDS = "1"
    $env:MIRA_REQUEST_TIMEOUT_SECONDS = "2"
    $env:MIRA_FAIL_CLOSED = "false"
    $env:MIRA_ENABLE_TEST_CONTROLS = "true"

    Write-Host "Starting loopback Mira Protect control plane..." -ForegroundColor Cyan
    $serverProcess = Start-Process `
        -FilePath $ServerExe `
        -ArgumentList @("--host", "127.0.0.1", "--port", "$Port", "--log-level", "warning") `
        -RedirectStandardOutput $serverOut `
        -RedirectStandardError $serverErr `
        -PassThru `
        -WindowStyle Hidden

    Wait-ForCondition -Attempts 80 -FailureMessage "Control plane did not become healthy." -Condition {
        if ($serverProcess.HasExited) {
            return $false
        }
        try {
            $health = Invoke-RestMethod -Method Get -Uri "$ControlPlaneUrl/health" -TimeoutSec 1
            return $health.status -eq "ok" -and $health.database -eq "ok"
        }
        catch {
            return $false
        }
    }
    Write-Host "[PASS] Control plane is healthy" -ForegroundColor Green

    Write-Host "Starting built Windows endpoint agent in enforce mode..." -ForegroundColor Cyan
    $agentProcess = Start-Process `
        -FilePath $AgentExe `
        -RedirectStandardOutput $agentOut `
        -RedirectStandardError $agentErr `
        -PassThru `
        -WindowStyle Hidden

    $headers = @{ Authorization = "Bearer $Token" }
    Wait-ForCondition -Attempts 60 -FailureMessage "Endpoint agent did not register a heartbeat." -Condition {
        if ($agentProcess.HasExited) {
            return $false
        }
        try {
            $summary = Invoke-RestMethod -Method Get -Uri "$ControlPlaneUrl/api/v1/dashboard/summary" -Headers $headers -TimeoutSec 1
            return [int]$summary.managed_devices -ge 1
        }
        catch {
            return $false
        }
    }
    Write-Host "[PASS] Windows endpoint heartbeat registered" -ForegroundColor Green

    Write-Host "Launching harmless synthetic protection target..." -ForegroundColor Cyan
    $targetProcess = Start-Process `
        -FilePath $CliExe `
        -ArgumentList @("synthetic-target", "--seconds", "90", "--mira-protect-test-block") `
        -RedirectStandardOutput $targetOut `
        -RedirectStandardError $targetErr `
        -PassThru `
        -WindowStyle Hidden

    Wait-ForCondition -Attempts 80 -FailureMessage "Built endpoint agent did not terminate the synthetic target." -Condition {
        if (Test-Path $agentOut) {
            $text = Get-Content $agentOut -Raw -ErrorAction SilentlyContinue
            if ($text -match '"event":\s*"process_terminated"') {
                return $true
            }
        }
        return $false
    }
    Write-Host "[PASS] Enforce mode terminated the synthetic target" -ForegroundColor Green

    Wait-ForCondition -Attempts 40 -FailureMessage "Endpoint agent did not report enforcement to the control plane." -Condition {
        if (Test-Path $agentOut) {
            $text = Get-Content $agentOut -Raw -ErrorAction SilentlyContinue
            if ($text -match '"event":\s*"enforcement_reported"') {
                return $true
            }
        }
        return $false
    }
    Write-Host "[PASS] Endpoint enforcement was acknowledged" -ForegroundColor Green

    $summary = Invoke-RestMethod -Method Get -Uri "$ControlPlaneUrl/api/v1/dashboard/summary" -Headers $headers
    $events = Invoke-RestMethod -Method Get -Uri "$ControlPlaneUrl/api/v1/events?limit=100" -Headers $headers

    if ([int]$summary.blocked_events -lt 1) {
        throw "Control plane did not persist a blocked event."
    }
    if ([int]$summary.enforcement_actions -lt 1) {
        throw "Control plane did not persist a successful enforcement action."
    }

    $matchedPolicy = $false
    $matchedEnforcement = $false
    foreach ($event in @($events)) {
        if (@($event.security.detections) -contains "endpoint-synthetic-protection-test") {
            $matchedPolicy = $true
        }
        if ($event.event_type -eq "endpoint.enforcement" -and $event.metadata.result -eq "succeeded") {
            $matchedEnforcement = $true
        }
    }
    if (-not $matchedPolicy) {
        throw "Persisted events did not contain the synthetic endpoint protection rule."
    }
    if (-not $matchedEnforcement) {
        throw "Persisted events did not contain a successful enforcement confirmation."
    }
    Write-Host "[PASS] Policy and enforcement evidence were persisted" -ForegroundColor Green

    $buildInfoPath = Join-Path $RepoRoot "dist\windows\BUILD-INFO.json"
    $buildInfo = $null
    if (Test-Path $buildInfoPath) {
        $buildInfo = Get-Content $buildInfoPath -Raw | ConvertFrom-Json
    }

    $report = [ordered]@{
        status = "pass"
        timestamp_utc = [DateTime]::UtcNow.ToString("o")
        test = "windows-local-endpoint-protection"
        platform = [Environment]::OSVersion.VersionString
        computer_name = $env:COMPUTERNAME
        control_plane = $ControlPlaneUrl
        mode = "enforce"
        test_controls_enabled = $true
        agent_executable = $AgentExe
        agent_sha256 = (Get-FileHash -Path $AgentExe -Algorithm SHA256).Hash.ToLowerInvariant()
        build = $buildInfo
        checks = @(
            "Windows source validation",
            "PyInstaller endpoint build",
            "control-plane database health",
            "Windows endpoint heartbeat",
            "synthetic process discovery",
            "central block policy",
            "endpoint process termination",
            "enforcement acknowledgement",
            "persistence verification"
        )
        summary = $summary
    }
    $report | ConvertTo-Json -Depth 8 | Set-Content -Path $ReportPath -Encoding UTF8

    Write-Host ""
    Write-Host "[PASS] Mira Protect Windows first-build test completed." -ForegroundColor Green
    Write-Host "Validation report: $ReportPath"
    Write-Host "Agent log:        $agentOut"
    Write-Host "Server log:       $serverOut"
    Write-Host "Build package:    $(Join-Path $RepoRoot "dist\windows\MiraProtect-Windows-Test.zip")"
}
finally {
    Stop-TestProcess $targetProcess
    Stop-TestProcess $agentProcess
    Stop-TestProcess $serverProcess

    $env:MIRA_DATABASE_URL = $previous.MIRA_DATABASE_URL
    $env:MIRA_CONTROL_PLANE_URL = $previous.MIRA_CONTROL_PLANE_URL
    $env:MIRA_ENDPOINT_TOKEN = $previous.MIRA_ENDPOINT_TOKEN
    $env:MIRA_AGENT_TOKEN = $previous.MIRA_AGENT_TOKEN
    $env:MIRA_AGENT_MODE = $previous.MIRA_AGENT_MODE
    $env:MIRA_POLL_SECONDS = $previous.MIRA_POLL_SECONDS
    $env:MIRA_HEARTBEAT_SECONDS = $previous.MIRA_HEARTBEAT_SECONDS
    $env:MIRA_REQUEST_TIMEOUT_SECONDS = $previous.MIRA_REQUEST_TIMEOUT_SECONDS
    $env:MIRA_FAIL_CLOSED = $previous.MIRA_FAIL_CLOSED
    $env:MIRA_ENABLE_TEST_CONTROLS = $previous.MIRA_ENABLE_TEST_CONTROLS
}
