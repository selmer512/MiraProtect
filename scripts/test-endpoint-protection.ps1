param(
    [string]$InstallDir = "$env:ProgramData\MiraProtect",
    [int]$WaitSeconds = 10,
    [switch]$SyntheticEnforcement
)

$ErrorActionPreference = "Stop"
$TaskName = "Mira Protect Endpoint Agent"
$Marker = "--mira-protect-test-block"
$ConfigPath = Join-Path $InstallDir "agent-config.json"

if (-not (Test-Path $ConfigPath)) {
    throw "Mira Protect agent configuration was not found at $ConfigPath. Install the agent first."
}

$config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
$ControlPlaneUrl = $config.control_plane_url.TrimEnd("/")
$Mode = $config.mode
$Token = [Environment]::GetEnvironmentVariable("MIRA_AGENT_TOKEN", "Machine")
$headers = @{}
if ($Token) {
    $headers["Authorization"] = "Bearer $Token"
}

Write-Host "Mira Protect managed Windows endpoint test" -ForegroundColor Cyan
Write-Host "Control plane: $ControlPlaneUrl"
Write-Host "Agent mode:    $Mode"

$health = Invoke-RestMethod -Method Get -Uri "$ControlPlaneUrl/health" -Headers $headers
if ($health.status -ne "ok") {
    throw "Control plane health check failed."
}
Write-Host "[PASS] Control plane is healthy" -ForegroundColor Green

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if (-not $task) {
    throw "Scheduled task $TaskName was not found."
}
if ($task.State -ne "Running") {
    Start-ScheduledTask -TaskName $TaskName
    Start-Sleep -Seconds 2
}
Write-Host "[PASS] Endpoint agent scheduled task is present" -ForegroundColor Green

$LogPath = Join-Path $InstallDir "logs\agent.log"
$heartbeatSeen = $false
for ($i = 0; $i -lt 20; $i++) {
    if (Test-Path $LogPath) {
        $logText = Get-Content $LogPath -Raw -ErrorAction SilentlyContinue
        if ($logText -match '"event":\s*"heartbeat_sent"') {
            $heartbeatSeen = $true
            break
        }
    }
    Start-Sleep -Milliseconds 500
}
if (-not $heartbeatSeen) {
    throw "No successful endpoint heartbeat was found in $LogPath."
}
Write-Host "[PASS] Endpoint heartbeat is reaching the control plane" -ForegroundColor Green

if (-not $SyntheticEnforcement) {
    Write-Host ""
    Write-Host "[PASS] Managed Windows endpoint connectivity test completed." -ForegroundColor Green
    Write-Host "Synthetic enforcement was not requested. This is the recommended validation for normal monitor-mode installations."
    return
}

if (-not [bool]$config.enable_test_controls) {
    throw "Synthetic enforcement is disabled in agent-config.json. Use the isolated local Windows harness for the first enforcement test, or explicitly enable test controls in a dedicated test environment."
}

$preflight = @{
    device_id = "managed-windows-preflight"
    hostname = $env:COMPUTERNAME
    username = "$env:USERDOMAIN\$env:USERNAME"
    pid = 0
    process_name = "mira-protect-synthetic-preflight"
    command_line = @("mira-protect-synthetic-preflight", $Marker)
    mode = "monitor"
    matched_local_rules = @("local:test-block")
} | ConvertTo-Json -Depth 5

$preflightResult = Invoke-RestMethod `
    -Method Post `
    -Uri "$ControlPlaneUrl/api/v1/endpoint/process/evaluate" `
    -Headers $headers `
    -ContentType "application/json" `
    -Body $preflight

if ($preflightResult.decision -ne "block" -or @($preflightResult.matched_rules) -notcontains "endpoint-synthetic-protection-test") {
    throw "The control plane does not have explicit synthetic test controls enabled. Do not enable them on a normal shared control plane; use scripts\test-windows-local.ps1 for the isolated enforcement test."
}
Write-Host "[PASS] Control plane synthetic test policy is explicitly enabled" -ForegroundColor Green

$notepad = Join-Path $env:SystemRoot "System32\notepad.exe"
if (-not (Test-Path $notepad)) {
    throw "The safe test target notepad.exe was not found."
}

Write-Host "Launching a benign Notepad process with the Mira Protect synthetic block marker..."
$process = Start-Process -FilePath $notepad -ArgumentList $Marker -PassThru
$pidUnderTest = $process.Id
Write-Host "Test PID: $pidUnderTest"

Start-Sleep -Seconds $WaitSeconds
$stillRunning = $null -ne (Get-Process -Id $pidUnderTest -ErrorAction SilentlyContinue)

if ($Mode -eq "enforce") {
    if ($stillRunning) {
        Stop-Process -Id $pidUnderTest -Force -ErrorAction SilentlyContinue
        throw "Protection test failed: the synthetic blocked process was still running in enforce mode."
    }
    Write-Host "[PASS] Enforce mode terminated the synthetic blocked process" -ForegroundColor Green
}
else {
    if (-not $stillRunning) {
        throw "Protection test failed: $Mode mode unexpectedly terminated the process."
    }
    Stop-Process -Id $pidUnderTest -Force -ErrorAction SilentlyContinue
    Write-Host "[PASS] $Mode mode observed the policy violation without endpoint termination" -ForegroundColor Green
}

Start-Sleep -Seconds 1
$events = Invoke-RestMethod -Method Get -Uri "$ControlPlaneUrl/api/v1/events?limit=200" -Headers $headers
$event = $events | Where-Object {
    $_.metadata.pid -eq $pidUnderTest -and
    $_.security.detections -contains "endpoint-synthetic-protection-test"
} | Select-Object -First 1

if (-not $event) {
    throw "Protection test failed: control plane did not retain the endpoint policy event for PID $pidUnderTest."
}

Write-Host "[PASS] Control plane retained the policy decision and endpoint evidence" -ForegroundColor Green
Write-Host "Event ID: $($event.event_id)"
Write-Host "Decision: $($event.security.policy_decision)"
Write-Host "Detections: $($event.security.detections -join ', ')"
Write-Host ""
Write-Host "[PASS] Managed Windows synthetic enforcement test completed." -ForegroundColor Green
