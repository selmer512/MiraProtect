param(
    [string]$InstallDir = "$env:ProgramData\MiraProtect",
    [int]$WaitSeconds = 10
)

$ErrorActionPreference = "Stop"
$TaskName = "Mira Protect Endpoint Agent"
$Marker = "--mira-protect-test-block"
$ConfigPath = Join-Path $InstallDir "agent-config.json"

if (-not (Test-Path $ConfigPath)) {
    throw "Mira Protect agent configuration was not found at $ConfigPath. Install the agent first."
}

$config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
$ControlPlaneUrl = $config.control_plane_url.TrimEnd('/')
$Mode = $config.mode
$Token = [Environment]::GetEnvironmentVariable("MIRA_AGENT_TOKEN", "Machine")
$headers = @{}
if ($Token) {
    $headers["Authorization"] = "Bearer $Token"
}

Write-Host "Mira Protect enterprise endpoint protection test" -ForegroundColor Cyan
Write-Host "Control plane: $ControlPlaneUrl"
Write-Host "Agent mode:    $Mode"

$health = Invoke-RestMethod -Method Get -Uri "$ControlPlaneUrl/health" -Headers $headers
if ($health.status -ne "ok") {
    throw "Control plane health check failed."
}
Write-Host "[PASS] Control plane is healthy" -ForegroundColor Green

$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if (-not $task) {
    throw "Scheduled task '$TaskName' was not found."
}
if ($task.State -ne "Running") {
    Start-ScheduledTask -TaskName $TaskName
    Start-Sleep -Seconds 2
}
Write-Host "[PASS] Endpoint agent scheduled task is present" -ForegroundColor Green

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
Write-Host "Enterprise endpoint protection test completed successfully." -ForegroundColor Green
