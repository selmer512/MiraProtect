param(
    [int]$Port = 18083,
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BuildRoot = Join-Path $RepoRoot ".build\windows"
$ServerExe = Join-Path $BuildRoot "venv\Scripts\mira-protect-server.exe"
$TestRoot = Join-Path $RepoRoot ".mira-test-control-plane-security"
$ControlPlaneUrl = "http://127.0.0.1:$Port"
$AdminToken = "mira-security-test-admin-token"
$EnrollmentToken = "mira-security-test-enrollment-token"
$TokenPepper = "mira-security-test-token-pepper"
$ReportPath = Join-Path $TestRoot "validation-report.json"
$serverProcess = $null

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
        if (& $Condition) { return }
        Start-Sleep -Milliseconds $DelayMilliseconds
    }
    throw $FailureMessage
}

function Get-RequestStatus {
    param(
        [string]$Method,
        [string]$Uri,
        [hashtable]$Headers = @{},
        [string]$Body = ""
    )
    try {
        $params = @{
            Method = $Method
            Uri = $Uri
            Headers = $Headers
            UseBasicParsing = $true
        }
        if ($Body) {
            $params["Body"] = $Body
            $params["ContentType"] = "application/json"
        }
        $response = Invoke-WebRequest @params
        return [int]$response.StatusCode
    }
    catch {
        if ($_.Exception.Response) {
            return [int]$_.Exception.Response.StatusCode
        }
        throw
    }
}

if (-not $SkipBuild) {
    Write-Host "Building and validating Mira Protect 0.4..." -ForegroundColor Cyan
    & (Join-Path $RepoRoot "scripts\build-windows-agent.ps1")
    if ($LASTEXITCODE -ne 0) {
        throw "Windows build failed with exit code $LASTEXITCODE."
    }
}

if (-not (Test-Path $ServerExe)) {
    throw "Security test server executable was not found: $ServerExe"
}

Remove-Item $TestRoot -Recurse -Force -ErrorAction SilentlyContinue
New-Item -Path $TestRoot -ItemType Directory -Force | Out-Null
$dbPath = (Join-Path $TestRoot "mira.db").Replace("\", "/")
$rejectOut = Join-Path $TestRoot "remote-http-reject.out.log"
$rejectErr = Join-Path $TestRoot "remote-http-reject.err.log"
$serverOut = Join-Path $TestRoot "server.out.log"
$serverErr = Join-Path $TestRoot "server.err.log"

$previous = @{
    MIRA_DATABASE_URL = $env:MIRA_DATABASE_URL
    MIRA_SECURITY_PROFILE = $env:MIRA_SECURITY_PROFILE
    MIRA_ADMIN_TOKEN = $env:MIRA_ADMIN_TOKEN
    MIRA_ENROLLMENT_TOKEN = $env:MIRA_ENROLLMENT_TOKEN
    MIRA_TOKEN_PEPPER = $env:MIRA_TOKEN_PEPPER
    MIRA_ENDPOINT_TOKEN = $env:MIRA_ENDPOINT_TOKEN
    MIRA_ALLOW_SHARED_ENDPOINT_TOKEN = $env:MIRA_ALLOW_SHARED_ENDPOINT_TOKEN
    MIRA_TLS_TERMINATED_UPSTREAM = $env:MIRA_TLS_TERMINATED_UPSTREAM
    MIRA_ALLOW_INSECURE_REMOTE = $env:MIRA_ALLOW_INSECURE_REMOTE
    MIRA_EFFECTIVE_TLS = $env:MIRA_EFFECTIVE_TLS
    MIRA_BIND_HOST = $env:MIRA_BIND_HOST
}

try {
    $env:MIRA_DATABASE_URL = "sqlite+pysqlite:///$dbPath"
    $env:MIRA_SECURITY_PROFILE = "development"
    $env:MIRA_ADMIN_TOKEN = $AdminToken
    $env:MIRA_ENROLLMENT_TOKEN = $EnrollmentToken
    $env:MIRA_TOKEN_PEPPER = $TokenPepper
    $env:MIRA_ENDPOINT_TOKEN = ""
    $env:MIRA_ALLOW_SHARED_ENDPOINT_TOKEN = "false"
    $env:MIRA_TLS_TERMINATED_UPSTREAM = "false"
    $env:MIRA_ALLOW_INSECURE_REMOTE = "false"
    $env:MIRA_EFFECTIVE_TLS = "false"

    Write-Host "Verifying insecure remote development bind is rejected..." -ForegroundColor Cyan
    $reject = Start-Process -FilePath $ServerExe -ArgumentList @(
        "--host", "0.0.0.0",
        "--port", "$Port",
        "--log-level", "warning"
    ) -RedirectStandardOutput $rejectOut -RedirectStandardError $rejectErr -PassThru -WindowStyle Hidden
    Wait-ForCondition -Attempts 20 -FailureMessage "Insecure remote control plane did not exit as required." -Condition {
        $reject.Refresh()
        return $reject.HasExited
    }
    $rejectText = ""
    if (Test-Path $rejectErr) { $rejectText += Get-Content $rejectErr -Raw }
    if (Test-Path $rejectOut) { $rejectText += Get-Content $rejectOut -Raw }
    if ($rejectText -notmatch "tls_configured") {
        throw "Remote HTTP rejection did not identify the missing TLS requirement."
    }
    Write-Host "[PASS] Development profile rejects insecure remote control-plane binding" -ForegroundColor Green

    $env:MIRA_TLS_TERMINATED_UPSTREAM = "true"
    Write-Host "Starting authenticated development control plane..." -ForegroundColor Cyan
    $serverProcess = Start-Process -FilePath $ServerExe -ArgumentList @(
        "--host", "127.0.0.1",
        "--port", "$Port",
        "--log-level", "warning"
    ) -RedirectStandardOutput $serverOut -RedirectStandardError $serverErr -PassThru -WindowStyle Hidden

    Wait-ForCondition -Attempts 80 -FailureMessage "Security-profile control plane did not become ready." -Condition {
        if ($serverProcess.HasExited) { return $false }
        try {
            $ready = Invoke-RestMethod -Method Get -Uri "$ControlPlaneUrl/ready" -TimeoutSec 1
            return $ready.status -eq "ready" -and $ready.security.profile -eq "development"
        }
        catch { return $false }
    }
    Write-Host "[PASS] Development security profile reports ready" -ForegroundColor Green

    $status = Get-RequestStatus -Method Get -Uri "$ControlPlaneUrl/api/v1/assets"
    if ($status -ne 401) { throw "Administrative API accepted an unauthenticated request: HTTP $status" }
    Write-Host "[PASS] Administrative API rejects unauthenticated requests" -ForegroundColor Green

    $status = Get-RequestStatus -Method Get -Uri "$ControlPlaneUrl/api/v1/assets" -Headers @{ Authorization = "Bearer $EnrollmentToken" }
    if ($status -ne 401) { throw "Enrollment credential was accepted as an admin credential: HTTP $status" }
    Write-Host "[PASS] Enrollment credential cannot access administrative APIs" -ForegroundColor Green

    $adminHeaders = @{ Authorization = "Bearer $AdminToken" }
    $assets = Invoke-RestMethod -Method Get -Uri "$ControlPlaneUrl/api/v1/assets" -Headers $adminHeaders
    if ($null -eq $assets) { $assets = @() }
    Write-Host "[PASS] Administrative credential can access protected APIs" -ForegroundColor Green

    $deviceId = "security-milestone-device"
    $enrollmentBody = @{
        device_id = $deviceId
        hostname = "SECURITY-MILESTONE-DEVICE"
        platform = "Windows"
        agent_version = "0.4.0"
    } | ConvertTo-Json -Depth 4
    $enrollment = Invoke-RestMethod -Method Post -Uri "$ControlPlaneUrl/api/v1/endpoint/enroll" -Headers @{ Authorization = "Bearer $EnrollmentToken" } -ContentType "application/json" -Body $enrollmentBody
    $deviceToken = [string]$enrollment.device_token
    if (-not $deviceToken) { throw "Endpoint enrollment did not return a device credential." }
    Write-Host "[PASS] Endpoint enrollment issued a device-scoped credential" -ForegroundColor Green

    $heartbeatBody = @{
        device_id = $deviceId
        hostname = "SECURITY-MILESTONE-DEVICE"
        platform = "Windows"
        mode = "monitor"
        agent_version = "0.4.0"
    } | ConvertTo-Json -Depth 4
    $deviceHeaders = @{ Authorization = "Bearer $deviceToken" }
    $heartbeatStatus = Get-RequestStatus -Method Post -Uri "$ControlPlaneUrl/api/v1/endpoint/heartbeat" -Headers $deviceHeaders -Body $heartbeatBody
    if ($heartbeatStatus -ne 200) { throw "Device credential heartbeat failed: HTTP $heartbeatStatus" }
    Write-Host "[PASS] Device credential is accepted for its endpoint API" -ForegroundColor Green

    $revocation = Invoke-RestMethod -Method Post -Uri "$ControlPlaneUrl/api/v1/endpoint/revoke/$deviceId" -Headers $adminHeaders
    if (-not $revocation.revoked) { throw "Endpoint credential revocation was not acknowledged." }
    $postRevokeStatus = Get-RequestStatus -Method Post -Uri "$ControlPlaneUrl/api/v1/endpoint/heartbeat" -Headers $deviceHeaders -Body $heartbeatBody
    if ($postRevokeStatus -ne 401) { throw "Revoked device credential remained usable: HTTP $postRevokeStatus" }
    Write-Host "[PASS] Revoked device credential is rejected" -ForegroundColor Green

    $events = Invoke-RestMethod -Method Get -Uri "$ControlPlaneUrl/api/v1/events?limit=100" -Headers $adminHeaders
    $revocationEvent = @($events) | Where-Object {
        $_.event_type -eq "endpoint.credential_revoked" -and $_.metadata.device_id -eq $deviceId
    } | Select-Object -First 1
    if (-not $revocationEvent) { throw "Credential revocation audit event was not persisted." }
    Write-Host "[PASS] Credential revocation audit evidence was persisted" -ForegroundColor Green

    $report = [ordered]@{
        status = "pass"
        timestamp_utc = [DateTime]::UtcNow.ToString("o")
        test = "control-plane-security-milestone"
        version = "0.4.0"
        security_profile = "development"
        transport_test = "upstream-tls-declared-for-loopback-api-test"
        checks = @(
            "insecure remote bind rejected",
            "security readiness",
            "admin API authentication",
            "credential separation",
            "endpoint enrollment",
            "device-scoped API access",
            "endpoint credential revocation",
            "revocation audit evidence"
        )
    }
    $report | ConvertTo-Json -Depth 6 | Set-Content -Path $ReportPath -Encoding UTF8

    Write-Host ""
    Write-Host "[PASS] Mira Protect control-plane security milestone completed." -ForegroundColor Green
    Write-Host "Validation report: $ReportPath"
}
finally {
    Stop-TestProcess $serverProcess
    $env:MIRA_DATABASE_URL = $previous.MIRA_DATABASE_URL
    $env:MIRA_SECURITY_PROFILE = $previous.MIRA_SECURITY_PROFILE
    $env:MIRA_ADMIN_TOKEN = $previous.MIRA_ADMIN_TOKEN
    $env:MIRA_ENROLLMENT_TOKEN = $previous.MIRA_ENROLLMENT_TOKEN
    $env:MIRA_TOKEN_PEPPER = $previous.MIRA_TOKEN_PEPPER
    $env:MIRA_ENDPOINT_TOKEN = $previous.MIRA_ENDPOINT_TOKEN
    $env:MIRA_ALLOW_SHARED_ENDPOINT_TOKEN = $previous.MIRA_ALLOW_SHARED_ENDPOINT_TOKEN
    $env:MIRA_TLS_TERMINATED_UPSTREAM = $previous.MIRA_TLS_TERMINATED_UPSTREAM
    $env:MIRA_ALLOW_INSECURE_REMOTE = $previous.MIRA_ALLOW_INSECURE_REMOTE
    $env:MIRA_EFFECTIVE_TLS = $previous.MIRA_EFFECTIVE_TLS
    $env:MIRA_BIND_HOST = $previous.MIRA_BIND_HOST
}