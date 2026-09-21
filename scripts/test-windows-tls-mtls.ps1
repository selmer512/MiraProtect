param(
    [int]$Port = 18443,
    [string]$InstallDir = "$env:ProgramData\MiraProtect-TLS-Test",
    [string]$TaskName = "Mira Protect Endpoint Agent - TLS Test",
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BuildRoot = Join-Path $RepoRoot ".build\windows"
$VenvScripts = Join-Path $BuildRoot "venv\Scripts"
$VenvPython = Join-Path $VenvScripts "python.exe"
$ServerExe = Join-Path $VenvScripts "mira-protect-server.exe"
$CliExe = Join-Path $VenvScripts "mira-protect.exe"
$Installer = Join-Path $RepoRoot "scripts\install-windows-agent.ps1"
$Uninstaller = Join-Path $RepoRoot "scripts\uninstall-windows-agent.ps1"
$TestRoot = Join-Path $RepoRoot ".mira-test-tls-mtls"
$PkiDir = Join-Path $TestRoot "pki"
$ControlPlaneUrl = "https://localhost:$Port"
$AdminToken = "mira-tls-test-admin-token"
$EnrollmentToken = "mira-tls-test-enrollment-token"
$TokenPepper = "mira-tls-test-token-pepper"
$DeviceId = "$($env:COMPUTERNAME.ToLowerInvariant())-mtls-test"
$PolicyCachePath = Join-Path $InstallDir "policy-cache.json"
$AgentLog = Join-Path $InstallDir "logs\agent.log"
$AgentConfig = Join-Path $InstallDir "agent-config.json"
$ReportPath = Join-Path $TestRoot "validation-report.json"
$EvidenceAgentLog = Join-Path $TestRoot "agent.log"
$EvidencePolicy = Join-Path $TestRoot "policy-cache.json"
$EvidenceConfig = Join-Path $TestRoot "agent-config.json"
$ServerOut = Join-Path $TestRoot "server.out.log"
$ServerErr = Join-Path $TestRoot "server.err.log"
$NoClientLog = Join-Path $TestRoot "no-client-cert.log"
$serverProcess = $null

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this TLS/mTLS milestone test from an elevated Windows PowerShell session."
    }
}

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
        [int]$Attempts = 80,
        [int]$DelayMilliseconds = 500,
        [string]$FailureMessage = "Condition did not become true."
    )
    for ($i = 0; $i -lt $Attempts; $i++) {
        if (& $Condition) { return }
        Start-Sleep -Milliseconds $DelayMilliseconds
    }
    throw $FailureMessage
}

Assert-Administrator

if (-not $SkipBuild) {
    Write-Host "Building and validating Mira Protect 0.4 TLS/mTLS milestone..." -ForegroundColor Cyan
    & (Join-Path $RepoRoot "scripts\build-windows-agent.ps1")
    if ($LASTEXITCODE -ne 0) { throw "Windows build failed with exit code $LASTEXITCODE." }
}

$BuildInfoPath = Join-Path $RepoRoot "dist\windows\BUILD-INFO.json"
$AgentExe = Join-Path $RepoRoot "dist\windows\MiraProtectAgent.exe"
if (Test-Path $BuildInfoPath) {
    $BuildInfo = Get-Content $BuildInfoPath -Raw | ConvertFrom-Json
    if ($BuildInfo.agent_executable -and (Test-Path $BuildInfo.agent_executable)) {
        $AgentExe = [string]$BuildInfo.agent_executable
    }
}

foreach ($required in @($VenvPython, $ServerExe, $CliExe, $AgentExe, $Installer, $Uninstaller)) {
    if (-not (Test-Path $required)) { throw "Required TLS/mTLS test component was not found: $required" }
}

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    & $Uninstaller -InstallDir $InstallDir -TaskName $TaskName
}
elseif (Test-Path $InstallDir) {
    Remove-Item $InstallDir -Recurse -Force
}

Remove-Item $TestRoot -Recurse -Force -ErrorAction SilentlyContinue
New-Item -Path $PkiDir -ItemType Directory -Force | Out-Null
Write-Host "Generating ephemeral test CA, server certificate, and client certificate..." -ForegroundColor Cyan
& $VenvPython (Join-Path $RepoRoot "scripts\generate-test-pki.py") $PkiDir
if ($LASTEXITCODE -ne 0) { throw "Ephemeral TLS test PKI generation failed with exit code $LASTEXITCODE." }

$CaFile = Join-Path $PkiDir "ca.crt"
$ServerCert = Join-Path $PkiDir "server.crt"
$ServerKey = Join-Path $PkiDir "server.key"
$ClientCert = Join-Path $PkiDir "client.crt"
$ClientKey = Join-Path $PkiDir "client.key"
foreach ($required in @($CaFile, $ServerCert, $ServerKey, $ClientCert, $ClientKey)) {
    if (-not (Test-Path $required)) { throw "PKI generator did not create required file: $required" }
}
Write-Host "[PASS] Ephemeral TLS/mTLS test PKI generated" -ForegroundColor Green

$dbPath = (Join-Path $TestRoot "mira.db").Replace("\", "/")
$previous = @{
    MIRA_DATABASE_URL = $env:MIRA_DATABASE_URL
    MIRA_SECURITY_PROFILE = $env:MIRA_SECURITY_PROFILE
    MIRA_ADMIN_TOKEN = $env:MIRA_ADMIN_TOKEN
    MIRA_ENROLLMENT_TOKEN = $env:MIRA_ENROLLMENT_TOKEN
    MIRA_TOKEN_PEPPER = $env:MIRA_TOKEN_PEPPER
    MIRA_ENDPOINT_TOKEN = $env:MIRA_ENDPOINT_TOKEN
    MIRA_ALLOW_SHARED_ENDPOINT_TOKEN = $env:MIRA_ALLOW_SHARED_ENDPOINT_TOKEN
    MIRA_TLS_CERT_FILE = $env:MIRA_TLS_CERT_FILE
    MIRA_TLS_KEY_FILE = $env:MIRA_TLS_KEY_FILE
    MIRA_TLS_CLIENT_CA_FILE = $env:MIRA_TLS_CLIENT_CA_FILE
    MIRA_TLS_REQUIRE_CLIENT_CERT = $env:MIRA_TLS_REQUIRE_CLIENT_CERT
    MIRA_TLS_TERMINATED_UPSTREAM = $env:MIRA_TLS_TERMINATED_UPSTREAM
    MIRA_ALLOW_INSECURE_REMOTE = $env:MIRA_ALLOW_INSECURE_REMOTE
    MIRA_EFFECTIVE_TLS = $env:MIRA_EFFECTIVE_TLS
    MIRA_BIND_HOST = $env:MIRA_BIND_HOST
    MIRA_ENDPOINT_POLICY_MODE = $env:MIRA_ENDPOINT_POLICY_MODE
    MIRA_POLICY_REFRESH_SECONDS = $env:MIRA_POLICY_REFRESH_SECONDS
    MIRA_ENABLE_TEST_CONTROLS = $env:MIRA_ENABLE_TEST_CONTROLS
}

try {
    $env:MIRA_DATABASE_URL = "sqlite+pysqlite:///$dbPath"
    $env:MIRA_SECURITY_PROFILE = "development"
    $env:MIRA_ADMIN_TOKEN = $AdminToken
    $env:MIRA_ENROLLMENT_TOKEN = $EnrollmentToken
    $env:MIRA_TOKEN_PEPPER = $TokenPepper
    $env:MIRA_ENDPOINT_TOKEN = ""
    $env:MIRA_ALLOW_SHARED_ENDPOINT_TOKEN = "false"
    $env:MIRA_TLS_CERT_FILE = $ServerCert
    $env:MIRA_TLS_KEY_FILE = $ServerKey
    $env:MIRA_TLS_CLIENT_CA_FILE = $CaFile
    $env:MIRA_TLS_REQUIRE_CLIENT_CERT = "true"
    $env:MIRA_TLS_TERMINATED_UPSTREAM = "false"
    $env:MIRA_ALLOW_INSECURE_REMOTE = "false"
    $env:MIRA_EFFECTIVE_TLS = "false"
    $env:MIRA_BIND_HOST = "127.0.0.1"
    $env:MIRA_ENDPOINT_POLICY_MODE = "monitor"
    $env:MIRA_POLICY_REFRESH_SECONDS = "30"
    $env:MIRA_ENABLE_TEST_CONTROLS = "false"

    Write-Host "Starting direct-TLS control plane with required client certificates..." -ForegroundColor Cyan
    $serverArgs = @("--host", "127.0.0.1", "--port", "$Port", "--log-level", "warning", "--ssl-certfile", $ServerCert, "--ssl-keyfile", $ServerKey, "--ssl-client-ca-file", $CaFile, "--require-client-cert")
    $serverProcess = Start-Process -FilePath $ServerExe -ArgumentList $serverArgs -RedirectStandardOutput $ServerOut -RedirectStandardError $ServerErr -PassThru -WindowStyle Hidden

    Wait-ForCondition -Attempts 80 -FailureMessage "TLS/mTLS control plane did not become ready." -Condition {
        if ($serverProcess.HasExited) { return $false }
        try {
            & $CliExe --url $ControlPlaneUrl --ca-file $CaFile --client-cert $ClientCert --client-key $ClientKey --json ready *> $null
            return $LASTEXITCODE -eq 0
        }
        catch {
            return $false
        }
    }
    Write-Host "[PASS] Direct TLS control plane is reachable with a trusted client certificate" -ForegroundColor Green

    $noClientExit = 1
    try {
        & $CliExe --url $ControlPlaneUrl --ca-file $CaFile ready *> $NoClientLog
        $noClientExit = $LASTEXITCODE
    }
    catch {
        $_ | Out-String | Add-Content -Path $NoClientLog
        $noClientExit = 1
    }
    if ($noClientExit -eq 0) { throw "mTLS control plane accepted a client without a certificate." }
    Write-Host "[PASS] mTLS rejects clients without a certificate" -ForegroundColor Green

    try {
        & $CliExe --url $ControlPlaneUrl --token $AdminToken --ca-file $CaFile --client-cert $ClientCert --client-key $ClientKey --json assets *> $null
        if ($LASTEXITCODE -ne 0) { throw "CLI exit code $LASTEXITCODE" }
    }
    catch {
        throw "Authenticated administrative API failed over direct TLS/mTLS: $($_.Exception.Message)"
    }
    Write-Host "[PASS] Administrative API authentication works over TLS/mTLS" -ForegroundColor Green

    Write-Host "Installing managed Windows endpoint against the TLS/mTLS control plane..." -ForegroundColor Cyan
    $installArgs = @{
        ControlPlaneUrl = $ControlPlaneUrl
        Mode = "monitor"
        EnrollmentToken = $EnrollmentToken
        TlsCaFile = $CaFile
        TlsClientCert = $ClientCert
        TlsClientKey = $ClientKey
        DeviceId = $DeviceId
        InstallDir = $InstallDir
        AgentBinary = $AgentExe
        TaskName = $TaskName
    }
    & $Installer @installArgs

    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    if ($task.State -ne "Running") { Start-ScheduledTask -TaskName $TaskName }
    Write-Host "[PASS] TLS/mTLS endpoint task installed under SYSTEM" -ForegroundColor Green

    Wait-ForCondition -FailureMessage "TLS/mTLS endpoint did not download and cache central policy." -Condition {
        Test-Path $PolicyCachePath
    }
    $policy = Get-Content $PolicyCachePath -Raw | ConvertFrom-Json
    if (-not $policy.policy_version) { throw "TLS/mTLS endpoint cached a policy without a version." }
    Write-Host "[PASS] Endpoint enrolled and downloaded policy through TLS/mTLS" -ForegroundColor Green

    Wait-ForCondition -Attempts 80 -FailureMessage "TLS/mTLS endpoint heartbeat did not reach inventory." -Condition {
        try {
            $json = & $CliExe --url $ControlPlaneUrl --token $AdminToken --ca-file $CaFile --client-cert $ClientCert --client-key $ClientKey --json assets 2>$null
            if ($LASTEXITCODE -ne 0 -or -not $json) { return $false }
            $assets = $json | ConvertFrom-Json
            $matched = @($assets) | Where-Object { $_.attributes.device_id -eq $DeviceId } | Select-Object -First 1
            return $null -ne $matched
        }
        catch { return $false }
    }
    Write-Host "[PASS] Persistent endpoint heartbeat succeeded through mutual TLS" -ForegroundColor Green

    if (Test-Path $AgentLog) { Copy-Item $AgentLog $EvidenceAgentLog -Force }
    if (Test-Path $PolicyCachePath) { Copy-Item $PolicyCachePath $EvidencePolicy -Force }
    if (Test-Path $AgentConfig) { Copy-Item $AgentConfig $EvidenceConfig -Force }

    $serverCertHash = (Get-FileHash -Path $ServerCert -Algorithm SHA256).Hash.ToLowerInvariant()
    $clientCertHash = (Get-FileHash -Path $ClientCert -Algorithm SHA256).Hash.ToLowerInvariant()
    $caCertHash = (Get-FileHash -Path $CaFile -Algorithm SHA256).Hash.ToLowerInvariant()
    $report = [ordered]@{
        status = "pass"
        timestamp_utc = [DateTime]::UtcNow.ToString("o")
        test = "windows-tls-mtls-milestone"
        version = "0.4.0"
        control_plane = $ControlPlaneUrl
        security_profile = "development"
        device_id = $DeviceId
        mode = "monitor"
        policy_version = $policy.policy_version
        tls = "direct"
        mtls_required = $true
        ca_certificate_sha256 = $caCertHash
        server_certificate_sha256 = $serverCertHash
        client_certificate_sha256 = $clientCertHash
        checks = @("ephemeral PKI generation", "direct server TLS", "client certificate requirement", "server certificate verification", "administrative authentication over TLS", "endpoint enrollment over TLS/mTLS", "versioned policy retrieval over TLS/mTLS", "persistent SYSTEM endpoint execution", "endpoint heartbeat over mutual TLS")
    }
    $report | ConvertTo-Json -Depth 8 | Set-Content -Path $ReportPath -Encoding UTF8

    Write-Host ""
    Write-Host "[PASS] Mira Protect Windows TLS/mTLS milestone completed." -ForegroundColor Green
    Write-Host "Validation report: $ReportPath"
    Write-Host "Agent log:        $EvidenceAgentLog"
    Write-Host "Policy cache:     $EvidencePolicy"
}
finally {
    if (Test-Path $AgentLog) { Copy-Item $AgentLog $EvidenceAgentLog -Force -ErrorAction SilentlyContinue }
    if (Test-Path $PolicyCachePath) { Copy-Item $PolicyCachePath $EvidencePolicy -Force -ErrorAction SilentlyContinue }
    if (Test-Path $AgentConfig) { Copy-Item $AgentConfig $EvidenceConfig -Force -ErrorAction SilentlyContinue }
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        try { & $Uninstaller -InstallDir $InstallDir -TaskName $TaskName }
        catch { Write-Warning "TLS/mTLS endpoint cleanup failed: $($_.Exception.Message)" }
    }
    Stop-TestProcess $serverProcess
    Remove-Item (Join-Path $PkiDir "server.key") -Force -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $PkiDir "client.key") -Force -ErrorAction SilentlyContinue
    $env:MIRA_DATABASE_URL = $previous.MIRA_DATABASE_URL
    $env:MIRA_SECURITY_PROFILE = $previous.MIRA_SECURITY_PROFILE
    $env:MIRA_ADMIN_TOKEN = $previous.MIRA_ADMIN_TOKEN
    $env:MIRA_ENROLLMENT_TOKEN = $previous.MIRA_ENROLLMENT_TOKEN
    $env:MIRA_TOKEN_PEPPER = $previous.MIRA_TOKEN_PEPPER
    $env:MIRA_ENDPOINT_TOKEN = $previous.MIRA_ENDPOINT_TOKEN
    $env:MIRA_ALLOW_SHARED_ENDPOINT_TOKEN = $previous.MIRA_ALLOW_SHARED_ENDPOINT_TOKEN
    $env:MIRA_TLS_CERT_FILE = $previous.MIRA_TLS_CERT_FILE
    $env:MIRA_TLS_KEY_FILE = $previous.MIRA_TLS_KEY_FILE
    $env:MIRA_TLS_CLIENT_CA_FILE = $previous.MIRA_TLS_CLIENT_CA_FILE
    $env:MIRA_TLS_REQUIRE_CLIENT_CERT = $previous.MIRA_TLS_REQUIRE_CLIENT_CERT
    $env:MIRA_TLS_TERMINATED_UPSTREAM = $previous.MIRA_TLS_TERMINATED_UPSTREAM
    $env:MIRA_ALLOW_INSECURE_REMOTE = $previous.MIRA_ALLOW_INSECURE_REMOTE
    $env:MIRA_EFFECTIVE_TLS = $previous.MIRA_EFFECTIVE_TLS
    $env:MIRA_BIND_HOST = $previous.MIRA_BIND_HOST
    $env:MIRA_ENDPOINT_POLICY_MODE = $previous.MIRA_ENDPOINT_POLICY_MODE
    $env:MIRA_POLICY_REFRESH_SECONDS = $previous.MIRA_POLICY_REFRESH_SECONDS
    $env:MIRA_ENABLE_TEST_CONTROLS = $previous.MIRA_ENABLE_TEST_CONTROLS
}
