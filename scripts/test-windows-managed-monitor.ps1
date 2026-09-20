param(
    [int]$Port = 18082,
    [string]$InstallDir = "$env:ProgramData\MiraProtect-Milestone-Test",
    [string]$TaskName = "Mira Protect Endpoint Agent - Milestone Test",
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BuildRoot = Join-Path $RepoRoot ".build\windows"
$VenvScripts = Join-Path $BuildRoot "venv\Scripts"
$AgentExe = Join-Path $RepoRoot "dist\windows\MiraProtectAgent.exe"
$ServerExe = Join-Path $VenvScripts "mira-protect-server.exe"
$Installer = Join-Path $RepoRoot "scripts\install-windows-agent.ps1"
$Uninstaller = Join-Path $RepoRoot "scripts\uninstall-windows-agent.ps1"
$TestRoot = Join-Path $RepoRoot ".mira-test-managed-windows"
$ControlPlaneUrl = "http://127.0.0.1:$Port"
$EnrollmentToken = "mira-managed-enrollment-test-token-change-me"
$TokenPepper = "mira-managed-token-pepper-change-me"
$CredentialPath = Join-Path $InstallDir "device-token.txt"
$PolicyCachePath = Join-Path $InstallDir "policy-cache.json"
$AgentLog = Join-Path $InstallDir "logs\agent.log"
$ReportPath = Join-Path $TestRoot "validation-report.json"

$serverProcess = $null
$targetProcess = $null

function Assert-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run this milestone test from an elevated Windows PowerShell session."
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
        if (& $Condition) {
            return
        }
        Start-Sleep -Milliseconds $DelayMilliseconds
    }
    throw $FailureMessage
}

Assert-Administrator

if (-not $SkipBuild) {
    Write-Host "Building Mira Protect 0.3 Windows endpoint..." -ForegroundColor Cyan
    & (Join-Path $RepoRoot "scripts\build-windows-agent.ps1")
    if ($LASTEXITCODE -ne 0) {
        throw "Windows build failed with exit code $LASTEXITCODE."
    }
}

$BuildInfoPath = Join-Path $RepoRoot "dist\windows\BUILD-INFO.json"
if (Test-Path $BuildInfoPath) {
    $BuildInfo = Get-Content $BuildInfoPath -Raw | ConvertFrom-Json
    if ($BuildInfo.agent_executable -and (Test-Path $BuildInfo.agent_executable)) {
        $AgentExe = [string]$BuildInfo.agent_executable
    }
}

foreach ($required in @($AgentExe, $ServerExe, $Installer, $Uninstaller)) {
    if (-not (Test-Path $required)) {
        throw "Required milestone component was not found: $required"
    }
}

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    & $Uninstaller -InstallDir $InstallDir -TaskName $TaskName
}
elseif (Test-Path $InstallDir) {
    Remove-Item $InstallDir -Recurse -Force
}

Remove-Item $TestRoot -Recurse -Force -ErrorAction SilentlyContinue
New-Item -Path $TestRoot -ItemType Directory -Force | Out-Null
$dbPath = (Join-Path $TestRoot "mira.db").Replace("\", "/")
$serverOut = Join-Path $TestRoot "server.out.log"
$serverErr = Join-Path $TestRoot "server.err.log"

$previous = @{
    MIRA_DATABASE_URL = $env:MIRA_DATABASE_URL
    MIRA_ENROLLMENT_TOKEN = $env:MIRA_ENROLLMENT_TOKEN
    MIRA_TOKEN_PEPPER = $env:MIRA_TOKEN_PEPPER
    MIRA_ENDPOINT_TOKEN = $env:MIRA_ENDPOINT_TOKEN
    MIRA_ALLOW_SHARED_ENDPOINT_TOKEN = $env:MIRA_ALLOW_SHARED_ENDPOINT_TOKEN
    MIRA_ENDPOINT_DENY_PROCESSES = $env:MIRA_ENDPOINT_DENY_PROCESSES
    MIRA_ENDPOINT_PROCESS_NAMES = $env:MIRA_ENDPOINT_PROCESS_NAMES
    MIRA_ENDPOINT_COMMAND_MARKERS = $env:MIRA_ENDPOINT_COMMAND_MARKERS
    MIRA_ENDPOINT_FAIL_CLOSED = $env:MIRA_ENDPOINT_FAIL_CLOSED
    MIRA_ENDPOINT_POLICY_MODE = $env:MIRA_ENDPOINT_POLICY_MODE
    MIRA_POLICY_REFRESH_SECONDS = $env:MIRA_POLICY_REFRESH_SECONDS
    MIRA_ENABLE_TEST_CONTROLS = $env:MIRA_ENABLE_TEST_CONTROLS
}

try {
    $env:MIRA_DATABASE_URL = "sqlite+pysqlite:///$dbPath"
    $env:MIRA_ENROLLMENT_TOKEN = $EnrollmentToken
    $env:MIRA_TOKEN_PEPPER = $TokenPepper
    $env:MIRA_ENDPOINT_TOKEN = ""
    $env:MIRA_ALLOW_SHARED_ENDPOINT_TOKEN = "false"
    $env:MIRA_ENDPOINT_DENY_PROCESSES = "notepad.exe"
    $env:MIRA_ENDPOINT_PROCESS_NAMES = ""
    $env:MIRA_ENDPOINT_COMMAND_MARKERS = ""
    $env:MIRA_ENDPOINT_FAIL_CLOSED = "false"
    $env:MIRA_ENDPOINT_POLICY_MODE = "monitor"
    $env:MIRA_POLICY_REFRESH_SECONDS = "30"
    $env:MIRA_ENABLE_TEST_CONTROLS = "false"

    Write-Host "Starting isolated enrollment-enabled control plane..." -ForegroundColor Cyan
    $serverProcess = Start-Process -FilePath $ServerExe -ArgumentList @(
        "--host", "127.0.0.1",
        "--port", "$Port",
        "--log-level", "warning"
    ) -RedirectStandardOutput $serverOut -RedirectStandardError $serverErr -PassThru -WindowStyle Hidden

    Wait-ForCondition -FailureMessage "Control plane did not become healthy." -Condition {
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
    Write-Host "[PASS] Enrollment-enabled control plane is healthy" -ForegroundColor Green

    Write-Host "Installing endpoint as persistent SYSTEM scheduled task in monitor mode..." -ForegroundColor Cyan
    & $Installer -ControlPlaneUrl $ControlPlaneUrl -Mode monitor -EnrollmentToken $EnrollmentToken -InstallDir $InstallDir -AgentBinary $AgentExe -TaskName $TaskName

    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
    if ($task.State -ne "Running") {
        Start-ScheduledTask -TaskName $TaskName
    }
    Write-Host "[PASS] Persistent SYSTEM endpoint task is installed" -ForegroundColor Green

    Wait-ForCondition -FailureMessage "Per-device credential was not created." -Condition {
        Test-Path $CredentialPath
    }
    $deviceToken = (Get-Content $CredentialPath -Raw).Trim()
    if (-not $deviceToken -or $deviceToken -eq $EnrollmentToken) {
        throw "Endpoint did not receive a distinct per-device credential."
    }
    Write-Host "[PASS] Bootstrap enrollment produced a distinct device credential" -ForegroundColor Green

    Wait-ForCondition -FailureMessage "Endpoint did not download and cache central policy." -Condition {
        Test-Path $PolicyCachePath
    }
    $policy = Get-Content $PolicyCachePath -Raw | ConvertFrom-Json
    if (@($policy.deny_processes) -notcontains "notepad.exe") {
        throw "Cached policy does not contain the centrally distributed notepad.exe deny rule."
    }
    if (-not $policy.policy_version) {
        throw "Cached endpoint policy has no policy version."
    }
    Write-Host "[PASS] Versioned central policy was downloaded and cached" -ForegroundColor Green

    Wait-ForCondition -FailureMessage "Managed endpoint did not send a successful heartbeat." -Condition {
        if (-not (Test-Path $AgentLog)) {
            return $false
        }
        $logText = Get-Content $AgentLog -Raw -ErrorAction SilentlyContinue
        return $logText -match '"event":\s*"heartbeat_sent"'
    }
    Write-Host "[PASS] Persistent endpoint heartbeat reached the control plane" -ForegroundColor Green

    $notepad = Join-Path $env:SystemRoot "System32\notepad.exe"
    if (-not (Test-Path $notepad)) {
        throw "notepad.exe was not found for the monitor-mode policy test."
    }

    Write-Host "Launching Notepad to validate central deny policy in monitor mode..." -ForegroundColor Cyan
    $targetProcess = Start-Process -FilePath $notepad -PassThru
    $pidUnderTest = $targetProcess.Id

    $matchedEvent = $null
    $script:matchedEvent = $null
    Wait-ForCondition -Attempts 60 -FailureMessage "Managed agent did not report the centrally denied process." -Condition {
        try {
            $events = Invoke-RestMethod -Method Get -Uri "$ControlPlaneUrl/api/v1/events?limit=200" -TimeoutSec 2
            $script:matchedEvent = @($events) | Where-Object {
                $_.metadata.pid -eq $pidUnderTest -and $_.metadata.process_name -eq "notepad.exe"
            } | Select-Object -First 1
            return $null -ne $script:matchedEvent
        }
        catch {
            return $false
        }
    }

    $matchedEvent = $script:matchedEvent
    if ($matchedEvent.security.policy_decision -ne "block") {
        throw "Central policy did not return BLOCK for the distributed deny-process rule."
    }
    if ($matchedEvent.metadata.agent_mode -ne "monitor") {
        throw "Endpoint process event was not evaluated in monitor mode."
    }
    if ($targetProcess.HasExited) {
        throw "Monitor mode terminated the centrally blocked process; it must remain observation-only."
    }
    Write-Host "[PASS] Central BLOCK decision was observed without terminating the process" -ForegroundColor Green

    $assets = Invoke-RestMethod -Method Get -Uri "$ControlPlaneUrl/api/v1/assets"
    $managedAsset = @($assets) | Where-Object {
        $_.attributes.device_id -eq $env:COMPUTERNAME.ToLowerInvariant()
    } | Select-Object -First 1
    if (-not $managedAsset) {
        throw "Managed endpoint inventory record was not found."
    }
    if ($managedAsset.attributes.policy_version -ne $policy.policy_version) {
        throw "Control plane did not record the endpoint applied policy version."
    }
    Write-Host "[PASS] Inventory records the endpoint applied policy version" -ForegroundColor Green

    $evidenceAgentLog = Join-Path $TestRoot "agent.log"
    $evidencePolicy = Join-Path $TestRoot "policy-cache.json"
    if (Test-Path $AgentLog) {
        Copy-Item $AgentLog $evidenceAgentLog -Force
    }
    if (Test-Path $PolicyCachePath) {
        Copy-Item $PolicyCachePath $evidencePolicy -Force
    }
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $credentialBytes = [Text.Encoding]::UTF8.GetBytes($deviceToken)
        $credentialHashBytes = $sha256.ComputeHash($credentialBytes)
        $deviceCredentialSha256 = -join (
            $credentialHashBytes | ForEach-Object { $_.ToString("x2") }
        )
    }
    finally {
        $sha256.Dispose()
    }

    $buildInfoPath = Join-Path $RepoRoot "dist\windows\BUILD-INFO.json"
    $buildInfo = $null
    if (Test-Path $buildInfoPath) {
        $buildInfo = Get-Content $buildInfoPath -Raw | ConvertFrom-Json
    }

    $report = [ordered]@{
        status = "pass"
        timestamp_utc = [DateTime]::UtcNow.ToString("o")
        test = "windows-managed-monitor-milestone"
        control_plane = $ControlPlaneUrl
        task_name = $TaskName
        install_dir = $InstallDir
        mode = "monitor"
        enrollment = "per-device"
        device_credential_sha256 = $deviceCredentialSha256
        policy_version = $policy.policy_version
        central_deny_process = "notepad.exe"
        central_decision = $matchedEvent.security.policy_decision
        target_remained_running = (-not $targetProcess.HasExited)
        build = $buildInfo
        checks = @(
            "per-device bootstrap enrollment",
            "device credential storage",
            "persistent SYSTEM scheduled task",
            "versioned central policy download",
            "local policy cache",
            "managed endpoint heartbeat",
            "central deny-process discovery",
            "central BLOCK decision",
            "monitor-mode non-termination",
            "applied policy version inventory"
        )
    }
    $report | ConvertTo-Json -Depth 8 | Set-Content -Path $ReportPath -Encoding UTF8

    Write-Host ""
    Write-Host "[PASS] Mira Protect managed Windows monitor milestone completed." -ForegroundColor Green
    Write-Host "Validation report: $ReportPath"
    Write-Host "Agent log:        $evidenceAgentLog"
    Write-Host "Policy cache:     $evidencePolicy"
}
finally {
    Stop-TestProcess $targetProcess

    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        try {
            & $Uninstaller -InstallDir $InstallDir -TaskName $TaskName
        }
        catch {
            Write-Warning "Milestone endpoint cleanup failed: $($_.Exception.Message)"
        }
    }
    Stop-TestProcess $serverProcess

    $env:MIRA_DATABASE_URL = $previous.MIRA_DATABASE_URL
    $env:MIRA_ENROLLMENT_TOKEN = $previous.MIRA_ENROLLMENT_TOKEN
    $env:MIRA_TOKEN_PEPPER = $previous.MIRA_TOKEN_PEPPER
    $env:MIRA_ENDPOINT_TOKEN = $previous.MIRA_ENDPOINT_TOKEN
    $env:MIRA_ALLOW_SHARED_ENDPOINT_TOKEN = $previous.MIRA_ALLOW_SHARED_ENDPOINT_TOKEN
    $env:MIRA_ENDPOINT_DENY_PROCESSES = $previous.MIRA_ENDPOINT_DENY_PROCESSES
    $env:MIRA_ENDPOINT_PROCESS_NAMES = $previous.MIRA_ENDPOINT_PROCESS_NAMES
    $env:MIRA_ENDPOINT_COMMAND_MARKERS = $previous.MIRA_ENDPOINT_COMMAND_MARKERS
    $env:MIRA_ENDPOINT_FAIL_CLOSED = $previous.MIRA_ENDPOINT_FAIL_CLOSED
    $env:MIRA_ENDPOINT_POLICY_MODE = $previous.MIRA_ENDPOINT_POLICY_MODE
    $env:MIRA_POLICY_REFRESH_SECONDS = $previous.MIRA_POLICY_REFRESH_SECONDS
    $env:MIRA_ENABLE_TEST_CONTROLS = $previous.MIRA_ENABLE_TEST_CONTROLS
}
