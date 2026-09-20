param(
    [string]$OutputDir = "",
    [switch]$SkipValidation
)

$ErrorActionPreference = "Stop"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if (-not $OutputDir) {
    $OutputDir = Join-Path $RepoRoot "dist\windows"
}

$BuildRoot = Join-Path $RepoRoot ".build\windows"
$VenvDir = Join-Path $BuildRoot "venv"
$WorkDir = Join-Path $BuildRoot "pyinstaller"
$SpecDir = Join-Path $BuildRoot "spec"
$StageDistDir = Join-Path $BuildRoot "dist"
$PackageDir = Join-Path $BuildRoot "package"
$EntryPoint = Join-Path $RepoRoot "scripts\windows_agent_entry.py"

function Assert-LastExitCode {
    param([string]$Step)
    if ($LASTEXITCODE -ne 0) {
        throw "$Step failed with exit code $LASTEXITCODE."
    }
}

function Resolve-BasePython {
    # Prefer an actual python.exe on PATH. The Windows Python launcher (py.exe)
    # may be installed even when no runtime exists, and probing it under
    # $ErrorActionPreference = "Stop" can abort the build before we can fall back.
    $python = Get-Command python -ErrorAction SilentlyContinue
    if ($python) {
        try {
            & $python.Source -c "import sys; raise SystemExit(0 if sys.version_info >= (3,12) else 1)" 2>$null
            if ($LASTEXITCODE -eq 0) {
                return @{
                    Exe = $python.Source
                    Prefix = @()
                }
            }
        }
        catch {
            # Continue to the launcher probe below.
        }
    }

    $py = Get-Command py -ErrorAction SilentlyContinue
    if ($py) {
        try {
            # -3 selects the newest installed Python 3 runtime rather than requiring
            # exactly Python 3.12. Any Python >=3.12 is supported by Mira Protect.
            & $py.Source -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3,12) else 1)" 2>$null
            if ($LASTEXITCODE -eq 0) {
                return @{
                    Exe = $py.Source
                    Prefix = @("-3")
                }
            }
        }
        catch {
            # Fall through to the actionable error below.
        }
    }

    throw "Python 3.12+ was not found. Install 64-bit Python 3.12 or newer, ensure 'python' or 'py' can launch it, then retry."
}

$basePython = Resolve-BasePython

if (Test-Path $VenvDir) {
    $venvPythonExisting = Join-Path $VenvDir "Scripts\python.exe"
    if (-not (Test-Path $venvPythonExisting)) {
        Remove-Item $VenvDir -Recurse -Force
    }
}

if (-not (Test-Path $VenvDir)) {
    New-Item -Path $BuildRoot -ItemType Directory -Force | Out-Null
    Write-Host "Creating Windows build virtual environment..." -ForegroundColor Cyan
    $venvArgs = @($basePython.Prefix) + @("-m", "venv", $VenvDir)
    & $basePython.Exe @venvArgs
    Assert-LastExitCode "Virtual environment creation"
}

$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    throw "Build virtual environment is missing $VenvPython."
}

Write-Host "Installing Mira Protect build dependencies..." -ForegroundColor Cyan
& $VenvPython -m pip install --upgrade pip
Assert-LastExitCode "pip upgrade"
& $VenvPython -m pip install -e "${RepoRoot}[dev,build]"
Assert-LastExitCode "Mira Protect build dependency installation"

if (-not $SkipValidation) {
    Write-Host "Validating PowerShell scripts..." -ForegroundColor Cyan
    $PowerShellScripts = Get-ChildItem (Join-Path $RepoRoot "scripts") -Filter "*.ps1" -File
    foreach ($script in $PowerShellScripts) {
        $tokens = $null
        $parseErrors = $null
        [System.Management.Automation.Language.Parser]::ParseFile(
            $script.FullName,
            [ref]$tokens,
            [ref]$parseErrors
        ) | Out-Null
        if ($parseErrors.Count -gt 0) {
            $details = ($parseErrors | ForEach-Object { $_.Message }) -join "; "
            throw "PowerShell syntax validation failed for $($script.Name): $details"
        }
    }

    Write-Host "Running Windows source validation..." -ForegroundColor Cyan
    $RuffExe = Join-Path $VenvDir "Scripts\ruff.exe"
    $PytestExe = Join-Path $VenvDir "Scripts\pytest.exe"
    foreach ($tool in @($RuffExe, $PytestExe)) {
        if (-not (Test-Path $tool)) {
            throw "Required validation tool was not installed: $tool"
        }
    }
    & $RuffExe check --config (Join-Path $RepoRoot "pyproject.toml") (Join-Path $RepoRoot "src") (Join-Path $RepoRoot "tests")
    Assert-LastExitCode "Ruff validation"

    $previousDb = $env:MIRA_DATABASE_URL
    $previousTests = $env:MIRA_ENABLE_TEST_CONTROLS
    try {
        $env:MIRA_DATABASE_URL = "sqlite+pysqlite:///:memory:"
        $env:MIRA_ENABLE_TEST_CONTROLS = "true"
        & $PytestExe -q (Join-Path $RepoRoot "tests")
        Assert-LastExitCode "Pytest validation"
    }
    finally {
        $env:MIRA_DATABASE_URL = $previousDb
        $env:MIRA_ENABLE_TEST_CONTROLS = $previousTests
    }
}

Remove-Item $WorkDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $SpecDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $StageDistDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $PackageDir -Recurse -Force -ErrorAction SilentlyContinue
New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
New-Item -Path $WorkDir -ItemType Directory -Force | Out-Null
New-Item -Path $SpecDir -ItemType Directory -Force | Out-Null
New-Item -Path $StageDistDir -ItemType Directory -Force | Out-Null
New-Item -Path $PackageDir -ItemType Directory -Force | Out-Null

$AgentExe = Join-Path $OutputDir "MiraProtectAgent.exe"
$StagedAgentExe = Join-Path $StageDistDir "MiraProtectAgent.exe"

Write-Host "Building MiraProtectAgent.exe..." -ForegroundColor Cyan
& $VenvPython -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --name "MiraProtectAgent" `
    --distpath $StageDistDir `
    --workpath $WorkDir `
    --specpath $SpecDir `
    --paths (Join-Path $RepoRoot "src") `
    $EntryPoint
Assert-LastExitCode "PyInstaller build"

if (-not (Test-Path $StagedAgentExe)) {
    throw "Build completed without producing $StagedAgentExe."
}

$hash = (Get-FileHash -Path $StagedAgentExe -Algorithm SHA256).Hash.ToLowerInvariant()
$shortHash = $hash.Substring(0, 12)
$VersionedAgentExe = Join-Path $OutputDir "MiraProtectAgent-0.3.0-$shortHash.exe"
Copy-Item $StagedAgentExe $VersionedAgentExe -Force

$PublishedAgentExe = $AgentExe
$publishedCanonical = $false
for ($attempt = 1; $attempt -le 10; $attempt++) {
    try {
        Copy-Item $StagedAgentExe $AgentExe -Force -ErrorAction Stop
        $publishedCanonical = $true
        break
    }
    catch {
        if ($attempt -lt 10) {
            Start-Sleep -Milliseconds 500
        }
    }
}
if (-not $publishedCanonical) {
    $PublishedAgentExe = $VersionedAgentExe
    Write-Warning "The existing $AgentExe is locked. The new build was published as $VersionedAgentExe instead."
}
$gitCommit = "unknown"
$gitBranch = "unknown"
if (Get-Command git -ErrorAction SilentlyContinue) {
    $gitCommit = (& git -C $RepoRoot rev-parse HEAD 2>$null)
    if (-not $gitCommit) { $gitCommit = "unknown" }
    $gitBranch = (& git -C $RepoRoot branch --show-current 2>$null)
    if (-not $gitBranch) { $gitBranch = "unknown" }
}

$buildInfo = [ordered]@{
    product = "Mira Protect Endpoint Agent"
    version = "0.3.0"
    platform = "windows"
    architecture = $env:PROCESSOR_ARCHITECTURE
    built_at_utc = [DateTime]::UtcNow.ToString("o")
    git_commit = "$gitCommit".Trim()
    git_branch = "$gitBranch".Trim()
    sha256 = $hash
    agent_executable = $PublishedAgentExe
    canonical_executable = $AgentExe
    canonical_updated = $publishedCanonical
    validation_skipped = [bool]$SkipValidation
}
$buildInfo | ConvertTo-Json -Depth 4 | Set-Content -Path (Join-Path $OutputDir "BUILD-INFO.json") -Encoding UTF8
"$hash  MiraProtectAgent.exe" | Set-Content -Path (Join-Path $OutputDir "SHA256SUMS.txt") -Encoding ASCII

Copy-Item $StagedAgentExe (Join-Path $PackageDir "MiraProtectAgent.exe")
Copy-Item (Join-Path $OutputDir "BUILD-INFO.json") (Join-Path $PackageDir "BUILD-INFO.json")
Copy-Item (Join-Path $OutputDir "SHA256SUMS.txt") (Join-Path $PackageDir "SHA256SUMS.txt")
Copy-Item (Join-Path $RepoRoot "scripts\install-windows-agent.ps1") (Join-Path $PackageDir "install-windows-agent.ps1")
Copy-Item (Join-Path $RepoRoot "scripts\test-endpoint-protection.ps1") (Join-Path $PackageDir "test-endpoint-protection.ps1")
Copy-Item (Join-Path $RepoRoot "scripts\uninstall-windows-agent.ps1") (Join-Path $PackageDir "uninstall-windows-agent.ps1")
Copy-Item (Join-Path $RepoRoot "config\endpoint-agent.example.json") (Join-Path $PackageDir "endpoint-agent.example.json")
Copy-Item (Join-Path $RepoRoot "docs\windows-first-build.md") (Join-Path $PackageDir "WINDOWS-FIRST-BUILD.md")

$zipPath = Join-Path $OutputDir "MiraProtect-Windows-Test.zip"
Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
Compress-Archive -Path (Join-Path $PackageDir "*") -DestinationPath $zipPath -CompressionLevel Optimal

Write-Host ""
Write-Host "[PASS] Mira Protect Windows endpoint build completed." -ForegroundColor Green
Write-Host "Agent:      $PublishedAgentExe"
if (-not $publishedCanonical) {
    Write-Host "Canonical:  $AgentExe (locked; not replaced)" -ForegroundColor Yellow
}
Write-Host "SHA-256:    $hash"
Write-Host "Package:    $zipPath"
Write-Host "Build info: $(Join-Path $OutputDir "BUILD-INFO.json")"
