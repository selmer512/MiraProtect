# Windows first build and endpoint protection test

Windows is the first supported Mira Protect endpoint build target. This path builds a native Windows endpoint executable locally, validates the Python source, starts a loopback control plane, runs the built endpoint agent, exercises a harmless central block decision, verifies endpoint termination, and writes a machine-readable validation report.

GitHub is source control only. This procedure does not use GitHub Actions.

## Requirements

- Windows 10 or Windows 11
- 64-bit Python 3.12 or newer
- PowerShell 5.1 or PowerShell 7+
- Git
- Internet access for the initial Python package installation
- Run from native Windows PowerShell, not WSL, because PyInstaller creates an executable for the operating system on which it runs

Administrator rights are not required for the first local same-user test. The later managed installation path uses an elevated PowerShell session because it installs a startup task under SYSTEM.

## One-command first build and test

From the MiraProtect repository:

```powershell
git checkout develop/initial-ai-security-platform
git pull
powershell -ExecutionPolicy Bypass -File .\scripts\test-windows-local.ps1
```

The test script calls `build-windows-agent.ps1` automatically. The build performs Ruff and Pytest validation before producing the endpoint executable.

## Expected build outputs

```text
dist\windows\MiraProtectAgent.exe
dist\windows\MiraProtect-Windows-Test.zip
dist\windows\BUILD-INFO.json
dist\windows\SHA256SUMS.txt
```

The ZIP contains the endpoint executable, checksum/build information, example endpoint configuration, installer, endpoint test script, and uninstaller.

## Expected test outputs

```text
.mira-test-windows\validation-report.json
.mira-test-windows\server.out.log
.mira-test-windows\server.err.log
.mira-test-windows\agent.out.log
.mira-test-windows\agent.err.log
.mira-test-windows\target.out.log
.mira-test-windows\target.err.log
.mira-test-windows\mira.db
```

A successful run ends with:

```text
[PASS] Mira Protect Windows first-build test completed.
```

The validation report records the built endpoint SHA-256, operating system, control-plane address, enforcement mode, build metadata, completed checks, and final dashboard counts.

## What the test actually proves

The Windows test validates this path:

```text
Windows endpoint
   -> locally built MiraProtectAgent.exe
   -> process and command-line discovery
   -> authenticated endpoint heartbeat
   -> normalized endpoint.process event
   -> central deterministic policy evaluation
   -> endpoint-synthetic-protection-test = BLOCK
   -> enforce decision returned to Windows agent
   -> harmless synthetic target terminated
   -> endpoint.enforcement acknowledgement
   -> decision and enforcement evidence persisted
   -> validation-report.json
```

The synthetic control is deliberately gated. `MIRA_ENABLE_TEST_CONTROLS` defaults to `false`; the local harness enables it only for the loopback test. If the control plane becomes unavailable and `MIRA_FAIL_CLOSED=false`, the synthetic marker does not cause an offline termination.

## Build only

To create the Windows endpoint package without running the end-to-end protection test:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build-windows-agent.ps1
```

Do not use `-SkipValidation` for an acceptance build.

## Re-run the endpoint test without rebuilding

After a successful build:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\test-windows-local.ps1 -SkipBuild
```

## If the test fails

Preserve `.mira-test-windows\`. The most useful files are:

```powershell
Get-Content .\.mira-test-windows\server.err.log
Get-Content .\.mira-test-windows\agent.out.log
Get-Content .\.mira-test-windows\agent.err.log
Get-Content .\.mira-test-windows\validation-report.json -ErrorAction SilentlyContinue
```

Also provide the terminal output from `test-windows-local.ps1`.

## After the first local pass

The next Windows gate is the managed installation path:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install-windows-agent.ps1 \
  -ControlPlaneUrl "https://<development-control-plane>" \
  -Mode monitor \
  -Token "<development-endpoint-token>" \
  -AgentBinary ".\dist\windows\MiraProtectAgent.exe"
```

That stage should begin in `monitor` mode. Guard and enforce modes should only be enabled after reviewing endpoint telemetry and centrally configured policy.
