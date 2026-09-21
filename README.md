# Mira Protect

Mira Protect is an extensible, vendor-neutral enterprise AI security control plane for discovering, monitoring, governing, detecting, responding to, and protecting AI use across corporate environments.

The architecture is guided by the OWASP GenAI COMPASS Observe -> Orient -> Decide -> Act methodology and is intended to cover external AI-enabled threats, enterprise productivity AI, custom generative AI, agentic systems, local models, model APIs, and future deployment patterns without binding the platform to a single vendor.

## Current development branch

`develop/initial-ai-security-platform`

## Current milestone

The project is at an **enterprise development alpha / TLS-mTLS transport milestone (0.4.0)** stage. The native Windows protection loop, persistent managed Windows monitor milestone, and secure control-plane authentication/revocation milestone have passed on Windows. Development is now validating a real certificate-backed HTTPS/mTLS control plane with the persistent Windows endpoint.

## Architecture

```text
Endpoint / Browser / SaaS / Network / Identity / Cloud / AI telemetry
                              |
                              v
                       Collector adapters
                              |
                              v
                     Universal AI events
                              |
                +-------------+-------------+
                |             |             |
                v             v             v
             Inventory     Detection      Policy
                |             |             |
                +-------------+-------------+
                              |
                              v
                         Persistence
                              |
                 +------------+------------+
                 |                         |
                 v                         v
            Investigation               Response
                                           |
                              monitor / guard / enforce
```

## Implemented foundation

- Vendor-neutral AI asset and event model
- User, device, identity, provider, model, data, agent, and tool context
- COMPASS-style threat catalog and initial detection content
- Contextual AI risk engine
- Deterministic policy engine with decision precedence
- Restricted/CUI data protection rule
- Human-approval control for AI-mediated production actions
- Unknown/unmanaged AI monitoring
- Endpoint process discovery and command-line inspection
- AI CLI/runtime discovery for tools such as Claude, Codex, Copilot, Cursor, Gemini, Ollama, LM Studio, Aider, and OpenCode
- Endpoint executable hashing
- Managed endpoint heartbeat and device inventory
- Per-device bootstrap enrollment and device-scoped credentials
- Endpoint credential revocation with audit evidence
- Security profiles for local, development, and production control planes
- Separate administrative API bearer authentication
- TLS server support and optional mutual TLS client-certificate enforcement
- Endpoint certificate verification, custom CA, and mTLS client identity support
- Remote Windows installer guardrail requiring HTTPS by default
- Versioned centralized endpoint policy distribution and local policy cache
- `monitor`, `guard`, and `enforce` endpoint modes
- Central endpoint deny policy
- Explicitly gated synthetic endpoint block test (`MIRA_ENABLE_TEST_CONTROLS`)
- Process termination enforcement for supported block decisions
- SQLite local development persistence
- PostgreSQL support for the containerized control plane
- FastAPI control plane
- CLI for health, inventory, events, findings, threats, and endpoint operation
- Local validation harness independent of GitHub Actions
- Windows installer/uninstaller prototype

## API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Service/database health |
| GET | `/ready` | Database and security-profile readiness |
| POST | `/api/v1/assets` | Register an AI-related asset |
| GET | `/api/v1/assets` | List known AI assets |
| POST | `/api/v1/events` | Ingest and evaluate normalized AI telemetry |
| GET | `/api/v1/events` | List events |
| GET | `/api/v1/findings` | List detection findings |
| GET | `/api/v1/threats` | List COMPASS-aligned threat content |
| GET | `/api/v1/dashboard/summary` | Return security summary counts |
| POST | `/api/v1/risk/score` | Calculate contextual AI risk |
| POST | `/api/v1/endpoint/enroll` | Exchange a bootstrap token for a per-device credential |
| GET | `/api/v1/endpoint/policy/{device_id}` | Retrieve authenticated versioned endpoint policy |
| POST | `/api/v1/endpoint/revoke/{device_id}` | Revoke a device credential (admin) |
| POST | `/api/v1/endpoint/heartbeat` | Register/update a managed endpoint |
| POST | `/api/v1/endpoint/process/evaluate` | Evaluate an endpoint process and return enforcement action |

## First build and test: Windows endpoint

Run this from native Windows PowerShell, not WSL, because the build produces a native Windows executable:

```powershell
git checkout develop/initial-ai-security-platform
git pull
powershell -ExecutionPolicy Bypass -File .\scripts\test-windows-local.ps1
```

The Windows harness validates the source, builds `MiraProtectAgent.exe` locally with PyInstaller, starts a loopback control plane, registers the built endpoint agent, launches a harmless synthetic target, verifies the central `BLOCK` decision, confirms process termination and enforcement acknowledgement, verifies persistence, and writes `.mira-test-windows\validation-report.json`.

Build artifacts are written under `dist\windows\`, including `MiraProtect-Windows-Test.zip`, `BUILD-INFO.json`, and `SHA256SUMS.txt`. Detailed instructions are in `docs/windows-first-build.md`.

The synthetic protection path is disabled by default and is enabled only inside the isolated local test through `MIRA_ENABLE_TEST_CONTROLS=true`.

## Next milestone test: persistent managed Windows monitor

After pulling the latest branch, open Windows PowerShell as Administrator and run:

    powershell -ExecutionPolicy Bypass -File .\scripts\test-windows-managed-monitor.ps1

This isolated harness rebuilds the endpoint, starts an enrollment-enabled control plane, installs the compiled agent as a persistent SYSTEM scheduled task, exchanges a bootstrap enrollment token for a per-device credential, downloads/caches versioned policy, and validates a centrally denied Notepad process in monitor mode. This milestone has passed on Windows: the control plane recorded BLOCK while Notepad remained running.

The milestone report is written to .mira-test-managed-windows\validation-report.json. The isolated scheduled task and ProgramData test directory are removed during cleanup.

## Secure control-plane milestone

Mira Protect 0.4.0 adds secure deployment controls before a remote development control plane is introduced.

From elevated Windows PowerShell:

    git pull
    powershell -ExecutionPolicy Bypass -File .\scripts\test-control-plane-security.ps1

The harness rebuilds and validates the project, proves a development-profile server refuses an insecure remote bind, verifies readiness checks, confirms the enrollment token cannot access administrative APIs, validates the separate admin credential, enrolls a device, revokes its credential, verifies the revoked credential is rejected, and confirms revocation evidence is persisted.

Direct TLS is supported with MIRA_TLS_CERT_FILE and MIRA_TLS_KEY_FILE. Optional mTLS uses MIRA_TLS_CLIENT_CA_FILE plus MIRA_TLS_REQUIRE_CLIENT_CERT=true. Approved reverse-proxy TLS termination can be declared with MIRA_TLS_TERMINATED_UPSTREAM=true.

Managed Windows endpoints require HTTPS for non-loopback control planes unless the installer is explicitly invoked with -AllowInsecureHttp for an isolated development network. Endpoint configuration supports a custom CA bundle and an optional client certificate/key pair.

## TLS/mTLS transport acceptance

The secure control-plane authentication/revocation milestone has passed on Windows. The next acceptance gate exercises the actual TLS stack rather than only configuration enforcement.

From elevated Windows PowerShell:

    git pull
    powershell -ExecutionPolicy Bypass -File .\scripts\test-windows-tls-mtls.ps1

The harness generates a short-lived local test CA, server certificate, and client certificate; starts the control plane with direct TLS and required client certificates; proves a client without a certificate is rejected; verifies the administrative API over mTLS; installs the Windows endpoint as SYSTEM; enrolls it through the agent's TLS stack; downloads the versioned policy; and verifies the persistent endpoint heartbeat over mutual TLS.

Evidence is written under .mira-test-tls-mtls. Ephemeral private keys are removed during normal cleanup and the entire test directory is ignored by Git.

## Secondary test: Linux CLI protection

The Linux CLI harness remains available for cross-platform development validation:

```bash
git checkout develop/initial-ai-security-platform
git pull
chmod +x scripts/validate-local.sh scripts/test-linux-cli.sh
./scripts/test-linux-cli.sh
```

Detailed instructions are in `docs/linux-cli-test.md`.

## CLI quick reference

After `pip install -e '.[dev]'`:

```bash
mira-protect doctor
mira-protect health
mira-protect summary
mira-protect assets
mira-protect events --limit 50
mira-protect findings --limit 50
mira-protect threats
mira-protect agent --once --mode monitor
```

Run the control plane directly:

```bash
mira-protect-server --host 127.0.0.1 --port 8080
```

Run the endpoint agent directly:

```bash
export MIRA_CONTROL_PLANE_URL=http://127.0.0.1:8080
export MIRA_AGENT_MODE=monitor
mira-protect-agent
```

## Containerized control plane

```bash
cp .env.example .env
# Configure enrollment, admin, and credential-pepper secrets before using a shared development environment.
# Set MIRA_SECURITY_PROFILE=development or production for non-local deployments.
docker compose up --build
```

OpenAPI documentation is available at `http://localhost:8080/docs` when running locally.

## Endpoint operating modes

- **monitor** — collect and evaluate activity without preventative endpoint action.
- **guard** — surface preventative decisions and findings without terminating processes.
- **enforce** — apply supported block decisions. The current prototype supports process termination.

Enterprise rollout should progress from monitor -> guard -> enforce after telemetry and policy have been reviewed.

## Core design principles

1. **Vendor neutral** — providers are adapters rather than architectural dependencies.
2. **AI is part of the enterprise attack surface** — users, identities, devices, applications, data, agents, tools, APIs, and infrastructure must be correlated.
3. **Trace actions end-to-end** — AI activity should remain attributable from the initiating human/workload through model/tool use to the resulting action.
4. **Monitor, guard, and enforce** — the same normalized policy layer should support passive visibility and preventative controls.
5. **Extensible threat content** — new attacks should be expressible as detections and policies instead of requiring architectural redesign.
6. **Continuous COMPASS** — Observe, Orient, Decide, and Act should become an operational loop rather than a periodic spreadsheet exercise.

## Next commercial-development milestones

- Certificate-backed device identity beyond bearer-token enrollment
- Signed policy/update artifacts and policy provenance
- Role-based administrative API authorization beyond the current separate admin credential
- Database migrations
- Linux service packaging and Windows managed packaging
- Expanded endpoint/network/browser discovery
- SIEM/SOAR and DLP integrations
- AI security graph and execution lineage
- Tamper resistance and controlled agent update mechanism
- Expanded detection and response content across COMPASS Profiles 1, 2A, 2B, and 2C

## Repository layout

```text
src/mira_protect/
  app.py             FastAPI control plane
  cli.py             operator/development CLI
  server.py          security-aware control-plane launcher
  security.py        deployment security profiles/readiness
  schemas.py         normalized domain/event models
  risk.py            AI risk engine
  policy.py          policy evaluation engine
  detection.py       normalized AI detections
  catalog.py         threat catalog
  collectors.py      collector SDK
  repository.py      persistence boundary
  endpoint_agent.py  managed endpoint process sensor/enforcer

scripts/
  build-windows-agent.ps1
  test-windows-local.ps1
  test-windows-managed-monitor.ps1
  test-control-plane-security.ps1
  test-windows-tls-mtls.ps1
  generate-test-pki.py
  windows_agent_entry.py
  validate-local.sh
  test-linux-cli.sh
  install-windows-agent.ps1
  test-endpoint-protection.ps1
  uninstall-windows-agent.ps1

docs/
  windows-first-build.md
  linux-cli-test.md
```

GitHub is used only as the source repository for this project. Validation and packaging are designed to run locally or inside the enterprise/commercial development environment; GitHub Actions is not part of the test or readiness model.
