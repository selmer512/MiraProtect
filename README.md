# Mira Protect

Mira Protect is an extensible, vendor-neutral enterprise AI security control plane for discovering, monitoring, governing, detecting, responding to, and protecting AI use across corporate environments.

The architecture is guided by the OWASP GenAI COMPASS Observe -> Orient -> Decide -> Act methodology and is intended to cover external AI-enabled threats, enterprise productivity AI, custom generative AI, agentic systems, local models, model APIs, and future deployment patterns without binding the platform to a single vendor.

## Current development branch

`develop/real-ai-cli-observability`

## Current milestone

Version `0.3.0` adds **real AI CLI discovery plus monitor/guard validation** on Linux. Mira Protect now distinguishes AI software discovery from security detection and from enforcement. Discovering a real AI tool does not automatically terminate it.

The previously validated synthetic Linux endpoint protection test remains available for the controlled `BLOCK -> terminate -> confirm -> persist` path.

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
- Deterministic policy engine with explicit allow/deny controls
- Restricted/CUI data protection rule
- Human-approval control for AI-mediated production actions
- Unknown/unmanaged AI monitoring
- Real AI CLI/runtime discovery and provider/product classification
- Signatures for Claude Code, Codex CLI, GitHub Copilot CLI, Gemini CLI, Ollama, LM Studio, Cursor, Aider, and OpenCode
- AI application inventory tied to endpoint/device identity
- Executable SHA-256 caching
- Parent-process lineage collection
- Managed endpoint heartbeat and health status
- Versioned endpoint policy distribution contract
- Endpoint policy-version reporting
- Bounded local telemetry queue for failed heartbeat/enforcement reports
- Safer cached-policy offline behavior
- `monitor`, `guard`, and `enforce` endpoint modes
- Safe synthetic endpoint block test
- Process termination enforcement for supported explicit block decisions
- SQLite local development persistence
- PostgreSQL support for the containerized control plane
- FastAPI control plane
- CLI for health, AI inventory, devices, policy, events, findings, threats, and endpoint operation
- Local validation harness independent of GitHub Actions
- Windows installer/uninstaller prototype

## API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Service/database/policy health |
| POST | `/api/v1/assets` | Register an AI-related asset |
| GET | `/api/v1/assets` | List known assets |
| GET | `/api/v1/ai-inventory` | List discovered AI applications |
| POST | `/api/v1/events` | Ingest and evaluate normalized AI telemetry |
| GET | `/api/v1/events` | List events |
| GET | `/api/v1/findings` | List detection findings |
| GET | `/api/v1/threats` | List COMPASS-aligned threat content |
| GET | `/api/v1/dashboard/summary` | Return security posture counts |
| POST | `/api/v1/risk/score` | Calculate contextual AI risk |
| GET | `/api/v1/endpoint/policy` | Return the active endpoint policy bundle |
| GET | `/api/v1/endpoint/devices` | Return managed endpoint health/status |
| POST | `/api/v1/endpoint/heartbeat` | Register/update a managed endpoint |
| POST | `/api/v1/endpoint/process/evaluate` | Classify/evaluate endpoint process telemetry |
| POST | `/api/v1/endpoint/enforcement` | Persist endpoint enforcement confirmation |

## Linux validation paths

### 1. Synthetic enforcement path

```bash
git checkout develop/real-ai-cli-observability
PYTHON_BIN=python3.12 bash scripts/test-linux-cli.sh
```

This verifies the controlled synthetic terminate path without targeting a real AI application.

### 2. Real AI CLI monitor/guard path

```bash
PYTHON_BIN=python3.12 bash scripts/test-linux-ai-monitor-guard.sh
```

The script searches for an installed `claude`, `codex`, `gemini`, `aider`, `ollama`, or `opencode` CLI. You can provide an explicit harmless command instead:

```bash
MIRA_AI_TEST_TOOL=claude \
MIRA_AI_TEST_COMMAND='claude --version' \
PYTHON_BIN=python3.12 \
bash scripts/test-linux-ai-monitor-guard.sh
```

Phase 1 validates real AI discovery in `monitor` mode. Phase 2 restarts in `guard` mode with an explicit central deny rule for the process discovered in phase 1 and verifies `BLOCK -> notify` with **no termination**.

Detailed implementation and acceptance criteria are in `docs/real-ai-cli-milestone.md`.

## CLI quick reference

After `pip install -e '.[dev]'`:

```bash
mira-protect doctor
mira-protect health
mira-protect summary
mira-protect devices
mira-protect inventory
mira-protect policy
mira-protect assets
mira-protect events --limit 50
mira-protect events --phase discovery
mira-protect findings --limit 50
mira-protect threats
mira-protect agent --once --mode monitor
```

## Endpoint operating modes

- **monitor** — discover, classify, evaluate, and record without preventative endpoint action.
- **guard** — surface explicit blocking decisions and findings without terminating processes.
- **enforce** — apply supported explicit block decisions. The current endpoint action is process termination.

Enterprise rollout should progress from monitor -> guard -> enforce only after the observed AI inventory and policy effects have been reviewed.

## Policy configuration

The v0.3 policy source is environment-backed and versioned. Key settings are documented in `.env.example`:

```text
MIRA_POLICY_VERSION
MIRA_ENDPOINT_ALLOW_PROCESSES
MIRA_ENDPOINT_DENY_PROCESSES
MIRA_APPROVED_AI_PROVIDERS
MIRA_ENABLE_TEST_CONTROLS
MIRA_OFFLINE_FAIL_CLOSED_ALLOWED
```

Allow entries take precedence when the same exact process is present in both allow and deny lists.

## Repository layout

```text
src/mira_protect/
  app.py             FastAPI control plane
  cli.py             operator/development CLI
  server.py          local control-plane launcher
  schemas.py         normalized domain/event models
  providers.py       AI product signature/classification registry
  policy_config.py   versioned endpoint policy source
  policy.py          policy evaluation engine
  detection.py       normalized AI detections
  catalog.py         threat catalog
  collectors.py      collector SDK
  repository.py      persistence boundary
  endpoint_agent.py  managed endpoint sensor/enforcer

scripts/
  validate-local.sh
  test-linux-cli.sh
  test-linux-ai-monitor-guard.sh
  install-windows-agent.ps1
  test-endpoint-protection.ps1
  uninstall-windows-agent.ps1

docs/
  linux-cli-test.md
  real-ai-cli-milestone.md
```

GitHub is used as the source repository. Validation runs locally or inside the enterprise/commercial development environment rather than depending on GitHub Actions.
