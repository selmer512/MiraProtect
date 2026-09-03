# Mira Protect

Mira Protect is an extensible, vendor-neutral enterprise AI security control plane for discovering, monitoring, governing, detecting, responding to, and protecting AI use across corporate environments.

The architecture is guided by the OWASP GenAI COMPASS Observe -> Orient -> Decide -> Act methodology and is intended to cover external AI-enabled threats, enterprise productivity AI, custom generative AI, agentic systems, local models, model APIs, and future deployment patterns without binding the platform to a single vendor.

## Current development branch

`develop/initial-ai-security-platform`

## Current milestone

The project is at an **enterprise development alpha / endpoint protection test** stage. The first supported test target is a Linux development endpoint operated from the CLI. Windows endpoint packaging remains in the repository for later testing.

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
- `monitor`, `guard`, and `enforce` endpoint modes
- Central endpoint deny policy
- Safe synthetic endpoint block test
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
| POST | `/api/v1/assets` | Register an AI-related asset |
| GET | `/api/v1/assets` | List known AI assets |
| POST | `/api/v1/events` | Ingest and evaluate normalized AI telemetry |
| GET | `/api/v1/events` | List events |
| GET | `/api/v1/findings` | List detection findings |
| GET | `/api/v1/threats` | List COMPASS-aligned threat content |
| GET | `/api/v1/dashboard/summary` | Return security summary counts |
| POST | `/api/v1/risk/score` | Calculate contextual AI risk |
| POST | `/api/v1/endpoint/heartbeat` | Register/update a managed endpoint |
| POST | `/api/v1/endpoint/process/evaluate` | Evaluate an endpoint process and return enforcement action |

## First test: Linux CLI protection

Requirements: Linux, Bash, Python 3.12+, and Python `venv` support.

```bash
git checkout develop/initial-ai-security-platform
chmod +x scripts/validate-local.sh scripts/test-linux-cli.sh
./scripts/validate-local.sh
./scripts/test-linux-cli.sh
```

The second script starts a local control plane and Linux endpoint agent, launches a harmless synthetic process carrying the dedicated Mira Protect test marker, verifies that the central policy returns `BLOCK`, verifies that the agent terminates the synthetic process in `enforce` mode, and confirms that the blocked event is persisted.

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
# Replace the example endpoint token before using a shared development environment.
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

- Per-device enrollment and stronger device identity
- Signed/versioned endpoint policy bundles and local policy cache
- TLS/mTLS deployment configuration
- RBAC for administrative APIs
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
  server.py          local control-plane launcher
  schemas.py         normalized domain/event models
  risk.py            AI risk engine
  policy.py          policy evaluation engine
  detection.py       normalized AI detections
  catalog.py         threat catalog
  collectors.py      collector SDK
  repository.py      persistence boundary
  endpoint_agent.py  managed endpoint process sensor/enforcer

scripts/
  validate-local.sh
  test-linux-cli.sh
  install-windows-agent.ps1
  test-endpoint-protection.ps1
  uninstall-windows-agent.ps1

docs/
  linux-cli-test.md
```

GitHub is used as the source repository. Validation is designed to run locally or inside the enterprise/commercial development environment rather than depending on GitHub Actions.
