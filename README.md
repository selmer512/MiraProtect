# Mira Protect

Mira Protect is an extensible, vendor-neutral enterprise AI security control plane for discovering, monitoring, governing, detecting, responding to, and protecting AI use across corporate environments.

The initial design is based on the OWASP GenAI COMPASS Observe → Orient → Decide → Act methodology and is intended to cover external AI-enabled threats, enterprise productivity AI, custom generative AI, agentic systems, local models, model APIs, and future AI deployment patterns without binding the platform to one vendor.

## Current development branch

`develop/initial-ai-security-platform`

## Initial architecture

```text
AI / Endpoint / SaaS / Network / Identity / Cloud telemetry
                         |
                         v
                  Collector adapters
                         |
                         v
                Universal AI events
                         |
          +--------------+--------------+
          |              |              |
          v              v              v
       Inventory      Risk Engine    Policy Engine
          |              |              |
          +--------------+--------------+
                         |
                         v
                AI Security Graph
                         |
             +-----------+-----------+
             |                       |
             v                       v
       Detection/IR              Governance
```

## Implemented in v0.1 foundation

- Vendor-neutral AI asset model
- Universal AI event schema
- AI actor, model, data, tool, and security contexts
- Deployment classifications spanning embedded AI through custom enterprise models
- COMPASS-style 5x5 base risk scoring with AI-specific contextual factors
- Extensible policy-rule engine
- Initial restricted-data protection rule
- Human-approval control for AI actions against production systems
- Unknown-provider monitoring rule
- FastAPI ingestion and inventory API
- Local Docker development stack
- Initial unit tests

## API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Service health |
| POST | `/api/v1/assets` | Register an AI-related asset |
| GET | `/api/v1/assets` | List known AI assets |
| POST | `/api/v1/events` | Ingest and evaluate normalized AI telemetry |
| GET | `/api/v1/events` | List ingested events |
| POST | `/api/v1/risk/score` | Calculate contextual AI risk |

## Run locally

```bash
docker compose up --build
```

Then open:

```text
http://localhost:8080/docs
```

## Core design principles

1. **Vendor neutral** — providers are adapters, not architectural dependencies.
2. **AI is part of the enterprise attack surface** — users, identities, devices, applications, data, agents, tools, APIs, and infrastructure are correlated together.
3. **Trace actions end-to-end** — AI activity should be attributable from initiating human or workload through model reasoning context, tool use, identity, target, and resulting action.
4. **Monitor, guard, and enforce** — policy evaluation is designed to support passive visibility, approval workflows, and preventative controls.
5. **Extensible threat content** — new AI attacks should be expressible as detections and policies rather than requiring architectural changes.
6. **Continuous COMPASS** — Observe, Orient, Decide, and Act should become an ongoing operational cycle rather than a periodic spreadsheet assessment.

## Next implementation milestones

### Phase 1 — Persistence and inventory
- PostgreSQL repositories for assets, events, identities, relationships, and findings
- Alembic migrations
- AI asset relationship graph
- provider and application inventory APIs

### Phase 2 — Collection framework
- collector SDK/interface
- browser and endpoint discovery adapters
- generic HTTP/API gateway telemetry adapter
- Microsoft, OpenAI, Anthropic, Google, AWS, and local-model adapters

### Phase 3 — Detection content
- COMPASS Profile 1 external AI threat detections
- Profile 2A enterprise AI governance detections
- Profile 2B productivity AI detections
- Profile 2C agentic and generative AI detections
- ATT&CK / ATLAS / CWE metadata mappings

### Phase 4 — Security graph and execution trace
- human → device → app → model → agent → tool → identity → resource lineage
- session and action reconstruction
- blast-radius analysis

### Phase 5 — Enforcement and response
- approval workflows
- tool authorization
- DLP decisions
- provider restrictions
- token/session revocation integrations
- AI-specific incident response playbooks

## Repository layout

```text
src/mira_protect/
  app.py       FastAPI service
  schemas.py   vendor-neutral domain/event models
  risk.py      AI risk engine
  policy.py    policy evaluation engine

tests/
  test_core.py
```

This repository is under active development.
