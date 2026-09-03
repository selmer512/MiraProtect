# Linux CLI enterprise protection test

This is the first supported Mira Protect endpoint protection test path. It is designed for an isolated Linux development system and does not require GitHub Actions.

## What this test proves

The test performs local lint/unit/import validation, starts a Mira Protect control plane, runs the endpoint agent in `enforce` mode, registers the Linux device, launches a harmless synthetic process containing the Mira Protect test marker, receives a central `BLOCK` decision, terminates that process, reports the enforcement result back to the control plane, persists the decision and enforcement evidence, and verifies the expected policy rule.

The synthetic target does not perform a malicious action. Its command line includes `--mira-protect-test-block`, which exists only to exercise the protection path safely. Synthetic test controls are disabled by default in normal v0.3 deployments and are enabled explicitly by this test script.

## Requirements

- Linux
- Bash
- Python 3.12+
- Python `venv` support
- Network access for the initial Python dependency installation
- Permission to inspect and terminate processes owned by the account running the test

Docker is not required for this first test. The test uses a temporary local SQLite database so the endpoint protection path can be validated with the fewest dependencies.

## Run the complete test

From the repository root on branch `develop/real-ai-cli-observability`:

```bash
PYTHON_BIN=python3.12 bash scripts/test-linux-cli.sh
```

The script automatically runs `scripts/validate-local.sh` first. To run validation separately:

```bash
PYTHON_BIN=python3.12 bash scripts/validate-local.sh
```

To skip that validation on a repeat protection run:

```bash
MIRA_SKIP_VALIDATION=1 PYTHON_BIN=python3.12 bash scripts/test-linux-cli.sh
```

The protection test uses TCP port `18080` by default. Override it if required:

```bash
MIRA_TEST_PORT=28080 PYTHON_BIN=python3.12 bash scripts/test-linux-cli.sh
```

Successful output ends with:

```text
[PASS] Linux CLI enterprise protection smoke test completed
```

The test writes its logs and SQLite database to `.mira-test/`:

```text
.mira-test/server.log
.mira-test/agent.log
.mira-test/target.log
.mira-test/telemetry-queue.jsonl
.mira-test/mira.db
```

## Automated pass criteria

The script fails unless all of the following occur:

1. The package installs successfully in a Python 3.12+ virtual environment.
2. Ruff completes successfully.
3. Pytest completes successfully.
4. The application, CLI, and endpoint agent import successfully.
5. The control plane reports healthy database state.
6. The Linux endpoint heartbeat is registered as a managed device.
7. The synthetic process is discovered by the endpoint agent.
8. `endpoint-synthetic-protection-test` returns a central `BLOCK` decision.
9. The endpoint agent terminates the synthetic target in `enforce` mode.
10. The agent reports successful enforcement back to the control plane.
11. The policy decision and enforcement confirmation are persisted.

## Manual CLI test

Create and activate the environment:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

Start a local control plane in terminal 1:

```bash
export MIRA_DATABASE_URL='sqlite+pysqlite:///./mira-protect-test.db'
export MIRA_ENDPOINT_TOKEN='replace-this-test-token'
export MIRA_ENABLE_TEST_CONTROLS='true'
export MIRA_POLICY_VERSION='manual-synthetic-test'
mira-protect-server --host 127.0.0.1 --port 8080
```

Check it from terminal 2:

```bash
source .venv/bin/activate
export MIRA_CONTROL_PLANE_URL='http://127.0.0.1:8080'
export MIRA_AGENT_TOKEN='replace-this-test-token'
mira-protect doctor
mira-protect health
mira-protect policy
```

Start the endpoint agent in enforce mode:

```bash
export MIRA_AGENT_MODE='enforce'
export MIRA_POLL_SECONDS='0.5'
export MIRA_HEARTBEAT_SECONDS='2'
mira-protect-agent
```

In terminal 3, launch the harmless protection target:

```bash
source .venv/bin/activate
mira-protect synthetic-target --seconds 120 --mira-protect-test-block
```

The target should be terminated by the agent. The agent terminal should record both `process_terminated` and `enforcement_reported` events.

Inspect the resulting control-plane data:

```bash
mira-protect summary
mira-protect devices
mira-protect assets
mira-protect events --limit 20
mira-protect findings --limit 20
```

The summary should show at least one managed device, one blocked event, and one successful enforcement action.

## Expected security path

```text
Linux process
   -> endpoint process discovery
   -> normalized endpoint.process event
   -> central policy evaluation
   -> endpoint-synthetic-protection-test = BLOCK
   -> enforce decision returned to agent
   -> process terminated
   -> endpoint.enforcement confirmation
   -> decision and enforcement evidence persisted
```

## Rollout behavior

The endpoint agent has three modes:

- `monitor`: record policy results, never terminate.
- `guard`: notify/record a preventative decision, but do not terminate.
- `enforce`: apply supported blocking decisions, including process termination.

The synthetic smoke test intentionally uses `enforce` only against the dedicated test target. Real AI tooling should be validated through `scripts/test-linux-ai-monitor-guard.sh` before any real process is considered for enforcement policy.

## Troubleshooting

If the test fails, preserve `.mira-test/` and review `server.log` and `agent.log`. Run `mira-protect doctor` to confirm the API and database are healthy. If the endpoint agent cannot inspect another user's process, run both the agent and synthetic target under the same account for this initial test.
