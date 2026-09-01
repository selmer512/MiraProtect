# Linux CLI enterprise protection test

This is the first supported Mira Protect endpoint protection test path. It is designed for an isolated Linux development system and does not require GitHub Actions.

## What this test proves

The test starts a local Mira Protect control plane, runs the endpoint agent in `enforce` mode, registers the Linux device, launches a harmless synthetic process containing the Mira Protect test marker, receives a central `BLOCK` decision, terminates that process, persists the security event, and verifies the expected policy rule.

The synthetic target does not perform a malicious action. Its command line includes `--mira-protect-test-block`, which exists only to exercise the protection path safely.

## Requirements

- Linux
- Bash
- Python 3.12+
- Python `venv` support
- Network access for the initial Python dependency installation
- Permission to inspect and terminate processes owned by the account running the test

Docker is not required for this first test. The test uses a temporary local SQLite database so the endpoint protection path can be validated with the fewest dependencies.

## Run the complete test

From the repository root on branch `develop/initial-ai-security-platform`:

```bash
chmod +x scripts/test-linux-cli.sh scripts/validate-local.sh
./scripts/validate-local.sh
./scripts/test-linux-cli.sh
```

The protection test uses TCP port `18080` by default. Override it if required:

```bash
MIRA_TEST_PORT=28080 ./scripts/test-linux-cli.sh
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
.mira-test/mira.db
```

## Manual CLI test

Create and activate the environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

Start a local control plane in terminal 1:

```bash
export MIRA_DATABASE_URL='sqlite+pysqlite:///./mira-protect-test.db'
export MIRA_ENDPOINT_TOKEN='replace-this-test-token'
mira-protect-server --host 127.0.0.1 --port 8080
```

Check it from terminal 2:

```bash
source .venv/bin/activate
export MIRA_CONTROL_PLANE_URL='http://127.0.0.1:8080'
export MIRA_AGENT_TOKEN='replace-this-test-token'
mira-protect doctor
mira-protect health
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

The target should be terminated by the agent. The agent terminal should record a `process_terminated` event.

Inspect the resulting control-plane data:

```bash
mira-protect summary
mira-protect assets
mira-protect events --limit 20
mira-protect findings --limit 20
```

## Expected security path

```text
Linux process
   -> endpoint process discovery
   -> normalized endpoint.process event
   -> central policy evaluation
   -> endpoint-synthetic-protection-test = BLOCK
   -> enforce decision returned to agent
   -> process terminated
   -> event persisted
```

## Rollout behavior

The endpoint agent has three modes:

- `monitor`: record policy results, never terminate.
- `guard`: notify/record a preventative decision, but do not terminate.
- `enforce`: apply supported blocking decisions, including process termination.

The first automated Linux smoke test intentionally uses `enforce` only against the dedicated synthetic target. Do not populate real process deny lists until monitor/guard telemetry has been reviewed.

## Troubleshooting

If the test fails, preserve `.mira-test/` and review `server.log` and `agent.log`. Run `mira-protect doctor` to confirm the API and database are healthy. If the endpoint agent cannot inspect another user's process, run both the agent and synthetic target under the same account for this initial test.
