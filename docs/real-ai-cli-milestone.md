# Real AI CLI observability milestone (v0.3.0)

This milestone moves Mira Protect beyond the dedicated synthetic enforcement target and into safe observation of real AI command-line tools on managed Linux endpoints.

## What changed

Mira Protect now separates three concepts that were previously too close together:

1. **Discovery** — identify that an AI application/process exists and attribute provider/product, device, user, executable, hash, parent chain, and policy version.
2. **Detection** — create a security finding when the observed behavior warrants review, such as an AI provider that has not been approved.
3. **Enforcement** — take preventative action only when an explicit central policy returns a blocking decision and the endpoint is running in `enforce` mode.

Discovering Claude Code, Codex CLI, Gemini CLI, GitHub Copilot CLI, Ollama, LM Studio, Cursor, Aider, or OpenCode does **not** by itself terminate the process.

## New control-plane capabilities

- `GET /api/v1/ai-inventory` — discovered endpoint AI applications.
- `GET /api/v1/endpoint/devices` — endpoint health, mode, policy version, queue depth, and last heartbeat.
- `GET /api/v1/endpoint/policy` — active versioned endpoint policy bundle.
- Endpoint process decisions now return policy version, policy reason codes, and classification/evidence fields.
- Endpoint discoveries register deterministic AI application assets tied to the device.
- Dashboard summary now includes AI application count and online/stale/offline device counts.

## Provider/product classification

Signatures live in `src/mira_protect/providers.py`. They are intentionally isolated from policy so additional AI tools can be added without adding vendor-specific logic to the control plane or endpoint agent.

Current signatures include:

- Anthropic Claude Code
- OpenAI Codex CLI
- GitHub Copilot CLI
- Google Gemini CLI
- Ollama
- LM Studio
- Cursor
- Aider
- OpenCode

Both process names and wrapper command lines are evaluated. This allows Mira Protect to identify AI tools launched through Node, Python, shell wrappers, or package-manager shims.

## Versioned endpoint policy

The first policy distribution contract is environment-backed and exposed through `/api/v1/endpoint/policy`. It contains:

- `version`
- `allow_processes`
- `deny_processes`
- `approved_providers`
- `test_controls_enabled`
- `offline_fail_closed_allowed`

The environment-backed implementation is an interim policy source. The endpoint and policy-engine contracts are designed so a database-backed policy service can replace it later.

Allowlist entries take precedence over deny entries for the same exact process name.

## Safer offline behavior

The endpoint no longer treats the synthetic test marker as an automatic offline block. When the control plane is unreachable, the endpoint defaults to observation.

Offline process termination requires all of the following:

- endpoint `fail_closed=true`
- the cached policy explicitly enables `offline_fail_closed_allowed`
- the process is in the cached explicit deny list
- the process is not in the cached allow list

This prevents loss of the control plane from turning generic AI discovery into broad local process termination.

## Telemetry queue

Failed heartbeat and enforcement-report telemetry is written to a bounded local JSONL queue and retried after connectivity is restored. The default queue is:

```text
~/.mira-protect/telemetry-queue.jsonl
```

The location and maximum item count are configurable.

## Executable hashing and lineage

Executable SHA-256 values are cached using path + file size + modification time so repeated observations do not re-hash unchanged binaries.

Endpoint process observations also include a configurable parent-process chain. The default depth is four processes.

## Linux acceptance test

The next acceptance test uses a **real installed AI CLI**. It first runs the tool in `monitor` mode, verifies inventory/classification, and confirms there is no termination. It then restarts the endpoint in `guard` mode with an explicit central deny rule for the process discovered during phase one. The expected result is `BLOCK -> notify`, not termination.

Run from the repository root:

```bash
PYTHON_BIN=python3.12 bash scripts/test-linux-ai-monitor-guard.sh
```

The script automatically looks for one of:

```text
claude
codex
gemini
aider
ollama
opencode
```

If a supported tool is not on `PATH`, provide a harmless command explicitly:

```bash
MIRA_AI_TEST_TOOL=claude \
MIRA_AI_TEST_COMMAND='claude --version' \
PYTHON_BIN=python3.12 \
bash scripts/test-linux-ai-monitor-guard.sh
```

The test intentionally uses version/help-style commands. Do not use a command that changes production resources.

Successful completion ends with:

```text
[PASS] Real AI CLI monitor/guard milestone test completed
```

Evidence is retained under:

```text
.mira-ai-test/
```

## Expected security behavior

### Monitor

```text
real AI CLI
  -> discovered
  -> provider/product classified
  -> AI application registered
  -> policy evaluated
  -> finding generated when appropriate
  -> observe only
```

### Guard

```text
real AI CLI
  -> explicit central deny rule
  -> BLOCK decision
  -> endpoint guard mode
  -> notify/record
  -> no process termination
```

### Enforce

Real AI tooling should not be placed into enforce-mode deny policy until monitor/guard evidence has been reviewed. The existing synthetic endpoint test remains the supported end-to-end process-termination test for this milestone.
