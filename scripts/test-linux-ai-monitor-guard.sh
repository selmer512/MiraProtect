#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
PORT="${MIRA_AI_TEST_PORT:-18081}"
TEST_ROOT="${MIRA_AI_TEST_ROOT:-$ROOT_DIR/.mira-ai-test}"
VENV_DIR="${MIRA_TEST_VENV:-$ROOT_DIR/.venv}"
CONTROL_PLANE_URL="http://127.0.0.1:${PORT}"
TOKEN="${MIRA_ENDPOINT_TOKEN:-mira-ai-observability-test-token-change-me}"

SERVER_PID=""
AGENT_PID=""
TEST_COMMAND="${MIRA_AI_TEST_COMMAND:-}"
TOOL_NAME="${MIRA_AI_TEST_TOOL:-}"

cleanup() {
  set +e
  if [[ -n "$AGENT_PID" ]] && kill -0 "$AGENT_PID" 2>/dev/null; then
    kill "$AGENT_PID" 2>/dev/null || true
    wait "$AGENT_PID" 2>/dev/null || true
  fi
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

pass() {
  echo "[PASS] $*"
}

info() {
  echo "[INFO] $*"
}

stop_agent() {
  if [[ -n "$AGENT_PID" ]] && kill -0 "$AGENT_PID" 2>/dev/null; then
    kill "$AGENT_PID" 2>/dev/null || true
    wait "$AGENT_PID" 2>/dev/null || true
  fi
  AGENT_PID=""
}

stop_server() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  SERVER_PID=""
}

select_ai_command() {
  if [[ -n "$TEST_COMMAND" ]]; then
    [[ -n "$TOOL_NAME" ]] || TOOL_NAME="custom"
    return
  fi

  local candidate
  for candidate in claude codex gemini aider ollama opencode; do
    if command -v "$candidate" >/dev/null 2>&1; then
      TOOL_NAME="$candidate"
      TEST_COMMAND="$candidate --version"
      return
    fi
  done

  fail "No supported AI CLI was found. Set MIRA_AI_TEST_COMMAND='claude --version' (or another installed AI CLI command) and retry."
}

start_server() {
  local deny_process="$1"
  local policy_version="$2"
  export MIRA_DATABASE_URL="sqlite+pysqlite:///$TEST_ROOT/mira.db"
  export MIRA_ENDPOINT_TOKEN="$TOKEN"
  export MIRA_POLICY_VERSION="$policy_version"
  export MIRA_ENDPOINT_DENY_PROCESSES="$deny_process"
  export MIRA_ENABLE_TEST_CONTROLS="true"

  mira-protect-server --host 127.0.0.1 --port "$PORT" --log-level warning \
    >"$TEST_ROOT/server.log" 2>&1 &
  SERVER_PID=$!

  for _ in $(seq 1 60); do
    if mira-protect --url "$CONTROL_PLANE_URL" --token "$TOKEN" doctor >/dev/null 2>&1; then
      return
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      cat "$TEST_ROOT/server.log" >&2 || true
      fail "Control plane exited before becoming ready"
    fi
    sleep 0.25
  done
  fail "Control plane did not become ready"
}

start_agent() {
  local mode="$1"
  local log_file="$2"
  export MIRA_CONTROL_PLANE_URL="$CONTROL_PLANE_URL"
  export MIRA_AGENT_TOKEN="$TOKEN"
  export MIRA_AGENT_MODE="$mode"
  export MIRA_POLL_SECONDS="0.10"
  export MIRA_HEARTBEAT_SECONDS="1"
  export MIRA_REQUEST_TIMEOUT_SECONDS="2"
  export MIRA_FAIL_CLOSED="false"
  export MIRA_QUEUE_FILE="$TEST_ROOT/telemetry-queue.jsonl"

  mira-protect-agent >"$log_file" 2>&1 &
  AGENT_PID=$!

  for _ in $(seq 1 40); do
    if mira-protect --url "$CONTROL_PLANE_URL" --token "$TOKEN" --json devices \
      | python -c 'import json,sys; raise SystemExit(0 if json.load(sys.stdin) else 1)' \
      >/dev/null 2>&1; then
      return
    fi
    if ! kill -0 "$AGENT_PID" 2>/dev/null; then
      cat "$log_file" >&2 || true
      fail "Endpoint agent exited before registering"
    fi
    sleep 0.25
  done
  fail "Endpoint agent did not register"
}

exercise_ai_command() {
  info "Exercising real AI CLI command: $TEST_COMMAND"
  for _ in $(seq 1 24); do
    timeout 3s bash -lc "$TEST_COMMAND" >/dev/null 2>&1 || true
    sleep 0.05
  done
}

command -v "$PYTHON_BIN" >/dev/null 2>&1 || fail "$PYTHON_BIN was not found"
select_ai_command

if [[ "${MIRA_SKIP_VALIDATION:-0}" != "1" ]]; then
  info "Running local lint/unit/import validation first"
  PYTHON_BIN="$PYTHON_BIN" MIRA_VALIDATION_VENV="$VENV_DIR" \
    bash "$ROOT_DIR/scripts/validate-local.sh"
fi

[[ -f "$VENV_DIR/bin/activate" ]] || fail "Expected virtual environment at $VENV_DIR"
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

mkdir -p "$TEST_ROOT"
rm -f "$TEST_ROOT/mira.db" "$TEST_ROOT/server.log" "$TEST_ROOT/monitor-agent.log" \
  "$TEST_ROOT/guard-agent.log" "$TEST_ROOT/telemetry-queue.jsonl"

info "Phase 1: monitor mode discovery"
start_server "" "2026.09.03-monitor"
start_agent "monitor" "$TEST_ROOT/monitor-agent.log"
exercise_ai_command

INVENTORY_JSON=""
for _ in $(seq 1 60); do
  INVENTORY_JSON="$(mira-protect --url "$CONTROL_PLANE_URL" --token "$TOKEN" --json inventory 2>/dev/null || echo '[]')"
  INVENTORY_COUNT="$(printf '%s' "$INVENTORY_JSON" | python -c 'import json,sys; print(len(json.load(sys.stdin)))' 2>/dev/null || echo 0)"
  if [[ "$INVENTORY_COUNT" -ge 1 ]]; then
    break
  fi
  sleep 0.25
done
[[ "${INVENTORY_COUNT:-0}" -ge 1 ]] || {
  cat "$TEST_ROOT/monitor-agent.log" >&2 || true
  fail "The real AI CLI was not discovered"
}

OBSERVED_PROCESS="$(printf '%s' "$INVENTORY_JSON" | python -c 'import json,sys; d=json.load(sys.stdin); print(d[0].get("attributes",{}).get("process_name", ""))')"
OBSERVED_PRODUCT="$(printf '%s' "$INVENTORY_JSON" | python -c 'import json,sys; d=json.load(sys.stdin); print(d[0].get("name", ""))')"
OBSERVED_PROVIDER="$(printf '%s' "$INVENTORY_JSON" | python -c 'import json,sys; d=json.load(sys.stdin); print(d[0].get("provider", ""))')"
[[ -n "$OBSERVED_PROCESS" ]] || fail "Inventory did not preserve the observed process name"

if grep -q '"event": "process_terminated"' "$TEST_ROOT/monitor-agent.log"; then
  fail "Monitor mode terminated a process"
fi
pass "Monitor mode discovered $OBSERVED_PRODUCT ($OBSERVED_PROVIDER) as process $OBSERVED_PROCESS without termination"

stop_agent
stop_server

info "Phase 2: guard mode with an explicit central deny rule for the discovered process"
start_server "$OBSERVED_PROCESS" "2026.09.03-guard"
start_agent "guard" "$TEST_ROOT/guard-agent.log"
exercise_ai_command

GUARD_BLOCK_SEEN=0
for _ in $(seq 1 60); do
  if grep -q '"decision": "block"' "$TEST_ROOT/guard-agent.log" \
    && grep -q '"effective_action": "notify"' "$TEST_ROOT/guard-agent.log"; then
    GUARD_BLOCK_SEEN=1
    break
  fi
  sleep 0.25
done
[[ "$GUARD_BLOCK_SEEN" -eq 1 ]] || {
  cat "$TEST_ROOT/guard-agent.log" >&2 || true
  fail "Guard mode did not receive the expected central block/notify decision"
}

if grep -q '"event": "process_terminated"' "$TEST_ROOT/guard-agent.log"; then
  fail "Guard mode terminated a real AI CLI process"
fi
pass "Guard mode converted the explicit central block into notification-only behavior"

EVENTS_JSON="$(mira-protect --url "$CONTROL_PLANE_URL" --token "$TOKEN" --json events --limit 200)"
EVENTS_JSON="$EVENTS_JSON" python - <<'PY'
import json
import os

events = json.loads(os.environ["EVENTS_JSON"])
if not any(
    "endpoint-denied-ai-process" in event.get("security", {}).get("detections", [])
    for event in events
):
    raise SystemExit("Expected endpoint-denied-ai-process evidence was not persisted")
if any(
    event.get("event_type") == "endpoint.enforcement"
    and event.get("metadata", {}).get("result") == "succeeded"
    for event in events
):
    raise SystemExit("Guard test unexpectedly recorded successful process enforcement")
PY
pass "Discovery, policy evidence, and no-enforcement guard behavior were persisted"

mira-protect --url "$CONTROL_PLANE_URL" --token "$TOKEN" inventory
mira-protect --url "$CONTROL_PLANE_URL" --token "$TOKEN" devices
mira-protect --url "$CONTROL_PLANE_URL" --token "$TOKEN" summary

echo
pass "Real AI CLI monitor/guard milestone test completed"
echo "Tool exercised: $TOOL_NAME"
echo "Observed provider/product: $OBSERVED_PROVIDER / $OBSERVED_PRODUCT"
echo "Observed process name: $OBSERVED_PROCESS"
echo "Logs and database: $TEST_ROOT"
