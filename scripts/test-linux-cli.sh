#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
PORT="${MIRA_TEST_PORT:-18080}"
TEST_ROOT="${MIRA_TEST_ROOT:-$ROOT_DIR/.mira-test}"
VENV_DIR="${MIRA_TEST_VENV:-$ROOT_DIR/.venv}"
CONTROL_PLANE_URL="http://127.0.0.1:${PORT}"
TOKEN="${MIRA_ENDPOINT_TOKEN:-mira-linux-cli-test-token-change-me}"

SERVER_PID=""
AGENT_PID=""
TARGET_PID=""

cleanup() {
  set +e
  if [[ -n "$TARGET_PID" ]] && kill -0 "$TARGET_PID" 2>/dev/null; then
    kill "$TARGET_PID" 2>/dev/null || true
  fi
  if [[ -n "$AGENT_PID" ]] && kill -0 "$AGENT_PID" 2>/dev/null; then
    kill "$AGENT_PID" 2>/dev/null || true
  fi
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
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

version_ok() {
  "$PYTHON_BIN" - <<'PY'
import sys
raise SystemExit(0 if sys.version_info >= (3, 12) else 1)
PY
}

ensure_venv() {
  if [[ -d "$VENV_DIR" ]] && { [[ ! -x "$VENV_DIR/bin/python" ]] || [[ ! -f "$VENV_DIR/bin/activate" ]]; }; then
    info "Removing incomplete Python virtual environment at $VENV_DIR"
    rm -rf "$VENV_DIR"
  fi

  if [[ ! -x "$VENV_DIR/bin/python" || ! -f "$VENV_DIR/bin/activate" ]]; then
    info "Creating Python virtual environment at $VENV_DIR"
    if ! "$PYTHON_BIN" -m venv "$VENV_DIR"; then
      rm -rf "$VENV_DIR"
      fail "Unable to create the Python virtual environment. Install the venv package for $PYTHON_BIN and retry."
    fi
  fi

  [[ -x "$VENV_DIR/bin/python" ]] || fail "Virtual environment is missing $VENV_DIR/bin/python"
  [[ -f "$VENV_DIR/bin/activate" ]] || fail "Virtual environment is missing $VENV_DIR/bin/activate"
}

command -v "$PYTHON_BIN" >/dev/null 2>&1 || fail "$PYTHON_BIN was not found"
version_ok || fail "Python 3.12+ is required"

if [[ "${MIRA_SKIP_VALIDATION:-0}" != "1" ]]; then
  info "Running local lint/unit/import validation first"
  PYTHON_BIN="$PYTHON_BIN" MIRA_VALIDATION_VENV="$VENV_DIR" \
    bash "$ROOT_DIR/scripts/validate-local.sh"
  export MIRA_SKIP_INSTALL=1
fi

mkdir -p "$TEST_ROOT"
rm -f "$TEST_ROOT/mira.db" "$TEST_ROOT/server.log" "$TEST_ROOT/agent.log" "$TEST_ROOT/target.log"

ensure_venv

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

if [[ "${MIRA_SKIP_INSTALL:-0}" != "1" ]]; then
  info "Installing Mira Protect in editable development mode"
  python -m pip install --upgrade pip >/dev/null
  python -m pip install -e "$ROOT_DIR[dev]" >/dev/null
fi

export MIRA_DATABASE_URL="sqlite+pysqlite:///$TEST_ROOT/mira.db"
export MIRA_CONTROL_PLANE_URL="$CONTROL_PLANE_URL"
export MIRA_ENDPOINT_TOKEN="$TOKEN"
export MIRA_AGENT_TOKEN="$TOKEN"
export MIRA_AGENT_MODE="enforce"
export MIRA_POLL_SECONDS="0.35"
export MIRA_HEARTBEAT_SECONDS="1"
export MIRA_REQUEST_TIMEOUT_SECONDS="2"
export MIRA_FAIL_CLOSED="false"

info "Starting control plane on $CONTROL_PLANE_URL"
mira-protect-server --host 127.0.0.1 --port "$PORT" --log-level warning >"$TEST_ROOT/server.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 60); do
  if mira-protect --url "$CONTROL_PLANE_URL" --token "$TOKEN" doctor >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    cat "$TEST_ROOT/server.log" >&2 || true
    fail "Control plane exited before becoming ready"
  fi
  sleep 0.25
done
mira-protect --url "$CONTROL_PLANE_URL" --token "$TOKEN" doctor >/dev/null 2>&1 \
  || fail "Control plane did not become ready"
pass "Control plane is healthy"

info "Starting Linux endpoint agent in enforce mode"
mira-protect-agent >"$TEST_ROOT/agent.log" 2>&1 &
AGENT_PID=$!

ASSET_COUNT=0
for _ in $(seq 1 40); do
  ASSET_COUNT="$(mira-protect --url "$CONTROL_PLANE_URL" --token "$TOKEN" --json summary 2>/dev/null \
    | python -c 'import json,sys; print(json.load(sys.stdin).get("managed_devices", 0))' 2>/dev/null || echo 0)"
  if [[ "$ASSET_COUNT" -ge 1 ]]; then
    break
  fi
  if ! kill -0 "$AGENT_PID" 2>/dev/null; then
    cat "$TEST_ROOT/agent.log" >&2 || true
    fail "Endpoint agent exited before registering"
  fi
  sleep 0.25
done
[[ "$ASSET_COUNT" -ge 1 ]] || fail "Endpoint agent did not register a heartbeat"
pass "Endpoint heartbeat registered"

info "Launching harmless synthetic process with Mira Protect block marker"
mira-protect synthetic-target --seconds 90 --mira-protect-test-block >"$TEST_ROOT/target.log" 2>&1 &
TARGET_PID=$!

TERMINATED=0
for _ in $(seq 1 60); do
  if grep -q '"event": "process_terminated"' "$TEST_ROOT/agent.log" 2>/dev/null; then
    TERMINATED=1
    break
  fi
  if ! kill -0 "$TARGET_PID" 2>/dev/null; then
    if grep -q 'process_terminated' "$TEST_ROOT/agent.log" 2>/dev/null; then
      TERMINATED=1
    fi
    break
  fi
  sleep 0.25
done

if [[ "$TERMINATED" -ne 1 ]]; then
  echo "--- server.log ---" >&2
  cat "$TEST_ROOT/server.log" >&2 || true
  echo "--- agent.log ---" >&2
  cat "$TEST_ROOT/agent.log" >&2 || true
  echo "--- target.log ---" >&2
  cat "$TEST_ROOT/target.log" >&2 || true
  fail "Synthetic target was not terminated by the endpoint agent"
fi
pass "Enforce mode terminated the synthetic target"

set +e
wait "$TARGET_PID" 2>/dev/null
TARGET_RC=$?
set -e
TARGET_PID=""
if [[ "$TARGET_RC" -eq 0 ]]; then
  fail "Synthetic target exited normally; expected security termination"
fi

REPORTED=0
for _ in $(seq 1 40); do
  if grep -q '"event": "enforcement_reported"' "$TEST_ROOT/agent.log" 2>/dev/null; then
    REPORTED=1
    break
  fi
  sleep 0.25
done
[[ "$REPORTED" -eq 1 ]] || fail "Endpoint did not confirm enforcement back to the control plane"
pass "Endpoint confirmed enforcement to the control plane"

SUMMARY_JSON="$(mira-protect --url "$CONTROL_PLANE_URL" --token "$TOKEN" --json summary)"
EVENTS_JSON="$(mira-protect --url "$CONTROL_PLANE_URL" --token "$TOKEN" --json events --limit 100)"

SUMMARY_JSON="$SUMMARY_JSON" EVENTS_JSON="$EVENTS_JSON" python - <<'PY'
import json
import os

summary = json.loads(os.environ["SUMMARY_JSON"])
events = json.loads(os.environ["EVENTS_JSON"])

if summary.get("managed_devices", 0) < 1:
    raise SystemExit("No managed device was registered")
if summary.get("blocked_events", 0) < 1:
    raise SystemExit("No blocked event was recorded")
if summary.get("enforcement_actions", 0) < 1:
    raise SystemExit("No successful enforcement confirmation was recorded")

matched_policy = False
matched_enforcement = False
for event in events:
    detections = event.get("security", {}).get("detections", [])
    if "endpoint-synthetic-protection-test" in detections:
        matched_policy = True
    if event.get("event_type") == "endpoint.enforcement" and event.get("metadata", {}).get("result") == "succeeded":
        matched_enforcement = True

if not matched_policy:
    raise SystemExit("Synthetic protection rule was not present in persisted events")
if not matched_enforcement:
    raise SystemExit("Successful endpoint enforcement event was not persisted")
PY
pass "Policy decision and endpoint enforcement confirmation are both persisted"

mira-protect --url "$CONTROL_PLANE_URL" --token "$TOKEN" summary

echo
pass "Linux CLI enterprise protection smoke test completed"
echo "Logs and test database: $TEST_ROOT"
echo "Control plane: $CONTROL_PLANE_URL"
echo "Mode tested: enforce"
