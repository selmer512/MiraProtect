#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${MIRA_VALIDATION_VENV:-$ROOT_DIR/.venv}"

fail() {
  echo "[FAIL] $*" >&2
  exit 1
}

command -v "$PYTHON_BIN" >/dev/null 2>&1 || fail "$PYTHON_BIN was not found"
"$PYTHON_BIN" - <<'PY' || fail "Python 3.12+ is required"
import sys
raise SystemExit(0 if sys.version_info >= (3, 12) else 1)
PY

if [[ ! -x "$VENV_DIR/bin/python" ]]; then
  echo "[INFO] Creating $VENV_DIR"
  "$PYTHON_BIN" -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
python -m pip install --upgrade pip >/dev/null
python -m pip install -e "$ROOT_DIR[dev]" >/dev/null

export MIRA_DATABASE_URL="sqlite+pysqlite:///:memory:"

printf '\n== Ruff ==\n'
ruff check "$ROOT_DIR/src" "$ROOT_DIR/tests"

printf '\n== Pytest ==\n'
pytest -q "$ROOT_DIR/tests"

printf '\n== Import smoke test ==\n'
python - <<'PY'
from mira_protect.app import app
from mira_protect.cli import build_parser
from mira_protect.endpoint_agent import AgentConfig

assert app.title == "Mira Protect"
assert build_parser().prog == "mira-protect"
assert AgentConfig().mode == "monitor"
print(f"{app.title} {app.version}: import smoke test passed")
PY

printf '\n[PASS] Local Mira Protect validation completed.\n'
