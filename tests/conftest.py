from __future__ import annotations

import os

# Keep tests deterministic regardless of shell configuration on a developer workstation.
os.environ.setdefault("MIRA_DATABASE_URL", "sqlite+pysqlite:///:memory:")
os.environ.pop("MIRA_ENDPOINT_TOKEN", None)
os.environ.pop("MIRA_ENDPOINT_DENY_PROCESSES", None)

os.environ.pop("MIRA_ENROLLMENT_TOKEN", None)
os.environ.pop("MIRA_ALLOW_SHARED_ENDPOINT_TOKEN", None)
os.environ.pop("MIRA_TOKEN_PEPPER", None)
os.environ.pop("MIRA_ENDPOINT_PROCESS_NAMES", None)
os.environ.pop("MIRA_ENDPOINT_COMMAND_MARKERS", None)
os.environ.pop("MIRA_ENDPOINT_FAIL_CLOSED", None)
os.environ.pop("MIRA_ENDPOINT_POLICY_MODE", None)
