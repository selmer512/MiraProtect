from __future__ import annotations

import os

# Keep tests deterministic regardless of shell configuration on a developer workstation.
# These values must be set before importing mira_protect.app because the repository and
# endpoint policy bundle are constructed at module import time.
os.environ.setdefault("MIRA_DATABASE_URL", "sqlite+pysqlite:///:memory:")
os.environ.setdefault("MIRA_ENABLE_TEST_CONTROLS", "true")
os.environ.setdefault("MIRA_POLICY_VERSION", "test-policy")
os.environ.pop("MIRA_ENDPOINT_TOKEN", None)
os.environ.pop("MIRA_ENDPOINT_ALLOW_PROCESSES", None)
os.environ.pop("MIRA_ENDPOINT_DENY_PROCESSES", None)
os.environ.pop("MIRA_APPROVED_AI_PROVIDERS", None)
