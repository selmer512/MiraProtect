from __future__ import annotations

import os

# Keep tests deterministic regardless of shell configuration on a developer workstation.
os.environ.setdefault("MIRA_DATABASE_URL", "sqlite+pysqlite:///:memory:")
os.environ.pop("MIRA_ENDPOINT_TOKEN", None)
os.environ.pop("MIRA_ENDPOINT_DENY_PROCESSES", None)
