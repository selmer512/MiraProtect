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

os.environ.pop("MIRA_ADMIN_TOKEN", None)
os.environ.pop("MIRA_SECURITY_PROFILE", None)
os.environ.pop("MIRA_TLS_CERT_FILE", None)
os.environ.pop("MIRA_TLS_KEY_FILE", None)
os.environ.pop("MIRA_TLS_CLIENT_CA_FILE", None)
os.environ.pop("MIRA_TLS_REQUIRE_CLIENT_CERT", None)
os.environ.pop("MIRA_TLS_TERMINATED_UPSTREAM", None)
os.environ.pop("MIRA_ALLOW_INSECURE_REMOTE", None)
os.environ.pop("MIRA_EFFECTIVE_TLS", None)
os.environ.pop("MIRA_BIND_HOST", None)
os.environ.pop("MIRA_TLS_VERIFY", None)
os.environ.pop("MIRA_TLS_CA_FILE", None)
os.environ.pop("MIRA_TLS_CLIENT_CERT", None)
os.environ.pop("MIRA_TLS_CLIENT_KEY", None)
os.environ.pop("MIRA_REQUIRE_HTTPS", None)
