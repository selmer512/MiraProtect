from __future__ import annotations

import os
from datetime import datetime, timezone

from .schemas import EndpointPolicyBundle


def _csv_env(name: str) -> list[str]:
    return sorted(
        {
            value.strip().lower()
            for value in os.getenv(name, "").split(",")
            if value.strip()
        }
    )


def _bool_env(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def get_endpoint_policy_bundle() -> EndpointPolicyBundle:
    """Build the current endpoint policy from environment-backed control-plane settings.

    This is intentionally a narrow configuration boundary. A database-backed policy
    service can replace it later without changing endpoint or policy-engine contracts.
    """

    return EndpointPolicyBundle(
        version=os.getenv("MIRA_POLICY_VERSION", "2026.09.03-1"),
        issued_at=datetime.now(timezone.utc),
        allow_processes=_csv_env("MIRA_ENDPOINT_ALLOW_PROCESSES"),
        deny_processes=_csv_env("MIRA_ENDPOINT_DENY_PROCESSES"),
        approved_providers=_csv_env("MIRA_APPROVED_AI_PROVIDERS"),
        test_controls_enabled=_bool_env("MIRA_ENABLE_TEST_CONTROLS", True),
        offline_fail_closed_allowed=_bool_env("MIRA_OFFLINE_FAIL_CLOSED_ALLOWED", False),
        metadata={
            "source": "environment",
            "policy_model": "endpoint-process-v1",
        },
    )
