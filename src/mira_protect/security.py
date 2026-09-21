from __future__ import annotations

import ipaddress
import os
from typing import Any


VALID_SECURITY_PROFILES = {"local", "development", "production"}


def _as_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def security_profile() -> str:
    profile = os.getenv("MIRA_SECURITY_PROFILE", "local").strip().lower()
    if profile not in VALID_SECURITY_PROFILES:
        raise ValueError(
            "MIRA_SECURITY_PROFILE must be one of: local, development, production"
        )
    return profile


def is_loopback_host(host: str) -> bool:
    normalized = host.strip().lower()
    if normalized in {"localhost", "::1"}:
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def security_status(
    *,
    bind_host: str | None = None,
    tls_enabled: bool | None = None,
) -> dict[str, Any]:
    profile = security_profile()
    enrollment_token = bool(os.getenv("MIRA_ENROLLMENT_TOKEN"))
    token_pepper = bool(os.getenv("MIRA_TOKEN_PEPPER"))
    admin_token = bool(os.getenv("MIRA_ADMIN_TOKEN"))
    shared_endpoint_token = bool(os.getenv("MIRA_ENDPOINT_TOKEN"))
    allow_shared = _as_bool(os.getenv("MIRA_ALLOW_SHARED_ENDPOINT_TOKEN", "false"))
    tls_terminated_upstream = _as_bool(os.getenv("MIRA_TLS_TERMINATED_UPSTREAM", "false"))

    remote_bind = bool(bind_host) and not is_loopback_host(str(bind_host))
    effective_tls = bool(tls_enabled) or tls_terminated_upstream

    checks = {
        "enrollment_token_configured": enrollment_token,
        "token_pepper_configured": token_pepper,
        "admin_token_configured": admin_token,
        "shared_endpoint_token_disabled": not shared_endpoint_token and not allow_shared,
        "tls_configured": effective_tls,
    }

    required: list[str] = []
    if profile in {"development", "production"}:
        for key in (
            "enrollment_token_configured",
            "token_pepper_configured",
            "admin_token_configured",
            "shared_endpoint_token_disabled",
        ):
            if not checks[key]:
                required.append(key)

    if profile == "production" and not effective_tls:
        required.append("tls_configured")
    elif profile == "development" and remote_bind and not effective_tls:
        if not _as_bool(os.getenv("MIRA_ALLOW_INSECURE_REMOTE", "false")):
            required.append("tls_configured")

    return {
        "profile": profile,
        "ready": not required,
        "checks": checks,
        "missing_requirements": required,
        "remote_bind": remote_bind,
        "tls_terminated_upstream": tls_terminated_upstream,
    }


def validate_server_security(
    *,
    bind_host: str,
    ssl_certfile: str | None,
    ssl_keyfile: str | None,
) -> dict[str, Any]:
    cert_configured = bool(ssl_certfile and ssl_keyfile)
    status = security_status(bind_host=bind_host, tls_enabled=cert_configured)
    if not status["ready"]:
        missing = ", ".join(status["missing_requirements"])
        raise RuntimeError(
            f"Mira Protect security profile '{status['profile']}' is not ready: {missing}"
        )
    return status
