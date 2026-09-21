from __future__ import annotations

import runpy
from pathlib import Path

import pytest
from cryptography import x509
from fastapi.testclient import TestClient

from mira_protect.app import app, repository
from mira_protect.security import security_status, validate_server_security


client = TestClient(app)


def setup_function() -> None:
    repository.clear()


def _configure_development_security(monkeypatch) -> None:
    monkeypatch.setenv("MIRA_SECURITY_PROFILE", "development")
    monkeypatch.setenv("MIRA_ENROLLMENT_TOKEN", "development-enrollment")
    monkeypatch.setenv("MIRA_TOKEN_PEPPER", "development-pepper")
    monkeypatch.setenv("MIRA_ADMIN_TOKEN", "development-admin")
    monkeypatch.setenv("MIRA_ALLOW_SHARED_ENDPOINT_TOKEN", "false")
    monkeypatch.setenv("MIRA_TLS_TERMINATED_UPSTREAM", "true")
    monkeypatch.delenv("MIRA_ENDPOINT_TOKEN", raising=False)


def test_development_profile_reports_missing_security_requirements(monkeypatch) -> None:
    monkeypatch.setenv("MIRA_SECURITY_PROFILE", "development")
    monkeypatch.setenv("MIRA_BIND_HOST", "0.0.0.0")
    monkeypatch.setenv("MIRA_TLS_TERMINATED_UPSTREAM", "false")

    status = security_status()

    assert status["ready"] is False
    assert "enrollment_token_configured" in status["missing_requirements"]
    assert "token_pepper_configured" in status["missing_requirements"]
    assert "admin_token_configured" in status["missing_requirements"]
    assert "tls_configured" in status["missing_requirements"]


def test_development_profile_accepts_upstream_tls(monkeypatch) -> None:
    _configure_development_security(monkeypatch)
    monkeypatch.setenv("MIRA_BIND_HOST", "0.0.0.0")
    monkeypatch.setenv("MIRA_TLS_TERMINATED_UPSTREAM", "true")

    status = security_status()

    assert status["ready"] is True
    assert status["checks"]["tls_configured"] is True


def test_remote_development_server_requires_tls_by_default(monkeypatch) -> None:
    _configure_development_security(monkeypatch)
    monkeypatch.setenv("MIRA_TLS_TERMINATED_UPSTREAM", "false")

    with pytest.raises(RuntimeError, match="tls_configured"):
        validate_server_security(
            bind_host="0.0.0.0",
            ssl_certfile=None,
            ssl_keyfile=None,
        )

    monkeypatch.setenv("MIRA_ALLOW_INSECURE_REMOTE", "true")
    status = validate_server_security(
        bind_host="0.0.0.0",
        ssl_certfile=None,
        ssl_keyfile=None,
    )
    assert status["ready"] is True


def test_production_profile_never_accepts_insecure_remote_override(monkeypatch) -> None:
    _configure_development_security(monkeypatch)
    monkeypatch.setenv("MIRA_SECURITY_PROFILE", "production")
    monkeypatch.setenv("MIRA_ALLOW_INSECURE_REMOTE", "true")
    monkeypatch.setenv("MIRA_TLS_TERMINATED_UPSTREAM", "false")

    with pytest.raises(RuntimeError, match="tls_configured"):
        validate_server_security(
            bind_host="0.0.0.0",
            ssl_certfile=None,
            ssl_keyfile=None,
        )


def test_admin_api_requires_separate_admin_token_in_development(monkeypatch) -> None:
    _configure_development_security(monkeypatch)

    unauthorized = client.get("/api/v1/assets")
    assert unauthorized.status_code == 401

    endpoint_token = client.get(
        "/api/v1/assets",
        headers={"Authorization": "Bearer development-enrollment"},
    )
    assert endpoint_token.status_code == 401

    authorized = client.get(
        "/api/v1/assets",
        headers={"Authorization": "Bearer development-admin"},
    )
    assert authorized.status_code == 200


def test_endpoint_revocation_invalidates_device_credential(monkeypatch) -> None:
    _configure_development_security(monkeypatch)

    enrollment = client.post(
        "/api/v1/endpoint/enroll",
        json={
            "device_id": "revoke-device-01",
            "hostname": "REVOKE-DEVICE-01",
            "platform": "Windows",
            "agent_version": "0.4.0",
        },
        headers={"Authorization": "Bearer development-enrollment"},
    )
    assert enrollment.status_code == 200
    device_token = enrollment.json()["device_token"]

    heartbeat = {
        "device_id": "revoke-device-01",
        "hostname": "REVOKE-DEVICE-01",
        "platform": "Windows",
        "mode": "monitor",
        "agent_version": "0.4.0",
    }
    before_revoke = client.post(
        "/api/v1/endpoint/heartbeat",
        json=heartbeat,
        headers={"Authorization": f"Bearer {device_token}"},
    )
    assert before_revoke.status_code == 200

    revoked = client.post(
        "/api/v1/endpoint/revoke/revoke-device-01",
        headers={"Authorization": "Bearer development-admin"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["revoked"] is True

    after_revoke = client.post(
        "/api/v1/endpoint/heartbeat",
        json=heartbeat,
        headers={"Authorization": f"Bearer {device_token}"},
    )
    assert after_revoke.status_code == 401

    events = client.get(
        "/api/v1/events",
        headers={"Authorization": "Bearer development-admin"},
    ).json()
    assert any(
        event["event_type"] == "endpoint.credential_revoked"
        and event["metadata"]["device_id"] == "revoke-device-01"
        for event in events
    )


def test_ready_endpoint_exposes_security_profile_without_secrets(monkeypatch) -> None:
    _configure_development_security(monkeypatch)
    monkeypatch.setenv("MIRA_TLS_TERMINATED_UPSTREAM", "true")

    response = client.get("/ready")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["security"]["profile"] == "development"
    serialized = response.text
    assert "development-admin" not in serialized
    assert "development-enrollment" not in serialized
    assert "development-pepper" not in serialized


def test_generated_tls_certificates_include_rfc5280_key_identifiers(tmp_path) -> None:
    script = Path(__file__).resolve().parents[1] / "scripts" / "generate-test-pki.py"
    generate = runpy.run_path(str(script))["generate"]
    generate(tmp_path)

    ca = x509.load_pem_x509_certificate((tmp_path / "ca.crt").read_bytes())
    server = x509.load_pem_x509_certificate((tmp_path / "server.crt").read_bytes())
    client = x509.load_pem_x509_certificate((tmp_path / "client.crt").read_bytes())

    ca_ski = ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    ca_aki = ca.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
    assert ca_aki == ca_ski

    for leaf in (server, client):
        leaf.extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
        leaf_aki = leaf.extensions.get_extension_for_class(
            x509.AuthorityKeyIdentifier
        ).value.key_identifier
        assert leaf_aki == ca_ski
