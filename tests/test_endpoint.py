from __future__ import annotations

import os

os.environ.setdefault("MIRA_DATABASE_URL", "sqlite+pysqlite:///:memory:")
os.environ.setdefault("MIRA_ENABLE_TEST_CONTROLS", "true")

from fastapi.testclient import TestClient

from mira_protect.app import app, repository
from mira_protect.endpoint_agent import AgentConfig, EndpointAgent, TEST_BLOCK_MARKER
from mira_protect.policy import PolicyEngine
from mira_protect.schemas import AIEvent, EventType, PolicyDecision


client = TestClient(app)


def setup_function() -> None:
    repository.clear()


def test_agent_detects_synthetic_block_marker_when_test_controls_enabled() -> None:
    agent = EndpointAgent(
        AgentConfig(
            control_plane_url="http://127.0.0.1:9",
            enable_test_controls=True,
        )
    )
    try:
        matches = agent._match_process(
            {
                "name": "notepad.exe",
                "cmdline": ["notepad.exe", TEST_BLOCK_MARKER],
            }
        )
    finally:
        agent.close()
    assert "local:test-block" in matches


def test_agent_ignores_synthetic_marker_when_test_controls_disabled() -> None:
    agent = EndpointAgent(
        AgentConfig(
            control_plane_url="http://127.0.0.1:9",
            enable_test_controls=False,
        )
    )
    try:
        matches = agent._match_process(
            {
                "name": "notepad.exe",
                "cmdline": ["notepad.exe", TEST_BLOCK_MARKER],
            }
        )
    finally:
        agent.close()
    assert "local:test-block" not in matches


def test_policy_blocks_synthetic_endpoint_test_from_command_line() -> None:
    event = AIEvent(
        event_type=EventType.ENDPOINT_PROCESS,
        input={"command_line": ["notepad.exe", TEST_BLOCK_MARKER]},
        metadata={
            "process_name": "notepad.exe",
            "matched_local_rules": ["local:test-block"],
        },
    )
    decision, rules = PolicyEngine().evaluate(event)
    assert decision == PolicyDecision.BLOCK
    assert "endpoint-synthetic-protection-test" in rules


def test_local_rule_metadata_cannot_force_synthetic_block_without_marker() -> None:
    event = AIEvent(
        event_type=EventType.ENDPOINT_PROCESS,
        input={"command_line": ["notepad.exe"]},
        metadata={
            "process_name": "notepad.exe",
            "matched_local_rules": ["local:test-block"],
        },
    )
    decision, rules = PolicyEngine().evaluate(event)
    assert decision != PolicyDecision.BLOCK
    assert "endpoint-synthetic-protection-test" not in rules


def test_synthetic_policy_is_disabled_without_explicit_test_flag(monkeypatch) -> None:
    monkeypatch.setenv("MIRA_ENABLE_TEST_CONTROLS", "false")
    event = AIEvent(
        event_type=EventType.ENDPOINT_PROCESS,
        input={"command_line": ["python", TEST_BLOCK_MARKER]},
        metadata={"process_name": "python"},
    )
    decision, rules = PolicyEngine().evaluate(event)
    assert decision != PolicyDecision.BLOCK
    assert "endpoint-synthetic-protection-test" not in rules


def test_offline_agent_does_not_block_test_marker_when_fail_closed_is_false() -> None:
    agent = EndpointAgent(
        AgentConfig(
            control_plane_url="http://127.0.0.1:9",
            request_timeout_seconds=0.05,
            fail_closed=False,
            enable_test_controls=True,
            mode="enforce",
        )
    )
    try:
        result = agent._evaluate(
            {
                "pid": 999999,
                "process_name": "python",
                "matched_local_rules": ["local:test-block"],
            }
        )
    finally:
        agent.close()
    assert result["decision"] == "monitor"
    assert result["effective_action"] == "observe"
    assert result["matched_rules"] == ["agent:offline-monitor"]


def test_endpoint_enforce_mode_requests_termination() -> None:
    response = client.post(
        "/api/v1/endpoint/process/evaluate",
        json={
            "device_id": "test-device-01",
            "hostname": "TEST-DEVICE-01",
            "username": "corp\\tester",
            "pid": 4242,
            "parent_pid": 100,
            "process_name": "notepad.exe",
            "executable": "C:\\Windows\\System32\\notepad.exe",
            "command_line": ["notepad.exe", TEST_BLOCK_MARKER],
            "agent_version": "0.3.0",
            "mode": "enforce",
            "matched_local_rules": ["local:test-block"],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "block"
    assert body["effective_action"] == "terminate"
    assert "endpoint-synthetic-protection-test" in body["matched_rules"]

    events = client.get("/api/v1/events").json()
    assert len(events) == 1
    assert events[0]["security"]["policy_decision"] == "block"


def test_endpoint_monitor_mode_never_requests_termination() -> None:
    response = client.post(
        "/api/v1/endpoint/process/evaluate",
        json={
            "device_id": "test-device-02",
            "hostname": "TEST-DEVICE-02",
            "pid": 4243,
            "process_name": "notepad.exe",
            "command_line": ["notepad.exe", TEST_BLOCK_MARKER],
            "mode": "monitor",
            "matched_local_rules": ["local:test-block"],
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["decision"] == "block"
    assert body["effective_action"] == "observe"


def test_endpoint_heartbeat_registers_managed_device_without_shadow_ai_finding() -> None:
    response = client.post(
        "/api/v1/endpoint/heartbeat",
        json={
            "device_id": "test-device-03",
            "hostname": "TEST-DEVICE-03",
            "username": "corp\\tester",
            "agent_version": "0.3.0",
            "mode": "guard",
            "platform": "Windows",
            "platform_version": "11",
            "ip_addresses": ["10.10.10.10"],
        },
    )
    assert response.status_code == 200
    asset = response.json()
    assert asset["kind"] == "device"
    assert asset["attributes"]["agent_mode"] == "guard"

    summary = client.get("/api/v1/dashboard/summary").json()
    assert summary["assets"] == 1
    assert summary["managed_devices"] == 1
    assert summary["events"] == 1
    assert summary["findings"] == 0


def test_endpoint_enforcement_confirmation_is_persisted() -> None:
    evaluation = client.post(
        "/api/v1/endpoint/process/evaluate",
        json={
            "device_id": "linux-test-01",
            "hostname": "linux-test-01",
            "username": "tester",
            "pid": 5001,
            "process_name": "python",
            "command_line": ["python", "synthetic-target", TEST_BLOCK_MARKER],
            "mode": "enforce",
            "matched_local_rules": ["local:test-block"],
        },
    )
    assert evaluation.status_code == 200
    decision = evaluation.json()

    report = client.post(
        "/api/v1/endpoint/enforcement",
        json={
            "device_id": "linux-test-01",
            "hostname": "linux-test-01",
            "username": "tester",
            "pid": 5001,
            "process_name": "python",
            "decision_event_id": decision["event_id"],
            "action": "terminate",
            "result": "succeeded",
            "mode": "enforce",
            "agent_version": "0.3.0",
        },
    )
    assert report.status_code == 200
    event = report.json()
    assert event["event_type"] == "endpoint.enforcement"
    assert event["parent_event_id"] == decision["event_id"]
    assert event["metadata"]["result"] == "succeeded"

    summary = client.get("/api/v1/dashboard/summary").json()
    assert summary["enforcement_actions"] == 1
    assert summary["enforcement_failures"] == 0


def test_endpoint_token_is_enforced_when_configured(monkeypatch) -> None:
    monkeypatch.setenv("MIRA_ENDPOINT_TOKEN", "test-secret")
    payload = {
        "device_id": "auth-test",
        "hostname": "auth-test",
        "mode": "monitor",
        "platform": "Linux",
    }

    unauthorized = client.post("/api/v1/endpoint/heartbeat", json=payload)
    assert unauthorized.status_code == 401

    authorized = client.post(
        "/api/v1/endpoint/heartbeat",
        json=payload,
        headers={"Authorization": "Bearer test-secret"},
    )
    assert authorized.status_code == 200


def test_endpoint_enrollment_issues_device_scoped_credential(monkeypatch) -> None:
    monkeypatch.setenv("MIRA_ENROLLMENT_TOKEN", "bootstrap-secret")
    monkeypatch.setenv("MIRA_ALLOW_SHARED_ENDPOINT_TOKEN", "false")
    payload = {
        "device_id": "enrolled-windows-01",
        "hostname": "ENROLLED-WINDOWS-01",
        "platform": "Windows",
        "platform_version": "11",
        "agent_version": "0.3.0",
    }

    unauthorized = client.post("/api/v1/endpoint/enroll", json=payload)
    assert unauthorized.status_code == 401

    enrolled = client.post(
        "/api/v1/endpoint/enroll",
        json=payload,
        headers={"Authorization": "Bearer bootstrap-secret"},
    )
    assert enrolled.status_code == 200
    enrollment = enrolled.json()
    assert enrollment["device_id"] == payload["device_id"]
    assert enrollment["device_token"]
    assert enrollment["policy_url"].endswith(payload["device_id"])

    heartbeat = {
        "device_id": payload["device_id"],
        "hostname": payload["hostname"],
        "platform": "Windows",
        "mode": "monitor",
        "agent_version": "0.3.0",
    }
    rejected = client.post(
        "/api/v1/endpoint/heartbeat",
        json=heartbeat,
        headers={"Authorization": "Bearer wrong-device-token"},
    )
    assert rejected.status_code == 401

    accepted = client.post(
        "/api/v1/endpoint/heartbeat",
        json=heartbeat,
        headers={"Authorization": f"Bearer {enrollment['device_token']}"},
    )
    assert accepted.status_code == 200
    summary = client.get("/api/v1/dashboard/summary").json()
    assert summary["enrolled_devices"] == 1
    events = client.get("/api/v1/events").json()
    assert any(event["event_type"] == "endpoint.enrollment" for event in events)

    other_device = dict(heartbeat)
    other_device["device_id"] = "different-device"
    cross_device = client.post(
        "/api/v1/endpoint/heartbeat",
        json=other_device,
        headers={"Authorization": f"Bearer {enrollment['device_token']}"},
    )
    assert cross_device.status_code == 401


def test_enrolled_endpoint_receives_versioned_policy(monkeypatch) -> None:
    monkeypatch.setenv("MIRA_ENROLLMENT_TOKEN", "policy-bootstrap")
    monkeypatch.setenv("MIRA_ALLOW_SHARED_ENDPOINT_TOKEN", "false")
    monkeypatch.setenv("MIRA_ENDPOINT_DENY_PROCESSES", "blocked-ai.exe,legacy-ai.exe")
    monkeypatch.setenv("MIRA_ENDPOINT_PROCESS_NAMES", "custom-assistant.exe")
    monkeypatch.setenv("MIRA_ENDPOINT_COMMAND_MARKERS", "corp-ai-wrapper")
    monkeypatch.setenv("MIRA_POLICY_REFRESH_SECONDS", "120")

    enrollment = client.post(
        "/api/v1/endpoint/enroll",
        json={
            "device_id": "policy-device-01",
            "hostname": "POLICY-DEVICE-01",
            "platform": "Windows",
        },
        headers={"Authorization": "Bearer policy-bootstrap"},
    )
    assert enrollment.status_code == 200
    token = enrollment.json()["device_token"]

    policy = client.get(
        "/api/v1/endpoint/policy/policy-device-01",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert policy.status_code == 200
    body = policy.json()
    assert len(body["policy_version"]) == 16
    assert body["refresh_seconds"] == 120
    assert body["deny_processes"] == ["blocked-ai.exe", "legacy-ai.exe"]
    assert body["process_names"] == ["custom-assistant.exe"]
    assert body["command_markers"] == ["corp-ai-wrapper"]
    assert body["enable_test_controls"] is True


def test_agent_loads_cached_policy_and_uses_cached_deny_offline(tmp_path) -> None:
    cache_path = tmp_path / "policy-cache.json"
    cache_path.write_text(
        """{
  "policy_version": "cached-policy-1",
  "refresh_seconds": 300,
  "deny_processes": ["blocked-ai.exe"],
  "process_names": [],
  "command_markers": [],
  "fail_closed": true,
  "enable_test_controls": false,
  "recommended_mode": "monitor"
}
""",
        encoding="utf-8",
    )
    agent = EndpointAgent(
        AgentConfig(
            control_plane_url="http://127.0.0.1:9",
            request_timeout_seconds=0.05,
            policy_cache_path=str(cache_path),
            fail_closed=False,
            mode="enforce",
        )
    )
    try:
        matches = agent._match_process(
            {
                "name": "blocked-ai.exe",
                "cmdline": ["blocked-ai.exe"],
            }
        )
        assert "local:central-deny-process:blocked-ai.exe" in matches
        assert agent.policy_version == "cached-policy-1"
        assert agent.config.fail_closed is True

        result = agent._evaluate(
            {
                "pid": 999998,
                "process_name": "blocked-ai.exe",
                "matched_local_rules": matches,
            }
        )
    finally:
        agent.close()

    assert result["decision"] == "block"
    assert result["effective_action"] == "terminate"
    assert result["matched_rules"] == ["agent:offline-cached-central-deny"]


def test_dashboard_marks_endpoint_with_stale_policy(monkeypatch) -> None:
    monkeypatch.setenv("MIRA_ENROLLMENT_TOKEN", "stale-policy-bootstrap")
    monkeypatch.setenv("MIRA_ALLOW_SHARED_ENDPOINT_TOKEN", "false")
    monkeypatch.setenv("MIRA_ENDPOINT_DENY_PROCESSES", "new-policy.exe")

    enrollment = client.post(
        "/api/v1/endpoint/enroll",
        json={
            "device_id": "stale-policy-device",
            "hostname": "STALE-POLICY-DEVICE",
            "platform": "Windows",
        },
        headers={"Authorization": "Bearer stale-policy-bootstrap"},
    )
    assert enrollment.status_code == 200
    token = enrollment.json()["device_token"]

    heartbeat = client.post(
        "/api/v1/endpoint/heartbeat",
        json={
            "device_id": "stale-policy-device",
            "hostname": "STALE-POLICY-DEVICE",
            "platform": "Windows",
            "mode": "monitor",
            "policy_version": "older-policy-version",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert heartbeat.status_code == 200

    summary = client.get("/api/v1/dashboard/summary").json()
    assert summary["enrolled_devices"] == 1
    assert summary["outdated_policy_devices"] == 1
