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
            "agent_version": "0.2.0",
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
            "agent_version": "0.2.0",
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
            "agent_version": "0.2.0",
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
