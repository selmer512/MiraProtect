from __future__ import annotations

import os

os.environ.setdefault("MIRA_DATABASE_URL", "sqlite+pysqlite:///:memory:")

from fastapi.testclient import TestClient

from mira_protect.app import app, repository
from mira_protect.endpoint_agent import AgentConfig, EndpointAgent, TEST_BLOCK_MARKER
from mira_protect.policy import PolicyEngine
from mira_protect.schemas import AIEvent, EventType


client = TestClient(app)


def setup_function() -> None:
    repository.clear()


def test_agent_detects_synthetic_block_marker() -> None:
    agent = EndpointAgent(AgentConfig(control_plane_url="http://127.0.0.1:9"))
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


def test_policy_blocks_synthetic_endpoint_test() -> None:
    event = AIEvent(
        event_type=EventType.ENDPOINT_PROCESS,
        metadata={
            "process_name": "notepad.exe",
            "matched_local_rules": ["local:test-block"],
        },
    )
    decision, rules = PolicyEngine().evaluate(event)
    assert decision.value == "block"
    assert "endpoint-synthetic-protection-test" in rules


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


def test_endpoint_heartbeat_registers_managed_device() -> None:
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
    assert summary["events"] == 1
