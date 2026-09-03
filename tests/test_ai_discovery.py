from __future__ import annotations

import os

os.environ.setdefault("MIRA_DATABASE_URL", "sqlite+pysqlite:///:memory:")

from fastapi.testclient import TestClient

from mira_protect.app import app, policy_bundle, repository
from mira_protect.policy import PolicyEngine
from mira_protect.providers import classify_ai_process
from mira_protect.schemas import (
    AIContext,
    AIEvent,
    EndpointPolicyBundle,
    EventType,
)

client = TestClient(app)


def setup_function() -> None:
    repository.clear()


def test_classifier_identifies_node_wrapped_claude_cli() -> None:
    match = classify_ai_process(
        "node",
        ["/usr/bin/node", "/home/tester/.local/bin/claude", "--version"],
    )
    assert match is not None
    assert match.provider == "anthropic"
    assert match.product == "Claude Code"


def test_real_ai_cli_discovery_creates_inventory_without_termination() -> None:
    response = client.post(
        "/api/v1/endpoint/process/evaluate",
        json={
            "device_id": "linux-ai-01",
            "hostname": "linux-ai-01",
            "username": "tester",
            "pid": 6001,
            "parent_pid": 5000,
            "process_name": "claude",
            "executable": "/usr/local/bin/claude",
            "command_line": ["claude", "--version"],
            "parent_chain": [
                {
                    "pid": 5000,
                    "process_name": "bash",
                    "executable": "/usr/bin/bash",
                    "command_line": ["bash"],
                }
            ],
            "mode": "monitor",
            "matched_local_rules": ["local:ai-process:claude"],
            "policy_version": policy_bundle.version,
        },
    )
    assert response.status_code == 200
    decision = response.json()
    assert decision["decision"] == "monitor"
    assert decision["effective_action"] == "observe"
    assert decision["evidence"]["provider"] == "anthropic"
    assert decision["evidence"]["product"] == "Claude Code"
    assert decision["evidence"]["parent_depth"] == 1
    assert decision["policy_version"] == policy_bundle.version

    inventory = client.get("/api/v1/ai-inventory").json()
    assert len(inventory) == 1
    assert inventory[0]["name"] == "Claude Code"
    assert inventory[0]["provider"] == "anthropic"
    assert inventory[0]["kind"] == "application"

    findings = client.get("/api/v1/findings").json()
    assert any(finding["detector_id"] == "MP-AI-006" for finding in findings)


def test_endpoint_policy_is_versioned() -> None:
    response = client.get("/api/v1/endpoint/policy")
    assert response.status_code == 200
    body = response.json()
    assert body["version"] == policy_bundle.version
    assert "allow_processes" in body
    assert "deny_processes" in body
    assert "approved_providers" in body


def test_allow_process_overrides_same_process_in_deny_list() -> None:
    bundle = EndpointPolicyBundle(
        version="test",
        allow_processes=["claude"],
        deny_processes=["claude"],
        approved_providers=["anthropic"],
        test_controls_enabled=False,
    )
    event = AIEvent(
        event_type=EventType.ENDPOINT_PROCESS,
        ai=AIContext(provider="anthropic", product="Claude Code"),
        metadata={"process_name": "claude", "provider_approved": True},
    )
    decision, rules = PolicyEngine(policy_bundle=bundle).evaluate(event)
    assert decision.value == "allow"
    assert "endpoint-denied-ai-process" not in rules


def test_explicit_deny_blocks_real_ai_process() -> None:
    bundle = EndpointPolicyBundle(
        version="test",
        deny_processes=["claude"],
        approved_providers=["anthropic"],
        test_controls_enabled=False,
    )
    event = AIEvent(
        event_type=EventType.ENDPOINT_PROCESS,
        ai=AIContext(provider="anthropic", product="Claude Code"),
        metadata={"process_name": "claude", "provider_approved": True},
    )
    decision, rules = PolicyEngine(policy_bundle=bundle).evaluate(event)
    assert decision.value == "block"
    assert "endpoint-denied-ai-process" in rules


def test_device_health_reports_current_policy_version() -> None:
    response = client.post(
        "/api/v1/endpoint/heartbeat",
        json={
            "device_id": "linux-health-01",
            "hostname": "linux-health-01",
            "username": "tester",
            "agent_version": "0.3.0",
            "mode": "guard",
            "platform": "Linux",
            "platform_version": "test",
            "policy_version": policy_bundle.version,
            "queue_depth": 2,
        },
    )
    assert response.status_code == 200

    devices = client.get("/api/v1/endpoint/devices").json()
    assert len(devices) == 1
    assert devices[0]["health"] == "online"
    assert devices[0]["policy_version"] == policy_bundle.version
    assert devices[0]["current_policy_version"] == policy_bundle.version
    assert devices[0]["queue_depth"] == 2
