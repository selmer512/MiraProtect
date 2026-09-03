from __future__ import annotations

from pathlib import Path

from mira_protect.endpoint_agent import AgentConfig, EndpointAgent


def _observation(process_name: str = "claude") -> dict:
    return {
        "device_id": "offline-test",
        "hostname": "offline-test",
        "username": "tester",
        "pid": 7001,
        "process_name": process_name,
        "command_line": [process_name, "--version"],
        "matched_local_rules": [f"local:ai-process:{process_name}"],
    }


def test_control_plane_outage_is_fail_open_by_default(tmp_path: Path) -> None:
    agent = EndpointAgent(
        AgentConfig(
            control_plane_url="http://127.0.0.1:9",
            request_timeout_seconds=0.05,
            fail_closed=True,
            queue_file=str(tmp_path / "queue.jsonl"),
        )
    )
    agent.policy = {
        "version": "cached-policy",
        "allow_processes": [],
        "deny_processes": ["claude"],
        "offline_fail_closed_allowed": False,
    }
    try:
        result = agent._evaluate(_observation())
    finally:
        agent.close()

    assert result["decision"] == "monitor"
    assert result["effective_action"] == "observe"


def test_offline_block_requires_explicit_cached_policy_authorization(tmp_path: Path) -> None:
    agent = EndpointAgent(
        AgentConfig(
            control_plane_url="http://127.0.0.1:9",
            request_timeout_seconds=0.05,
            fail_closed=True,
            queue_file=str(tmp_path / "queue.jsonl"),
        )
    )
    agent.policy = {
        "version": "cached-policy",
        "allow_processes": [],
        "deny_processes": ["claude"],
        "offline_fail_closed_allowed": True,
    }
    try:
        result = agent._evaluate(_observation())
    finally:
        agent.close()

    assert result["decision"] == "block"
    assert result["effective_action"] == "terminate"
    assert result["matched_rules"] == ["agent:offline-cached-explicit-deny"]


def test_allowlist_prevents_cached_offline_block(tmp_path: Path) -> None:
    agent = EndpointAgent(
        AgentConfig(
            control_plane_url="http://127.0.0.1:9",
            request_timeout_seconds=0.05,
            fail_closed=True,
            queue_file=str(tmp_path / "queue.jsonl"),
        )
    )
    agent.policy = {
        "version": "cached-policy",
        "allow_processes": ["claude"],
        "deny_processes": ["claude"],
        "offline_fail_closed_allowed": True,
    }
    try:
        result = agent._evaluate(_observation())
    finally:
        agent.close()

    assert result["decision"] == "monitor"


def test_executable_hash_cache_refreshes_when_file_changes(tmp_path: Path) -> None:
    executable = tmp_path / "ai-tool"
    executable.write_bytes(b"version-one")
    agent = EndpointAgent(
        AgentConfig(
            control_plane_url="http://127.0.0.1:9",
            queue_file=str(tmp_path / "queue.jsonl"),
        )
    )
    try:
        first = agent._hash_executable(str(executable))
        second = agent._hash_executable(str(executable))
        assert first == second
        assert len(agent._hash_cache) == 1

        executable.write_bytes(b"version-two-with-a-different-size")
        third = agent._hash_executable(str(executable))
    finally:
        agent.close()

    assert third != first


def test_telemetry_queue_is_bounded(tmp_path: Path) -> None:
    queue_file = tmp_path / "queue.jsonl"
    agent = EndpointAgent(
        AgentConfig(
            control_plane_url="http://127.0.0.1:9",
            queue_file=str(queue_file),
            max_queue_items=2,
        )
    )
    try:
        agent._queue_telemetry("/first", {"value": 1})
        agent._queue_telemetry("/second", {"value": 2})
        agent._queue_telemetry("/third", {"value": 3})
        depth = agent._queue_depth()
        contents = queue_file.read_text(encoding="utf-8")
    finally:
        agent.close()

    assert depth == 2
    assert "/first" not in contents
    assert "/second" in contents
    assert "/third" in contents
