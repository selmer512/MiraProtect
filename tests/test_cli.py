from __future__ import annotations

from mira_protect.cli import build_parser
from mira_protect.detection import DetectionEngine
from mira_protect.endpoint_agent import TEST_BLOCK_MARKER
from mira_protect.schemas import AIEvent, EventType


def test_cli_accepts_linux_protection_test_marker() -> None:
    parser = build_parser()
    args = parser.parse_args(["synthetic-target", "--seconds", "1", TEST_BLOCK_MARKER])
    assert args.command == "synthetic-target"
    assert args.mira_protect_test_block is True
    assert args.seconds == 1


def test_cli_global_json_option_parses_before_command() -> None:
    parser = build_parser()
    args = parser.parse_args(["--json", "events", "--limit", "10"])
    assert args.json is True
    assert args.limit == 10


def test_endpoint_heartbeat_does_not_create_unknown_provider_finding() -> None:
    event = AIEvent(event_type=EventType.ENDPOINT_HEARTBEAT)
    findings = DetectionEngine().evaluate(event)
    assert all(finding.detector_id != "MP-AI-004" for finding in findings)
