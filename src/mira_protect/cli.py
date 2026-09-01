from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import time
from typing import Any

import httpx

from .endpoint_agent import AgentConfig, EndpointAgent, TEST_BLOCK_MARKER

DEFAULT_URL = "http://127.0.0.1:8080"


def _client(args: argparse.Namespace) -> httpx.Client:
    base_url = str(args.url or os.getenv("MIRA_CONTROL_PLANE_URL", DEFAULT_URL)).rstrip("/")
    token = args.token or os.getenv("MIRA_AGENT_TOKEN") or os.getenv("MIRA_ENDPOINT_TOKEN")
    headers = {"User-Agent": "MiraProtectCLI/0.2.0"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return httpx.Client(base_url=base_url, headers=headers, timeout=args.timeout)


def _emit(value: Any, as_json: bool) -> None:
    if as_json:
        print(json.dumps(value, indent=2, default=str, sort_keys=True))
        return

    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                print(f"{key}:")
                print(json.dumps(item, indent=2, default=str))
            else:
                print(f"{key}: {item}")
        return

    if isinstance(value, list):
        if not value:
            print("No results.")
            return
        for index, item in enumerate(value, start=1):
            print(f"[{index}]")
            print(json.dumps(item, indent=2, default=str))
        return

    print(value)


def _get(args: argparse.Namespace, path: str, params: dict[str, Any] | None = None) -> Any:
    with _client(args) as client:
        response = client.get(path, params=params)
        response.raise_for_status()
        return response.json()


def _command_health(args: argparse.Namespace) -> int:
    _emit(_get(args, "/health"), args.json)
    return 0


def _command_summary(args: argparse.Namespace) -> int:
    _emit(_get(args, "/api/v1/dashboard/summary"), args.json)
    return 0


def _command_assets(args: argparse.Namespace) -> int:
    _emit(_get(args, "/api/v1/assets"), args.json)
    return 0


def _command_events(args: argparse.Namespace) -> int:
    _emit(_get(args, "/api/v1/events", {"limit": args.limit}), args.json)
    return 0


def _command_findings(args: argparse.Namespace) -> int:
    _emit(_get(args, "/api/v1/findings", {"limit": args.limit}), args.json)
    return 0


def _command_threats(args: argparse.Namespace) -> int:
    _emit(_get(args, "/api/v1/threats"), args.json)
    return 0


def _command_doctor(args: argparse.Namespace) -> int:
    report: dict[str, Any] = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "control_plane": str(args.url or os.getenv("MIRA_CONTROL_PLANE_URL", DEFAULT_URL)),
    }
    try:
        health = _get(args, "/health")
        report["health"] = health
        report["ready"] = health.get("status") == "ok" and health.get("database") == "ok"
    except Exception as exc:
        report["ready"] = False
        report["error"] = str(exc)
    _emit(report, args.json)
    return 0 if report["ready"] else 1


def _command_agent(args: argparse.Namespace) -> int:
    config = AgentConfig.load()
    if args.url:
        config.control_plane_url = args.url.rstrip("/")
    if args.token:
        config.token = args.token
    if args.mode:
        config.mode = args.mode
    if args.poll_seconds is not None:
        config.poll_seconds = args.poll_seconds

    agent = EndpointAgent(config)
    if args.once:
        try:
            count = agent.run_once()
            _emit({"evaluated": count, "mode": config.mode, "device_id": config.device_id}, args.json)
        finally:
            agent.close()
        return 0

    agent.run_forever()
    return 0


def _command_synthetic_target(args: argparse.Namespace) -> int:
    # This is intentionally harmless. The marker exists only so the endpoint agent can
    # exercise an end-to-end BLOCK -> terminate decision without targeting a real tool.
    if not args.mira_protect_test_block:
        print(
            "Synthetic target refused to run without the explicit test marker. "
            f"Add {TEST_BLOCK_MARKER}.",
            file=sys.stderr,
        )
        return 2

    started = time.monotonic()
    print(
        json.dumps(
            {
                "event": "synthetic_target_started",
                "pid": os.getpid(),
                "marker": TEST_BLOCK_MARKER,
                "seconds": args.seconds,
            }
        ),
        flush=True,
    )
    while time.monotonic() - started < args.seconds:
        time.sleep(0.25)
    print(json.dumps({"event": "synthetic_target_completed", "pid": os.getpid()}), flush=True)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mira-protect",
        description="Mira Protect enterprise AI security control-plane CLI",
    )
    parser.add_argument(
        "--url",
        default=None,
        help="Control-plane base URL (default: MIRA_CONTROL_PLANE_URL or http://127.0.0.1:8080)",
    )
    parser.add_argument("--token", default=None, help="Endpoint/API bearer token")
    parser.add_argument("--timeout", type=float, default=5.0, help="HTTP timeout in seconds")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")

    subparsers = parser.add_subparsers(dest="command", required=True)

    commands = {
        "health": ("Show control-plane health", _command_health),
        "summary": ("Show dashboard summary", _command_summary),
        "assets": ("List discovered/managed assets", _command_assets),
        "threats": ("List COMPASS-aligned threat catalog", _command_threats),
        "doctor": ("Check whether this CLI can reach a ready control plane", _command_doctor),
    }
    for name, (help_text, handler) in commands.items():
        command = subparsers.add_parser(name, help=help_text)
        command.set_defaults(handler=handler)

    events = subparsers.add_parser("events", help="List normalized security events")
    events.add_argument("--limit", type=int, default=50)
    events.set_defaults(handler=_command_events)

    findings = subparsers.add_parser("findings", help="List detection findings")
    findings.add_argument("--limit", type=int, default=50)
    findings.set_defaults(handler=_command_findings)

    agent = subparsers.add_parser("agent", help="Run the managed endpoint agent")
    agent.add_argument("--once", action="store_true", help="Run one endpoint scan and exit")
    agent.add_argument("--mode", choices=("monitor", "guard", "enforce"), default=None)
    agent.add_argument("--poll-seconds", type=float, default=None)
    agent.set_defaults(handler=_command_agent)

    target = subparsers.add_parser(
        "synthetic-target",
        help="Run a harmless process used to validate endpoint termination",
    )
    target.add_argument("--seconds", type=float, default=120.0)
    target.add_argument(
        TEST_BLOCK_MARKER,
        dest="mira_protect_test_block",
        action="store_true",
        help="Required safety marker that makes the target eligible for the synthetic block policy",
    )
    target.set_defaults(handler=_command_synthetic_target)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        result = int(args.handler(args))
    except httpx.HTTPStatusError as exc:
        body = exc.response.text[:1000]
        print(f"HTTP {exc.response.status_code}: {body}", file=sys.stderr)
        raise SystemExit(1) from exc
    except httpx.HTTPError as exc:
        print(f"Control-plane request failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    except KeyboardInterrupt:
        raise SystemExit(130)
    raise SystemExit(result)


if __name__ == "__main__":
    main()
