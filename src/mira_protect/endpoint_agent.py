from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import psutil

AGENT_VERSION = "0.2.0"
TEST_BLOCK_MARKER = "--mira-protect-test-block"

DEFAULT_AI_PROCESS_NAMES = {
    "aider",
    "aider.exe",
    "claude",
    "claude.exe",
    "codex",
    "codex.exe",
    "copilot",
    "copilot.exe",
    "cursor",
    "cursor.exe",
    "gemini",
    "gemini.exe",
    "lmstudio",
    "lmstudio.exe",
    "ollama",
    "ollama.exe",
    "opencode",
    "opencode.exe",
}

DEFAULT_COMMAND_MARKERS = {
    "@anthropic-ai/claude-code",
    "aider-chat",
    "github copilot",
    "ollama run",
    "openai codex",
    TEST_BLOCK_MARKER,
}


@dataclass
class AgentConfig:
    control_plane_url: str = "http://127.0.0.1:8080"
    token: str | None = None
    device_id: str = field(default_factory=lambda: socket.gethostname().lower())
    mode: str = "monitor"
    poll_seconds: float = 2.0
    heartbeat_seconds: float = 60.0
    request_timeout_seconds: float = 5.0
    fail_closed: bool = False
    hash_executables: bool = True
    max_hash_bytes: int = 100 * 1024 * 1024
    process_names: set[str] = field(default_factory=lambda: set(DEFAULT_AI_PROCESS_NAMES))
    command_markers: set[str] = field(default_factory=lambda: set(DEFAULT_COMMAND_MARKERS))

    @classmethod
    def load(cls) -> "AgentConfig":
        data: dict[str, Any] = {}
        config_path = os.getenv("MIRA_AGENT_CONFIG")
        if config_path:
            with Path(config_path).expanduser().open("r", encoding="utf-8") as handle:
                data = json.load(handle)

        cfg = cls()
        cfg.control_plane_url = str(
            os.getenv("MIRA_CONTROL_PLANE_URL", data.get("control_plane_url", cfg.control_plane_url))
        ).rstrip("/")
        cfg.token = os.getenv("MIRA_AGENT_TOKEN", data.get("token"))
        cfg.device_id = str(os.getenv("MIRA_DEVICE_ID", data.get("device_id", cfg.device_id)))
        cfg.mode = str(os.getenv("MIRA_AGENT_MODE", data.get("mode", cfg.mode))).lower()
        cfg.poll_seconds = float(os.getenv("MIRA_POLL_SECONDS", data.get("poll_seconds", cfg.poll_seconds)))
        cfg.heartbeat_seconds = float(
            os.getenv("MIRA_HEARTBEAT_SECONDS", data.get("heartbeat_seconds", cfg.heartbeat_seconds))
        )
        cfg.request_timeout_seconds = float(
            os.getenv(
                "MIRA_REQUEST_TIMEOUT_SECONDS",
                data.get("request_timeout_seconds", cfg.request_timeout_seconds),
            )
        )
        cfg.fail_closed = _as_bool(os.getenv("MIRA_FAIL_CLOSED", data.get("fail_closed", cfg.fail_closed)))
        cfg.hash_executables = _as_bool(
            os.getenv("MIRA_HASH_EXECUTABLES", data.get("hash_executables", cfg.hash_executables))
        )
        cfg.max_hash_bytes = int(data.get("max_hash_bytes", cfg.max_hash_bytes))

        if data.get("process_names"):
            cfg.process_names.update(str(v).lower() for v in data["process_names"])
        if data.get("command_markers"):
            cfg.command_markers.update(str(v).lower() for v in data["command_markers"])

        if cfg.mode not in {"monitor", "guard", "enforce"}:
            raise ValueError("MIRA_AGENT_MODE must be monitor, guard, or enforce")
        if cfg.poll_seconds < 0.25:
            raise ValueError("poll_seconds must be at least 0.25 seconds")
        return cfg


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log(event: str, **fields: Any) -> None:
    print(json.dumps({"timestamp": _utc_now(), "event": event, **fields}, default=str), flush=True)


def _sha256(path: str | None, max_bytes: int) -> str | None:
    if not path:
        return None
    try:
        file_path = Path(path)
        if not file_path.is_file() or file_path.stat().st_size > max_bytes:
            return None
        digest = hashlib.sha256()
        with file_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, PermissionError):
        return None


def _ip_addresses() -> list[str]:
    addresses: set[str] = set()
    try:
        for values in psutil.net_if_addrs().values():
            for addr in values:
                if addr.family in {socket.AF_INET, socket.AF_INET6}:
                    value = addr.address.split("%", 1)[0]
                    if value and not value.startswith("127.") and value != "::1":
                        addresses.add(value)
    except Exception:
        pass
    return sorted(addresses)


class EndpointAgent:
    def __init__(self, config: AgentConfig) -> None:
        self.config = config
        headers = {"User-Agent": f"MiraProtectEndpoint/{AGENT_VERSION}"}
        if config.token:
            headers["Authorization"] = f"Bearer {config.token}"
        self.client = httpx.Client(
            base_url=config.control_plane_url,
            headers=headers,
            timeout=config.request_timeout_seconds,
        )
        self.seen: dict[tuple[int, float], float] = {}
        self.last_heartbeat = 0.0

    def close(self) -> None:
        self.client.close()

    def heartbeat(self) -> None:
        payload = {
            "device_id": self.config.device_id,
            "hostname": socket.gethostname(),
            "username": _username(),
            "agent_version": AGENT_VERSION,
            "mode": self.config.mode,
            "platform": platform.system(),
            "platform_version": platform.version(),
            "ip_addresses": _ip_addresses(),
        }
        try:
            response = self.client.post("/api/v1/endpoint/heartbeat", json=payload)
            response.raise_for_status()
            _log("heartbeat_sent", device_id=self.config.device_id, mode=self.config.mode)
        except Exception as exc:
            _log("heartbeat_failed", error=str(exc), control_plane=self.config.control_plane_url)

    def run_once(self) -> int:
        evaluated = 0
        now = time.monotonic()
        if now - self.last_heartbeat >= self.config.heartbeat_seconds:
            self.heartbeat()
            self.last_heartbeat = now

        current_keys: set[tuple[int, float]] = set()
        for proc in psutil.process_iter(["pid", "ppid", "name", "exe", "cmdline", "create_time", "username"]):
            if proc.pid == os.getpid():
                continue
            try:
                info = proc.info
                create_time = float(info.get("create_time") or 0.0)
                key = (proc.pid, create_time)
                current_keys.add(key)
                if key in self.seen:
                    continue

                matched_rules = self._match_process(info)
                self.seen[key] = now
                if not matched_rules:
                    continue

                evaluated += 1
                observation = self._observation(info, matched_rules)
                decision = self._evaluate(observation)
                self._apply_decision(proc, observation, decision)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as exc:
                _log("process_evaluation_error", pid=proc.pid, error=str(exc))

        stale = [key for key in self.seen if key not in current_keys]
        for key in stale:
            self.seen.pop(key, None)
        return evaluated

    def run_forever(self) -> None:
        _log(
            "agent_started",
            version=AGENT_VERSION,
            device_id=self.config.device_id,
            mode=self.config.mode,
            control_plane=self.config.control_plane_url,
            fail_closed=self.config.fail_closed,
        )
        try:
            while True:
                self.run_once()
                time.sleep(self.config.poll_seconds)
        except KeyboardInterrupt:
            _log("agent_stopped", reason="keyboard_interrupt")
        finally:
            self.close()

    def _match_process(self, info: dict[str, Any]) -> list[str]:
        name = str(info.get("name") or "").lower()
        cmdline = [str(v) for v in (info.get("cmdline") or [])]
        command = " ".join(cmdline).lower()
        matches: list[str] = []

        if name in self.config.process_names:
            matches.append(f"local:ai-process:{name}")
        for marker in sorted(self.config.command_markers):
            if marker and marker in command:
                rule = "local:test-block" if marker == TEST_BLOCK_MARKER else f"local:ai-command:{marker}"
                matches.append(rule)
        return sorted(set(matches))

    def _observation(self, info: dict[str, Any], matched_rules: list[str]) -> dict[str, Any]:
        executable = info.get("exe")
        create_time = info.get("create_time")
        started_at = None
        if create_time:
            started_at = datetime.fromtimestamp(float(create_time), timezone.utc).isoformat()
        return {
            "device_id": self.config.device_id,
            "hostname": socket.gethostname(),
            "username": info.get("username") or _username(),
            "pid": int(info.get("pid") or 0),
            "parent_pid": info.get("ppid"),
            "process_name": str(info.get("name") or "unknown"),
            "executable": executable,
            "command_line": [str(v) for v in (info.get("cmdline") or [])],
            "executable_sha256": (
                _sha256(str(executable), self.config.max_hash_bytes)
                if self.config.hash_executables
                else None
            ),
            "started_at": started_at,
            "agent_version": AGENT_VERSION,
            "mode": self.config.mode,
            "matched_local_rules": matched_rules,
            "attributes": {"platform": platform.system()},
        }

    def _evaluate(self, observation: dict[str, Any]) -> dict[str, Any]:
        try:
            response = self.client.post("/api/v1/endpoint/process/evaluate", json=observation)
            response.raise_for_status()
            result = response.json()
            _log(
                "process_evaluated",
                pid=observation["pid"],
                process=observation["process_name"],
                decision=result.get("decision"),
                effective_action=result.get("effective_action"),
                matched_rules=result.get("matched_rules", []),
            )
            return result
        except Exception as exc:
            _log(
                "control_plane_unavailable",
                pid=observation["pid"],
                process=observation["process_name"],
                error=str(exc),
            )
            local_test_block = "local:test-block" in observation.get("matched_local_rules", [])
            should_block = self.config.fail_closed or local_test_block
            return {
                "decision": "block" if should_block else "monitor",
                "effective_action": "terminate" if should_block else "observe",
                "matched_rules": ["agent:offline-fail-closed"] if should_block else ["agent:offline-monitor"],
                "message": "Local fallback decision while control plane is unavailable",
            }

    def _apply_decision(
        self,
        proc: psutil.Process,
        observation: dict[str, Any],
        decision: dict[str, Any],
    ) -> None:
        action = str(decision.get("effective_action", "observe")).lower()
        if action != "terminate":
            return

        if self.config.mode != "enforce":
            _log(
                "termination_suppressed",
                pid=proc.pid,
                process=observation["process_name"],
                mode=self.config.mode,
                reason="agent_not_in_enforce_mode",
            )
            return

        try:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except psutil.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
            _log(
                "process_terminated",
                pid=proc.pid,
                process=observation["process_name"],
                matched_rules=decision.get("matched_rules", []),
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            _log(
                "process_termination_failed",
                pid=proc.pid,
                process=observation["process_name"],
                error=str(exc),
            )


def _username() -> str | None:
    try:
        return psutil.Process().username()
    except Exception:
        return os.getenv("USERNAME") or os.getenv("USER")


def main() -> None:
    try:
        config = AgentConfig.load()
    except Exception as exc:
        _log("configuration_error", error=str(exc))
        raise SystemExit(2) from exc

    if "--once" in sys.argv:
        agent = EndpointAgent(config)
        try:
            count = agent.run_once()
            _log("scan_complete", evaluated=count)
        finally:
            agent.close()
        return

    EndpointAgent(config).run_forever()


if __name__ == "__main__":
    main()
