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

AGENT_VERSION = "0.3.0"
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
}


@dataclass
class AgentConfig:
    control_plane_url: str = "http://127.0.0.1:8080"
    token: str | None = None
    enrollment_token: str | None = None
    credential_path: str | None = None
    policy_cache_path: str | None = None
    policy_refresh_seconds: float = 300.0
    device_id: str = field(default_factory=lambda: socket.gethostname().lower())
    mode: str = "monitor"
    poll_seconds: float = 2.0
    heartbeat_seconds: float = 60.0
    request_timeout_seconds: float = 5.0
    fail_closed: bool = False
    enable_test_controls: bool = False
    hash_executables: bool = True
    max_hash_bytes: int = 100 * 1024 * 1024
    process_names: set[str] = field(default_factory=lambda: set(DEFAULT_AI_PROCESS_NAMES))
    command_markers: set[str] = field(default_factory=lambda: set(DEFAULT_COMMAND_MARKERS))

    @classmethod
    def load(cls) -> "AgentConfig":
        data: dict[str, Any] = {}
        config_path = os.getenv("MIRA_AGENT_CONFIG")
        if config_path:
            config_file = Path(config_path).expanduser()
            with config_file.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
        else:
            config_file = None

        cfg = cls()
        cfg.control_plane_url = str(
            os.getenv("MIRA_CONTROL_PLANE_URL", data.get("control_plane_url", cfg.control_plane_url))
        ).rstrip("/")
        cfg.credential_path = os.getenv(
            "MIRA_AGENT_CREDENTIAL_PATH",
            data.get("credential_path"),
        )
        cfg.policy_cache_path = os.getenv(
            "MIRA_POLICY_CACHE_PATH",
            data.get("policy_cache_path"),
        )
        if config_file:
            if not cfg.credential_path:
                cfg.credential_path = str(config_file.with_name("device-token.txt"))
            if not cfg.policy_cache_path:
                cfg.policy_cache_path = str(config_file.with_name("policy-cache.json"))

        cfg.token = os.getenv("MIRA_AGENT_TOKEN", data.get("token"))
        if not cfg.token and cfg.credential_path:
            cfg.token = _read_secret(cfg.credential_path)

        cfg.enrollment_token = os.getenv(
            "MIRA_ENROLLMENT_TOKEN",
            data.get("enrollment_token"),
        )
        cfg.device_id = str(os.getenv("MIRA_DEVICE_ID", data.get("device_id", cfg.device_id)))
        cfg.mode = str(os.getenv("MIRA_AGENT_MODE", data.get("mode", cfg.mode))).lower()
        cfg.poll_seconds = float(
            os.getenv("MIRA_POLL_SECONDS", data.get("poll_seconds", cfg.poll_seconds))
        )
        cfg.heartbeat_seconds = float(
            os.getenv("MIRA_HEARTBEAT_SECONDS", data.get("heartbeat_seconds", cfg.heartbeat_seconds))
        )
        cfg.request_timeout_seconds = float(
            os.getenv(
                "MIRA_REQUEST_TIMEOUT_SECONDS",
                data.get("request_timeout_seconds", cfg.request_timeout_seconds),
            )
        )
        cfg.policy_refresh_seconds = float(
            os.getenv(
                "MIRA_POLICY_REFRESH_SECONDS",
                data.get("policy_refresh_seconds", cfg.policy_refresh_seconds),
            )
        )
        cfg.fail_closed = _as_bool(
            os.getenv("MIRA_FAIL_CLOSED", data.get("fail_closed", cfg.fail_closed))
        )
        cfg.enable_test_controls = _as_bool(
            os.getenv(
                "MIRA_ENABLE_TEST_CONTROLS",
                data.get("enable_test_controls", cfg.enable_test_controls),
            )
        )
        cfg.hash_executables = _as_bool(
            os.getenv("MIRA_HASH_EXECUTABLES", data.get("hash_executables", cfg.hash_executables))
        )
        cfg.max_hash_bytes = int(data.get("max_hash_bytes", cfg.max_hash_bytes))

        if data.get("process_names"):
            cfg.process_names.update(str(value).lower() for value in data["process_names"])
        if data.get("command_markers"):
            cfg.command_markers.update(str(value).lower() for value in data["command_markers"])

        if cfg.mode not in {"monitor", "guard", "enforce"}:
            raise ValueError("MIRA_AGENT_MODE must be monitor, guard, or enforce")
        if cfg.poll_seconds < 0.25:
            raise ValueError("poll_seconds must be at least 0.25 seconds")
        if cfg.policy_refresh_seconds < 30:
            raise ValueError("policy_refresh_seconds must be at least 30 seconds")
        return cfg


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log(event: str, **fields: Any) -> None:
    print(json.dumps({"timestamp": _utc_now(), "event": event, **fields}, default=str), flush=True)


def _read_secret(path: str) -> str | None:
    try:
        value = Path(path).expanduser().read_text(encoding="utf-8").strip()
        return value or None
    except OSError:
        return None


def _write_secret(path: str, value: str) -> None:
    destination = Path(path).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(value + "\n", encoding="utf-8")
    try:
        os.chmod(temporary, 0o600)
    except OSError:
        pass
    os.replace(temporary, destination)
    try:
        os.chmod(destination, 0o600)
    except OSError:
        pass


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
        self.base_process_names = set(config.process_names)
        self.base_command_markers = set(config.command_markers)
        self.central_deny_processes: set[str] = set()
        self.policy_version: str | None = None
        self.recommended_mode: str | None = None
        self.seen: dict[tuple[int, float], float] = {}
        self.last_heartbeat = 0.0
        self.last_policy_refresh = 0.0

        headers = {"User-Agent": f"MiraProtectEndpoint/{AGENT_VERSION}"}
        if config.token:
            headers["Authorization"] = f"Bearer {config.token}"
        self.client = httpx.Client(
            base_url=config.control_plane_url,
            headers=headers,
            timeout=config.request_timeout_seconds,
        )
        self._load_policy_cache()

    def close(self) -> None:
        self.client.close()

    def _set_token(self, token: str) -> None:
        self.config.token = token
        self.client.headers["Authorization"] = f"Bearer {token}"

    def enroll(self) -> bool:
        if self.config.token:
            return True
        if not self.config.enrollment_token:
            _log(
                "enrollment_skipped",
                device_id=self.config.device_id,
                reason="no_device_credential_or_enrollment_token",
            )
            return False

        payload = {
            "device_id": self.config.device_id,
            "hostname": socket.gethostname(),
            "platform": platform.system(),
            "platform_version": platform.version(),
            "agent_version": AGENT_VERSION,
        }
        headers = {"Authorization": f"Bearer {self.config.enrollment_token}"}
        try:
            response = self.client.post("/api/v1/endpoint/enroll", json=payload, headers=headers)
            response.raise_for_status()
            result = response.json()
            token = str(result["device_token"])
            self._set_token(token)
            if self.config.credential_path:
                _write_secret(self.config.credential_path, token)
            self.config.enrollment_token = None
            _log(
                "endpoint_enrolled",
                device_id=self.config.device_id,
                policy_url=result.get("policy_url"),
            )
            return True
        except Exception as exc:
            _log(
                "endpoint_enrollment_failed",
                device_id=self.config.device_id,
                error=str(exc),
            )
            return False

    def _load_policy_cache(self) -> None:
        if not self.config.policy_cache_path:
            return
        try:
            payload = json.loads(
                Path(self.config.policy_cache_path).expanduser().read_text(encoding="utf-8")
            )
            self._apply_policy(payload, source="cache")
        except (OSError, ValueError, TypeError):
            return

    def _save_policy_cache(self, payload: dict[str, Any]) -> None:
        if not self.config.policy_cache_path:
            return
        path = Path(self.config.policy_cache_path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)

    def _apply_policy(self, payload: dict[str, Any], *, source: str) -> None:
        deny_processes = {
            str(value).lower()
            for value in payload.get("deny_processes", [])
            if str(value).strip()
        }
        process_names = {
            str(value).lower()
            for value in payload.get("process_names", [])
            if str(value).strip()
        }
        command_markers = {
            str(value).lower()
            for value in payload.get("command_markers", [])
            if str(value).strip()
        }

        self.central_deny_processes = deny_processes
        self.config.process_names = self.base_process_names | process_names | deny_processes
        self.config.command_markers = self.base_command_markers | command_markers
        self.config.fail_closed = _as_bool(payload.get("fail_closed", self.config.fail_closed))
        self.config.enable_test_controls = _as_bool(
            payload.get("enable_test_controls", self.config.enable_test_controls)
        )

        refresh = payload.get("refresh_seconds")
        if refresh is not None:
            self.config.policy_refresh_seconds = max(30.0, min(float(refresh), 86400.0))

        self.policy_version = str(payload.get("policy_version") or "") or None
        recommended = payload.get("recommended_mode")
        self.recommended_mode = str(recommended) if recommended else None
        _log(
            "policy_applied",
            source=source,
            policy_version=self.policy_version,
            deny_processes=len(self.central_deny_processes),
            recommended_mode=self.recommended_mode,
        )

    def refresh_policy(self, *, force: bool = False) -> bool:
        if not self.config.token:
            return False
        now = time.monotonic()
        if not force and now - self.last_policy_refresh < self.config.policy_refresh_seconds:
            return True

        try:
            response = self.client.get(f"/api/v1/endpoint/policy/{self.config.device_id}")
            response.raise_for_status()
            payload = response.json()
            previous_version = self.policy_version
            self._apply_policy(payload, source="control_plane")
            self._save_policy_cache(payload)
            self.last_policy_refresh = now
            if previous_version != self.policy_version:
                _log(
                    "policy_updated",
                    previous_version=previous_version,
                    policy_version=self.policy_version,
                )
            return True
        except Exception as exc:
            self.last_policy_refresh = now
            _log(
                "policy_refresh_failed",
                device_id=self.config.device_id,
                policy_version=self.policy_version,
                error=str(exc),
            )
            return False

    def heartbeat(self) -> None:
        if not self.config.token and not self.enroll():
            _log(
                "heartbeat_skipped",
                device_id=self.config.device_id,
                reason="endpoint_not_authenticated",
            )
            return

        payload = {
            "device_id": self.config.device_id,
            "hostname": socket.gethostname(),
            "username": _username(),
            "agent_version": AGENT_VERSION,
            "mode": self.config.mode,
            "platform": platform.system(),
            "platform_version": platform.version(),
            "ip_addresses": _ip_addresses(),
            "policy_version": self.policy_version,
        }
        try:
            response = self.client.post("/api/v1/endpoint/heartbeat", json=payload)
            response.raise_for_status()
            _log(
                "heartbeat_sent",
                device_id=self.config.device_id,
                mode=self.config.mode,
                policy_version=self.policy_version,
            )
        except Exception as exc:
            _log("heartbeat_failed", error=str(exc), control_plane=self.config.control_plane_url)

    def run_once(self) -> int:
        evaluated = 0
        now = time.monotonic()

        if not self.config.token:
            self.enroll()
        if self.config.token:
            self.refresh_policy()

        if now - self.last_heartbeat >= self.config.heartbeat_seconds:
            self.heartbeat()
            self.last_heartbeat = now

        current_keys: set[tuple[int, float]] = set()
        for proc in psutil.process_iter(
            ["pid", "ppid", "name", "exe", "cmdline", "create_time", "username"]
        ):
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
            test_controls=self.config.enable_test_controls,
            policy_version=self.policy_version,
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
        cmdline = [str(value) for value in (info.get("cmdline") or [])]
        command = " ".join(cmdline).lower()
        matches: list[str] = []

        if name in self.central_deny_processes:
            matches.append(f"local:central-deny-process:{name}")
        if name in self.config.process_names:
            matches.append(f"local:ai-process:{name}")
        if self.config.enable_test_controls and TEST_BLOCK_MARKER in command:
            matches.append("local:test-block")
        for marker in sorted(self.config.command_markers):
            if marker and marker in command:
                matches.append(f"local:ai-command:{marker}")
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
            "command_line": [str(value) for value in (info.get("cmdline") or [])],
            "executable_sha256": (
                _sha256(str(executable), self.config.max_hash_bytes)
                if self.config.hash_executables
                else None
            ),
            "started_at": started_at,
            "agent_version": AGENT_VERSION,
            "mode": self.config.mode,
            "matched_local_rules": matched_rules,
            "attributes": {
                "platform": platform.system(),
                "policy_version": self.policy_version,
            },
        }

    def _evaluate(self, observation: dict[str, Any]) -> dict[str, Any]:
        if not self.config.token:
            self.enroll()
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
                policy_version=self.policy_version,
            )
            return result
        except Exception as exc:
            _log(
                "control_plane_unavailable",
                pid=observation["pid"],
                process=observation["process_name"],
                error=str(exc),
            )
            matched_rules = observation.get("matched_local_rules", [])
            cached_central_deny = any(
                str(rule).startswith("local:central-deny-process:") for rule in matched_rules
            )
            should_block = self.config.fail_closed and cached_central_deny
            return {
                "decision": "block" if should_block else "monitor",
                "effective_action": "terminate" if should_block else "observe",
                "matched_rules": (
                    ["agent:offline-cached-central-deny"]
                    if should_block
                    else ["agent:offline-monitor"]
                ),
                "message": "Local fallback decision while control plane is unavailable",
            }

    def _report_enforcement(
        self,
        observation: dict[str, Any],
        decision: dict[str, Any],
        result: str,
        *,
        reason: str | None = None,
        error: str | None = None,
    ) -> None:
        decision_event_id = decision.get("event_id")
        if not decision_event_id:
            _log(
                "enforcement_report_skipped",
                pid=observation.get("pid"),
                result=result,
                reason="no_central_decision_event",
            )
            return

        payload = {
            "device_id": self.config.device_id,
            "hostname": socket.gethostname(),
            "username": observation.get("username") or _username(),
            "pid": observation["pid"],
            "process_name": observation["process_name"],
            "decision_event_id": decision_event_id,
            "action": str(decision.get("effective_action", "terminate")),
            "result": result,
            "mode": self.config.mode,
            "agent_version": AGENT_VERSION,
            "reason": reason,
            "error": error,
        }
        try:
            response = self.client.post("/api/v1/endpoint/enforcement", json=payload)
            response.raise_for_status()
            _log(
                "enforcement_reported",
                pid=observation["pid"],
                decision_event_id=decision_event_id,
                result=result,
            )
        except Exception as exc:
            _log(
                "enforcement_report_failed",
                pid=observation["pid"],
                decision_event_id=decision_event_id,
                result=result,
                error=str(exc),
            )

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
            self._report_enforcement(
                observation,
                decision,
                "suppressed",
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
            self._report_enforcement(observation, decision, "succeeded")
        except psutil.NoSuchProcess:
            _log(
                "process_already_exited",
                pid=proc.pid,
                process=observation["process_name"],
            )
            self._report_enforcement(
                observation,
                decision,
                "succeeded",
                reason="process_already_exited",
            )
        except psutil.AccessDenied as exc:
            _log(
                "process_termination_failed",
                pid=proc.pid,
                process=observation["process_name"],
                error=str(exc),
            )
            self._report_enforcement(observation, decision, "failed", error=str(exc))


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
