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

from .providers import classify_ai_process, known_ai_command_markers, known_ai_process_names

AGENT_VERSION = "0.3.0"
TEST_BLOCK_MARKER = "--mira-protect-test-block"

DEFAULT_AI_PROCESS_NAMES = known_ai_process_names()
DEFAULT_COMMAND_MARKERS = known_ai_command_markers() | {TEST_BLOCK_MARKER}


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
    parent_depth: int = 4
    queue_file: str = field(
        default_factory=lambda: str(Path.home() / ".mira-protect" / "telemetry-queue.jsonl")
    )
    max_queue_items: int = 1000
    process_names: set[str] = field(default_factory=lambda: set(DEFAULT_AI_PROCESS_NAMES))
    command_markers: set[str] = field(default_factory=lambda: set(DEFAULT_COMMAND_MARKERS))

    @classmethod
    def load(cls) -> AgentConfig:
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
        cfg.parent_depth = int(data.get("parent_depth", cfg.parent_depth))
        cfg.queue_file = str(os.getenv("MIRA_QUEUE_FILE", data.get("queue_file", cfg.queue_file)))
        cfg.max_queue_items = int(data.get("max_queue_items", cfg.max_queue_items))

        if data.get("process_names"):
            cfg.process_names.update(str(value).lower() for value in data["process_names"])
        if data.get("command_markers"):
            cfg.command_markers.update(str(value).lower() for value in data["command_markers"])

        if cfg.mode not in {"monitor", "guard", "enforce"}:
            raise ValueError("MIRA_AGENT_MODE must be monitor, guard, or enforce")
        if cfg.poll_seconds < 0.1:
            raise ValueError("poll_seconds must be at least 0.1 seconds")
        if cfg.parent_depth < 0 or cfg.parent_depth > 16:
            raise ValueError("parent_depth must be between 0 and 16")
        return cfg


def _as_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _log(event: str, **fields: Any) -> None:
    print(json.dumps({"timestamp": _utc_now(), "event": event, **fields}, default=str), flush=True)


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
        self.policy: dict[str, Any] = {
            "version": None,
            "allow_processes": [],
            "deny_processes": [],
            "approved_providers": [],
            "offline_fail_closed_allowed": False,
        }
        self._hash_cache: dict[str, tuple[int, int, str | None]] = {}

    def close(self) -> None:
        self.client.close()

    @property
    def policy_version(self) -> str | None:
        value = self.policy.get("version")
        return str(value) if value else None

    def _refresh_policy(self) -> None:
        try:
            response = self.client.get("/api/v1/endpoint/policy")
            response.raise_for_status()
            new_policy = response.json()
            changed = new_policy.get("version") != self.policy.get("version")
            self.policy = new_policy
            if changed:
                _log(
                    "policy_updated",
                    version=self.policy_version,
                    allow_processes=self.policy.get("allow_processes", []),
                    deny_processes=self.policy.get("deny_processes", []),
                )
        except Exception as exc:
            _log("policy_refresh_failed", error=str(exc), cached_version=self.policy_version)

    def _queue_path(self) -> Path:
        return Path(self.config.queue_file).expanduser()

    def _queue_depth(self) -> int:
        path = self._queue_path()
        if not path.exists():
            return 0
        try:
            return sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
        except OSError:
            return 0

    def _queue_telemetry(self, path: str, payload: dict[str, Any]) -> None:
        queue_path = self._queue_path()
        try:
            queue_path.parent.mkdir(parents=True, exist_ok=True)
            items: list[str] = []
            if queue_path.exists():
                items = [line for line in queue_path.read_text(encoding="utf-8").splitlines() if line]
            item = json.dumps(
                {"queued_at": _utc_now(), "path": path, "payload": payload},
                default=str,
            )
            items.append(item)
            items = items[-self.config.max_queue_items :]
            queue_path.write_text("\n".join(items) + "\n", encoding="utf-8")
            _log("telemetry_queued", path=path, queue_depth=len(items))
        except OSError as exc:
            _log("telemetry_queue_failed", path=path, error=str(exc))

    def _flush_queue(self) -> None:
        queue_path = self._queue_path()
        if not queue_path.exists():
            return
        try:
            raw_items = [line for line in queue_path.read_text(encoding="utf-8").splitlines() if line]
        except OSError as exc:
            _log("telemetry_queue_read_failed", error=str(exc))
            return

        remaining: list[str] = []
        sent = 0
        for index, raw in enumerate(raw_items):
            try:
                item = json.loads(raw)
                response = self.client.post(str(item["path"]), json=item["payload"])
                response.raise_for_status()
                sent += 1
            except Exception:
                remaining.extend(raw_items[index:])
                break

        try:
            if remaining:
                queue_path.write_text("\n".join(remaining) + "\n", encoding="utf-8")
            else:
                queue_path.unlink(missing_ok=True)
        except OSError as exc:
            _log("telemetry_queue_write_failed", error=str(exc))
            return

        if sent:
            _log("telemetry_queue_flushed", sent=sent, remaining=len(remaining))

    def heartbeat(self) -> None:
        self._refresh_policy()
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
            "queue_depth": self._queue_depth(),
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
            self._flush_queue()
        except Exception as exc:
            _log("heartbeat_failed", error=str(exc), control_plane=self.config.control_plane_url)
            self._queue_telemetry("/api/v1/endpoint/heartbeat", payload)

    def run_once(self) -> int:
        evaluated = 0
        now = time.monotonic()
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
                observation = self._observation(proc, info, matched_rules)
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
        cmdline = [str(value) for value in (info.get("cmdline") or [])]
        command = " ".join(cmdline).lower()
        matches: list[str] = []

        product_match = classify_ai_process(name, cmdline)
        if product_match:
            product_key = product_match.product.lower().replace(" ", "-")
            matches.append(f"local:ai-product:{product_match.provider}:{product_key}")

        if name in self.config.process_names:
            matches.append(f"local:ai-process:{name}")
        for marker in sorted(self.config.command_markers):
            if marker and marker in command:
                rule = "local:test-block" if marker == TEST_BLOCK_MARKER else f"local:ai-command:{marker}"
                matches.append(rule)
        return sorted(set(matches))

    def _parent_chain(self, proc: psutil.Process) -> list[dict[str, Any]]:
        chain: list[dict[str, Any]] = []
        current = proc
        for _ in range(self.config.parent_depth):
            try:
                parent = current.parent()
                if parent is None:
                    break
                chain.append(
                    {
                        "pid": parent.pid,
                        "process_name": parent.name(),
                        "executable": parent.exe() if parent.exe() else None,
                        "command_line": parent.cmdline(),
                    }
                )
                current = parent
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, OSError):
                break
        return chain

    def _hash_executable(self, executable: str | None) -> str | None:
        if not executable or not self.config.hash_executables:
            return None
        try:
            file_path = Path(executable)
            stat = file_path.stat()
            if not file_path.is_file() or stat.st_size > self.config.max_hash_bytes:
                return None
            key = str(file_path)
            fingerprint = (int(stat.st_size), int(stat.st_mtime_ns))
            cached = self._hash_cache.get(key)
            if cached and cached[:2] == fingerprint:
                return cached[2]

            digest = hashlib.sha256()
            with file_path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            value = digest.hexdigest()
            self._hash_cache[key] = (fingerprint[0], fingerprint[1], value)
            return value
        except (OSError, PermissionError):
            return None

    def _observation(
        self,
        proc: psutil.Process,
        info: dict[str, Any],
        matched_rules: list[str],
    ) -> dict[str, Any]:
        executable = str(info.get("exe")) if info.get("exe") else None
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
            "executable_sha256": self._hash_executable(executable),
            "parent_chain": self._parent_chain(proc),
            "started_at": started_at,
            "agent_version": AGENT_VERSION,
            "mode": self.config.mode,
            "matched_local_rules": matched_rules,
            "policy_version": self.policy_version,
            "attributes": {
                "platform": platform.system(),
                "platform_release": platform.release(),
            },
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
                provider=result.get("evidence", {}).get("provider"),
                product=result.get("evidence", {}).get("product"),
                policy_version=result.get("policy_version"),
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
            name = str(observation.get("process_name", "")).lower()
            allow = {str(value).lower() for value in self.policy.get("allow_processes", [])}
            deny = {str(value).lower() for value in self.policy.get("deny_processes", [])}
            cached_explicit_deny = name in deny and name not in allow
            offline_enforcement_allowed = bool(self.policy.get("offline_fail_closed_allowed", False))
            should_block = (
                self.config.fail_closed and offline_enforcement_allowed and cached_explicit_deny
            )
            return {
                "decision": "block" if should_block else "monitor",
                "effective_action": "terminate" if should_block else "observe",
                "matched_rules": [
                    "agent:offline-cached-explicit-deny" if should_block else "agent:offline-monitor"
                ],
                "policy_version": self.policy_version,
                "reason_codes": ["control-plane-unavailable"],
                "evidence": {"process_name": name, "cached_explicit_deny": cached_explicit_deny},
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
            "policy_version": decision.get("policy_version") or self.policy_version,
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
            self._queue_telemetry("/api/v1/endpoint/enforcement", payload)

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
                policy_version=decision.get("policy_version"),
                matched_rules=decision.get("matched_rules", []),
            )
            self._report_enforcement(observation, decision, "succeeded")
        except psutil.NoSuchProcess:
            _log("process_already_exited", pid=proc.pid, process=observation["process_name"])
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
