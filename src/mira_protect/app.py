from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from uuid import NAMESPACE_URL, uuid5

from fastapi import FastAPI, Header, HTTPException, Query, status

from .catalog import get_catalog
from .detection import DetectionEngine
from .policy import PolicyEngine
from .repository import Repository
from .risk import RiskEngine
from .security import security_profile, security_status
from .schemas import (
    AIAsset,
    AIContext,
    AIEvent,
    Actor,
    AssetKind,
    DashboardSummary,
    DeploymentType,
    DetectionFinding,
    EndpointDecision,
    EndpointEnforcementReport,
    EndpointEnrollmentRequest,
    EndpointEnrollmentResponse,
    EndpointHeartbeat,
    EndpointPolicyBundle,
    EndpointProcessObservation,
    EnforcementMode,
    EventType,
    PolicyDecision,
    RiskFactors,
    RiskLevel,
    RiskResult,
    ThreatCatalogItem,
)

app = FastAPI(
    title="Mira Protect",
    version="0.4.0",
    description="Vendor-neutral enterprise AI security control plane",
)

risk_engine = RiskEngine()
policy_engine = PolicyEngine()
detection_engine = DetectionEngine()
repository = Repository()


def _as_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _bearer_token(authorization: str | None) -> str:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return ""


def _hash_endpoint_token(token: str) -> str:
    pepper = os.getenv("MIRA_TOKEN_PEPPER", "")
    if pepper:
        return hmac.new(pepper.encode(), token.encode(), hashlib.sha256).hexdigest()
    return hashlib.sha256(token.encode()).hexdigest()


def _require_admin_token(authorization: str | None) -> None:
    expected = os.getenv("MIRA_ADMIN_TOKEN")
    if not expected:
        if security_profile() == "local":
            return
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Administrative API authentication is not configured",
        )

    supplied = _bearer_token(authorization)
    if not supplied or not hmac.compare_digest(supplied, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Mira Protect administrative token",
        )


def _require_enrollment_token(authorization: str | None) -> None:
    expected = os.getenv("MIRA_ENROLLMENT_TOKEN")
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Endpoint enrollment is not configured",
        )
    supplied = _bearer_token(authorization)
    if not hmac.compare_digest(supplied, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Mira Protect enrollment token",
        )


def _require_endpoint_identity(authorization: str | None, device_id: str) -> None:
    supplied = _bearer_token(authorization)
    enrolled_hash = repository.get_endpoint_credential_hash(device_id)

    if enrolled_hash:
        if not supplied or not hmac.compare_digest(_hash_endpoint_token(supplied), enrolled_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Mira Protect device credential",
            )
        repository.touch_endpoint_credential(device_id)
        return

    shared_expected = os.getenv("MIRA_ENDPOINT_TOKEN")
    enrollment_configured = bool(os.getenv("MIRA_ENROLLMENT_TOKEN"))
    allow_shared = _as_bool(
        os.getenv(
            "MIRA_ALLOW_SHARED_ENDPOINT_TOKEN",
            "false" if enrollment_configured else "true",
        )
    )

    if shared_expected and allow_shared:
        if hmac.compare_digest(supplied, shared_expected):
            return
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Mira Protect endpoint token",
        )

    if enrollment_configured:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Endpoint is not enrolled",
        )

    if shared_expected and not hmac.compare_digest(supplied, shared_expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Mira Protect endpoint token",
        )


def _parse_csv_env(name: str) -> list[str]:
    return sorted(
        {
            value.strip().lower()
            for value in os.getenv(name, "").split(",")
            if value.strip()
        }
    )


def _endpoint_policy_bundle() -> EndpointPolicyBundle:
    refresh_seconds = int(os.getenv("MIRA_POLICY_REFRESH_SECONDS", "300"))
    refresh_seconds = max(30, min(refresh_seconds, 86400))
    deny_processes = _parse_csv_env("MIRA_ENDPOINT_DENY_PROCESSES")
    process_names = _parse_csv_env("MIRA_ENDPOINT_PROCESS_NAMES")
    command_markers = _parse_csv_env("MIRA_ENDPOINT_COMMAND_MARKERS")
    fail_closed = _as_bool(os.getenv("MIRA_ENDPOINT_FAIL_CLOSED", "false"))
    enable_test_controls = _as_bool(os.getenv("MIRA_ENABLE_TEST_CONTROLS", "false"))

    mode_raw = os.getenv("MIRA_ENDPOINT_POLICY_MODE", "").strip().lower()
    recommended_mode = EnforcementMode(mode_raw) if mode_raw in {"monitor", "guard", "enforce"} else None

    policy_body = {
        "refresh_seconds": refresh_seconds,
        "deny_processes": deny_processes,
        "process_names": process_names,
        "command_markers": command_markers,
        "fail_closed": fail_closed,
        "enable_test_controls": enable_test_controls,
        "recommended_mode": recommended_mode.value if recommended_mode else None,
    }
    policy_version = hashlib.sha256(
        json.dumps(policy_body, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()[:16]

    return EndpointPolicyBundle(
        policy_version=policy_version,
        refresh_seconds=refresh_seconds,
        deny_processes=deny_processes,
        process_names=process_names,
        command_markers=command_markers,
        fail_closed=fail_closed,
        enable_test_controls=enable_test_controls,
        recommended_mode=recommended_mode,
    )


def _process_event(event: AIEvent) -> tuple[AIEvent, list[DetectionFinding]]:
    findings = detection_engine.evaluate(event)
    decision, matched_rules = policy_engine.evaluate(event)
    event.security.policy_decision = decision
    event.security.detections = sorted(
        set(event.security.detections + matched_rules + [f.detector_id for f in findings])
    )
    if findings:
        severity_order = {
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4,
        }
        highest = max(findings, key=lambda finding: severity_order[finding.severity]).severity
        event.security.risk_level = highest
    repository.save_event(event)
    repository.save_findings(findings)
    return event, findings


def _infer_process_provider(process_name: str, command_line: list[str]) -> tuple[str | None, str]:
    text = f"{process_name} {' '.join(command_line)}".lower()
    mappings = [
        ("claude", "anthropic", "Claude Code"),
        ("codex", "openai", "Codex CLI"),
        ("copilot", "github", "GitHub Copilot"),
        ("gemini", "google", "Gemini CLI"),
        ("ollama", "local", "Ollama"),
        ("lmstudio", "local", "LM Studio"),
        ("cursor", "cursor", "Cursor"),
        ("aider", "community", "Aider"),
        ("opencode", "community", "OpenCode"),
    ]
    for marker, provider, product in mappings:
        if marker in text:
            return provider, product
    return None, process_name


@app.get("/health")
def health() -> dict[str, str]:
    database = "ok" if repository.health() else "unavailable"
    return {
        "status": "ok" if database == "ok" else "degraded",
        "service": "mira-protect",
        "version": "0.4.0",
        "database": database,
    }


@app.get("/ready")
def ready() -> dict[str, object]:
    database_ready = repository.health()
    security = security_status()
    return {
        "status": "ready" if database_ready and security["ready"] else "not_ready",
        "database": "ok" if database_ready else "unavailable",
        "security": security,
    }


@app.post("/api/v1/assets", response_model=AIAsset)
def register_asset(
    asset: AIAsset,
    authorization: str | None = Header(default=None),
) -> AIAsset:
    _require_admin_token(authorization)
    return repository.save_asset(asset)


@app.get("/api/v1/assets", response_model=list[AIAsset])
def list_assets(authorization: str | None = Header(default=None)) -> list[AIAsset]:
    _require_admin_token(authorization)
    return repository.list_assets()


@app.post("/api/v1/risk/score", response_model=RiskResult)
def score_risk(
    factors: RiskFactors,
    authorization: str | None = Header(default=None),
) -> RiskResult:
    _require_admin_token(authorization)
    return risk_engine.score(factors)


@app.post("/api/v1/events", response_model=AIEvent)
def ingest_event(
    event: AIEvent,
    authorization: str | None = Header(default=None),
) -> AIEvent:
    _require_admin_token(authorization)
    processed, _ = _process_event(event)
    return processed


@app.get("/api/v1/events", response_model=list[AIEvent])
def list_events(
    limit: int = Query(default=200, ge=1, le=2000),
    authorization: str | None = Header(default=None),
) -> list[AIEvent]:
    _require_admin_token(authorization)
    return repository.list_events(limit=limit)


@app.get("/api/v1/findings", response_model=list[DetectionFinding])
def list_findings(
    limit: int = Query(default=200, ge=1, le=2000),
    authorization: str | None = Header(default=None),
) -> list[DetectionFinding]:
    _require_admin_token(authorization)
    return repository.list_findings(limit=limit)


@app.get("/api/v1/threats", response_model=list[ThreatCatalogItem])
def list_threats(
    authorization: str | None = Header(default=None),
) -> list[ThreatCatalogItem]:
    _require_admin_token(authorization)
    return get_catalog()


@app.get("/api/v1/dashboard/summary", response_model=DashboardSummary)
def dashboard_summary(
    authorization: str | None = Header(default=None),
) -> DashboardSummary:
    _require_admin_token(authorization)
    assets = repository.list_assets()
    events = repository.list_events(limit=2000)
    findings = repository.list_findings(limit=2000)
    enforcement_events = [event for event in events if event.event_type == EventType.ENDPOINT_ENFORCEMENT]
    return DashboardSummary(
        assets=len(assets),
        managed_devices=sum(1 for asset in assets if asset.kind == AssetKind.DEVICE),
        enrolled_devices=repository.count_endpoint_credentials(),
        outdated_policy_devices=sum(
            1
            for asset in assets
            if asset.kind == AssetKind.DEVICE
            and asset.attributes.get("available_policy_version")
            and asset.attributes.get("policy_version")
            != asset.attributes.get("available_policy_version")
        ),
        events=len(events),
        findings=len(findings),
        blocked_events=sum(
            1 for event in events if event.security.policy_decision == PolicyDecision.BLOCK
        ),
        approval_events=sum(
            1
            for event in events
            if event.security.policy_decision == PolicyDecision.REQUIRE_APPROVAL
        ),
        enforcement_actions=sum(
            1 for event in enforcement_events if event.metadata.get("result") == "succeeded"
        ),
        enforcement_failures=sum(
            1 for event in enforcement_events if event.metadata.get("result") == "failed"
        ),
        critical_findings=sum(1 for finding in findings if finding.severity == RiskLevel.CRITICAL),
        high_findings=sum(1 for finding in findings if finding.severity == RiskLevel.HIGH),
        unapproved_assets=sum(1 for asset in assets if not asset.approved),
    )


@app.post("/api/v1/endpoint/enroll", response_model=EndpointEnrollmentResponse)
def endpoint_enroll(
    enrollment: EndpointEnrollmentRequest,
    authorization: str | None = Header(default=None),
) -> EndpointEnrollmentResponse:
    _require_enrollment_token(authorization)

    device_token = secrets.token_urlsafe(48)
    repository.save_endpoint_credential(
        enrollment.device_id,
        _hash_endpoint_token(device_token),
    )
    enrollment_event = AIEvent(
        event_type=EventType.ENDPOINT_ENROLLMENT,
        actor=Actor(
            device_id=enrollment.device_id,
            identity=enrollment.device_id,
        ),
        metadata={
            "hostname": enrollment.hostname,
            "platform": enrollment.platform,
            "platform_version": enrollment.platform_version,
            "agent_version": enrollment.agent_version,
            "credential_type": "per-device-bearer",
        },
    )
    _process_event(enrollment_event)

    return EndpointEnrollmentResponse(
        device_id=enrollment.device_id,
        device_token=device_token,
        policy_url=f"/api/v1/endpoint/policy/{enrollment.device_id}",
        message="Endpoint enrolled; store the device credential securely.",
    )


@app.post("/api/v1/endpoint/revoke/{device_id}")
def revoke_endpoint(
    device_id: str,
    authorization: str | None = Header(default=None),
) -> dict[str, object]:
    _require_admin_token(authorization)
    revoked = repository.revoke_endpoint_credential(device_id)
    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Managed endpoint credential was not found",
        )
    return {"device_id": device_id, "revoked": True}


@app.get("/api/v1/endpoint/policy/{device_id}", response_model=EndpointPolicyBundle)
def endpoint_policy(
    device_id: str,
    authorization: str | None = Header(default=None),
) -> EndpointPolicyBundle:
    _require_endpoint_identity(authorization, device_id)
    return _endpoint_policy_bundle()


@app.post("/api/v1/endpoint/heartbeat", response_model=AIAsset)
def endpoint_heartbeat(
    heartbeat: EndpointHeartbeat,
    authorization: str | None = Header(default=None),
) -> AIAsset:
    _require_endpoint_identity(authorization, heartbeat.device_id)
    policy = _endpoint_policy_bundle()
    applied_policy_version = heartbeat.policy_version
    asset = AIAsset(
        asset_id=uuid5(NAMESPACE_URL, f"mira-protect-device:{heartbeat.device_id}"),
        kind=AssetKind.DEVICE,
        name=heartbeat.hostname,
        owner=heartbeat.username,
        environment="enterprise-endpoint",
        approved=True,
        integrations=["mira-protect-endpoint-agent"],
        attributes={
            "device_id": heartbeat.device_id,
            "agent_version": heartbeat.agent_version,
            "agent_mode": heartbeat.mode.value,
            "platform": heartbeat.platform,
            "platform_version": heartbeat.platform_version,
            "ip_addresses": heartbeat.ip_addresses,
            "policy_version": applied_policy_version,
            "available_policy_version": policy.policy_version,
            "last_heartbeat": heartbeat.timestamp.isoformat(),
        },
    )
    repository.save_asset(asset)

    event = AIEvent(
        event_type=EventType.ENDPOINT_HEARTBEAT,
        actor=Actor(
            user_id=heartbeat.username,
            device_id=heartbeat.device_id,
            identity=heartbeat.username,
        ),
        metadata={
            "hostname": heartbeat.hostname,
            "agent_version": heartbeat.agent_version,
            "agent_mode": heartbeat.mode.value,
            "platform": heartbeat.platform,
            "platform_version": heartbeat.platform_version,
            "ip_addresses": heartbeat.ip_addresses,
            "policy_version": applied_policy_version,
            "available_policy_version": policy.policy_version,
        },
    )
    _process_event(event)
    return asset


@app.post("/api/v1/endpoint/process/evaluate", response_model=EndpointDecision)
def evaluate_endpoint_process(
    observation: EndpointProcessObservation,
    authorization: str | None = Header(default=None),
) -> EndpointDecision:
    _require_endpoint_identity(authorization, observation.device_id)
    provider, product = _infer_process_provider(
        observation.process_name,
        observation.command_line,
    )
    event = AIEvent(
        event_type=EventType.ENDPOINT_PROCESS,
        timestamp=observation.observed_at,
        actor=Actor(
            user_id=observation.username,
            device_id=observation.device_id,
            identity=observation.username,
        ),
        ai=AIContext(
            provider=provider,
            product=product,
            deployment_type=(
                DeploymentType.PRETRAINED_OR_FINETUNED
                if provider == "local"
                else DeploymentType.VENDOR_UI
            ),
        ),
        input={"command_line": observation.command_line},
        metadata={
            "hostname": observation.hostname,
            "pid": observation.pid,
            "parent_pid": observation.parent_pid,
            "process_name": observation.process_name,
            "executable": observation.executable,
            "executable_sha256": observation.executable_sha256,
            "started_at": observation.started_at.isoformat() if observation.started_at else None,
            "agent_version": observation.agent_version,
            "agent_mode": observation.mode.value,
            "matched_local_rules": observation.matched_local_rules,
            "endpoint_attributes": observation.attributes,
        },
    )
    event, findings = _process_event(event)

    if event.security.policy_decision == PolicyDecision.BLOCK:
        if observation.mode == EnforcementMode.ENFORCE:
            effective_action = "terminate"
            message = "Policy blocked the process; endpoint agent should terminate it."
        elif observation.mode == EnforcementMode.GUARD:
            effective_action = "notify"
            message = (
                "Policy would block the process; guard mode records and notifies without termination."
            )
        else:
            effective_action = "observe"
            message = "Policy would block the process; monitor mode records only."
    elif event.security.policy_decision == PolicyDecision.REQUIRE_APPROVAL:
        effective_action = "notify"
        message = "Human approval is required before the related AI action proceeds."
    else:
        effective_action = "observe"
        message = "No preventative endpoint action is required."

    return EndpointDecision(
        decision=event.security.policy_decision,
        effective_action=effective_action,
        matched_rules=event.security.detections,
        finding_ids=[finding.finding_id for finding in findings],
        event_id=event.event_id,
        message=message,
    )


@app.post("/api/v1/endpoint/enforcement", response_model=AIEvent)
def endpoint_enforcement(
    report: EndpointEnforcementReport,
    authorization: str | None = Header(default=None),
) -> AIEvent:
    """Persist endpoint confirmation that a preventative action was attempted."""

    _require_endpoint_identity(authorization, report.device_id)
    event = AIEvent(
        event_type=EventType.ENDPOINT_ENFORCEMENT,
        timestamp=report.timestamp,
        parent_event_id=report.decision_event_id,
        trace_id=str(report.decision_event_id),
        actor=Actor(
            user_id=report.username,
            device_id=report.device_id,
            identity=report.username,
        ),
        metadata={
            "hostname": report.hostname,
            "pid": report.pid,
            "process_name": report.process_name,
            "decision_event_id": str(report.decision_event_id),
            "action": report.action,
            "result": report.result.value,
            "mode": report.mode.value,
            "agent_version": report.agent_version,
            "reason": report.reason,
            "error": report.error,
        },
    )
    event.security.policy_decision = PolicyDecision.BLOCK
    repository.save_event(event)
    return event
