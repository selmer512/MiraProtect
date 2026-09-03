from __future__ import annotations

import hmac
import os
from uuid import NAMESPACE_URL, uuid5

from fastapi import FastAPI, Header, HTTPException, Query, status

from .catalog import get_catalog
from .detection import DetectionEngine
from .policy import PolicyEngine
from .repository import Repository
from .risk import RiskEngine
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
    EndpointHeartbeat,
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
    version="0.2.0",
    description="Vendor-neutral enterprise AI security control plane",
)

risk_engine = RiskEngine()
policy_engine = PolicyEngine()
detection_engine = DetectionEngine()
repository = Repository()


def _require_endpoint_token(authorization: str | None) -> None:
    """Require a shared endpoint token when MIRA_ENDPOINT_TOKEN is configured.

    Authentication is optional for isolated local labs. Shared enterprise development
    environments should configure MIRA_ENDPOINT_TOKEN and deploy the same value to a
    managed endpoint through MIRA_AGENT_TOKEN. Per-device enrollment replaces this
    bootstrap model in a later milestone.
    """

    expected = os.getenv("MIRA_ENDPOINT_TOKEN")
    if not expected:
        return
    supplied = ""
    if authorization and authorization.lower().startswith("bearer "):
        supplied = authorization[7:].strip()
    if not hmac.compare_digest(supplied, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Mira Protect endpoint token",
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
        "version": "0.2.0",
        "database": database,
    }


@app.post("/api/v1/assets", response_model=AIAsset)
def register_asset(asset: AIAsset) -> AIAsset:
    return repository.save_asset(asset)


@app.get("/api/v1/assets", response_model=list[AIAsset])
def list_assets() -> list[AIAsset]:
    return repository.list_assets()


@app.post("/api/v1/risk/score", response_model=RiskResult)
def score_risk(factors: RiskFactors) -> RiskResult:
    return risk_engine.score(factors)


@app.post("/api/v1/events", response_model=AIEvent)
def ingest_event(event: AIEvent) -> AIEvent:
    processed, _ = _process_event(event)
    return processed


@app.get("/api/v1/events", response_model=list[AIEvent])
def list_events(limit: int = Query(default=200, ge=1, le=2000)) -> list[AIEvent]:
    return repository.list_events(limit=limit)


@app.get("/api/v1/findings", response_model=list[DetectionFinding])
def list_findings(limit: int = Query(default=200, ge=1, le=2000)) -> list[DetectionFinding]:
    return repository.list_findings(limit=limit)


@app.get("/api/v1/threats", response_model=list[ThreatCatalogItem])
def list_threats() -> list[ThreatCatalogItem]:
    return get_catalog()


@app.get("/api/v1/dashboard/summary", response_model=DashboardSummary)
def dashboard_summary() -> DashboardSummary:
    assets = repository.list_assets()
    events = repository.list_events(limit=2000)
    findings = repository.list_findings(limit=2000)
    enforcement_events = [event for event in events if event.event_type == EventType.ENDPOINT_ENFORCEMENT]
    return DashboardSummary(
        assets=len(assets),
        managed_devices=sum(1 for asset in assets if asset.kind == AssetKind.DEVICE),
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


@app.post("/api/v1/endpoint/heartbeat", response_model=AIAsset)
def endpoint_heartbeat(
    heartbeat: EndpointHeartbeat,
    authorization: str | None = Header(default=None),
) -> AIAsset:
    _require_endpoint_token(authorization)
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
        },
    )
    _process_event(event)
    return asset


@app.post("/api/v1/endpoint/process/evaluate", response_model=EndpointDecision)
def evaluate_endpoint_process(
    observation: EndpointProcessObservation,
    authorization: str | None = Header(default=None),
) -> EndpointDecision:
    _require_endpoint_token(authorization)
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

    _require_endpoint_token(authorization)
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
    # An enforcement acknowledgement describes the result of an already-evaluated
    # decision; re-running it through policy would create a second policy decision.
    event.security.policy_decision = PolicyDecision.BLOCK
    repository.save_event(event)
    return event
