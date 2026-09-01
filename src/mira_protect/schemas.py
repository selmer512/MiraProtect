from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class DeploymentType(str, Enum):
    EMBEDDED = "embedded"
    VENDOR_UI = "vendor_ui"
    MODEL_API = "model_api"
    ENTERPRISE_LICENSED = "enterprise_licensed"
    PRETRAINED_OR_FINETUNED = "pretrained_or_finetuned"
    SPECIALIZED = "specialized"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class AssetKind(str, Enum):
    AI_SYSTEM = "ai_system"
    MODEL = "model"
    AGENT = "agent"
    TOOL = "tool"
    MCP_SERVER = "mcp_server"
    RAG_PIPELINE = "rag_pipeline"
    VECTOR_STORE = "vector_store"
    DATA_SOURCE = "data_source"
    IDENTITY = "identity"
    APPLICATION = "application"
    DEVICE = "device"
    PROVIDER = "provider"


class EventType(str, Enum):
    INTERACTION = "ai.interaction"
    TOOL_CALL = "ai.tool_call"
    MODEL_CALL = "ai.model_call"
    DATA_ACCESS = "ai.data_access"
    ACTION = "ai.action"
    POLICY_DECISION = "ai.policy_decision"
    DETECTION = "ai.detection"
    ASSET_DISCOVERED = "ai.asset_discovered"
    ENDPOINT_PROCESS = "endpoint.process"
    ENDPOINT_ENFORCEMENT = "endpoint.enforcement"
    ENDPOINT_HEARTBEAT = "endpoint.heartbeat"


class PolicyDecision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REQUIRE_APPROVAL = "require_approval"
    MONITOR = "monitor"


class EnforcementMode(str, Enum):
    MONITOR = "monitor"
    GUARD = "guard"
    ENFORCE = "enforce"


class EnforcementResult(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SUPPRESSED = "suppressed"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatProfile(str, Enum):
    EXTERNAL = "profile_1_external"
    INTERNAL_GENERAL = "profile_2a_internal"
    ENTERPRISE_ASSISTANT = "profile_2b_enterprise_assistant"
    AGENTIC = "profile_2c_agentic"


class FindingStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class Actor(BaseModel):
    user_id: str | None = None
    device_id: str | None = None
    identity: str | None = None
    source_ip: str | None = None


class AIContext(BaseModel):
    provider: str | None = None
    product: str | None = None
    model: str | None = None
    deployment_type: DeploymentType = DeploymentType.UNKNOWN
    agent_id: str | None = None
    session_id: str | None = None


class DataContext(BaseModel):
    classifications: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    destinations: list[str] = Field(default_factory=list)
    contains_sensitive_data: bool = False


class ToolInvocation(BaseModel):
    name: str
    operation: str | None = None
    target: str | None = None
    arguments: dict[str, Any] = Field(default_factory=dict)


class SecurityContext(BaseModel):
    policy_decision: PolicyDecision = PolicyDecision.MONITOR
    risk_score: float = 0
    risk_level: RiskLevel = RiskLevel.LOW
    detections: list[str] = Field(default_factory=list)
    approval_id: str | None = None


class AIEvent(BaseModel):
    event_id: UUID = Field(default_factory=uuid4)
    event_type: EventType
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    trace_id: str | None = None
    parent_event_id: UUID | None = None
    actor: Actor = Field(default_factory=Actor)
    ai: AIContext = Field(default_factory=AIContext)
    data: DataContext = Field(default_factory=DataContext)
    tools: list[ToolInvocation] = Field(default_factory=list)
    input: dict[str, Any] = Field(default_factory=dict)
    output: dict[str, Any] = Field(default_factory=dict)
    security: SecurityContext = Field(default_factory=SecurityContext)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AIAsset(BaseModel):
    asset_id: UUID = Field(default_factory=uuid4)
    kind: AssetKind
    name: str
    provider: str | None = None
    deployment_type: DeploymentType = DeploymentType.UNKNOWN
    owner: str | None = None
    environment: str | None = None
    data_classifications: list[str] = Field(default_factory=list)
    identities: list[str] = Field(default_factory=list)
    integrations: list[str] = Field(default_factory=list)
    internet_exposed: bool = False
    approved: bool = False
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    attributes: dict[str, Any] = Field(default_factory=dict)


class DetectionFinding(BaseModel):
    finding_id: UUID = Field(default_factory=uuid4)
    event_id: UUID
    detector_id: str
    title: str
    description: str
    profile: ThreatProfile
    severity: RiskLevel
    status: FindingStatus = FindingStatus.OPEN
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    evidence: dict[str, Any] = Field(default_factory=dict)
    recommended_actions: list[str] = Field(default_factory=list)
    framework_refs: dict[str, list[str]] = Field(default_factory=dict)


class ThreatCatalogItem(BaseModel):
    threat_id: str
    profile: ThreatProfile
    category: str
    name: str
    description: str
    sample_signals: list[str] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)
    framework_refs: dict[str, list[str]] = Field(default_factory=dict)


class DashboardSummary(BaseModel):
    assets: int = 0
    managed_devices: int = 0
    events: int = 0
    findings: int = 0
    blocked_events: int = 0
    approval_events: int = 0
    enforcement_actions: int = 0
    enforcement_failures: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    unapproved_assets: int = 0


class RiskFactors(BaseModel):
    impact: int = Field(ge=1, le=5)
    likelihood: int = Field(ge=1, le=5)
    data_sensitivity: float = Field(default=1.0, ge=0.1, le=5.0)
    privilege: float = Field(default=1.0, ge=0.1, le=5.0)
    autonomy: float = Field(default=1.0, ge=0.1, le=5.0)
    exposure: float = Field(default=1.0, ge=0.1, le=5.0)
    reachability: float = Field(default=1.0, ge=0.1, le=5.0)
    control_effectiveness: float = Field(default=1.0, ge=0.0, le=1.0)


class RiskResult(BaseModel):
    base_risk: float
    contextual_risk: float
    residual_risk: float
    normalized_score: float
    level: RiskLevel


class EndpointProcessObservation(BaseModel):
    """Process telemetry submitted by a managed endpoint agent.

    Command-line data is included because AI CLI tools are frequently wrappers around
    Python, Node, PowerShell, or shell processes and cannot be reliably identified by
    executable name alone.
    """

    device_id: str
    hostname: str
    username: str | None = None
    pid: int = Field(ge=0)
    parent_pid: int | None = Field(default=None, ge=0)
    process_name: str
    executable: str | None = None
    command_line: list[str] = Field(default_factory=list)
    executable_sha256: str | None = None
    started_at: datetime | None = None
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    agent_version: str = "0.2.0"
    mode: EnforcementMode = EnforcementMode.MONITOR
    matched_local_rules: list[str] = Field(default_factory=list)
    attributes: dict[str, Any] = Field(default_factory=dict)


class EndpointDecision(BaseModel):
    decision: PolicyDecision
    effective_action: str
    matched_rules: list[str] = Field(default_factory=list)
    finding_ids: list[UUID] = Field(default_factory=list)
    event_id: UUID
    message: str | None = None


class EndpointHeartbeat(BaseModel):
    device_id: str
    hostname: str
    username: str | None = None
    agent_version: str = "0.2.0"
    mode: EnforcementMode = EnforcementMode.MONITOR
    platform: str
    platform_version: str | None = None
    ip_addresses: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EndpointEnforcementReport(BaseModel):
    """Confirmation from an endpoint that a requested preventative action was attempted."""

    device_id: str
    hostname: str
    username: str | None = None
    pid: int = Field(ge=0)
    process_name: str
    decision_event_id: UUID
    action: str
    result: EnforcementResult
    mode: EnforcementMode
    agent_version: str = "0.2.0"
    reason: str | None = None
    error: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
