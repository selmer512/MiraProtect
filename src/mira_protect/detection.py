from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable

from .schemas import AIEvent, DetectionFinding, EventType, RiskLevel, ThreatProfile


@dataclass(frozen=True)
class Detector:
    detector_id: str
    title: str
    description: str
    profile: ThreatProfile
    severity: RiskLevel
    predicate: Callable[[AIEvent], bool]
    recommended_actions: list[str]
    framework_refs: dict[str, list[str]]


class DetectionEngine:
    """Vendor-neutral detections for observable AI security behaviors."""

    PROMPT_INJECTION_MARKERS = (
        "ignore all previous instructions",
        "ignore previous instructions",
        "system prompt",
        "developer message",
        "override all",
        "bypass all",
    )

    PROVIDER_RELEVANT_EVENTS = {
        EventType.INTERACTION,
        EventType.TOOL_CALL,
        EventType.MODEL_CALL,
        EventType.DATA_ACCESS,
        EventType.ACTION,
        EventType.ENDPOINT_PROCESS,
    }

    def __init__(self, detectors: list[Detector] | None = None) -> None:
        self.detectors = detectors or self.default_detectors()

    @staticmethod
    def _searchable_text(event: AIEvent) -> str:
        return json.dumps(
            {
                "input": event.input,
                "output": event.output,
                "metadata": event.metadata,
                "tools": [tool.model_dump(mode="json") for tool in event.tools],
            },
            default=str,
        ).lower()

    def evaluate(self, event: AIEvent) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []
        text = self._searchable_text(event)
        event.metadata.setdefault("_searchable_text", text)
        try:
            for detector in self.detectors:
                if detector.predicate(event):
                    findings.append(
                        DetectionFinding(
                            event_id=event.event_id,
                            detector_id=detector.detector_id,
                            title=detector.title,
                            description=detector.description,
                            profile=detector.profile,
                            severity=detector.severity,
                            evidence={
                                "event_type": event.event_type.value,
                                "provider": event.ai.provider,
                                "product": event.ai.product,
                                "model": event.ai.model,
                                "trace_id": event.trace_id,
                            },
                            recommended_actions=detector.recommended_actions,
                            framework_refs=detector.framework_refs,
                        )
                    )
        finally:
            event.metadata.pop("_searchable_text", None)
        return findings

    @classmethod
    def default_detectors(cls) -> list[Detector]:
        def text(event: AIEvent) -> str:
            return str(event.metadata.get("_searchable_text", ""))

        return [
            Detector(
                detector_id="MP-AI-001",
                title="Potential prompt injection",
                description="Input or retrieved context contains common instruction-override language.",
                profile=ThreatProfile.AGENTIC,
                severity=RiskLevel.HIGH,
                predicate=lambda e: any(marker in text(e) for marker in cls.PROMPT_INJECTION_MARKERS),
                recommended_actions=[
                    "Preserve the full execution trace and retrieved context.",
                    "Prevent autonomous tool execution until the content is reviewed.",
                    "Identify whether the instruction originated from a user, document, webpage, or tool result.",
                ],
                framework_refs={"CWE": ["CWE-77", "CWE-1427"], "OWASP_COMPASS": ["Profile 2C"]},
            ),
            Detector(
                detector_id="MP-AI-002",
                title="Sensitive data sent to an unapproved AI provider",
                description="Restricted or CUI-classified data is associated with an AI provider that is not marked approved.",
                profile=ThreatProfile.INTERNAL_GENERAL,
                severity=RiskLevel.CRITICAL,
                predicate=lambda e: (
                    any(c.upper() in {"CUI", "RESTRICTED"} for c in e.data.classifications)
                    and not bool(e.metadata.get("provider_approved", False))
                ),
                recommended_actions=[
                    "Block transmission where enforcement is available.",
                    "Preserve the prompt, destination, identity, and data-source evidence.",
                    "Review provider authorization and applicable data handling requirements.",
                ],
                framework_refs={"OWASP_COMPASS": ["Profile 2A", "Profile 2B"]},
            ),
            Detector(
                detector_id="MP-AI-003",
                title="AI tool targeting production",
                description="An AI-mediated tool invocation targets a production resource and requires explicit authorization.",
                profile=ThreatProfile.AGENTIC,
                severity=RiskLevel.HIGH,
                predicate=lambda e: any(
                    (tool.target or "").lower().startswith("production") for tool in e.tools
                ),
                recommended_actions=[
                    "Require verified human approval before execution.",
                    "Validate the agent identity, credential scope, and requested operation.",
                    "Record command/result lineage for incident reconstruction.",
                ],
                framework_refs={"OWASP_COMPASS": ["Profile 2C"], "CWE": ["CWE-94", "CWE-78"]},
            ),
            Detector(
                detector_id="MP-AI-004",
                title="Unmanaged or unknown AI provider",
                description="AI activity was observed without a known provider identity.",
                profile=ThreatProfile.INTERNAL_GENERAL,
                severity=RiskLevel.MEDIUM,
                predicate=lambda e: (
                    e.event_type in cls.PROVIDER_RELEVANT_EVENTS and not bool(e.ai.provider)
                ),
                recommended_actions=[
                    "Identify the application, model runtime, endpoint, and owner.",
                    "Register the system in the AI asset inventory.",
                    "Determine whether the usage is authorized.",
                ],
                framework_refs={"OWASP_COMPASS": ["Profile 2A Shadow AI"]},
            ),
            Detector(
                detector_id="MP-AI-005",
                title="High-depth agent or tool chain",
                description="Telemetry indicates unusually deep delegated or chained execution.",
                profile=ThreatProfile.AGENTIC,
                severity=RiskLevel.HIGH,
                predicate=lambda e: int(e.metadata.get("chain_depth", 0) or 0) >= 8,
                recommended_actions=[
                    "Pause or throttle additional delegated execution.",
                    "Review the trace for recursive behavior, indirect prompt injection, or runaway automation.",
                    "Apply maximum delegation and tool-call depth policies.",
                ],
                framework_refs={"OWASP_COMPASS": ["Profile 2C Multi-Agent", "Profile 2C Infrastructure"]},
            ),
            Detector(
                detector_id="MP-AI-006",
                title="Discovered AI software is not approved",
                description="A known AI application was discovered on an endpoint but its provider is not in the approved provider registry.",
                profile=ThreatProfile.INTERNAL_GENERAL,
                severity=RiskLevel.MEDIUM,
                predicate=lambda e: (
                    e.event_type == EventType.ENDPOINT_PROCESS
                    and bool(e.ai.provider)
                    and not bool(e.metadata.get("provider_approved", False))
                ),
                recommended_actions=[
                    "Confirm the business use case and responsible owner.",
                    "Review data classifications and integrations before authorization.",
                    "Add the provider to the approved registry only after governance review.",
                ],
                framework_refs={"OWASP_COMPASS": ["Profile 2A Shadow AI"]},
            ),
        ]
