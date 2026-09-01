from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Callable

from .schemas import AIEvent, EventType, PolicyDecision


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    description: str
    predicate: Callable[[AIEvent], bool]
    decision: PolicyDecision


class PolicyEngine:
    """Deterministic policy evaluation over normalized Mira Protect events.

    The engine is intentionally provider-neutral. Endpoint enforcement rules consume
    normalized process metadata so the same control plane can later accept events from
    EDR, MDM, browser, SWG, model gateway, and SaaS collectors.
    """

    PROVIDER_RELEVANT_EVENTS = {
        EventType.INTERACTION,
        EventType.TOOL_CALL,
        EventType.MODEL_CALL,
        EventType.DATA_ACCESS,
        EventType.ACTION,
        EventType.ENDPOINT_PROCESS,
    }

    def __init__(self, rules: list[PolicyRule] | None = None) -> None:
        self.rules = rules or self.default_rules()

    def evaluate(self, event: AIEvent) -> tuple[PolicyDecision, list[str]]:
        matched: list[str] = []
        decision = PolicyDecision.ALLOW
        precedence = {
            PolicyDecision.ALLOW: 0,
            PolicyDecision.MONITOR: 1,
            PolicyDecision.REQUIRE_APPROVAL: 2,
            PolicyDecision.BLOCK: 3,
        }

        for rule in self.rules:
            if rule.predicate(event):
                matched.append(rule.rule_id)
                if precedence[rule.decision] > precedence[decision]:
                    decision = rule.decision

        return decision, matched

    @classmethod
    def default_rules(cls) -> list[PolicyRule]:
        deny_processes = {
            value.strip().lower()
            for value in os.getenv("MIRA_ENDPOINT_DENY_PROCESSES", "").split(",")
            if value.strip()
        }

        return [
            PolicyRule(
                rule_id="protect-restricted-data-external-ai",
                description="Block restricted data from unapproved external AI destinations.",
                predicate=lambda e: (
                    any(c.upper() in {"CUI", "RESTRICTED"} for c in e.data.classifications)
                    and not bool(e.metadata.get("provider_approved", False))
                ),
                decision=PolicyDecision.BLOCK,
            ),
            PolicyRule(
                rule_id="production-tool-human-approval",
                description="Require approval for AI tool actions targeting production.",
                predicate=lambda e: any(
                    (tool.target or "").lower().startswith("production") for tool in e.tools
                ),
                decision=PolicyDecision.REQUIRE_APPROVAL,
            ),
            PolicyRule(
                rule_id="endpoint-synthetic-protection-test",
                description="Block the harmless Mira Protect endpoint test marker.",
                predicate=lambda e: (
                    e.event_type == EventType.ENDPOINT_PROCESS
                    and "local:test-block" in e.metadata.get("matched_local_rules", [])
                ),
                decision=PolicyDecision.BLOCK,
            ),
            PolicyRule(
                rule_id="endpoint-denied-ai-process",
                description="Block centrally denied AI process names on managed endpoints.",
                predicate=lambda e: (
                    e.event_type == EventType.ENDPOINT_PROCESS
                    and str(e.metadata.get("process_name", "")).lower() in deny_processes
                ),
                decision=PolicyDecision.BLOCK,
            ),
            PolicyRule(
                rule_id="unknown-ai-provider-monitor",
                description="Monitor use of AI systems without a known provider.",
                predicate=lambda e: (
                    e.event_type in cls.PROVIDER_RELEVANT_EVENTS and not bool(e.ai.provider)
                ),
                decision=PolicyDecision.MONITOR,
            ),
        ]
