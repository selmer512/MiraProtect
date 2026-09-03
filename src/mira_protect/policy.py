from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .policy_config import get_endpoint_policy_bundle
from .schemas import AIEvent, EndpointPolicyBundle, EventType, PolicyDecision


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    description: str
    predicate: Callable[[AIEvent], bool]
    decision: PolicyDecision


class PolicyEngine:
    """Deterministic policy evaluation over normalized Mira Protect events.

    Product discovery and enforcement are deliberately separate. Merely observing a
    known AI tool produces inventory/telemetry; preventative action requires an explicit
    central policy rule such as a deny-process entry or the dedicated synthetic test.
    """

    PROVIDER_RELEVANT_EVENTS = {
        EventType.INTERACTION,
        EventType.TOOL_CALL,
        EventType.MODEL_CALL,
        EventType.DATA_ACCESS,
        EventType.ACTION,
        EventType.ENDPOINT_PROCESS,
    }

    def __init__(
        self,
        rules: list[PolicyRule] | None = None,
        policy_bundle: EndpointPolicyBundle | None = None,
    ) -> None:
        self.policy_bundle = policy_bundle or get_endpoint_policy_bundle()
        self.rules = rules or self.default_rules(self.policy_bundle)

    @property
    def policy_version(self) -> str:
        return self.policy_bundle.version

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
    def default_rules(cls, bundle: EndpointPolicyBundle) -> list[PolicyRule]:
        deny_processes = {value.lower() for value in bundle.deny_processes}
        allow_processes = {value.lower() for value in bundle.allow_processes}
        approved_providers = {value.lower() for value in bundle.approved_providers}

        rules = [
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
                rule_id="endpoint-denied-ai-process",
                description="Block explicitly denied process names on managed endpoints.",
                predicate=lambda e: (
                    e.event_type == EventType.ENDPOINT_PROCESS
                    and str(e.metadata.get("process_name", "")).lower() in deny_processes
                    and str(e.metadata.get("process_name", "")).lower() not in allow_processes
                ),
                decision=PolicyDecision.BLOCK,
            ),
            PolicyRule(
                rule_id="unapproved-ai-provider-monitor",
                description="Monitor discovered AI software whose provider is not approved.",
                predicate=lambda e: (
                    e.event_type in cls.PROVIDER_RELEVANT_EVENTS
                    and bool(e.ai.provider)
                    and str(e.ai.provider).lower() not in approved_providers
                ),
                decision=PolicyDecision.MONITOR,
            ),
            PolicyRule(
                rule_id="unknown-ai-provider-monitor",
                description="Monitor AI-relevant activity without a known provider identity.",
                predicate=lambda e: (
                    e.event_type in cls.PROVIDER_RELEVANT_EVENTS and not bool(e.ai.provider)
                ),
                decision=PolicyDecision.MONITOR,
            ),
        ]

        if bundle.test_controls_enabled:
            rules.append(
                PolicyRule(
                    rule_id="endpoint-synthetic-protection-test",
                    description="Block the harmless Mira Protect endpoint test marker.",
                    predicate=lambda e: (
                        e.event_type == EventType.ENDPOINT_PROCESS
                        and "local:test-block" in e.metadata.get("matched_local_rules", [])
                    ),
                    decision=PolicyDecision.BLOCK,
                )
            )
        return rules
