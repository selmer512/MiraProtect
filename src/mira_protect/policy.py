from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .schemas import AIEvent, PolicyDecision


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    description: str
    predicate: Callable[[AIEvent], bool]
    decision: PolicyDecision


class PolicyEngine:
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

    @staticmethod
    def default_rules() -> list[PolicyRule]:
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
                    (tool.target or "").lower().startswith("production")
                    for tool in e.tools
                ),
                decision=PolicyDecision.REQUIRE_APPROVAL,
            ),
            PolicyRule(
                rule_id="unknown-ai-provider-monitor",
                description="Monitor use of AI systems without a known provider.",
                predicate=lambda e: not bool(e.ai.provider),
                decision=PolicyDecision.MONITOR,
            ),
        ]
