from mira_protect.policy import PolicyEngine
from mira_protect.risk import RiskEngine
from mira_protect.schemas import (
    AIContext,
    AIEvent,
    DataContext,
    EventType,
    PolicyDecision,
    RiskFactors,
    ToolInvocation,
)


def test_risk_engine_returns_bounded_score() -> None:
    result = RiskEngine().score(
        RiskFactors(
            impact=5,
            likelihood=5,
            data_sensitivity=5,
            privilege=5,
            autonomy=5,
            exposure=5,
            reachability=5,
            control_effectiveness=1,
        )
    )
    assert result.normalized_score == 100
    assert result.level.value == "critical"


def test_restricted_data_to_unapproved_provider_is_blocked() -> None:
    event = AIEvent(
        event_type=EventType.INTERACTION,
        ai=AIContext(provider="example-ai"),
        data=DataContext(classifications=["CUI"]),
        metadata={"provider_approved": False},
    )
    decision, rules = PolicyEngine().evaluate(event)
    assert decision == PolicyDecision.BLOCK
    assert "protect-restricted-data-external-ai" in rules


def test_production_tool_call_requires_approval() -> None:
    event = AIEvent(
        event_type=EventType.TOOL_CALL,
        tools=[ToolInvocation(name="shell", operation="execute", target="production-web")],
        metadata={"provider_approved": True},
    )
    decision, rules = PolicyEngine().evaluate(event)
    assert decision == PolicyDecision.REQUIRE_APPROVAL
    assert "production-tool-human-approval" in rules
