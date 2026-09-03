from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Iterable

from .schemas import AIContext, AIEvent, Actor, DataContext, DeploymentType, EventType, ToolInvocation


class Collector(ABC):
    """Adapter boundary for any endpoint, browser, network, SaaS, cloud, or AI telemetry source."""

    collector_id: str

    @abstractmethod
    def normalize(self, record: dict[str, Any]) -> Iterable[AIEvent]:
        """Translate source-specific telemetry into Mira Protect AI events."""


class GenericCollector(Collector):
    """Prototype adapter for JSON records from gateways, scripts, EDR enrichment, or SaaS exports.

    The record format is intentionally simple so teams can test the platform before a
    dedicated vendor adapter exists.
    """

    collector_id = "generic-json-v1"

    def normalize(self, record: dict[str, Any]) -> Iterable[AIEvent]:
        timestamp = record.get("timestamp")
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        elif timestamp is None:
            timestamp = datetime.now(timezone.utc)

        tools = [ToolInvocation.model_validate(tool) for tool in record.get("tools", [])]
        classifications = [str(v) for v in record.get("data_classifications", [])]

        yield AIEvent(
            event_type=EventType(record.get("event_type", EventType.INTERACTION.value)),
            timestamp=timestamp,
            trace_id=record.get("trace_id"),
            actor=Actor(
                user_id=record.get("user_id"),
                device_id=record.get("device_id"),
                identity=record.get("identity"),
                source_ip=record.get("source_ip"),
            ),
            ai=AIContext(
                provider=record.get("provider"),
                product=record.get("product"),
                model=record.get("model"),
                deployment_type=DeploymentType(record.get("deployment_type", "unknown")),
                agent_id=record.get("agent_id"),
                session_id=record.get("session_id"),
            ),
            data=DataContext(
                classifications=classifications,
                sources=[str(v) for v in record.get("data_sources", [])],
                destinations=[str(v) for v in record.get("data_destinations", [])],
                contains_sensitive_data=bool(record.get("contains_sensitive_data", False)),
            ),
            tools=tools,
            input=record.get("input", {}),
            output=record.get("output", {}),
            metadata={
                **record.get("metadata", {}),
                "collector_id": self.collector_id,
                "provider_approved": bool(record.get("provider_approved", False)),
            },
        )


COLLECTORS: dict[str, Collector] = {GenericCollector.collector_id: GenericCollector()}


def register_collector(collector: Collector) -> None:
    COLLECTORS[collector.collector_id] = collector


def get_collector(collector_id: str) -> Collector:
    try:
        return COLLECTORS[collector_id]
    except KeyError as exc:
        raise KeyError(f"Unknown collector: {collector_id}") from exc
