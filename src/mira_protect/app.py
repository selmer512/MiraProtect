from __future__ import annotations

from fastapi import FastAPI

from .policy import PolicyEngine
from .risk import RiskEngine
from .schemas import AIAsset, AIEvent, RiskFactors, RiskResult

app = FastAPI(
    title="Mira Protect",
    version="0.1.0",
    description="Vendor-neutral enterprise AI security control plane",
)

risk_engine = RiskEngine()
policy_engine = PolicyEngine()

# MVP in-memory stores. Persistence adapters will replace these behind repository interfaces.
assets: dict[str, AIAsset] = {}
events: dict[str, AIEvent] = {}


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "mira-protect"}


@app.post("/api/v1/assets", response_model=AIAsset)
def register_asset(asset: AIAsset) -> AIAsset:
    assets[str(asset.asset_id)] = asset
    return asset


@app.get("/api/v1/assets", response_model=list[AIAsset])
def list_assets() -> list[AIAsset]:
    return list(assets.values())


@app.post("/api/v1/risk/score", response_model=RiskResult)
def score_risk(factors: RiskFactors) -> RiskResult:
    return risk_engine.score(factors)


@app.post("/api/v1/events", response_model=AIEvent)
def ingest_event(event: AIEvent) -> AIEvent:
    decision, matched_rules = policy_engine.evaluate(event)
    event.security.policy_decision = decision
    event.security.detections = sorted(set(event.security.detections + matched_rules))
    events[str(event.event_id)] = event
    return event


@app.get("/api/v1/events", response_model=list[AIEvent])
def list_events() -> list[AIEvent]:
    return list(events.values())
