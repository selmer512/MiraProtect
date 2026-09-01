from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Iterable, TypeVar

from sqlalchemy import JSON, DateTime, String, create_engine, delete, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from .schemas import AIAsset, AIEvent, DetectionFinding


class Base(DeclarativeBase):
    pass


class AssetRecord(Base):
    __tablename__ = "ai_assets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )


class EventRecord(Base):
    __tablename__ = "ai_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class FindingRecord(Base):
    __tablename__ = "ai_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    event_id: Mapped[str] = mapped_column(String(36), index=True, nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


T = TypeVar("T")


class Repository:
    """Small persistence boundary used by the prototype.

    SQLite works out of the box for local execution and tests. PostgreSQL is selected by
    setting MIRA_DATABASE_URL (the Docker stack does this automatically).
    """

    def __init__(self, database_url: str | None = None) -> None:
        self.database_url = database_url or os.getenv(
            "MIRA_DATABASE_URL", "sqlite+pysqlite:///./mira_protect.db"
        )
        kwargs: dict = {"pool_pre_ping": True}
        if self.database_url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False}
        self.engine = create_engine(self.database_url, **kwargs)
        Base.metadata.create_all(self.engine)

    def save_asset(self, asset: AIAsset) -> AIAsset:
        payload = asset.model_dump(mode="json")
        with Session(self.engine) as session:
            existing = session.get(AssetRecord, str(asset.asset_id))
            if existing:
                existing.payload = payload
                existing.updated_at = datetime.now(timezone.utc)
            else:
                session.add(AssetRecord(id=str(asset.asset_id), payload=payload))
            session.commit()
        return asset

    def save_event(self, event: AIEvent) -> AIEvent:
        with Session(self.engine) as session:
            record = EventRecord(
                id=str(event.event_id),
                payload=event.model_dump(mode="json"),
                timestamp=event.timestamp,
            )
            session.merge(record)
            session.commit()
        return event

    def save_findings(self, findings: Iterable[DetectionFinding]) -> None:
        with Session(self.engine) as session:
            for finding in findings:
                session.merge(
                    FindingRecord(
                        id=str(finding.finding_id),
                        event_id=str(finding.event_id),
                        payload=finding.model_dump(mode="json"),
                        timestamp=finding.timestamp,
                    )
                )
            session.commit()

    def list_assets(self) -> list[AIAsset]:
        with Session(self.engine) as session:
            rows = session.scalars(select(AssetRecord).order_by(AssetRecord.updated_at.desc())).all()
            return [AIAsset.model_validate(row.payload) for row in rows]

    def list_events(self, limit: int = 200) -> list[AIEvent]:
        with Session(self.engine) as session:
            rows = session.scalars(
                select(EventRecord).order_by(EventRecord.timestamp.desc()).limit(limit)
            ).all()
            return [AIEvent.model_validate(row.payload) for row in rows]

    def list_findings(self, limit: int = 200) -> list[DetectionFinding]:
        with Session(self.engine) as session:
            rows = session.scalars(
                select(FindingRecord).order_by(FindingRecord.timestamp.desc()).limit(limit)
            ).all()
            return [DetectionFinding.model_validate(row.payload) for row in rows]

    def clear(self) -> None:
        with Session(self.engine) as session:
            session.execute(delete(FindingRecord))
            session.execute(delete(EventRecord))
            session.execute(delete(AssetRecord))
            session.commit()
