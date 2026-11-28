"""SQLite persistence layer (behind clean repository methods for DynamoDB migration)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.dialects.sqlite import insert
from sqlalchemy import func
from sqlmodel import Session, SQLModel, create_engine, select

from .models import AuditEvent, Finding, Investigation, ModelPreferences, ModelTrace, Remediation


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Store:
    def __init__(self, database_url: str) -> None:
        connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
        self.engine = create_engine(database_url, connect_args=connect_args)

    def init_db(self) -> None:
        SQLModel.metadata.create_all(self.engine)

    def get_model_preferences(self) -> ModelPreferences:
        with Session(self.engine) as session:
            return session.get(ModelPreferences, 1) or ModelPreferences()

    def save_model_preferences(self, investigation: str | None, patcher: str | None) -> None:
        values = {"investigation": investigation, "patcher": patcher}
        stmt = insert(ModelPreferences).values(id=1, **values).on_conflict_do_update(index_elements=["id"], set_=values)
        with Session(self.engine) as session:
            session.execute(stmt)
            session.commit()

    # --- Findings ---
    def list_findings(self) -> list[Finding]:
        with Session(self.engine) as s:
            stmt = select(Finding).order_by(Finding.updated_at.desc())  # type: ignore[union-attr]
            return list(s.exec(stmt).all())

    def get_finding(self, finding_id: str) -> Finding | None:
        with Session(self.engine) as s:
            return s.get(Finding, finding_id)

    def find_open_by_address(self, candidate: Finding) -> Finding | None:
        with Session(self.engine) as s:
            stmt = select(Finding).where(
                Finding.address == candidate.address,
                Finding.account_id == candidate.account_id,
                Finding.region == candidate.region,
                func.lower(Finding.repo) == candidate.repo,
                Finding.root_dir == candidate.root_dir,
                Finding.state_lineage == candidate.state_lineage,
                Finding.status != "resolved",
            )
            return s.exec(stmt).first()

    def save_restore_batch(self, findings: list[Finding], remediations: list[Remediation]) -> None:
        with Session(self.engine, expire_on_commit=False) as session:
            for finding in findings:
                finding.updated_at = _utcnow()
                session.add(finding)
            session.add_all(remediations)
            session.commit()

    def save_finding(self, finding: Finding) -> Finding:
        finding.updated_at = _utcnow()
        with Session(self.engine) as s:
            s.add(finding)
            s.commit()
            s.refresh(finding)
            return finding

    # --- Investigations ---
    def list_investigations(self, finding_id: str) -> list[Investigation]:
        with Session(self.engine) as s:
            stmt = (
                select(Investigation)
                .where(Investigation.finding_id == finding_id)
                .order_by(Investigation.created_at.desc())  # type: ignore[union-attr]
            )
            return list(s.exec(stmt).all())

    def latest_investigation(self, finding_id: str) -> Investigation | None:
        items = self.list_investigations(finding_id)
        return items[0] if items else None

    def save_investigation(self, inv: Investigation) -> Investigation:
        with Session(self.engine) as s:
            s.add(inv)
            s.commit()
            s.refresh(inv)
            return inv

    # --- Remediations ---
    def list_remediations(self, finding_id: str) -> list[Remediation]:
        with Session(self.engine) as s:
            stmt = (
                select(Remediation)
                .where(Remediation.finding_id == finding_id)
                .order_by(Remediation.created_at.desc())  # type: ignore[union-attr]
            )
            return list(s.exec(stmt).all())

    def get_remediation(self, remediation_id: str) -> Remediation | None:
        with Session(self.engine) as s:
            return s.get(Remediation, remediation_id)

    def list_restore_batch(self, correlation_id: str) -> list[Remediation]:
        with Session(self.engine) as s:
            return list(s.exec(select(Remediation).where(
                Remediation.correlation_id == correlation_id, Remediation.direction == "restore"
            )).all())

    def save_remediation(self, rem: Remediation) -> Remediation:
        rem.updated_at = _utcnow()
        with Session(self.engine) as s:
            s.add(rem)
            s.commit()
            s.refresh(rem)
            return rem

    # --- Audit ---
    def record_audit(
        self,
        finding_id: str,
        event_type: str,
        summary: str,
        *,
        actor: str = "system",
        details: dict[str, Any] | None = None,
    ) -> AuditEvent:
        evt = AuditEvent(
            finding_id=finding_id,
            event_type=event_type,
            actor=actor,
            summary=summary,
            details_json=json.dumps(details or {}, default=str),
        )
        with Session(self.engine) as s:
            s.add(evt)
            s.commit()
            s.refresh(evt)
            return evt

    def list_audit(self, finding_id: str) -> list[AuditEvent]:
        with Session(self.engine) as s:
            stmt = (
                select(AuditEvent)
                .where(AuditEvent.finding_id == finding_id)
                .order_by(AuditEvent.created_at.desc())  # type: ignore[union-attr]
            )
            return list(s.exec(stmt).all())

    # --- Model Traces (Prompts Sent & Replies Received) ---
    def save_model_trace(self, trace: ModelTrace) -> ModelTrace:
        with Session(self.engine) as s:
            s.add(trace)
            s.commit()
            s.refresh(trace)
            return trace

    def list_model_traces(self, finding_id: str | None = None, limit: int = 50) -> list[ModelTrace]:
        with Session(self.engine) as s:
            stmt = select(ModelTrace)
            if finding_id:
                stmt = stmt.where(ModelTrace.finding_id == finding_id)
            stmt = stmt.order_by(ModelTrace.created_at.desc()).limit(limit)  # type: ignore[union-attr]
            return list(s.exec(stmt).all())
