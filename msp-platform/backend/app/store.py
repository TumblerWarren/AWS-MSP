"""SQLite persistence layer (behind clean repository methods for DynamoDB migration)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.dialects.sqlite import insert
from sqlmodel import Session, SQLModel, create_engine, select

from .models import AuditEvent, Finding, Investigation, ModelPreferences, Remediation


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

    def find_open_by_address(self, address: str, account_id: str) -> Finding | None:
        with Session(self.engine) as s:
            stmt = select(Finding).where(
                Finding.address == address,
                Finding.account_id == account_id,
                Finding.status != "resolved",
            )
            return s.exec(stmt).first()

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
