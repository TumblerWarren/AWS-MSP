"""SQLModel database entities and Pydantic API/agent schemas."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field as PydanticField
from sqlmodel import Field, SQLModel


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _uid(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex[:10]}"


# ---------------------------------------------------------------------------
# Structured Agent Output Schemas
# ---------------------------------------------------------------------------


class EvidenceItem(BaseModel):
    source: str = PydanticField(description="Where this evidence came from (e.g. CloudTrail, AWS EC2 API, Terraform Plan, Git).")
    timestamp: str | None = PydanticField(default=None, description="ISO-8601 timestamp if applicable.")
    summary: str = PydanticField(description="Concise factual summary of what was observed.")
    raw_ref: str | None = PydanticField(default=None, description="Event ID, ARN, commit SHA, or API call reference.")


class ImpactedResource(BaseModel):
    resource_id: str = PydanticField(description="AWS resource ID or ARN.")
    resource_type: str = PydanticField(description="AWS resource type (e.g. EC2 Instance, RDS DB Instance, Security Group).")
    relationship: str = PydanticField(description="How this resource depends on or is affected by the drifted resource.")
    risk: Literal["low", "medium", "high", "critical"] = "medium"


class InvestigationReport(BaseModel):
    """Structured output returned by the Strands Investigation Agent."""

    headline: str = PydanticField(description="One-line executive summary of what drifted and why it matters.")
    severity: Literal["low", "medium", "high", "critical"] = PydanticField(
        description="Assessed operational/security severity."
    )
    summary: str = PydanticField(description="Clear explanation of what changed in AWS vs Terraform.")
    root_cause: str = PydanticField(description="Most likely cause based on CloudTrail, live AWS state, and Terraform context.")
    actor: str = PydanticField(default="Unknown", description="IAM principal / user / role that performed the out-of-band change, if found in CloudTrail.")
    event_time: str | None = PydanticField(default=None, description="UTC timestamp of the CloudTrail event if found.")
    event_name: str | None = PydanticField(default=None, description="AWS API action name from CloudTrail if found.")
    blast_radius_summary: str = PydanticField(description="What else in the account/VPC could be affected by this drift or its remediation.")
    impacted_resources: list[ImpactedResource] = PydanticField(default_factory=list)
    recommended_action: Literal["restore", "update_terraform", "needs_review"] = PydanticField(
        description="Recommended engineer direction: restore AWS to Terraform, or update Terraform to adopt the AWS change."
    )
    recommendation_rationale: str = PydanticField(description="Why this direction is recommended and what risks to watch for.")
    confidence: float = PydanticField(ge=0.0, le=1.0, description="Confidence score from 0.0 to 1.0 based on available evidence.")
    evidence_timeline: list[EvidenceItem] = PydanticField(default_factory=list)
    open_questions: list[str] = PydanticField(default_factory=list, description="Gaps or questions the engineer should verify before acting.")


# ---------------------------------------------------------------------------
# Persistence Tables (SQLite now; clean repository boundary for DynamoDB later)
# ---------------------------------------------------------------------------


class Finding(SQLModel, table=True):
    id: str = Field(default_factory=lambda: _uid("fnd"), primary_key=True)
    address: str = Field(index=True)
    resource_type: str = Field(index=True)
    resource_name: str = ""
    resource_id: str | None = Field(default=None, index=True)
    drift_kind: str = "modified"  # modified | deleted
    severity: str = "medium"  # low | medium | high | critical
    status: str = Field(default="open", index=True)
    # open | investigating | investigated | remediating | resolved | blocked

    account_id: str = "sandbox"
    region: str = "us-east-1"
    repo: str = "msp-sandbox-infra"
    root_dir: str = "infra"
    commit_sha: str | None = None
    state_serial: int | None = None
    state_lineage: str | None = None

    drift_hash: str
    fingerprint: str = Field(index=True)
    changes_json: str = "[]"
    restore_actions_json: str = "[]"
    redacted_plan_json: str = "{}"

    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class Investigation(SQLModel, table=True):
    id: str = Field(default_factory=lambda: _uid("inv"), primary_key=True)
    finding_id: str = Field(index=True)
    status: str = "completed"  # running | completed | failed
    engine: str = "strands-bedrock-mcp"
    model_id: str = ""
    mcp_servers_json: str = "[]"
    report_json: str = "{}"
    error: str | None = None
    created_at: datetime = Field(default_factory=_utcnow)
    completed_at: datetime | None = None


class Remediation(SQLModel, table=True):
    id: str = Field(default_factory=lambda: _uid("rem"), primary_key=True)
    finding_id: str = Field(index=True)
    direction: str  # restore | update_terraform
    status: str = "pending"
    # pending | running | awaiting_approval | pr_open | blocked | succeeded | failed
    decided_by: str = "engineer"
    rationale: str = ""
    bound_fingerprint: str
    bound_drift_hash: str
    correlation_id: str = Field(default_factory=lambda: _uid("cor"))

    github_run_id: int | None = None
    github_run_url: str | None = None
    pr_number: int | None = None
    pr_url: str | None = None
    branch_name: str | None = None

    patch_summary: str | None = None
    patch_diff: str | None = None
    policy_result_json: str | None = None
    error: str | None = None

    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)


class AuditEvent(SQLModel, table=True):
    id: str = Field(default_factory=lambda: _uid("aud"), primary_key=True)
    finding_id: str = Field(index=True)
    event_type: str
    actor: str = "system"
    summary: str
    details_json: str = "{}"
    created_at: datetime = Field(default_factory=_utcnow)


class ModelPreferences(SQLModel, table=True):
    id: int = Field(default=1, primary_key=True)
    investigation: str | None = None
    patcher: str | None = None


# ---------------------------------------------------------------------------
# API Request / Response DTOs
# ---------------------------------------------------------------------------


class UpdateModelsRequest(BaseModel):
    investigation: str | None
    patcher: str | None


class IngestPlanRequest(BaseModel):
    plan: dict[str, Any]
    meta: dict[str, Any] = PydanticField(default_factory=dict)


class TriggerScanRequest(BaseModel):
    ref: str | None = None


class DecisionRequest(BaseModel):
    decided_by: str = "engineer"
    rationale: str = ""
    expected_fingerprint: str | None = None
    # Optional custom instruction for the Terraform patcher agent
    extra_instructions: str = ""


class VerifyRequest(BaseModel):
    # Optional redacted plan payload for offline/local verification testing
    plan: dict[str, Any] | None = None
    meta: dict[str, Any] = PydanticField(default_factory=dict)


class UpdateCredentialsRequest(BaseModel):
    aws_access_key_id: str | None = None
    aws_secret_access_key: str | None = None
    aws_session_token: str | None = None
    aws_region: str | None = None
    investigator_role_arn: str | None = None
    github_repo: str | None = None
    github_token: str | None = None

