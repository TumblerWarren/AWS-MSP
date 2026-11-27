"""End-to-end API & negative-safety tests (offline/mocked agent calls + real policy gate)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from app.agents.patcher import PatchResult
from app.config import Settings
from app.demo_fixtures import clean_plan, combined_demo_plan, rds_retention_drift_plan
from app.main import create_app
from app.models import EvidenceItem, ImpactedResource, InvestigationReport


def _make_client(tmp_path: Path) -> TestClient:
    db_path = tmp_path / "test.db"
    settings = Settings(
        database_url=f"sqlite:///{db_path}",
        github_repo="",
        github_token="",
        dry_run_github=True,
    )
    app = create_app(settings)
    return TestClient(app)


def _mock_sg_report() -> InvestigationReport:
    return InvestigationReport(
        headline="Port 22 (SSH) opened to 0.0.0.0/0 on app security group",
        severity="critical",
        summary="aws_security_group.app has an out-of-band ingress rule allowing TCP/22 from anywhere.",
        root_cause="Manual console or CLI AuthorizeSecurityGroupIngress outside CI/CD.",
        actor="arn:aws:iam::111122223333:role/sandbox-admin",
        event_time="2026-11-22T12:00:00Z",
        event_name="AuthorizeSecurityGroupIngress",
        blast_radius_summary="Exposes attached EC2 app server and increases lateral risk to RDS via rds-sg.",
        impacted_resources=[
            ImpactedResource(
                resource_id="i-0f9e8d7c6b5a43210",
                resource_type="EC2 Instance",
                relationship="Attached to aws_security_group.app",
                risk="critical",
            ),
            ImpactedResource(
                resource_id="msp-sandbox-postgres",
                resource_type="RDS DB Instance",
                relationship="rds-sg accepts TCP/5432 from app-sg",
                risk="high",
            ),
        ],
        recommended_action="restore",
        recommendation_rationale="SSH 0.0.0.0/0 violates baseline; revert AWS to Terraform immediately.",
        confidence=0.94,
        evidence_timeline=[
            EvidenceItem(
                source="CloudTrail",
                timestamp="2026-11-22T12:00:00Z",
                summary="AuthorizeSecurityGroupIngress added 0.0.0.0/0:22",
            )
        ],
    )


def test_full_restore_and_verify_lifecycle(tmp_path: Path):
    with _make_client(tmp_path) as client:
        # 1. Ingest drift plan (SG, EC2, RDS)
        r = client.post(
            "/api/scans/ingest",
            json={"plan": combined_demo_plan(), "meta": {"account_id": "111122223333"}},
        )
        assert r.status_code == 200
        findings = r.json()["findings"]
        assert len(findings) == 3

        sg = next(f for f in findings if f["address"] == "aws_security_group.app")
        assert sg["severity"] == "critical"

        # 2. Run investigation (mocking live Strands/Bedrock call)
        with patch(
            "app.services.orchestrator.investigate_finding",
            new=AsyncMock(return_value=(_mock_sg_report(), "strands-bedrock-mcp", ["aws-api", "cloudtrail"])),
        ):
            inv_r = client.post(f"/api/findings/{sg['id']}/investigate")
            assert inv_r.status_code == 200
            detail = inv_r.json()
            assert detail["status"] == "investigated"
            assert detail["latest_investigation"]["report"]["recommended_action"] == "restore"

        # 3. Negative test: stale fingerprint MUST be rejected with 409
        stale_r = client.post(
            f"/api/findings/{sg['id']}/remediate/restore",
            json={"decided_by": "alice", "rationale": "revert", "expected_fingerprint": "deadbeef"},
        )
        assert stale_r.status_code == 409

        # 4. Valid fingerprint -> Restore succeeds through pre-flight policy gate
        ok_r = client.post(
            f"/api/findings/{sg['id']}/remediate/restore",
            json={"decided_by": "alice", "rationale": "revert unauthorized SSH", "expected_fingerprint": detail["fingerprint"]},
        )
        assert ok_r.status_code == 200
        rem = ok_r.json()["latest_remediation"]
        assert rem["direction"] == "restore"
        assert rem["policy_result"]["decision"] == "allow"
        assert rem["status"] == "awaiting_approval"

        # 5. Independent verification with clean plan -> Finding resolved
        ver_r = client.post(f"/api/findings/{sg['id']}/verify", json={"plan": clean_plan()})
        assert ver_r.status_code == 200
        assert ver_r.json()["status"] == "resolved"
        assert len(ver_r.json()["audit_events"]) >= 4


def test_update_terraform_flow_opens_patch(tmp_path: Path):
    with _make_client(tmp_path) as client:
        r = client.post(
            "/api/scans/ingest",
            json={"plan": combined_demo_plan(), "meta": {"account_id": "111122223333"}},
        )
        ec2 = next(f for f in r.json()["findings"] if f["address"] == "aws_instance.app")

        fake_patch = PatchResult(
            summary="Updated Owner tag on aws_instance.app to payments-oncall.",
            diff="--- a/infra/compute_and_rds.tf\n+++ b/infra/compute_and_rds.tf\n-    Owner = \"platform-team\"\n+    Owner = \"payments-oncall\"\n",
            modified_files=["infra/compute_and_rds.tf"],
            engine="claude-agent-sdk",
        )
        with patch("app.services.orchestrator.patch_terraform_workspace", new=AsyncMock(return_value=fake_patch)):
            upd_r = client.post(
                f"/api/findings/{ec2['id']}/remediate/update-terraform",
                json={
                    "decided_by": "bob",
                    "rationale": "Ownership moved to payments-oncall",
                    "expected_fingerprint": ec2["fingerprint"],
                },
            )
            assert upd_r.status_code == 200
            rem = upd_r.json()["latest_remediation"]
            assert rem["direction"] == "update_terraform"
            assert rem["status"] == "pr_open"
            assert "payments-oncall" in rem["patch_diff"]


def test_negative_safety_rds_replace_is_blocked(tmp_path: Path):
    with _make_client(tmp_path) as client:
        plan = rds_retention_drift_plan()
        # Simulate a dangerous plan that would replace RDS
        plan["resource_changes"][0]["change"]["actions"] = ["delete", "create"]
        ing = client.post("/api/scans/ingest", json={"plan": plan, "meta": {"account_id": "111122223333"}})
        assert ing.status_code == 200
        rds = ing.json()["findings"][0]

        res = client.post(
            f"/api/findings/{rds['id']}/remediate/restore",
            json={"decided_by": "alice", "rationale": "try restore", "expected_fingerprint": rds["fingerprint"]},
        )
        assert res.status_code == 200
        body = res.json()
        assert body["status"] == "blocked"
        assert body["latest_remediation"]["status"] == "blocked"
        assert body["latest_remediation"]["policy_result"]["decision"] == "block"


def test_agentcore_ping_and_invocations_endpoint(tmp_path: Path):
    with _make_client(tmp_path) as client:
        assert client.get("/ping").json() == {"status": "Healthy"}
        seed = client.post(
            "/api/scans/ingest",
            json={"plan": combined_demo_plan(), "meta": {"account_id": "111122223333"}},
        ).json()["findings"]
        sg_id = next(f["id"] for f in seed if f["address"] == "aws_security_group.app")

        with patch(
            "app.services.orchestrator.investigate_finding",
            new=AsyncMock(return_value=(_mock_sg_report(), "strands-bedrock-mcp", ["aws-api", "cloudtrail"])),
        ):
            inv = client.post("/invocations", json={"action": "investigate", "finding_id": sg_id})
            assert inv.status_code == 200
            assert inv.json()["status"] == "investigated"


def test_update_credentials_supports_static_key_and_temporary_session(tmp_path: Path):
    with _make_client(tmp_path) as client:
        # 1. Static IAM Access Key + Secret Key (no session token)
        r1 = client.post(
            "/api/config/credentials",
            json={
                "aws_access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "aws_session_token": "",
                "aws_region": "ap-south-1",
            },
        )
        assert r1.status_code == 200
        assert r1.json()["aws_credentials_detected"] is True
        assert r1.json()["aws_credential_mode"] == "access_key"

        # 2. Temporary STS Credentials (Access Key + Secret Key + Session Token)
        r2 = client.post(
            "/api/config/credentials",
            json={
                "aws_access_key_id": "ASIAIOSFODNN7EXAMPLE",
                "aws_secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "aws_session_token": "FwoGZXIvYXdzEBYaDH...",
                "aws_region": "ap-south-1",
            },
        )
        assert r2.status_code == 200
        assert r2.json()["aws_credentials_detected"] is True
        assert r2.json()["aws_credential_mode"] == "temporary_session"


