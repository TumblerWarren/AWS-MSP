"""End-to-end API & negative-safety tests (offline/mocked agent calls + real policy gate)."""

from __future__ import annotations

import json
from io import BytesIO
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest
from botocore.exceptions import ClientError
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


@pytest.mark.parametrize("github_status, api_status", [(204, 200), (403, 502)])
def test_trigger_scan_reports_github_dispatch_result(tmp_path: Path, github_status: int, api_status: int):
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        github_repo="example/infrastructure",
        github_token="example-token",
        dry_run_github=False,
    )
    upstream_body = "Upstream response body"
    upstream_response = httpx.Response(github_status, text=upstream_body if github_status == 403 else "")
    with TestClient(create_app(settings)) as client, patch.object(
        httpx.AsyncClient, "post", new=AsyncMock(return_value=upstream_response)
    ) as dispatch:
        response = client.post("/api/scans/trigger", json={})

    assert response.status_code == api_status
    assert dispatch.await_args.args == (
        "https://api.github.com/repos/example/infrastructure/actions/workflows/drift-check.yml/dispatches",
    )
    if github_status == 204:
        assert response.json()["correlation_id"] == dispatch.await_args.kwargs["json"]["inputs"]["correlation_id"]
    else:
        assert "HTTP 403" in response.json()["detail"]
        assert "Actions: Read and write" in response.json()["detail"]
        assert upstream_body not in response.text
        assert settings.github_token not in response.text


@pytest.mark.parametrize("s3_error", [None, "NoSuchKey", "AccessDenied"])
def test_sync_drift_report_reads_s3_and_legacy_artifacts(tmp_path: Path, s3_error: str | None):
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        github_repo="Example/Infrastructure",
        github_token="example-token",
        dry_run_github=False,
        drift_report_bucket="msp-drift-reports-test",
    )
    run = {"id": 42, "run_attempt": 2, "run_number": 7, "status": "completed", "conclusion": "success"}
    report = {"plan.redacted.json": combined_demo_plan(), "meta.json": {"account_id": "111122223333"}}
    body = BytesIO(json.dumps(report).encode())
    s3 = Mock()
    s3.get_object.return_value = {"Body": body}
    if s3_error:
        s3.get_object.side_effect = ClientError({"Error": {"Code": s3_error}}, "GetObject")

    with (
        TestClient(create_app(settings)) as client,
        patch("app.services.orchestrator.boto3.client", return_value=s3),
        patch("app.services.github_client.GitHubClient.list_workflow_runs", return_value=[run]),
        patch("app.services.github_client.GitHubClient.list_run_artifacts", return_value=[{"name": "drift-report-42", "id": 5}]) as list_artifacts,
        patch("app.services.github_client.GitHubClient.download_artifact_files", return_value=report) as download,
    ):
        response = client.post("/api/scans/sync")

    s3.get_object.assert_called_once_with(Bucket=settings.drift_report_bucket, Key="drift-reports/example/infrastructure/42/2.json")
    if s3_error == "AccessDenied":
        assert response.status_code == 502
        assert "AWS permissions" in response.json()["detail"]
    else:
        assert response.status_code == 200
        assert response.json()["synced"] is True
        assert len(response.json()["findings"]) == 3

    if s3_error == "NoSuchKey":
        list_artifacts.assert_awaited_once_with(42)
        download.assert_awaited_once_with(5)
    else:
        list_artifacts.assert_not_awaited()
        download.assert_not_awaited()
    if s3_error is None:
        assert body.closed
    body.close()


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


def test_model_preferences_persist_and_apply_to_investigations(tmp_path: Path):
    haiku = "in.anthropic.claude-haiku-4-5-20251001-v1:0"
    preferences = {"investigation": haiku, "patcher": None}
    with _make_client(tmp_path) as client:
        config = client.get("/api/config").json()
        assert config["model_preferences"] == {"investigation": None, "patcher": None}
        saved = client.put("/api/config/models", json=preferences)
        assert saved.status_code == 200
        assert saved.json()["strands_model_id"] == haiku
        rejected = client.put("/api/config/models", json={**preferences, "patcher": "unsupported-model"})
        assert rejected.status_code == 422

    with _make_client(tmp_path) as client:
        assert client.get("/api/config").json()["model_preferences"] == preferences
        findings = client.post("/api/scans/ingest", json={"plan": combined_demo_plan()}).json()["findings"]
        finding = next(f for f in findings if f["address"] == "aws_security_group.app")
        with patch(
            "app.services.orchestrator.investigate_finding",
            new=AsyncMock(return_value=(_mock_sg_report(), "strands-bedrock", [])),
        ) as investigate:
            response = client.post(f"/api/findings/{finding['id']}/investigate")
        assert response.status_code == 200
        assert response.json()["latest_investigation"]["model_id"] == haiku
        agent_settings = investigate.await_args.args[1]
        assert agent_settings.strands_model_id == haiku
        assert agent_settings.bedrock_region == "ap-south-1"

        reset = client.put("/api/config/models", json={"investigation": None, "patcher": None})
        assert reset.status_code == 200
        assert reset.json()["strands_model_id"] == config["strands_model_id"]


def test_workspace_restores_group_five_findings_into_two_plans(tmp_path: Path):
    primary = "example/networking"
    secondary = "example/compute"
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'test.db'}", github_repo=primary,
                        github_token="example-token", dry_run_github=False, terraform_repositories={secondary: "main"})
    baseline = {"root_dir": "infra", "commit_sha": "1" * 40, "state_serial": 4, "account_id": "111122223333"}
    full = combined_demo_plan()
    short = {**full, "resource_drift": full["resource_drift"][:2], "resource_changes": full["resource_changes"][:2]}
    dispatch = AsyncMock(side_effect=[{"workflow_run_id": 17}, {"workflow_run_id": 18}])
    with TestClient(create_app(settings)) as client, patch("app.services.github_client.GitHubClient.dispatch_workflow", autospec=True, side_effect=dispatch):
        a = client.post("/api/scans/ingest", json={"plan": short, "meta": {**baseline, "repo": primary, "state_lineage": "network-state"}}).json()["findings"]
        b = client.post("/api/scans/ingest", json={"plan": full, "meta": {**baseline, "repo": secondary, "state_lineage": "compute-state"}}).json()["findings"]
        assert len(client.get("/api/findings").json()) == 5

        def prepare(items):
            return client.post("/api/remediations/restore-workspace", json={"selections": [
                {"finding_id": f["id"], "fingerprint": f["fingerprint"]} for f in items
            ]})

        assert prepare(a + b).status_code == 409
        blocked = prepare(a[:1])
        assert blocked.status_code == 409
        assert a[1]["address"] in blocked.json()["detail"]
        dispatch.assert_not_awaited()

        assert prepare(b).status_code == 200
        prepared = prepare(a)
        assert prepared.status_code == 200
        assert prepare(a).status_code == 409
        assert [(call.args[0].repo, call.args[0].default_branch) for call in dispatch.await_args_list] == [(secondary, "main"), (primary, "master")]
        assert [len(json.loads(call.kwargs["inputs"]["allowed_addresses"])) for call in dispatch.await_args_list] == [3, 2]

        remediation = prepared.json()["remediation"]
        with (
            patch("app.services.github_client.GitHubClient.get_workflow_run", return_value={"id": 18, "status": "completed", "conclusion": "success"}),
            patch("app.services.github_client.GitHubClient.list_run_jobs", return_value=[
                {"name": "Apply Approved Restore Plan", "conclusion": "success"},
                {"name": "Verify Restored Resources", "conclusion": "success"},
            ]),
        ):
            refreshed = client.get(f"/api/remediations/{remediation['id']}/refresh")
        assert refreshed.json()["status"] == "succeeded"
        assert [client.get(f"/api/findings/{f['id']}").json()["status"] for f in a] == ["resolved", "resolved"]
        assert client.get(f"/api/findings/{b[0]['id']}").json()["status"] == "remediating"


def test_update_terraform_flow_opens_patch(tmp_path: Path):
    with _make_client(tmp_path) as client:
        r = client.post(
            "/api/scans/ingest",
            json={"plan": combined_demo_plan(), "meta": {"account_id": "111122223333"}},
        )
        ec2 = next(f for f in r.json()["findings"] if f["address"] == "aws_instance.app")
        model = "au.anthropic.claude-sonnet-5-5"
        assert client.put("/api/config/models", json={"investigation": None, "patcher": model}).status_code == 200

        fake_patch = PatchResult(
            summary="Updated Owner tag on aws_instance.app to payments-oncall.",
            diff="--- a/infra/compute_and_rds.tf\n+++ b/infra/compute_and_rds.tf\n-    Owner = \"platform-team\"\n+    Owner = \"payments-oncall\"\n",
            modified_files=["infra/compute_and_rds.tf"],
            engine="claude-agent-sdk",
        )
        with patch("app.services.orchestrator.patch_terraform_workspace", new=AsyncMock(return_value=fake_patch)) as patcher:
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
            agent_settings = patcher.await_args.kwargs["settings"]
            assert agent_settings.claude_model == model
            assert agent_settings.bedrock_region == "ap-southeast-2"


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


