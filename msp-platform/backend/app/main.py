"""FastAPI application entrypoint for MSP MVP 1."""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .config import BEDROCK_MODELS, Settings, get_settings
from .services.github_client import GitHubError
from .models import (
    AuditEvent,
    DecisionRequest,
    Finding,
    IngestPlanRequest,
    Investigation,
    ModelTrace,
    Remediation,
    RestoreBatchRequest,
    TriggerScanRequest,
    UpdateCredentialsRequest,
    UpdateModelsRequest,
    VerifyRequest,
)
from .services.aws_session import aws_credential_mode, has_aws_credentials
from .services.orchestrator import Orchestrator
from .store import Store


def _serialize_investigation(inv: Investigation | None) -> dict[str, Any] | None:
    if inv is None:
        return None
    report = None
    if inv.report_json and inv.report_json != "{}":
        try:
            report = json.loads(inv.report_json)
        except json.JSONDecodeError:
            report = None
    return {
        "id": inv.id,
        "finding_id": inv.finding_id,
        "status": inv.status,
        "engine": inv.engine,
        "model_id": inv.model_id,
        "mcp_servers": json.loads(inv.mcp_servers_json or "[]"),
        "report": report,
        "error": inv.error,
        "created_at": inv.created_at.isoformat(),
        "completed_at": inv.completed_at.isoformat() if inv.completed_at else None,
    }


def _serialize_remediation(rem: Remediation | None) -> dict[str, Any] | None:
    if rem is None:
        return None
    return {
        "id": rem.id,
        "finding_id": rem.finding_id,
        "direction": rem.direction,
        "status": rem.status,
        "decided_by": rem.decided_by,
        "rationale": rem.rationale,
        "bound_fingerprint": rem.bound_fingerprint,
        "bound_drift_hash": rem.bound_drift_hash,
        "correlation_id": rem.correlation_id,
        "github_run_id": rem.github_run_id,
        "github_run_url": rem.github_run_url,
        "pr_number": rem.pr_number,
        "pr_url": rem.pr_url,
        "branch_name": rem.branch_name,
        "patch_summary": rem.patch_summary,
        "patch_diff": rem.patch_diff,
        "policy_result": json.loads(rem.policy_result_json) if rem.policy_result_json else None,
        "error": rem.error,
        "created_at": rem.created_at.isoformat(),
        "updated_at": rem.updated_at.isoformat(),
    }


def _serialize_audit(ev: AuditEvent) -> dict[str, Any]:
    return {
        "id": ev.id,
        "finding_id": ev.finding_id,
        "event_type": ev.event_type,
        "actor": ev.actor,
        "summary": ev.summary,
        "details": json.loads(ev.details_json or "{}"),
        "created_at": ev.created_at.isoformat(),
    }


def _serialize_trace(tr: ModelTrace) -> dict[str, Any]:
    return {
        "id": tr.id,
        "finding_id": tr.finding_id,
        "finding_address": tr.finding_address,
        "kind": tr.kind,
        "status": tr.status,
        "engine": tr.engine,
        "model_id": tr.model_id,
        "bedrock_region": tr.bedrock_region,
        "mcp_servers": json.loads(tr.mcp_servers_json or "[]"),
        "system_prompt": tr.system_prompt,
        "user_prompt": tr.user_prompt,
        "reply_text": tr.reply_text,
        "events": json.loads(tr.events_json or "[]"),
        "error": tr.error,
        "created_at": tr.created_at.isoformat(),
        "completed_at": tr.completed_at.isoformat() if tr.completed_at else None,
    }


def _serialize_finding(store: Store, f: Finding, *, full: bool = False) -> dict[str, Any]:
    invs = store.list_investigations(f.id)
    rems = store.list_remediations(f.id)
    base = {
        "id": f.id,
        "address": f.address,
        "resource_type": f.resource_type,
        "resource_name": f.resource_name,
        "resource_id": f.resource_id,
        "drift_kind": f.drift_kind,
        "severity": f.severity,
        "status": f.status,
        "account_id": f.account_id,
        "region": f.region,
        "repo": f.repo,
        "root_dir": f.root_dir,
        "commit_sha": f.commit_sha,
        "state_serial": f.state_serial,
        "state_lineage": f.state_lineage,
        "drift_hash": f.drift_hash,
        "fingerprint": f.fingerprint,
        "changes": json.loads(f.changes_json or "[]"),
        "restore_actions": json.loads(f.restore_actions_json or "[]"),
        "created_at": f.created_at.isoformat(),
        "updated_at": f.updated_at.isoformat(),
        "latest_investigation": _serialize_investigation(invs[0] if invs else None),
        "latest_remediation": _serialize_remediation(rems[0] if rems else None),
    }
    if full:
        base["redacted_plan"] = json.loads(f.redacted_plan_json or "{}")
        base["investigations"] = [_serialize_investigation(i) for i in invs]
        base["remediations"] = [_serialize_remediation(r) for r in rems]
        base["audit_events"] = [_serialize_audit(a) for a in store.list_audit(f.id)]
    return base


def create_app(settings: Settings | None = None) -> FastAPI:
    cfg = settings or get_settings()
    store = Store(cfg.database_url)
    orch = Orchestrator(store, cfg)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        store.init_db()
        yield

    app = FastAPI(title="MSP Drift Investigation & Reconciliation API", version="0.1.0", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    def get_store() -> Store:
        return store

    def get_orch() -> Orchestrator:
        return orch

    @app.get("/api/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    # Bedrock AgentCore Runtime container contract (/ping + /invocations on port 8080)
    @app.get("/ping")
    def agentcore_ping() -> dict[str, str]:
        return {"status": "Healthy"}

    @app.post("/invocations")
    async def agentcore_invocations(
        payload: dict[str, Any] = Body(...),
        o: Orchestrator = Depends(get_orch),
        s: Store = Depends(get_store),
    ) -> dict[str, Any]:
        """Bedrock AgentCore Runtime / direct agent invocation endpoint.

        Supports:
          - {"action": "investigate", "finding_id": "..."}
          - {"action": "ingest_and_investigate", "plan": {...}, "meta": {...}}
          - {"action": "update_terraform", "finding_id": "...", "rationale": "..."}
        """
        action = payload.get("action", "investigate")
        if action == "ingest_and_investigate":
            findings = o.ingest_plan(payload.get("plan") or {}, payload.get("meta") or {})
            results = []
            for f in findings:
                f = await o.run_investigation(f.id)
                results.append(_serialize_finding(s, f, full=True))
            return {"action": action, "count": len(results), "findings": results}

        finding_id = payload.get("finding_id")
        if not finding_id:
            raise HTTPException(status_code=400, detail="finding_id is required")

        if action == "update_terraform":
            f = await o.decide_update_terraform(
                finding_id,
                decided_by=payload.get("decided_by", "agentcore"),
                rationale=payload.get("rationale", ""),
                expected_fingerprint=payload.get("expected_fingerprint"),
                extra_instructions=payload.get("extra_instructions", ""),
            )
            return _serialize_finding(s, f, full=True)

        f = await o.run_investigation(finding_id)
        return _serialize_finding(s, f, full=True)

    @app.get("/api/config")
    def platform_config() -> dict[str, Any]:
        preferences = store.get_model_preferences()
        investigation = preferences.investigation if preferences.investigation in BEDROCK_MODELS else None
        patcher = preferences.patcher if cfg.claude_use_bedrock and preferences.patcher in BEDROCK_MODELS else None
        investigation_id, _ = cfg.resolve_bedrock_model(cfg.strands_model_id, investigation)
        patcher_id, _ = cfg.resolve_bedrock_model(cfg.claude_model, patcher)
        return {
            "github_configured": cfg.github_configured,
            "github_repo": cfg.github_repo,
            "aws_region": cfg.aws_region,
            "aws_credentials_detected": has_aws_credentials(),
            "aws_credential_mode": aws_credential_mode(),
            "investigator_role_configured": bool(cfg.investigator_role_arn),
            "investigator_role_arn": cfg.investigator_role_arn,
            "strands_model_id": investigation_id,
            "claude_model": patcher_id,
            "claude_use_bedrock": cfg.claude_use_bedrock,
            "aws_mcp_enabled": cfg.aws_mcp_enabled,
            "model_preferences": {"investigation": investigation, "patcher": patcher},
            "bedrock_models": [{"id": model_id, "label": label} for model_id, (label, _) in BEDROCK_MODELS.items()],
        }

    @app.put("/api/config/models")
    def update_models(body: UpdateModelsRequest) -> dict[str, Any]:
        if body.investigation is not None and body.investigation not in BEDROCK_MODELS:
            raise HTTPException(status_code=422, detail="Choose a supported investigation model.")
        if body.patcher is not None and (not cfg.claude_use_bedrock or body.patcher not in BEDROCK_MODELS):
            raise HTTPException(status_code=422, detail="Choose a supported Bedrock patching model or use the deployment default.")
        store.save_model_preferences(body.investigation, body.patcher)
        return platform_config()

    @app.post("/api/config/credentials")
    def update_credentials(body: UpdateCredentialsRequest) -> dict[str, Any]:
        """Update AWS Access Key / Secret Key / optional Session Token & GitHub credentials at runtime."""
        if body.aws_region is not None and body.aws_region.strip():
            cfg.aws_region = body.aws_region.strip()
        if body.aws_access_key_id is not None:
            cfg.aws_access_key_id = body.aws_access_key_id.strip()
        if body.aws_secret_access_key is not None:
            cfg.aws_secret_access_key = body.aws_secret_access_key.strip()
        if body.aws_session_token is not None:
            cfg.aws_session_token = body.aws_session_token.strip()
        if body.investigator_role_arn is not None:
            cfg.investigator_role_arn = body.investigator_role_arn.strip()
        if body.github_repo is not None and body.github_repo.strip():
            cfg.github_repo = body.github_repo.strip()
        if body.github_token is not None:
            cfg.github_token = body.github_token.strip()
        cfg.sync_aws_env()
        return platform_config()

    @app.get("/api/findings")
    def list_findings(s: Store = Depends(get_store)) -> list[dict[str, Any]]:
        return [_serialize_finding(s, f) for f in s.list_findings()]

    @app.get("/api/findings/{finding_id}")
    def get_finding(finding_id: str, s: Store = Depends(get_store)) -> dict[str, Any]:
        f = s.get_finding(finding_id)
        if not f:
            raise HTTPException(status_code=404, detail="Finding not found")
        return _serialize_finding(s, f, full=True)

    @app.post("/api/scans/trigger")
    async def trigger_scan(body: TriggerScanRequest, o: Orchestrator = Depends(get_orch)) -> dict[str, Any]:
        return await o.trigger_scan(ref=body.ref)

    @app.get("/api/scans")
    def list_scans(o: Orchestrator = Depends(get_orch)) -> list[dict[str, Any]]:
        return o.list_scans()

    @app.get("/api/scans/active")
    def get_active_scan(o: Orchestrator = Depends(get_orch)) -> dict[str, Any] | None:
        return o.get_latest_scan()

    @app.get("/api/scans/{correlation_id}")
    async def poll_scan(correlation_id: str, o: Orchestrator = Depends(get_orch)) -> dict[str, Any]:
        return await o.poll_scan_status(correlation_id)

    @app.get("/api/traces")
    def list_traces(finding_id: str | None = None, s: Store = Depends(get_store)) -> list[dict[str, Any]]:
        return [_serialize_trace(t) for t in s.list_model_traces(finding_id=finding_id)]

    @app.post("/api/scans/sync")
    async def sync_latest_scan(o: Orchestrator = Depends(get_orch), s: Store = Depends(get_store)) -> dict[str, Any]:
        repos = cfg.registered_repositories
        if len(repos) <= 1:
            res = await o.sync_latest_drift_run(next(iter(repos), None))
        else:
            results, messages = [], []
            for repo in repos:
                try:
                    result = await o.sync_latest_drift_run(repo)
                    results.append(result)
                    messages.append(f"{repo}: {result['message']}")
                except HTTPException as exc:
                    messages.append(f"{repo}: {exc.detail}")
                except GitHubError:
                    messages.append(f"{repo}: GitHub could not provide the scan report.")
            res = {
                "synced": any(result["synced"] for result in results),
                "run_id": None,
                "message": " · ".join(messages),
                "findings": [finding for result in results for finding in result["findings"]],
            }
        return {
            "synced": res["synced"],
            "run_id": res["run_id"],
            "run_url": res.get("run_url"),
            "message": res["message"],
            "findings": [_serialize_finding(s, f) for f in res.get("findings", [])],
        }

    @app.post("/api/scans/ingest")
    def ingest_plan(
        body: IngestPlanRequest,
        o: Orchestrator = Depends(get_orch),
        s: Store = Depends(get_store),
    ) -> dict[str, Any]:
        findings = o.ingest_plan(body.plan, body.meta)
        return {"ingested": len(findings), "findings": [_serialize_finding(s, f) for f in findings]}

    @app.post("/api/findings/{finding_id}/investigate")
    async def investigate(
        finding_id: str,
        o: Orchestrator = Depends(get_orch),
        s: Store = Depends(get_store),
    ) -> dict[str, Any]:
        f = await o.run_investigation(finding_id)
        return _serialize_finding(s, f, full=True)

    @app.post("/api/findings/{finding_id}/remediate/restore")
    async def remediate_restore(
        finding_id: str,
        body: DecisionRequest,
        o: Orchestrator = Depends(get_orch),
        s: Store = Depends(get_store),
    ) -> dict[str, Any]:
        f = await o.decide_restore(
            finding_id,
            decided_by=body.decided_by,
            rationale=body.rationale,
            expected_fingerprint=body.expected_fingerprint,
        )
        return _serialize_finding(s, f, full=True)

    @app.post("/api/remediations/restore-workspace")
    async def restore_workspace(body: RestoreBatchRequest, o: Orchestrator = Depends(get_orch)) -> dict[str, Any]:
        findings, remediation = await o.restore_workspace(body.selections, body.rationale)
        return {"finding_ids": [finding.id for finding in findings], "remediation": _serialize_remediation(remediation)}

    @app.get("/api/remediations/{remediation_id}/refresh")
    async def refresh_workspace_restore(remediation_id: str, o: Orchestrator = Depends(get_orch)) -> dict[str, Any] | None:
        return _serialize_remediation(await o.refresh_workspace_restore(remediation_id))

    @app.post("/api/findings/{finding_id}/remediate/update-terraform")
    async def remediate_update_terraform(
        finding_id: str,
        body: DecisionRequest,
        o: Orchestrator = Depends(get_orch),
        s: Store = Depends(get_store),
    ) -> dict[str, Any]:
        f = await o.decide_update_terraform(
            finding_id,
            decided_by=body.decided_by,
            rationale=body.rationale,
            expected_fingerprint=body.expected_fingerprint,
            extra_instructions=body.extra_instructions,
        )
        return _serialize_finding(s, f, full=True)

    @app.post("/api/findings/{finding_id}/verify")
    async def verify_finding(
        finding_id: str,
        body: VerifyRequest,
        o: Orchestrator = Depends(get_orch),
        s: Store = Depends(get_store),
    ) -> dict[str, Any]:
        f = await o.verify_finding(finding_id, plan=body.plan)
        return _serialize_finding(s, f, full=True)

    @app.get("/api/findings/{finding_id}/audit")
    def list_audit(finding_id: str, s: Store = Depends(get_store)) -> list[dict[str, Any]]:
        if not s.get_finding(finding_id):
            raise HTTPException(status_code=404, detail="Finding not found")
        return [_serialize_audit(a) for a in s.list_audit(finding_id)]

    # Serve compiled React SPA when frontend/dist exists (used in Docker / AWS deployment)
    frontend_dist = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"
    if frontend_dist.is_dir():
        assets_dir = frontend_dist / "assets"
        if assets_dir.is_dir():
            app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")

        @app.get("/", include_in_schema=False)
        def serve_spa_index():
            return FileResponse(str(frontend_dist / "index.html"))

    return app


app = create_app()
