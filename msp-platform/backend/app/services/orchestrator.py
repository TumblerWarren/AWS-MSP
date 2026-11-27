"""Core orchestration service connecting drift ingestion, AI agents, policy gate, and GitHub CI."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import HTTPException
from msp_policy import drift_entries, drift_hash, evaluate, fingerprint, redact_plan

from ..agents.investigator import investigate_finding
from ..agents.patcher import patch_terraform_workspace
from ..config import Settings
from ..models import Finding, Investigation, Remediation
from ..services.github_client import GitHubClient, GitHubError
from ..store import Store

logger = logging.getLogger(__name__)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _infer_severity(resource_type: str, changes: list[dict[str, Any]], drift_kind: str) -> str:
    if drift_kind == "deleted":
        return "critical"
    if resource_type == "aws_security_group":
        blob = json.dumps(changes)
        if "0.0.0.0/0" in blob or "::/0" in blob:
            return "critical"
        return "high"
    if resource_type in ("aws_db_instance", "aws_rds_cluster", "aws_vpc"):
        return "high"
    if resource_type == "aws_instance":
        paths = {c.get("path", "") for c in changes}
        if paths and all(p.startswith("tags.") for p in paths):
            return "low"
        return "medium"
    return "medium"


def _resolve_tf_dir(base_root: Path, root_dir: str = "infra") -> tuple[Path, str]:
    """Locate the sandbox Terraform directory whether base_root is a monorepo (AWS-MSP) or standalone."""
    for candidate in (root_dir, "msp-sandbox-infra/infra", "infra"):
        p = base_root / candidate
        if p.is_dir():
            return p, candidate
    return base_root / root_dir, root_dir


def _read_local_tf_context(infra_root: Path, root_dir: str = "infra") -> str:
    """Read Terraform .tf files from the local infra checkout to give agents full context."""
    tf_dir, rel_dir = _resolve_tf_dir(infra_root, root_dir)
    if not tf_dir.is_dir():
        return ""
    chunks: list[str] = []
    for path in sorted(tf_dir.glob("*.tf")):
        try:
            content = path.read_text(encoding="utf-8")
            chunks.append(f"### File: {rel_dir}/{path.name}\n```hcl\n{content}\n```")
        except OSError:
            continue
    return "\n\n".join(chunks)


class Orchestrator:
    def __init__(self, store: Store, settings: Settings) -> None:
        self.store = store
        self.settings = settings

    def _gh(self) -> GitHubClient:
        return GitHubClient(
            repo=self.settings.github_repo,
            token=self.settings.github_token,
            default_branch=self.settings.github_default_branch,
        )

    # ------------------------------------------------------------------
    # 1. Drift Ingestion & Scanning
    # ------------------------------------------------------------------

    def ingest_plan(self, raw_plan: dict[str, Any], meta: dict[str, Any] | None = None) -> list[Finding]:
        """Redact a Terraform plan JSON, extract drift entries, and upsert Findings."""
        meta = meta or {}
        plan = raw_plan if raw_plan.get("msp_redacted") else redact_plan(raw_plan)
        entries = drift_entries(plan)
        account_id = str(meta.get("account_id") or "sandbox-account")
        region = str(meta.get("region") or self.settings.aws_region)
        repo = str(meta.get("repo") or self.settings.github_repo or "msp-sandbox-infra")
        root_dir = str(meta.get("root_dir") or "infra")
        commit_sha = meta.get("commit_sha") or "local-head"
        state_serial = meta.get("state_serial")
        state_lineage = meta.get("state_lineage")

        saved: list[Finding] = []
        for entry in entries:
            changes_list = [c.to_dict() for c in entry.changes]
            d_hash = drift_hash(plan, [entry.address])
            fp = fingerprint(
                commit_sha=commit_sha,
                state_serial=state_serial,
                state_lineage=state_lineage,
                address=entry.address,
                drift_digest=d_hash,
            )
            severity = _infer_severity(entry.type, changes_list, entry.kind)

            existing = self.store.find_open_by_address(entry.address, account_id)
            if existing:
                changed_evidence = existing.fingerprint != fp
                existing.resource_id = entry.resource_id or existing.resource_id
                existing.drift_kind = entry.kind
                existing.severity = severity
                existing.commit_sha = commit_sha
                existing.state_serial = state_serial
                existing.state_lineage = state_lineage
                existing.drift_hash = d_hash
                existing.fingerprint = fp
                existing.changes_json = json.dumps(changes_list, default=str)
                existing.restore_actions_json = json.dumps(list(entry.restore_actions or []))
                existing.redacted_plan_json = json.dumps(plan, default=str)
                if changed_evidence and existing.status == "investigated":
                    existing.status = "open"
                finding = self.store.save_finding(existing)
                self.store.record_audit(
                    finding.id,
                    "drift_updated" if changed_evidence else "drift_reconfirmed",
                    f"Drift re-scanned for {finding.address} (fp={fp[:12]}).",
                    details={"fingerprint": fp, "evidence_changed": changed_evidence},
                )
            else:
                finding = self.store.save_finding(
                    Finding(
                        address=entry.address,
                        resource_type=entry.type,
                        resource_name=entry.name,
                        resource_id=entry.resource_id,
                        drift_kind=entry.kind,
                        severity=severity,
                        status="open",
                        account_id=account_id,
                        region=region,
                        repo=repo,
                        root_dir=root_dir,
                        commit_sha=commit_sha,
                        state_serial=state_serial,
                        state_lineage=state_lineage,
                        drift_hash=d_hash,
                        fingerprint=fp,
                        changes_json=json.dumps(changes_list, default=str),
                        restore_actions_json=json.dumps(list(entry.restore_actions or [])),
                        redacted_plan_json=json.dumps(plan, default=str),
                    )
                )
                self.store.record_audit(
                    finding.id,
                    "drift_detected",
                    f"Detected {entry.kind} drift on {finding.address} ({finding.resource_id or 'no-id'}).",
                    details={"fingerprint": fp, "drift_hash": d_hash, "severity": severity},
                )
            saved.append(finding)
        return saved

    async def trigger_scan(self, ref: str | None = None) -> dict[str, Any]:
        if not self.settings.github_configured:
            raise HTTPException(
                status_code=400,
                detail="GitHub token/repo not configured. Set MSP_GITHUB_TOKEN (or MSP_GITHUB_PAT in GitHub Secrets).",
            )
        correlation_id = f"scan-{uuid4().hex[:8]}"
        gh = self._gh()
        await gh.dispatch_workflow(
            "drift-check.yml",
            inputs={"correlation_id": correlation_id},
            ref=ref,
        )
        return {
            "mode": "github_actions",
            "correlation_id": correlation_id,
            "message": f"Dispatched drift-check.yml on {self.settings.github_repo} (correlation={correlation_id}). Click 'Sync GitHub' once the run finishes.",
        }

    async def sync_latest_drift_run(self) -> dict[str, Any]:
        """Fetch the latest completed drift-check.yml artifact from GitHub Actions and ingest it."""
        if not self.settings.github_configured:
            raise HTTPException(status_code=400, detail="GitHub token/repo not configured.")
        gh = self._gh()
        runs = await gh.list_workflow_runs("drift-check.yml", per_page=10)
        completed = next((r for r in runs if r.get("status") == "completed" and r.get("conclusion") == "success"), None)
        if not completed:
            in_prog = next((r for r in runs if r.get("status") != "completed"), None)
            if in_prog:
                return {"synced": False, "run_id": in_prog["id"], "findings": [], "message": f"drift-check.yml run #{in_prog['run_number']} is still {in_prog['status']}..."}
            raise HTTPException(status_code=404, detail="No completed drift-check.yml runs found on GitHub.")

        artifacts = await gh.list_run_artifacts(completed["id"])
        drift_art = next((a for a in artifacts if str(a.get("name", "")).startswith("drift-report-")), None)
        if not drift_art:
            raise HTTPException(status_code=404, detail=f"No drift-report artifact found in run #{completed['run_number']}.")

        files = await gh.download_artifact_files(drift_art["id"])
        plan = files.get("plan.redacted.json")
        meta = files.get("meta.json") or {}
        if not plan:
            raise HTTPException(status_code=500, detail="plan.redacted.json missing from GitHub artifact.")
        findings = self.ingest_plan(plan, meta)
        return {
            "synced": True,
            "run_id": completed["id"],
            "run_url": completed.get("html_url"),
            "findings": findings,
            "message": f"Synced run #{completed['run_number']}: ingested {len(findings)} drift finding(s) from AWS.",
        }

    # ------------------------------------------------------------------
    # 2. AI Investigation (Strands Agents SDK + Official AWS MCP Servers)
    # ------------------------------------------------------------------

    async def run_investigation(self, finding_id: str) -> Finding:
        finding = self.store.get_finding(finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        finding.status = "investigating"
        self.store.save_finding(finding)
        self.store.record_audit(
            finding.id,
            "investigation_started",
            f"Started AI investigation for {finding.address}.",
            actor="strands-investigator",
        )

        tf_context = _read_local_tf_context(self.settings.resolved_local_infra_path, finding.root_dir)
        inv = self.store.save_investigation(
            Investigation(
                finding_id=finding.id,
                status="running",
                engine="strands-bedrock-mcp",
                model_id=self.settings.strands_model_id,
            )
        )

        try:
            report, engine_name, mcp_servers = await investigate_finding(finding, self.settings, tf_context)
            inv.status = "completed"
            inv.engine = engine_name
            inv.mcp_servers_json = json.dumps(mcp_servers)
            inv.report_json = report.model_dump_json()
            inv.completed_at = _utcnow()
            self.store.save_investigation(inv)

            finding.severity = report.severity
            finding.status = "investigated"
            self.store.save_finding(finding)

            self.store.record_audit(
                finding.id,
                "investigation_completed",
                f"Investigation completed via {engine_name}: recommended {report.recommended_action} "
                f"(confidence {int(report.confidence * 100)}%).",
                actor=engine_name,
                details={
                    "investigation_id": inv.id,
                    "actor_found": report.actor,
                    "recommended_action": report.recommended_action,
                    "mcp_servers": mcp_servers,
                },
            )
            return finding
        except Exception as exc:
            inv.status = "failed"
            inv.error = str(exc)
            inv.completed_at = _utcnow()
            self.store.save_investigation(inv)
            finding.status = "open"
            self.store.save_finding(finding)
            self.store.record_audit(
                finding.id,
                "investigation_failed",
                f"Investigation failed: {exc}",
                actor="strands-investigator",
            )
            raise HTTPException(status_code=500, detail=f"Investigation failed: {exc}") from exc

    # ------------------------------------------------------------------
    # 3. Engineer Decision A: Restore AWS
    # ------------------------------------------------------------------

    def _assert_fresh_fingerprint(self, finding: Finding, expected_fingerprint: str | None) -> None:
        if expected_fingerprint and expected_fingerprint != finding.fingerprint:
            self.store.record_audit(
                finding.id,
                "decision_rejected_stale",
                "Rejected reconciliation decision because evidence fingerprint changed.",
                details={"expected": expected_fingerprint, "current": finding.fingerprint},
            )
            raise HTTPException(
                status_code=409,
                detail=(
                    f"Stale evidence: you approved fingerprint {expected_fingerprint[:12]}, "
                    f"but current finding evidence is {finding.fingerprint[:12]}. Please review the updated diff."
                ),
            )

    async def decide_restore(
        self,
        finding_id: str,
        *,
        decided_by: str,
        rationale: str,
        expected_fingerprint: str | None = None,
    ) -> Finding:
        finding = self.store.get_finding(finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        self._assert_fresh_fingerprint(finding, expected_fingerprint)

        # Deterministic pre-flight policy check on the finding's own redacted plan
        # (authoritative gate ALSO runs inside GitHub Actions on the live plan).
        plan = json.loads(finding.redacted_plan_json or "{}")
        single_resource_plan = dict(plan)
        single_resource_plan["resource_changes"] = [
            rc for rc in plan.get("resource_changes", []) if rc.get("address") == finding.address
        ]
        policy = evaluate(
            single_resource_plan,
            mode="restore",
            allowed=[finding.address],
            expected_drift_hash=finding.drift_hash,
            expected_commit=finding.commit_sha,
            actual_commit=finding.commit_sha,
        )

        rem = Remediation(
            finding_id=finding.id,
            direction="restore",
            status="pending",
            decided_by=decided_by,
            rationale=rationale,
            bound_fingerprint=finding.fingerprint,
            bound_drift_hash=finding.drift_hash,
            policy_result_json=json.dumps(policy, default=str),
        )

        if policy["decision"] == "block":
            rem.status = "blocked"
            rem.error = "Blocked by deterministic pre-flight policy gate."
            self.store.save_remediation(rem)
            finding.status = "blocked"
            self.store.save_finding(finding)
            self.store.record_audit(
                finding.id,
                "remediation_blocked",
                f"Restore blocked by policy gate for {finding.address}.",
                actor="policy-engine",
                details={"remediation_id": rem.id, "checks": policy["checks"]},
            )
            return finding

        if self.settings.github_configured:
            gh = self._gh()
            try:
                await gh.dispatch_workflow(
                    "restore.yml",
                    inputs={
                        "finding_id": finding.id,
                        "correlation_id": rem.correlation_id,
                        "allowed_addresses": json.dumps([finding.address]),
                        "expected_drift_hash": finding.drift_hash,
                        "expected_commit": finding.commit_sha or "",
                    },
                )
                rem.status = "awaiting_approval"
                rem.github_run_url = f"https://github.com/{self.settings.github_repo}/actions/workflows/restore.yml"
            except GitHubError as exc:
                rem.status = "failed"
                rem.error = str(exc)
                self.store.save_remediation(rem)
                raise HTTPException(status_code=502, detail=str(exc)) from exc
        else:
            rem.status = "awaiting_approval"
            rem.patch_summary = (
                "Local preview mode: policy gate passed. Connect MSP_GITHUB_REPO & MSP_GITHUB_TOKEN "
                "to dispatch restore.yml to GitHub Actions for human Environment approval."
            )

        self.store.save_remediation(rem)
        finding.status = "remediating"
        self.store.save_finding(finding)
        self.store.record_audit(
            finding.id,
            "restore_dispatched",
            f"Restore AWS approved by {decided_by} (fp={finding.fingerprint[:12]}).",
            actor=decided_by,
            details={"remediation_id": rem.id, "correlation_id": rem.correlation_id, "rationale": rationale},
        )
        return finding

    # ------------------------------------------------------------------
    # 4. Engineer Decision B: Update Terraform (Claude Agent SDK -> PR)
    # ------------------------------------------------------------------

    async def decide_update_terraform(
        self,
        finding_id: str,
        *,
        decided_by: str,
        rationale: str,
        expected_fingerprint: str | None = None,
        extra_instructions: str = "",
    ) -> Finding:
        finding = self.store.get_finding(finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        self._assert_fresh_fingerprint(finding, expected_fingerprint)

        branch_name = f"msp/drift-fix-{finding.id}"
        rem = self.store.save_remediation(
            Remediation(
                finding_id=finding.id,
                direction="update_terraform",
                status="running",
                decided_by=decided_by,
                rationale=rationale,
                bound_fingerprint=finding.fingerprint,
                bound_drift_hash=finding.drift_hash,
                branch_name=branch_name,
            )
        )
        self.store.record_audit(
            finding.id,
            "update_terraform_started",
            f"Update Terraform approved by {decided_by}; launching Claude Agent SDK patcher.",
            actor=decided_by,
            details={"remediation_id": rem.id, "branch": branch_name, "rationale": rationale},
        )

        # Work strictly inside an isolated temp copy of the Terraform repo
        with tempfile.TemporaryDirectory(prefix="msp-patch-") as tmp:
            work_dir = Path(tmp) / "repo"
            try:
                self._prepare_repo_workspace(work_dir, branch_name)
                _, resolved_rel = _resolve_tf_dir(work_dir, finding.root_dir)
                finding.root_dir = resolved_rel
                patch = await patch_terraform_workspace(
                    repo_dir=work_dir,
                    finding=finding,
                    settings=self.settings,
                    extra_instructions=extra_instructions,
                )
                rem.patch_summary = patch.summary
                rem.patch_diff = patch.diff

                if not patch.diff.strip():
                    rem.status = "failed"
                    rem.error = "Patcher agent finished without modifying any Terraform files."
                    self.store.save_remediation(rem)
                    return finding

                if self.settings.github_configured:
                    pr = await self._commit_push_and_open_pr(work_dir, branch_name, finding, rationale, patch.summary)
                    rem.pr_number = pr.get("number")
                    rem.pr_url = pr.get("html_url")
                    rem.status = "pr_open"
                else:
                    rem.status = "pr_open"
                    rem.patch_summary = (
                        f"{patch.summary}\n\n"
                        "(Local preview mode: patch generated and diffed cleanly in an isolated temp workspace. "
                        "Connect MSP_GITHUB_REPO & MSP_GITHUB_TOKEN to push the branch and open a real PR.)"
                    )

                self.store.save_remediation(rem)
                finding.status = "remediating"
                self.store.save_finding(finding)
                self.store.record_audit(
                    finding.id,
                    "terraform_patch_prepared",
                    f"Prepared Terraform patch via {patch.engine} on branch {branch_name}.",
                    actor=patch.engine,
                    details={
                        "remediation_id": rem.id,
                        "modified_files": patch.modified_files,
                        "pr_url": rem.pr_url,
                    },
                )
                return finding
            except Exception as exc:
                rem.status = "failed"
                rem.error = str(exc)
                self.store.save_remediation(rem)
                self.store.record_audit(
                    finding.id,
                    "update_terraform_failed",
                    f"Terraform patch failed: {exc}",
                    actor="claude-patcher",
                )
                raise HTTPException(status_code=500, detail=f"Update Terraform failed: {exc}") from exc

    def _prepare_repo_workspace(self, work_dir: Path, branch_name: str) -> None:
        if self.settings.github_configured:
            clone_url = f"https://x-access-token:{self.settings.github_token}@github.com/{self.settings.github_repo}.git"
            subprocess.run(
                ["git", "clone", "--depth", "1", "--branch", self.settings.github_default_branch, clone_url, str(work_dir)],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(["git", "-C", str(work_dir), "checkout", "-b", branch_name], check=True, capture_output=True)
            return

        src = self.settings.resolved_local_infra_path
        if not src.exists():
            raise RuntimeError(f"Local infra repo path not found: {src}")
        shutil.copytree(src, work_dir, ignore=shutil.ignore_patterns(".git", ".terraform", "*.tfstate*"))
        subprocess.run(["git", "init", "-q", str(work_dir)], check=True)
        subprocess.run(["git", "-C", str(work_dir), "config", "user.email", "msp-bot@local"], check=True)
        subprocess.run(["git", "-C", str(work_dir), "config", "user.name", "MSP Bot"], check=True)
        subprocess.run(["git", "-C", str(work_dir), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(work_dir), "commit", "-q", "-m", "baseline"], check=True)
        subprocess.run(["git", "-C", str(work_dir), "checkout", "-q", "-b", branch_name], check=True)

    async def _commit_push_and_open_pr(
        self,
        work_dir: Path,
        branch_name: str,
        finding: Finding,
        rationale: str,
        patch_summary: str,
    ) -> dict[str, Any]:
        subprocess.run(["git", "-C", str(work_dir), "config", "user.email", "msp-bot@users.noreply.github.com"], check=True)
        subprocess.run(["git", "-C", str(work_dir), "config", "user.name", "MSP Drift Bot"], check=True)
        subprocess.run(["git", "-C", str(work_dir), "add", "-A"], check=True)
        msg = f"fix(drift): reconcile {finding.address} ({finding.id})"
        subprocess.run(["git", "-C", str(work_dir), "commit", "-m", msg], check=True, capture_output=True, text=True)
        subprocess.run(["git", "-C", str(work_dir), "push", "-u", "origin", branch_name], check=True, capture_output=True, text=True)

        body = (
            f"## Drift Reconciliation PR\n\n"
            f"- **Finding:** `{finding.id}`\n"
            f"- **Resource:** `{finding.address}` (`{finding.resource_id or 'n/a'}`)\n"
            f"- **Approved Evidence Fingerprint:** `{finding.fingerprint}`\n"
            f"- **Engineer Rationale:** {rationale or '_none provided_'}\n\n"
            f"### Patch Summary\n{patch_summary}\n\n"
            f"> `pr-plan.yml` will run `terraform plan` in `update` mode and require **0 planned changes** "
            f"before this PR can be merged.\n"
        )
        return await self._gh().open_pull_request(
            title=f"Reconcile drift on {finding.address} ({finding.id})",
            body=body,
            head=branch_name,
        )

    # ------------------------------------------------------------------
    # 5. Independent Post-Remediation Verification
    # ------------------------------------------------------------------

    async def verify_finding(self, finding_id: str, plan: dict[str, Any] | None = None) -> Finding:
        finding = self.store.get_finding(finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        if plan is None:
            if not self.settings.github_configured:
                raise HTTPException(
                    status_code=400,
                    detail="Provide a verification plan payload in local mode, or configure GitHub to dispatch drift-check.yml.",
                )
            correlation_id = f"verify-{finding.id}-{uuid4().hex[:6]}"
            await self._gh().dispatch_workflow("drift-check.yml", inputs={"correlation_id": correlation_id})
            self.store.record_audit(
                finding.id,
                "verification_dispatched",
                f"Dispatched independent verification drift-check.yml (correlation={correlation_id}).",
            )
            return finding

        redacted = plan if plan.get("msp_redacted") else redact_plan(plan)
        remaining = [e for e in drift_entries(redacted) if e.address == finding.address]
        gate = evaluate(redacted, mode="verify")

        if not remaining and gate["decision"] == "allow":
            finding.status = "resolved"
            self.store.save_finding(finding)
            for rem in self.store.list_remediations(finding.id):
                if rem.status in ("awaiting_approval", "pr_open", "running"):
                    rem.status = "succeeded"
                    self.store.save_remediation(rem)
            self.store.record_audit(
                finding.id,
                "verification_passed",
                f"Independent verification confirmed 0 drift remaining on {finding.address}. Finding resolved.",
                details={"policy_gate": gate},
            )
        else:
            self.store.record_audit(
                finding.id,
                "verification_failed",
                f"Verification still sees drift or planned changes on {finding.address}.",
                details={"remaining_drift": [e.to_dict() for e in remaining], "policy_gate": gate},
            )
        return finding
