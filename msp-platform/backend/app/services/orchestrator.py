"""Core orchestration service connecting drift ingestion, AI agents, policy gate, and GitHub CI."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import shutil
import subprocess
import tempfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import boto3
import httpx
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import HTTPException
from msp_policy import drift_entries, drift_hash, evaluate, fingerprint, redact_plan
from starlette.concurrency import run_in_threadpool

from ..agents.investigator import (
    SYSTEM_PROMPT as INVESTIGATOR_SYSTEM_PROMPT,
    build_investigation_prompt,
    investigate_finding,
)
from ..agents.patcher import (
    SYSTEM_PROMPT as PATCHER_SYSTEM_PROMPT,
    build_patch_prompt,
    patch_terraform_workspace,
)
from ..config import Settings
from ..models import Finding, Investigation, ModelTrace, Remediation, RestoreSelection
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
    for base in (base_root, base_root.parent):
        for candidate in (root_dir, "msp-sandbox-infra/stacks/networking", "msp-sandbox-infra/infra", "infra"):
            p = base / candidate
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
        self._restore_lock = asyncio.Lock()
        self._scans: dict[str, dict[str, Any]] = {}
        self._latest_scan_id: str | None = None

    def _gh(self, repo: str | None = None) -> GitHubClient:
        repo = repo or self.settings.github_repo
        branch = self.settings.registered_repositories.get(repo.strip().lower())
        if not branch:
            raise HTTPException(status_code=409, detail="The Terraform repository is not registered for GitHub Actions.")
        return GitHubClient(
            repo=repo,
            token=self.settings.github_token,
            default_branch=branch,
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
        repo = str(meta.get("repo") or self.settings.github_repo or "msp-sandbox-infra").strip().lower()
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

            candidate = Finding(
                address=entry.address, resource_type=entry.type, resource_name=entry.name,
                account_id=account_id, region=region, repo=repo, root_dir=root_dir,
                state_lineage=state_lineage, drift_hash=d_hash, fingerprint=fp,
            )
            existing = self.store.find_open_by_address(candidate)
            if existing:
                changed_evidence = existing.fingerprint != fp
                existing.repo = repo
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

    async def _dispatch_scan(
        self, repo: str, ref: str | None, correlation_id: str, root_dir: str | None = None
    ) -> dict[str, Any] | None:
        if not self.settings.github_configured:
            raise HTTPException(
                status_code=400,
                detail="GitHub token/repo not configured. Set MSP_GITHUB_TOKEN (or MSP_GITHUB_PAT in GitHub Secrets).",
            )
        gh = self._gh(repo)
        inputs: dict[str, str] = {"correlation_id": correlation_id}
        if root_dir:
            inputs["root_dir"] = root_dir
        try:
            return await gh.dispatch_workflow(
                "drift-check.yml",
                inputs=inputs,
                ref=ref,
            )
        except GitHubError as exc:
            logger.warning("Drift scan dispatch rejected by GitHub (HTTP %s)", exc.status_code)
            if exc.status_code in (401, 403, 404):
                detail = (
                    f"GitHub rejected the drift scan (HTTP {exc.status_code}). Check that the configured "
                    "GitHub token can access this repository and has permission to dispatch drift-check.yml "
                    "(Actions: Read and write for a fine-grained token)."
                )
            else:
                detail = f"GitHub rejected the drift scan (HTTP {exc.status_code}). Check the workflow and branch."
            raise HTTPException(status_code=502, detail=detail) from exc
        except httpx.TimeoutException as exc:
            raise HTTPException(status_code=504, detail="GitHub timed out while dispatching the drift scan.") from exc
        except httpx.RequestError as exc:
            raise HTTPException(status_code=502, detail="Could not reach GitHub to dispatch the drift scan.") from exc

    @staticmethod
    def _recompute_scan_progress(scan: dict[str, Any]) -> dict[str, Any]:
        weights = {"queued": 15, "in_progress": 55, "syncing": 85, "synced": 100, "failed": 100}
        targets = scan["targets"]
        total = max(len(targets), 1)
        pct = round(sum(weights.get(t["status"], 10) for t in targets) / total)
        done = [t for t in targets if t["status"] in ("synced", "failed")]
        failed = [t for t in targets if t["status"] == "failed"]
        synced = [t for t in targets if t["status"] == "synced"]
        findings_total = sum(t.get("findings_count", 0) for t in targets)
        scan["progress_pct"] = pct
        scan["completed_count"] = len(done)
        scan["total_count"] = len(targets)
        scan["findings_ingested"] = findings_total
        scan["updated_at"] = _utcnow().isoformat()
        if len(done) == len(targets):
            if len(failed) == len(targets):
                scan["status"] = "failed"
                scan["message"] = f"Drift scan failed across {len(failed)} stack(s)."
            elif failed:
                scan["status"] = "partial_failure"
                scan["message"] = (
                    f"Scan finished: {len(synced)}/{len(targets)} stack(s) synced "
                    f"({findings_total} finding(s)); {len(failed)} failed."
                )
            else:
                scan["status"] = "completed"
                scan["message"] = (
                    f"Scan complete: {len(synced)}/{len(targets)} stack(s) synced "
                    f"({findings_total} drift finding(s) detected)."
                )
        else:
            in_prog = sum(1 for t in targets if t["status"] == "in_progress")
            scan["status"] = "running"
            scan["message"] = (
                f"Scanning {len(targets)} stack(s) · {len(done)}/{len(targets)} complete"
                + (f" ({in_prog} running)" if in_prog else " (queued on GitHub Actions)")
            )
        return scan

    async def trigger_scan(self, ref: str | None = None) -> dict[str, Any]:
        if not self.settings.github_configured:
            raise HTTPException(status_code=400, detail="GitHub token/repo not configured.")
        correlation_id = f"scan-{uuid4().hex[:8]}"
        started_at = _utcnow().isoformat()
        repos = list(self.settings.registered_repositories)
        primary = self.settings.github_repo.strip().lower()
        targets_spec: list[tuple[str, str | None]] = []
        for repo in repos:
            if repo == primary and self.settings.terraform_roots:
                targets_spec.extend((repo, root) for root in self.settings.terraform_roots)
            else:
                targets_spec.append((repo, None))
        results = []
        scan_targets: list[dict[str, Any]] = []
        for repo, root in targets_spec:
            label = root.split("/")[-1] if root else repo.split("/")[-1]
            full_label = f"{repo} ({root})" if root else repo
            try:
                dispatched = await self._dispatch_scan(repo, ref, correlation_id, root_dir=root)
                results.append(f"{full_label}: dispatched")
                scan_targets.append({
                    "repo": repo,
                    "root_dir": root,
                    "label": label,
                    "status": "queued",
                    "conclusion": None,
                    "run_id": (dispatched or {}).get("workflow_run_id"),
                    "run_number": None,
                    "run_url": (dispatched or {}).get("html_url"),
                    "findings_count": 0,
                    "error": None,
                })
            except HTTPException as exc:
                if len(targets_spec) == 1:
                    raise
                results.append(f"{full_label}: {exc.detail}")
                scan_targets.append({
                    "repo": repo,
                    "root_dir": root,
                    "label": label,
                    "status": "failed",
                    "conclusion": "failure",
                    "run_id": None,
                    "run_number": None,
                    "run_url": None,
                    "findings_count": 0,
                    "error": exc.detail,
                })
        scan = self._recompute_scan_progress({
            "correlation_id": correlation_id,
            "started_at": started_at,
            "updated_at": started_at,
            "status": "running",
            "progress_pct": 15,
            "completed_count": 0,
            "total_count": len(scan_targets),
            "findings_ingested": 0,
            "message": "Dispatched drift-check.yml on GitHub Actions...",
            "steps": [
                {
                    "time": started_at,
                    "message": f"Dispatched drift-check.yml for {len(scan_targets)} stack(s): {', '.join(t['label'] for t in scan_targets)}.",
                }
            ],
            "targets": scan_targets,
        })
        self._scans[correlation_id] = scan
        self._latest_scan_id = correlation_id
        return {
            "mode": "github_actions",
            "correlation_id": correlation_id,
            "message": " · ".join(results),
            "scan": scan,
        }

    def get_latest_scan(self) -> dict[str, Any] | None:
        if not self._latest_scan_id:
            return None
        return self._scans.get(self._latest_scan_id)

    def list_scans(self) -> list[dict[str, Any]]:
        return list(reversed(list(self._scans.values())))

    @staticmethod
    def _log_scan_step(scan: dict[str, Any], message: str) -> None:
        steps = scan.setdefault("steps", [])
        if not steps or steps[-1].get("message") != message:
            steps.append({"time": _utcnow().isoformat(), "message": message})

    async def poll_scan_status(self, correlation_id: str) -> dict[str, Any]:
        """Poll GitHub Actions for a dispatched scan and auto-ingest completed reports."""
        scan = self._scans.get(correlation_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found.")
        if scan["status"] in ("completed", "partial_failure", "failed"):
            return scan

        by_repo: dict[str, list[dict[str, Any]]] = {}
        for t in scan["targets"]:
            if t["status"] not in ("synced", "failed"):
                by_repo.setdefault(t["repo"], []).append(t)

        started_dt = datetime.fromisoformat(scan["started_at"])
        for repo, pending_targets in by_repo.items():
            gh = self._gh(repo)
            try:
                runs = await gh.list_workflow_runs("drift-check.yml", per_page=25)
            except (GitHubError, httpx.RequestError) as exc:
                logger.warning("Poll list_workflow_runs failed for %s: %s", repo, exc)
                continue

            claimed_ids = {t["run_id"] for t in scan["targets"] if t.get("run_id")}
            for target in pending_targets:
                run = None
                if target.get("run_id"):
                    run = next((r for r in runs if r.get("id") == target["run_id"]), None)
                if run is None:
                    # Match by correlation_id + root_dir in display_title
                    for candidate in runs:
                        cid = candidate.get("id")
                        if cid in claimed_ids:
                            continue
                        title = str(candidate.get("display_title") or "")
                        if f"[{correlation_id}]" in title:
                            if not target["root_dir"] or target["root_dir"] in title:
                                run = candidate
                                break
                if run is None:
                    # Fallback for older workflow runs without correlation_id in run-name:
                    # match runs created shortly before/after scan start for this root_dir
                    for candidate in runs:
                        cid = candidate.get("id")
                        if cid in claimed_ids:
                            continue
                        created_raw = candidate.get("created_at")
                        if not created_raw:
                            continue
                        try:
                            created_dt = datetime.fromisoformat(created_raw.replace("Z", "+00:00"))
                        except ValueError:
                            continue
                        if (created_dt - started_dt).total_seconds() < -15:
                            continue
                        title = str(candidate.get("display_title") or "")
                        if not target["root_dir"] or target["root_dir"] in title:
                            run = candidate
                            break

                if run is None:
                    continue

                claimed_ids.add(run["id"])
                prev_status = target["status"]
                target["run_id"] = run["id"]
                target["run_number"] = run.get("run_number")
                target["run_url"] = run.get("html_url")
                gh_status = run.get("status")
                conclusion = run.get("conclusion")
                target["conclusion"] = conclusion

                if gh_status in ("queued", "waiting", "pending", "requested"):
                    target["status"] = "queued"
                    if prev_status != "queued" or not target.get("_logged_queued"):
                        target["_logged_queued"] = True
                        self._log_scan_step(scan, f"{target['label']}: GitHub Actions run #{run.get('run_number')} queued.")
                elif gh_status == "in_progress":
                    target["status"] = "in_progress"
                    if prev_status != "in_progress":
                        self._log_scan_step(
                            scan, f"{target['label']}: GitHub Actions run #{run.get('run_number')} running Terraform plan..."
                        )
                elif gh_status == "completed":
                    if conclusion != "success":
                        target["status"] = "failed"
                        target["error"] = f"Workflow finished with conclusion '{conclusion}'."
                        self._log_scan_step(
                            scan, f"{target['label']}: run #{run.get('run_number')} failed ({conclusion})."
                        )
                        continue
                    target["status"] = "syncing"
                    self._log_scan_step(
                        scan, f"{target['label']}: run #{run.get('run_number')} succeeded — fetching redacted drift report..."
                    )
                    try:
                        files = await self._load_run_report(gh, run, repo)
                        if files is None:
                            target["status"] = "failed"
                            target["error"] = f"No drift report found for run #{run.get('run_number')}."
                            self._log_scan_step(scan, f"{target['label']}: drift report missing for run #{run.get('run_number')}.")
                            continue
                        plan = files.get("plan.redacted.json")
                        meta = files.get("meta.json") or {}
                        if not isinstance(plan, dict) or not plan or not isinstance(meta, dict):
                            target["status"] = "failed"
                            target["error"] = "Invalid drift report payload."
                            self._log_scan_step(scan, f"{target['label']}: invalid drift report payload.")
                            continue
                        ingested = self.ingest_plan(plan, {**meta, "repo": repo})
                        target["findings_count"] = len(ingested)
                        target["status"] = "synced"
                        self._log_scan_step(
                            scan,
                            f"{target['label']}: auto-synced {len(ingested)} drift finding(s) from run #{run.get('run_number')}.",
                        )
                    except HTTPException as exc:
                        target["status"] = "failed"
                        target["error"] = str(exc.detail)
                        self._log_scan_step(scan, f"{target['label']}: sync failed ({exc.detail}).")
                    except Exception as exc:
                        target["status"] = "failed"
                        target["error"] = str(exc)
                        self._log_scan_step(scan, f"{target['label']}: sync error ({exc}).")

        updated = self._recompute_scan_progress(scan)
        if updated["status"] in ("completed", "partial_failure", "failed"):
            self._log_scan_step(updated, updated["message"])
        return updated

    def _read_s3_drift_report(self, run_id: int, attempt: int, repo: str) -> dict[str, Any] | None:
        key = f"drift-reports/{repo}/{run_id}/{attempt}.json"
        try:
            s3 = boto3.client("s3", region_name=self.settings.aws_region)
            result = s3.get_object(Bucket=self.settings.drift_report_bucket, Key=key)
            with closing(result["Body"]) as body:
                report = json.load(body)
        except (BotoCoreError, ClientError) as exc:
            code = exc.response.get("Error", {}).get("Code") if isinstance(exc, ClientError) else type(exc).__name__
            if code in ("NoSuchKey", "404"):
                return None
            logger.warning("S3 drift report read failed for run %s (%s)", run_id, code)
            raise HTTPException(
                status_code=502, detail="Could not read the S3 drift report. Check the bucket and AWS permissions."
            ) from exc
        except ValueError as exc:
            raise HTTPException(status_code=502, detail="The S3 drift report contains invalid JSON.") from exc
        if not isinstance(report, dict):
            raise HTTPException(status_code=502, detail="The S3 drift report has an invalid format.")
        return report

    async def _load_run_report(self, gh: GitHubClient, run: dict[str, Any], repo: str) -> dict[str, Any] | None:
        files = None
        if self.settings.drift_report_bucket:
            files = await run_in_threadpool(self._read_s3_drift_report, run["id"], run.get("run_attempt") or 1, repo)
        if files is None:
            artifacts = await gh.list_run_artifacts(run["id"])
            drift_art = next((a for a in artifacts if str(a.get("name", "")).startswith("drift-report-")), None)
            if drift_art is None:
                return None
            files = await gh.download_artifact_files(drift_art["id"])
        return files

    async def sync_latest_drift_run(self, repo: str | None = None) -> dict[str, Any]:
        """Ingest the latest successful drift report(s) per Terraform folder in the repository."""
        if not self.settings.github_configured:
            raise HTTPException(status_code=400, detail="GitHub token/repo not configured.")
        repo = (repo or self.settings.github_repo).strip().lower()
        gh = self._gh(repo)
        expected_roots = (
            set(self.settings.terraform_roots)
            if repo == self.settings.github_repo.strip().lower() and len(self.settings.terraform_roots) > 1
            else set()
        )
        runs = await gh.list_workflow_runs("drift-check.yml", per_page=30 if expected_roots else 10)
        completed_runs = [r for r in runs if r.get("status") == "completed" and r.get("conclusion") == "success"]
        if not completed_runs:
            in_prog = next((r for r in runs if r.get("status") != "completed"), None)
            if in_prog:
                return {"synced": False, "run_id": in_prog["id"], "findings": [], "message": f"drift-check.yml run #{in_prog['run_number']} is still {in_prog['status']}..."}
            raise HTTPException(status_code=404, detail="No completed drift-check.yml runs found on GitHub.")

        if not expected_roots:
            completed = completed_runs[0]
            files = await self._load_run_report(gh, completed, repo)
            if files is None:
                raise HTTPException(status_code=404, detail=f"No drift report found for run #{completed['run_number']}.")
            plan = files.get("plan.redacted.json")
            meta = files.get("meta.json") or {}
            if not isinstance(plan, dict) or not plan or not isinstance(meta, dict):
                raise HTTPException(status_code=502, detail="The drift report contains an invalid plan or metadata.")
            findings = self.ingest_plan(plan, {**meta, "repo": repo})
            return {
                "synced": True,
                "run_id": completed["id"],
                "run_url": completed.get("html_url"),
                "findings": findings,
                "message": f"Synced run #{completed['run_number']}: ingested {len(findings)} drift finding(s) from AWS.",
            }

        seen_roots: set[str] = set()
        all_findings: list[Finding] = []
        summaries: list[str] = []
        for completed in completed_runs:
            files = await self._load_run_report(gh, completed, repo)
            if files is None:
                continue
            plan = files.get("plan.redacted.json")
            meta = files.get("meta.json") or {}
            if not isinstance(plan, dict) or not plan or not isinstance(meta, dict):
                continue
            root = str(meta.get("root_dir") or "infra")
            if root in seen_roots:
                continue
            seen_roots.add(root)
            ingested = self.ingest_plan(plan, {**meta, "repo": repo})
            all_findings.extend(ingested)
            summaries.append(f"{root.split('/')[-1]} (#{completed['run_number']}: {len(ingested)})")
            if expected_roots <= seen_roots:
                break

        if not seen_roots:
            raise HTTPException(status_code=404, detail="No drift reports found for recent drift-check.yml runs.")
        return {
            "synced": True,
            "run_id": completed_runs[0]["id"],
            "run_url": completed_runs[0].get("html_url"),
            "findings": all_findings,
            "message": f"Synced {len(seen_roots)} folder(s): {', '.join(summaries)}.",
        }

    # ------------------------------------------------------------------
    # 2. AI Investigation (Strands Agents SDK + Official AWS MCP Servers)
    # ------------------------------------------------------------------

    async def run_investigation(self, finding_id: str) -> Finding:
        finding = self.store.get_finding(finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        model_id, region = self.settings.resolve_bedrock_model(
            self.settings.strands_model_id, self.store.get_model_preferences().investigation
        )
        settings = self.settings.model_copy(update={"strands_model_id": model_id, "bedrock_region": region})
        finding.status = "investigating"
        self.store.save_finding(finding)
        self.store.record_audit(
            finding.id,
            "investigation_started",
            f"Started AI investigation for {finding.address}.",
            actor="strands-investigator",
        )

        tf_context = ""
        if not self.settings.github_configured or finding.repo.lower() == self.settings.github_repo.strip().lower():
            tf_context = _read_local_tf_context(self.settings.resolved_local_infra_path, finding.root_dir)
        user_prompt = build_investigation_prompt(finding, tf_context)
        trace_events: list[dict[str, str]] = [
            {"stage": "start", "detail": f"Sending drift context for {finding.address} to {model_id} ({region})."}
        ]
        trace = self.store.save_model_trace(
            ModelTrace(
                finding_id=finding.id,
                finding_address=finding.address,
                kind="investigation",
                status="running",
                engine="strands-bedrock-mcp",
                model_id=model_id,
                bedrock_region=region,
                system_prompt=INVESTIGATOR_SYSTEM_PROMPT,
                user_prompt=user_prompt,
                events_json=json.dumps(trace_events),
            )
        )
        inv = self.store.save_investigation(
            Investigation(
                finding_id=finding.id,
                status="running",
                engine="strands-bedrock-mcp",
                model_id=model_id,
            )
        )

        try:
            report, engine_name, mcp_servers = await investigate_finding(
                finding, settings, tf_context, trace_events=trace_events
            )
            inv.status = "completed"
            inv.engine = engine_name
            inv.mcp_servers_json = json.dumps(mcp_servers)
            inv.report_json = report.model_dump_json()
            inv.completed_at = _utcnow()
            self.store.save_investigation(inv)

            trace_events.append(
                {
                    "stage": "completed",
                    "detail": f"Received structured InvestigationReport (recommended={report.recommended_action}, confidence={int(report.confidence * 100)}%).",
                }
            )
            trace.status = "completed"
            trace.engine = engine_name
            trace.mcp_servers_json = json.dumps(mcp_servers)
            trace.reply_text = json.dumps(report.model_dump(), indent=2)
            trace.events_json = json.dumps(trace_events, default=str)
            trace.completed_at = _utcnow()
            self.store.save_model_trace(trace)

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
                    "trace_id": trace.id,
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

            trace_events.append({"stage": "error", "detail": str(exc)})
            trace.status = "failed"
            trace.error = str(exc)
            trace.events_json = json.dumps(trace_events, default=str)
            trace.completed_at = _utcnow()
            self.store.save_model_trace(trace)

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
        if self.settings.github_configured:
            if not expected_fingerprint:
                raise HTTPException(status_code=422, detail="Review the finding's current evidence before preparing a restore.")
            findings, _ = await self.restore_workspace(
                [RestoreSelection(finding_id=finding.id, fingerprint=finding.fingerprint)], rationale, decided_by
            )
            return findings[0]

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

    async def restore_workspace(
        self, selections: list[RestoreSelection], rationale: str, decided_by: str = "engineer"
    ) -> tuple[list[Finding], Remediation]:
        async with self._restore_lock:
            return await self._prepare_workspace_restore(selections, rationale, decided_by)

    async def _prepare_workspace_restore(
        self, selections: list[RestoreSelection], rationale: str, decided_by: str
    ) -> tuple[list[Finding], Remediation]:
        if not self.settings.github_configured:
            raise HTTPException(status_code=400, detail="Configure GitHub before preparing a workspace plan.")
        if not selections or len({item.finding_id for item in selections}) != len(selections):
            raise HTTPException(status_code=422, detail="Select each finding once.")
        findings = []
        for item in selections:
            finding = self.store.get_finding(item.finding_id)
            if not finding:
                raise HTTPException(status_code=404, detail="Finding not found")
            self._assert_fresh_fingerprint(finding, item.fingerprint)
            if not item.fingerprint or finding.status == "resolved":
                raise HTTPException(status_code=409, detail="Each selected finding must be open with current evidence.")
            findings.append(finding)

        def workspace(f: Finding) -> tuple:
            return f.repo, f.root_dir, f.account_id, f.region, f.state_lineage, f.state_serial, f.commit_sha

        first = findings[0]
        if not first.state_lineage or first.state_serial is None or not first.commit_sha or any(
            workspace(f) != workspace(first) for f in findings
        ):
            raise HTTPException(status_code=409, detail="Select findings from one workspace and its latest scan.")
        for f in self.store.list_findings():
            if f.status != "resolved" and (f.account_id, f.region, f.state_lineage) == (first.account_id, first.region, first.state_lineage) and (
                f.repo != first.repo or f.root_dir != first.root_dir
            ):
                raise HTTPException(status_code=409, detail="This state is reported by multiple Terraform owners. Resolve the ownership conflict first.")
            if workspace(f)[:5] == workspace(first)[:5]:
                latest = self.store.list_remediations(f.id)
                if latest and latest[0].direction == "restore" and latest[0].status in {"running", "awaiting_approval"}:
                    raise HTTPException(status_code=409, detail="Refresh the workspace's existing restore before starting another.")

        plan = json.loads(first.redacted_plan_json)
        addresses = sorted({finding.address for finding in findings})
        if len(addresses) != len(findings) or any(drift_hash(plan, [f.address]) != f.drift_hash for f in findings):
            raise HTTPException(status_code=409, detail="Sync a fresh workspace scan before preparing a restore.")

        bound_hash = drift_hash(plan, addresses)
        policy = evaluate(plan, mode="restore", allowed=addresses, expected_drift_hash=bound_hash)
        if policy["decision"] == "block":
            reasons = [
                f"{check['message']} {', '.join(check['addresses'])}".strip()
                for check in policy["checks"] if check["status"] == "fail"
            ]
            raise HTTPException(status_code=409, detail=" ".join(reasons))

        gh = self._gh(first.repo)
        correlation_id = f"restore-{uuid4().hex}"
        try:
            run = await gh.dispatch_workflow("restore.yml", inputs={
                "finding_id": first.id, "correlation_id": correlation_id,
                "allowed_addresses": json.dumps(addresses), "expected_drift_hash": bound_hash,
                "expected_commit": first.commit_sha, "expected_account": first.account_id,
                "expected_region": first.region, "expected_root": first.root_dir,
                "expected_lineage": first.state_lineage, "expected_serial": str(first.state_serial),
            })
        except (GitHubError, httpx.RequestError) as exc:
            raise HTTPException(status_code=502, detail="GitHub could not start the workspace restore plan.") from exc

        remediations = []
        for finding in findings:
            finding.status = "remediating"
            remediations.append(Remediation(
                finding_id=finding.id, direction="restore", status="running", decided_by=decided_by,
                rationale=rationale, bound_fingerprint=finding.fingerprint, bound_drift_hash=bound_hash,
                correlation_id=correlation_id, github_run_id=(run or {}).get("workflow_run_id"),
                github_run_url=(run or {}).get("html_url") or f"https://github.com/{first.repo}/actions/workflows/restore.yml",
                policy_result_json=json.dumps(policy),
            ))
        self.store.save_restore_batch(findings, remediations)
        for finding in findings:
            self.store.record_audit(
                finding.id, "workspace_restore_requested", f"Requested workspace restore plan for {len(addresses)} resources.",
                actor=decided_by, details={"correlation_id": correlation_id, "addresses": addresses},
            )
        return findings, remediations[0]

    async def refresh_workspace_restore(self, remediation_id: str) -> Remediation:
        rem = self.store.get_remediation(remediation_id)
        if not rem or rem.direction != "restore" or not rem.correlation_id.startswith("restore-"):
            raise HTTPException(status_code=404, detail="Workspace restore not found.")
        if rem.status not in {"running", "awaiting_approval"}:
            return rem
        first = self.store.get_finding(rem.finding_id)
        if not first:
            raise HTTPException(status_code=404, detail="Restore finding not found.")
        gh = self._gh(first.repo)
        try:
            run = await gh.get_workflow_run(rem.github_run_id) if rem.github_run_id else next((
                candidate for candidate in await gh.list_workflow_runs("restore.yml", per_page=100)
                if candidate.get("display_title") == f"Restore {rem.correlation_id}"
            ), None)
            if run is None:
                return rem
            jobs = {job["name"]: job for job in await gh.list_run_jobs(run["id"])}
        except (GitHubError, httpx.RequestError) as exc:
            raise HTTPException(status_code=502, detail="Could not read the workspace restore status from GitHub.") from exc

        apply = jobs.get("Apply Approved Restore Plan", {})
        verified = jobs.get("Verify Restored Resources", {}).get("conclusion") == "success"
        status, error = "running", None
        if run.get("status") == "completed":
            if apply.get("conclusion") == "success" and verified and run.get("conclusion") == "success":
                status = "succeeded"
            elif jobs.get("Plan & Deterministic Policy Gate", {}).get("conclusion") == "failure":
                status, error = "blocked", "The workspace plan failed validation. Review the linked GitHub run."
            elif apply.get("conclusion") == "skipped" and run.get("conclusion") == "success":
                status = "plan_ready"
            else:
                status, error = "failed", "Apply or verification did not complete. Review the linked GitHub run."
        elif apply.get("status") in {"waiting", "pending"}:
            status = "awaiting_approval"

        records = self.store.list_restore_batch(rem.correlation_id)
        findings = []
        for record in records:
            record.github_run_id, record.github_run_url = run["id"], run.get("html_url")
            record.status, record.error = status, error
            record.updated_at = _utcnow()
            finding = self.store.get_finding(record.finding_id)
            if finding and finding.status == "remediating" and status in {"succeeded", "blocked", "failed", "plan_ready"}:
                finding.status = "resolved" if status == "succeeded" and finding.fingerprint == record.bound_fingerprint else "open"
                findings.append(finding)
        self.store.save_restore_batch(findings, records)
        return next(record for record in records if record.id == remediation_id)

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
                self._prepare_repo_workspace(work_dir, branch_name, finding)
                _, resolved_rel = _resolve_tf_dir(work_dir, finding.root_dir)
                finding.root_dir = resolved_rel
                patcher_settings = self.settings
                patch_model_id = self.settings.claude_model
                patch_region = self.settings.aws_region
                if self.settings.claude_use_bedrock:
                    patch_model_id, patch_region = self.settings.resolve_bedrock_model(
                        self.settings.claude_model, self.store.get_model_preferences().patcher
                    )
                    patcher_settings = self.settings.model_copy(
                        update={"claude_model": patch_model_id, "bedrock_region": patch_region}
                    )
                patch_prompt = build_patch_prompt(finding, extra_instructions)
                patch_trace = self.store.save_model_trace(
                    ModelTrace(
                        finding_id=finding.id,
                        finding_address=finding.address,
                        kind="patcher",
                        status="running",
                        engine="claude-agent-sdk",
                        model_id=patch_model_id,
                        bedrock_region=patch_region,
                        system_prompt=PATCHER_SYSTEM_PROMPT,
                        user_prompt=patch_prompt,
                        events_json=json.dumps([{"stage": "start", "detail": f"Launching Claude Agent SDK on {finding.root_dir}/."}]),
                    )
                )
                try:
                    patch = await patch_terraform_workspace(
                        repo_dir=work_dir,
                        finding=finding,
                        settings=patcher_settings,
                        extra_instructions=extra_instructions,
                    )
                except Exception as patch_exc:
                    patch_trace.status = "failed"
                    patch_trace.error = str(patch_exc)
                    patch_trace.completed_at = _utcnow()
                    self.store.save_model_trace(patch_trace)
                    raise
                patch_trace.status = "completed"
                patch_trace.engine = patch.engine
                patch_trace.reply_text = (
                    f"{patch.summary}\n\n--- Modified Files ---\n"
                    + ("\n".join(patch.modified_files) or "(none)")
                    + f"\n\n--- Unified Diff ---\n{patch.diff or '(empty diff)'}"
                )
                patch_trace.events_json = json.dumps(
                    [{"stage": "start", "detail": f"Launched Claude Agent SDK on {finding.root_dir}/."}]
                    + list(patch.trace_events)
                    + [{"stage": "completed", "detail": f"Modified {len(patch.modified_files)} file(s)."}],
                    default=str,
                )
                patch_trace.completed_at = _utcnow()
                self.store.save_model_trace(patch_trace)
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

    def _prepare_repo_workspace(self, work_dir: Path, branch_name: str, finding: Finding) -> None:
        if self.settings.github_configured:
            gh = self._gh(finding.repo)
            clone_url = f"https://github.com/{gh.repo}.git"
            auth = base64.b64encode(f"x-access-token:{gh.token}".encode()).decode()
            auth_env = {**os.environ, "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.https://github.com/.extraHeader",
                        "GIT_CONFIG_VALUE_0": f"Authorization: Basic {auth}"}
            subprocess.run(
                ["git", "clone", "--depth", "1", "--branch", gh.default_branch, clone_url, str(work_dir)],
                check=True,
                capture_output=True,
                text=True,
                env=auth_env,
            )
            head = subprocess.check_output(["git", "-C", str(work_dir), "rev-parse", "HEAD"], text=True).strip()
            if head != finding.commit_sha:
                raise RuntimeError("The Terraform revision changed. Sync a fresh scan before preparing a patch.")
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
        head = subprocess.check_output(["git", "-C", str(work_dir), "rev-parse", "HEAD"], text=True).strip()
        changed = subprocess.check_output(
            ["git", "-C", str(work_dir), "diff", "--no-renames", "--name-only", "-z", "HEAD"], text=True
        )
        untracked = subprocess.check_output(
            ["git", "-C", str(work_dir), "ls-files", "--others", "--exclude-standard", "-z"], text=True
        )
        files = set((changed + untracked).split("\0")) - {""}
        root = Path(finding.root_dir)
        if head != finding.commit_sha or not files or any(
            Path(file).suffix != ".tf" or not Path(file).is_relative_to(root) or (work_dir / file).is_symlink()
            for file in files
        ):
            raise RuntimeError("The patch must only change Terraform files inside the approved root.")
        subprocess.run(["git", "-C", str(work_dir), "config", "user.email", "msp-bot@users.noreply.github.com"], check=True)
        subprocess.run(["git", "-C", str(work_dir), "config", "user.name", "MSP Drift Bot"], check=True)
        subprocess.run(["git", "-C", str(work_dir), "add", "-A"], check=True)
        msg = f"fix(drift): reconcile {finding.address} ({finding.id})"
        subprocess.run(["git", "-C", str(work_dir), "commit", "-m", msg], check=True, capture_output=True, text=True)
        gh = self._gh(finding.repo)
        auth = base64.b64encode(f"x-access-token:{gh.token}".encode()).decode()
        auth_env = {**os.environ, "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "http.https://github.com/.extraHeader",
                    "GIT_CONFIG_VALUE_0": f"Authorization: Basic {auth}"}
        subprocess.run(["git", "-C", str(work_dir), "push", "-u", "origin", branch_name], check=True, capture_output=True, text=True, env=auth_env)

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
        return await gh.open_pull_request(
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

        if self.settings.github_configured and plan is not None:
            raise HTTPException(status_code=400, detail="Use CI results to verify a live workspace.")

        if plan is None:
            if not self.settings.github_configured:
                raise HTTPException(
                    status_code=400,
                    detail="Provide a verification plan payload in local mode, or configure GitHub to dispatch drift-check.yml.",
                )
            correlation_id = f"verify-{finding.id}-{uuid4().hex[:6]}"
            await self._dispatch_scan(finding.repo, None, correlation_id)
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
