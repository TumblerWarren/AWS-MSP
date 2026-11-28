"""Async GitHub REST API client for workflows, redacted plan artifacts, and PRs."""

from __future__ import annotations

import io
import json
import zipfile
from typing import Any

import httpx


class GitHubError(RuntimeError):
    def __init__(self, message: str, *, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class GitHubClient:
    def __init__(self, repo: str, token: str, default_branch: str = "master") -> None:
        self.repo = repo.strip()
        self.token = token.strip()
        self.default_branch = default_branch
        self.base_url = f"https://api.github.com/repos/{self.repo}"

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    async def dispatch_workflow(
        self,
        workflow_file: str,
        inputs: dict[str, str],
        ref: str | None = None,
    ) -> dict[str, Any] | None:
        url = f"{self.base_url}/actions/workflows/{workflow_file}/dispatches"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                url,
                headers=self._headers(),
                json={"ref": ref or self.default_branch, "inputs": inputs},
            )
            if resp.status_code not in (200, 201, 204):
                raise GitHubError(
                    f"dispatch {workflow_file} failed ({resp.status_code}): {resp.text}",
                    status_code=resp.status_code,
                )
            if resp.status_code == 200 and resp.content:
                return resp.json()
            return None

    async def list_workflow_runs(self, workflow_file: str, per_page: int = 10) -> list[dict[str, Any]]:
        url = f"{self.base_url}/actions/workflows/{workflow_file}/runs"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url, headers=self._headers(), params={"per_page": per_page})
            if resp.status_code != 200:
                raise GitHubError(f"list runs failed ({resp.status_code}): {resp.text}")
            return resp.json().get("workflow_runs", [])

    async def get_workflow_run(self, run_id: int) -> dict[str, Any]:
        url = f"{self.base_url}/actions/runs/{run_id}"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url, headers=self._headers())
            if resp.status_code != 200:
                raise GitHubError(f"get run {run_id} failed ({resp.status_code}): {resp.text}")
            return resp.json()

    async def list_run_jobs(self, run_id: int) -> list[dict[str, Any]]:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(f"{self.base_url}/actions/runs/{run_id}/jobs", headers=self._headers())
            if resp.status_code != 200:
                raise GitHubError("GitHub did not return the restore job status.", status_code=resp.status_code)
            return resp.json().get("jobs", [])

    async def list_run_artifacts(self, run_id: int) -> list[dict[str, Any]]:
        url = f"{self.base_url}/actions/runs/{run_id}/artifacts"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url, headers=self._headers())
            if resp.status_code != 200:
                raise GitHubError(f"list artifacts failed ({resp.status_code}): {resp.text}")
            return resp.json().get("artifacts", [])

    async def download_artifact_files(self, artifact_id: int) -> dict[str, Any]:
        """Download a GitHub Actions artifact zip and parse any JSON files inside."""
        url = f"{self.base_url}/actions/artifacts/{artifact_id}/zip"
        async with httpx.AsyncClient(timeout=60.0, follow_redirects=True) as client:
            resp = await client.get(url, headers=self._headers())
            if resp.status_code != 200:
                raise GitHubError(f"download artifact {artifact_id} failed ({resp.status_code}): {resp.text}")
            out: dict[str, Any] = {}
            with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
                for name in zf.namelist():
                    if name.endswith(".json"):
                        out[name.split("/")[-1]] = json.loads(zf.read(name).decode("utf-8"))
            return out

    async def open_pull_request(
        self,
        *,
        title: str,
        body: str,
        head: str,
        base: str | None = None,
    ) -> dict[str, Any]:
        url = f"{self.base_url}/pulls"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                url,
                headers=self._headers(),
                json={
                    "title": title,
                    "body": body,
                    "head": head,
                    "base": base or self.default_branch,
                },
            )
            if resp.status_code not in (200, 201):
                raise GitHubError(f"create PR failed ({resp.status_code}): {resp.text}")
            return resp.json()

    async def get_pull_request(self, pr_number: int) -> dict[str, Any]:
        url = f"{self.base_url}/pulls/{pr_number}"
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(url, headers=self._headers())
            if resp.status_code != 200:
                raise GitHubError(f"get PR #{pr_number} failed ({resp.status_code}): {resp.text}")
            return resp.json()
