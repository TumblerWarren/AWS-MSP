"""Terraform Patcher Agent built with the official Claude Agent SDK (`claude-agent-sdk`).

Design principles:
- Uses the prebuilt Claude Agent SDK natively inside an isolated temporary checkout
  of the target Terraform repository.
- No custom HCL regexes or hand-rolled file-editing loops: Claude uses its built-in
  coding tools (Read, Edit, Write, Glob, Grep, Bash) directly on the temp repo.
- Safety is enforced by isolation (temp copy only; no AWS credentials passed to the
  coding agent) and by GitHub Actions running `terraform plan` + the deterministic
  `msp_policy` gate in `update` mode (requiring 0 planned changes) on the opened PR.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from claude_agent_sdk import ClaudeAgentOptions, ResultMessage, query

from ..config import Settings
from ..models import Finding
from ..services.aws_session import has_aws_credentials

logger = logging.getLogger(__name__)


@dataclass
class PatchResult:
    summary: str
    diff: str
    modified_files: list[str]
    engine: str = "claude-agent-sdk"


SYSTEM_PROMPT = """\
You are a senior Terraform engineer reconciling intentional AWS configuration drift.

An engineer has reviewed an out-of-band AWS change and explicitly chosen
**Update Terraform** so that the Terraform codebase matches live AWS state.

Guidelines:
- Inspect the Terraform files in the repository before editing.
- Make the minimal, idiomatic HCL change needed so that `terraform plan` shows
  ZERO changes for the drifted resource and ZERO unintended changes for any other resource.
- Preserve variables, formatting, comments, and conventions used in the repository.
- Do not hardcode secrets or credentials.
- If `terraform` is available in PATH, you may run `terraform fmt` on modified files.
- Never run `terraform apply` or touch remote AWS state.
"""


def _build_patch_prompt(finding: Finding, extra_instructions: str = "") -> str:
    changes = json.loads(finding.changes_json or "[]")
    lines = [
        f"Update the Terraform configuration in `{finding.root_dir}/` to reconcile drift on:",
        f"- **Terraform Address:** `{finding.address}`",
        f"- **Resource Type:** `{finding.resource_type}`",
        f"- **AWS Resource ID:** `{finding.resource_id or 'unknown'}`",
        "",
        "## Observed Drift (before = current Terraform, after = live AWS to adopt)",
        f"```json\n{json.dumps(changes, indent=2)}\n```",
    ]
    if extra_instructions.strip():
        lines.extend(["", "## Additional Engineer Instructions", extra_instructions.strip()])
    lines.extend(
        [
            "",
            "Apply the minimal HCL update so Terraform matches the `after` (live AWS) state, "
            "and conclude with a concise summary of what you changed and why.",
        ]
    )
    return "\n".join(lines)


def _claude_env(settings: Settings) -> dict[str, str]:
    """Environment passed to the Claude Agent SDK subprocess."""
    env: dict[str, str] = {}
    if settings.claude_use_bedrock:
        env["CLAUDE_CODE_USE_BEDROCK"] = "1"
        env["AWS_REGION"] = settings.aws_region
    # Forward optional Anthropic proxy / key if present in host env
    for key in ("ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "ANTHROPIC_AUTH_TOKEN"):
        if os.environ.get(key):
            env[key] = os.environ[key]
    return env


def _has_claude_auth(settings: Settings) -> bool:
    if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"):
        return True
    return settings.claude_use_bedrock and has_aws_credentials()


async def patch_terraform_workspace(
    *,
    repo_dir: Path,
    finding: Finding,
    settings: Settings,
    extra_instructions: str = "",
) -> PatchResult:
    """Run Claude Agent SDK inside an isolated temp clone of the Terraform repo."""
    if not _has_claude_auth(settings):
        raise RuntimeError(
            "Claude Agent SDK needs credentials to patch Terraform: configure temporary AWS credentials "
            "for Bedrock (MSP_CLAUDE_USE_BEDROCK=true) or set ANTHROPIC_API_KEY."
        )

    options = ClaudeAgentOptions(
        cwd=str(repo_dir),
        model=settings.claude_model,
        system_prompt=SYSTEM_PROMPT,
        permission_mode="acceptEdits",
        allowed_tools=["Read", "Edit", "Write", "Glob", "Grep", "Bash"],
        env=_claude_env(settings),
        max_turns=15,
    )

    summary_text = ""
    async for message in query(prompt=_build_patch_prompt(finding, extra_instructions), options=options):
        if isinstance(message, ResultMessage):
            if message.is_error:
                raise RuntimeError(f"Claude Agent SDK patcher error: {message.result}")
            if message.result:
                summary_text = message.result

    diff = subprocess.run(
        ["git", "-C", str(repo_dir), "diff"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout

    status_out = subprocess.run(
        ["git", "-C", str(repo_dir), "status", "--porcelain"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    modified_files = [line[3:].strip() for line in status_out.splitlines() if line.strip()]

    return PatchResult(
        summary=summary_text.strip() or f"Updated Terraform for {finding.address}.",
        diff=diff,
        modified_files=modified_files,
        engine="claude-agent-sdk",
    )
