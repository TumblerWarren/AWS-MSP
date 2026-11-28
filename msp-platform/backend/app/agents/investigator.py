"""Drift Investigation Agent built with AWS Strands Agents SDK + official AWS Labs MCP servers.

Design principles:
- Uses the prebuilt AWS Strands Agents SDK (`strands-agents`) on Bedrock.
- Mounts official AWS Labs MCP servers directly (no custom tool wrappers):
    * `awslabs.aws-api-mcp-server` (READ_OPERATIONS_ONLY=true)
    * `awslabs.cloudtrail-mcp-server`
- Safety is enforced at the infrastructure boundary (read-only STS role with explicit
  Deny on secrets and Terraform state + READ_OPERATIONS_ONLY=true), NOT by
  over-constraining how the agent reasons or explores.
"""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import ExitStack
from typing import Any

from mcp import StdioServerParameters, stdio_client
from strands import Agent
from strands.models import BedrockModel
from strands.tools.mcp import MCPClient

from ..config import Settings
from ..models import EvidenceItem, Finding, ImpactedResource, InvestigationReport
from ..services.aws_session import build_readonly_mcp_env, has_aws_credentials

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
You are a senior AWS cloud and Terraform infrastructure investigator.

A Terraform refresh-only plan detected configuration drift between Terraform code
and live AWS infrastructure. Your job is to investigate the drift thoroughly using
your read-only AWS and CloudTrail MCP tools, explain what happened and why it matters,
and give the engineer a clear recommendation:
- `restore`: Terraform is the desired state and AWS should be reverted.
- `update_terraform`: The live AWS change looks intentional and Terraform should be updated to match.
- `needs_review`: Evidence is ambiguous and the engineer should confirm intent before acting.

How to investigate:
- Use CloudTrail MCP tools to find who modified the resource, when, and via which API call.
- Use AWS API MCP tools (read-only) to inspect the live resource and discover connected/dependent
  resources (such as EC2 instances attached to a security group, RDS instances referencing that
  security group, subnets, VPCs, or security risks like 0.0.0.0/0 exposure).
- Compare what you find in live AWS against the Terraform source code provided in context.
- Be factual and cite concrete resource IDs, principals, timestamps, and API calls you observed.
  Never invent CloudTrail events or resource IDs you did not observe.
"""


def build_investigation_prompt(finding: Finding, tf_context: str) -> str:
    changes = json.loads(finding.changes_json or "[]")
    restore_actions = json.loads(finding.restore_actions_json or "[]")
    sections = [
        "## Drift Finding",
        f"- **Finding ID:** `{finding.id}`",
        f"- **Terraform Address:** `{finding.address}`",
        f"- **Resource Type:** `{finding.resource_type}`",
        f"- **AWS Resource ID:** `{finding.resource_id or 'unknown'}`",
        f"- **Drift Kind:** `{finding.drift_kind}`",
        f"- **Account / Region:** `{finding.account_id}` / `{finding.region}`",
        f"- **Commit SHA:** `{finding.commit_sha or 'unknown'}`",
        f"- **Planned Restore Actions (if reverted):** `{restore_actions}`",
        "",
        "## Attribute Diff (Expected in Terraform -> Actual in Live AWS)",
        f"```json\n{json.dumps(changes, indent=2)}\n```",
    ]
    if tf_context:
        sections.extend(["", "## Relevant Terraform Source Files", tf_context])
    sections.extend(
        [
            "",
            "Investigate this drift using the available AWS and CloudTrail MCP tools, "
            "then return your structured InvestigationReport.",
        ]
    )
    return "\n".join(sections)


_build_investigation_prompt = build_investigation_prompt


def _create_aws_mcp_clients(env: dict[str, str]) -> list[tuple[str, MCPClient]]:
    """Build official AWS Labs MCP clients over stdio via uvx."""
    specs = [
        (
            "awslabs.aws-api-mcp-server",
            "aws_api",
            StdioServerParameters(
                command="uvx",
                args=["awslabs.aws-api-mcp-server@latest"],
                env=env,
            ),
        ),
        (
            "awslabs.cloudtrail-mcp-server",
            "cloudtrail",
            StdioServerParameters(
                command="uvx",
                args=["awslabs.cloudtrail-mcp-server@latest"],
                env=env,
            ),
        ),
    ]
    return [
        (
            name,
            MCPClient(
                lambda params=p: stdio_client(params),
                prefix=prefix,
                startup_timeout=60,
            ),
        )
        for name, prefix, p in specs
    ]


def _summarize_strands_messages(messages: list[Any]) -> list[dict[str, str]]:
    """Extract readable tool calls and assistant steps from Strands agent.messages."""
    steps: list[dict[str, str]] = []
    for msg in messages or []:
        role = msg.get("role", "unknown") if isinstance(msg, dict) else getattr(msg, "role", "unknown")
        content = msg.get("content", []) if isinstance(msg, dict) else getattr(msg, "content", [])
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict):
                continue
            if "toolUse" in block:
                tu = block["toolUse"]
                name = tu.get("name", "tool")
                inp = json.dumps(tu.get("input", {}), default=str)[:400]
                steps.append({"stage": "tool_call", "detail": f"{name}({inp})"})
            elif "toolResult" in block:
                tr = block["toolResult"]
                status = tr.get("status", "ok")
                preview = json.dumps(tr.get("content", []), default=str)[:400]
                steps.append({"stage": "tool_result", "detail": f"[{status}] {preview}"})
            elif "text" in block and role == "assistant":
                txt = str(block["text"]).strip()
                if txt:
                    steps.append({"stage": "assistant", "detail": txt[:800]})
    return steps


def _run_strands_sync(
    finding: Finding,
    settings: Settings,
    tf_context: str,
    trace_events: list[dict[str, str]] | None = None,
) -> tuple[InvestigationReport, str, list[str]]:
    """Run the Strands Investigation Agent synchronously inside a worker thread."""
    bedrock_region = settings.bedrock_region_for_model(settings.strands_model_id)
    model = BedrockModel(
        model_id=settings.strands_model_id,
        region_name=bedrock_region,
    )
    prompt = build_investigation_prompt(finding, tf_context)

    mcp_names: list[str] = []
    tools: list[Any] = []
    if trace_events is not None:
        trace_events.append({"stage": "init", "detail": f"Initialized BedrockModel {settings.strands_model_id} in {bedrock_region}."})

    with ExitStack() as stack:
        if settings.aws_mcp_enabled:
            mcp_env = build_readonly_mcp_env(settings.aws_region, settings.investigator_role_arn)
            for name, client in _create_aws_mcp_clients(mcp_env):
                try:
                    stack.enter_context(client)
                    mcp_tools = client.list_tools_sync()
                    tools.extend(mcp_tools)
                    mcp_names.append(name)
                    logger.info("Mounted MCP server %s (%d tools).", name, len(mcp_tools))
                    if trace_events is not None:
                        trace_events.append({"stage": "mcp", "detail": f"Mounted {name} ({len(mcp_tools)} tools)."})
                except Exception as exc:
                    logger.warning("Failed to mount MCP server %s: %s", name, exc)
                    if trace_events is not None:
                        trace_events.append({"stage": "mcp_warn", "detail": f"Could not mount {name}: {exc}"})

        agent = Agent(
            model=model,
            tools=tools,
            system_prompt=SYSTEM_PROMPT,
        )
        result = agent(prompt, structured_output_model=InvestigationReport)
        if trace_events is not None:
            trace_events.extend(_summarize_strands_messages(getattr(agent, "messages", [])))
        report = result.structured_output
        if not isinstance(report, InvestigationReport):
            report = InvestigationReport.model_validate(report)
        engine = "strands-bedrock-mcp" if mcp_names else "strands-bedrock"
        return report, engine, mcp_names


async def investigate_finding(
    finding: Finding,
    settings: Settings,
    tf_context: str,
    trace_events: list[dict[str, str]] | None = None,
) -> tuple[InvestigationReport, str, list[str]]:
    """Investigate a drift finding using Strands Agents SDK + official AWS Labs MCP servers."""
    if not has_aws_credentials():
        raise RuntimeError(
            "No AWS credentials detected. Configure AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY "
            "(or attach an ECS Task Role) to run live Strands + AWS MCP investigation."
        )

    return await asyncio.to_thread(_run_strands_sync, finding, settings, tf_context, trace_events)
