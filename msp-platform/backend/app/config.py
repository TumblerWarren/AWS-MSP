"""Application configuration via environment variables (.env) and runtime updates."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv
from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Load .env into os.environ so boto3, Strands BedrockModel, AWS MCP servers,
# and Claude Agent SDK subprocesses immediately see AWS_* variables.
load_dotenv(override=False)

DEFAULT_BEDROCK_MODEL_ID = "au.anthropic.claude-sonnet-4-6"
BEDROCK_MODELS = {
    DEFAULT_BEDROCK_MODEL_ID: ("Claude Sonnet 4.6 · Australia", "ap-southeast-2"),
    "au.anthropic.claude-sonnet-5-5": ("Claude Sonnet 5.5 · Australia", "ap-southeast-2"),
    "in.anthropic.claude-haiku-4-5-20251001-v1:0": ("Claude Haiku 4.5 · India", "ap-south-1"),
}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="MSP_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    database_url: str = "sqlite:///./msp.db"

    # Target IaC repository (GitHub + local path fallback)
    github_repo: str = "TumblerWarren/AWS-MSP"  # owner/repo
    github_token: str = ""
    github_default_branch: str = "master"
    terraform_repositories: dict[str, str] = Field(default_factory=dict)
    terraform_roots: list[str] = Field(default_factory=list)
    local_infra_repo_path: str = "../../msp-sandbox-infra"
    dry_run_github: bool = False
    drift_report_bucket: str = ""

    # AWS credentials (supports static IAM key+secret OR temporary key+secret+session_token)
    aws_region: str = Field(
        default="ap-south-1",
        validation_alias=AliasChoices("MSP_AWS_REGION", "AWS_REGION", "AWS_DEFAULT_REGION"),
    )
    aws_access_key_id: str = Field(
        default="",
        validation_alias=AliasChoices("MSP_AWS_ACCESS_KEY_ID", "AWS_ACCESS_KEY_ID"),
    )
    aws_secret_access_key: str = Field(
        default="",
        validation_alias=AliasChoices("MSP_AWS_SECRET_ACCESS_KEY", "AWS_SECRET_ACCESS_KEY"),
    )
    aws_session_token: str = Field(
        default="",
        validation_alias=AliasChoices("MSP_AWS_SESSION_TOKEN", "AWS_SESSION_TOKEN"),
    )
    investigator_role_arn: str = ""

    # Strands Investigation Agent (AWS Bedrock + AWS Labs MCP servers)
    bedrock_region: str = ""
    strands_model_id: str = DEFAULT_BEDROCK_MODEL_ID
    aws_mcp_enabled: bool = True

    # Claude Agent SDK Patcher (Bedrock or Anthropic API)
    claude_use_bedrock: bool = True
    claude_model: str = DEFAULT_BEDROCK_MODEL_ID

    def bedrock_region_for_model(self, model_id: str) -> str:
        if self.bedrock_region:
            return self.bedrock_region
        if model_id == DEFAULT_BEDROCK_MODEL_ID:
            return BEDROCK_MODELS[DEFAULT_BEDROCK_MODEL_ID][1]
        return self.aws_region

    def resolve_bedrock_model(self, default_id: str, selected_id: str | None) -> tuple[str, str]:
        if selected_id and selected_id in BEDROCK_MODELS:
            return selected_id, BEDROCK_MODELS[selected_id][1]
        return default_id, self.bedrock_region_for_model(default_id)

    @property
    def github_configured(self) -> bool:
        return bool(self.github_repo and self.github_token and not self.dry_run_github)

    @property
    def registered_repositories(self) -> dict[str, str]:
        repos = {repo.lower(): branch for repo, branch in self.terraform_repositories.items()}
        if self.github_repo:
            repos.setdefault(self.github_repo.strip().lower(), self.github_default_branch)
        return repos

    @property
    def resolved_local_infra_path(self) -> Path:
        base = Path(__file__).resolve().parent.parent
        return (base / self.local_infra_repo_path).resolve()

    def sync_aws_env(self) -> None:
        """Propagate configured AWS credentials into os.environ for SDKs and subprocesses."""
        if self.aws_region:
            os.environ["AWS_REGION"] = self.aws_region
            os.environ["AWS_DEFAULT_REGION"] = self.aws_region
        if self.aws_access_key_id and self.aws_secret_access_key:
            os.environ["AWS_ACCESS_KEY_ID"] = self.aws_access_key_id.strip()
            os.environ["AWS_SECRET_ACCESS_KEY"] = self.aws_secret_access_key.strip()
            if self.aws_session_token.strip():
                os.environ["AWS_SESSION_TOKEN"] = self.aws_session_token.strip()
            else:
                # When using a permanent IAM Access Key + Secret without a session token,
                # make sure any stale AWS_SESSION_TOKEN is removed.
                os.environ.pop("AWS_SESSION_TOKEN", None)


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    s.sync_aws_env()
    return s
