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
    local_infra_repo_path: str = "../../msp-sandbox-infra"
    dry_run_github: bool = False

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
    strands_model_id: str = "apac.anthropic.claude-sonnet-4-20250514-v1:0"
    aws_mcp_enabled: bool = True

    # Claude Agent SDK Patcher (Bedrock or Anthropic API)
    claude_use_bedrock: bool = True
    claude_model: str = "apac.anthropic.claude-sonnet-4-20250514-v1:0"

    @property
    def github_configured(self) -> bool:
        return bool(self.github_repo and self.github_token and not self.dry_run_github)

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
