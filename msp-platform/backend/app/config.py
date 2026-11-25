"""Application configuration via environment variables (.env)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="MSP_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    database_url: str = "sqlite:///./msp.db"

    # Target IaC repository (GitHub + local path fallback)
    github_repo: str = "TumblerWarren/AWS-MSP"  # owner/repo
    github_token: str = ""
    github_default_branch: str = "master"
    local_infra_repo_path: str = "../../msp-sandbox-infra"
    dry_run_github: bool = False

    # AWS & read-only investigator role
    aws_region: str = "ap-south-1"
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


@lru_cache
def get_settings() -> Settings:
    return Settings()
