"""AWS credential and STS session helper.

Supports three credential modes out of the box:
1. IAM Access Key + Secret Key (`AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY`)
2. Temporary STS Session Credentials (`AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` + `AWS_SESSION_TOKEN`)
3. Standard AWS credential chain (env vars, `~/.aws/credentials`, instance/ECS task role)

When `MSP_INVESTIGATOR_ROLE_ARN` is set, assumes that read-only IAM role via STS so
the AWS Labs MCP server subprocesses run strictly under read-only permissions.
"""

from __future__ import annotations

import logging
import os

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

logger = logging.getLogger(__name__)


def has_aws_credentials() -> bool:
    """Return True if boto3 can resolve AWS credentials (static key, temp session, or profile/role)."""
    try:
        session = boto3.Session(
            aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID") or None,
            aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY") or None,
            aws_session_token=os.environ.get("AWS_SESSION_TOKEN") or None,
            region_name=os.environ.get("AWS_REGION") or "ap-south-1",
        )
        creds = session.get_credentials()
        if creds is None:
            return False
        frozen = creds.get_frozen_credentials()
        return bool(frozen and frozen.access_key and frozen.secret_key)
    except Exception:
        return False


def aws_credential_mode() -> str:
    """Return 'temporary_session', 'access_key', 'ambient_profile', or 'none'."""
    ak = os.environ.get("AWS_ACCESS_KEY_ID", "").strip()
    sk = os.environ.get("AWS_SECRET_ACCESS_KEY", "").strip()
    st = os.environ.get("AWS_SESSION_TOKEN", "").strip()
    if ak and sk:
        return "temporary_session" if st else "access_key"
    if has_aws_credentials():
        return "ambient_profile"
    return "none"


def build_readonly_mcp_env(region: str, role_arn: str) -> dict[str, str]:
    """Return environment variables for AWS Labs MCP servers.

    Always sets `READ_OPERATIONS_ONLY=true`. If `role_arn` is set, assumes that
    read-only IAM role via STS using the active credentials (static key or temp session).
    """
    env = dict(os.environ)
    env["AWS_REGION"] = region
    env["AWS_DEFAULT_REGION"] = region
    env["READ_OPERATIONS_ONLY"] = "true"
    env["FASTMCP_LOG_LEVEL"] = "ERROR"

    # Strip empty AWS_SESSION_TOKEN so boto3 inside MCP servers never sends an empty header
    if not env.get("AWS_SESSION_TOKEN", "").strip():
        env.pop("AWS_SESSION_TOKEN", None)

    if not role_arn:
        return env

    try:
        sts = boto3.client(
            "sts",
            region_name=region,
            aws_access_key_id=env.get("AWS_ACCESS_KEY_ID") or None,
            aws_secret_access_key=env.get("AWS_SECRET_ACCESS_KEY") or None,
            aws_session_token=env.get("AWS_SESSION_TOKEN") or None,
        )
        resp = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="msp-drift-investigator",
            DurationSeconds=900,
        )
        creds = resp["Credentials"]
        env["AWS_ACCESS_KEY_ID"] = creds["AccessKeyId"]
        env["AWS_SECRET_ACCESS_KEY"] = creds["SecretAccessKey"]
        env["AWS_SESSION_TOKEN"] = creds["SessionToken"]
        env.pop("AWS_PROFILE", None)
        logger.info("Assumed read-only investigator role %s for MCP subprocesses.", role_arn)
    except (NoCredentialsError, ClientError, BotoCoreError) as exc:
        logger.warning(
            "Could not assume investigator role %s (%s); continuing with READ_OPERATIONS_ONLY=true.",
            role_arn,
            exc,
        )

    return env
