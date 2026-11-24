"""AWS STS session helper for scoping AI investigator MCP servers to read-only credentials.

Your temporary IAM access keys on this machine are used ONLY to assume the
`msp-investigator-readonly` role (which has ReadOnlyAccess + explicit DENY on
Secrets Manager, SSM Parameter Store, KMS Decrypt, and the Terraform state bucket).
"""

from __future__ import annotations

import logging
import os

import boto3
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

logger = logging.getLogger(__name__)


def has_aws_credentials() -> bool:
    """Return True if boto3 can find AWS credentials in the current environment."""
    try:
        session = boto3.Session()
        creds = session.get_credentials()
        return creds is not None and creds.get_frozen_credentials().access_key is not None
    except Exception:
        return False


def build_readonly_mcp_env(region: str, role_arn: str) -> dict[str, str]:
    """Return environment variables for AWS Labs MCP servers.

    If `role_arn` is set, assumes that read-only IAM role via STS so the MCP
    server subprocesses physically cannot run mutating API calls or read secrets/state.
    """
    env = dict(os.environ)
    env["AWS_REGION"] = region
    env["AWS_DEFAULT_REGION"] = region
    env["READ_OPERATIONS_ONLY"] = "true"
    env["FASTMCP_LOG_LEVEL"] = "ERROR"

    if not role_arn:
        return env

    try:
        sts = boto3.client("sts", region_name=region)
        resp = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="msp-drift-investigator",
            DurationSeconds=900,
        )
        creds = resp["Credentials"]
        env["AWS_ACCESS_KEY_ID"] = creds["AccessKeyId"]
        env["AWS_SECRET_ACCESS_KEY"] = creds["SecretAccessKey"]
        env["AWS_SESSION_TOKEN"] = creds["SessionToken"]
        # Clear profile overrides so the assumed session credentials are strictly used.
        env.pop("AWS_PROFILE", None)
        logger.info("Assumed read-only investigator role %s for MCP subprocesses.", role_arn)
    except (NoCredentialsError, ClientError, BotoCoreError) as exc:
        logger.warning("Could not assume investigator role %s: %s", role_arn, exc)
        raise

    return env
