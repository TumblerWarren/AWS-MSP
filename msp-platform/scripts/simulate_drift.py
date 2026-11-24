"""Introduce realistic out-of-band drift in the sandbox AWS account for MVP testing.

Usage:
    uv run python scripts/simulate_drift.py sg-open-ssh --sg-id sg-0123456789abcdef0
    uv run python scripts/simulate_drift.py ec2-tag --instance-id i-0123456789abcdef0
    uv run python scripts/simulate_drift.py rds-retention --db-id msp-sandbox-postgres --days 7
"""

from __future__ import annotations

import argparse
import sys

import boto3


def sg_open_ssh(sg_id: str, region: str) -> None:
    ec2 = boto3.client("ec2", region_name=region)
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "Emergency SSH debug"}],
            }
        ],
    )
    print(f"Opened TCP/22 to 0.0.0.0/0 on {sg_id} in {region}.")


def ec2_tag(instance_id: str, region: str, key: str, value: str) -> None:
    ec2 = boto3.client("ec2", region_name=region)
    ec2.create_tags(Resources=[instance_id], Tags=[{"Key": key, "Value": value}])
    print(f"Set tag {key}={value} on {instance_id} in {region}.")


def rds_retention(db_id: str, region: str, days: int) -> None:
    rds = boto3.client("rds", region_name=region)
    rds.modify_db_instance(
        DBInstanceIdentifier=db_id,
        BackupRetentionPeriod=days,
        ApplyImmediately=True,
    )
    print(f"Modified backup_retention_period={days} on {db_id} in {region}.")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Introduce sandbox drift for MSP MVP testing.")
    p.add_argument("--region", default="us-east-1")
    sub = p.add_subparsers(dest="scenario", required=True)

    s1 = sub.add_parser("sg-open-ssh", help="Open SSH 0.0.0.0/0 on the app security group")
    s1.add_argument("--sg-id", required=True)

    s2 = sub.add_parser("ec2-tag", help="Mutate a tag on the sandbox EC2 instance")
    s2.add_argument("--instance-id", required=True)
    s2.add_argument("--key", default="Owner")
    s2.add_argument("--value", default="payments-oncall")

    s3 = sub.add_parser("rds-retention", help="Change RDS backup retention period")
    s3.add_argument("--db-id", required=True)
    s3.add_argument("--days", type=int, default=7)

    args = p.parse_args(argv)
    if args.scenario == "sg-open-ssh":
        sg_open_ssh(args.sg_id, args.region)
    elif args.scenario == "ec2-tag":
        ec2_tag(args.instance_id, args.region, args.key, args.value)
    elif args.scenario == "rds-retention":
        rds_retention(args.db_id, args.region, args.days)
    return 0


if __name__ == "__main__":
    sys.exit(main())
