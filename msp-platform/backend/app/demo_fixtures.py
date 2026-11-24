"""Realistic Terraform plan JSON fixtures for local demo & automated testing.

Covers the three core MVP scenarios:
1. Security Group drift: port 22 opened to 0.0.0.0/0 on aws_security_group.app
2. EC2 drift: Owner tag modified out-of-band on aws_instance.app
3. RDS drift: backup_retention_period modified on aws_db_instance.main (plus a
   negative-safety fixture where an RDS replace is attempted and must be blocked)
"""

from __future__ import annotations

from typing import Any


def sg_ssh_drift_plan() -> dict[str, Any]:
    before_ingress = [
        {
            "cidr_blocks": ["10.42.0.0/16"],
            "description": "Internal HTTPS traffic",
            "from_port": 443,
            "ipv6_cidr_blocks": [],
            "prefix_list_ids": [],
            "protocol": "tcp",
            "security_groups": [],
            "self": False,
            "to_port": 443,
        }
    ]
    after_ingress = before_ingress + [
        {
            "cidr_blocks": ["0.0.0.0/0"],
            "description": "Emergency SSH debug",
            "from_port": 22,
            "ipv6_cidr_blocks": [],
            "prefix_list_ids": [],
            "protocol": "tcp",
            "security_groups": [],
            "self": False,
            "to_port": 22,
        }
    ]
    base = {
        "id": "sg-0a1b2c3d4e5f67890",
        "name": "msp-sandbox-app-sg",
        "vpc_id": "vpc-0abc12345def67890",
        "description": "Application tier security group (strict internal HTTPS only)",
        "tags": {"Name": "msp-sandbox-app-sg", "Tier": "application"},
    }
    return {
        "format_version": "1.2",
        "terraform_version": "1.10.5",
        "prior_state": {
            "values": {"root_module": {"resources": [{"values": {"password": "SUPER_SECRET_DB_PASSWORD_123"}}]}}
        },
        "resource_drift": [
            {
                "address": "aws_security_group.app",
                "mode": "managed",
                "type": "aws_security_group",
                "name": "app",
                "change": {
                    "actions": ["update"],
                    "before": {**base, "ingress": before_ingress},
                    "after": {**base, "ingress": after_ingress},
                    "before_sensitive": {},
                    "after_sensitive": {},
                },
            }
        ],
        "resource_changes": [
            {
                "address": "aws_security_group.app",
                "mode": "managed",
                "type": "aws_security_group",
                "name": "app",
                "change": {
                    "actions": ["update"],
                    "before": {**base, "ingress": after_ingress},
                    "after": {**base, "ingress": before_ingress},
                    "before_sensitive": {},
                    "after_sensitive": {},
                },
            }
        ],
        "applyable": True,
        "complete": True,
        "errored": False,
    }


def ec2_tag_drift_plan() -> dict[str, Any]:
    base = {
        "id": "i-0f9e8d7c6b5a43210",
        "instance_type": "t3.micro",
        "subnet_id": "subnet-01122334455667788",
        "vpc_security_group_ids": ["sg-0a1b2c3d4e5f67890"],
        "user_data": "sensitive-bootstrap-token-xyz",
    }
    before_tags = {"Name": "msp-sandbox-app-ec2", "Service": "orders-api", "Owner": "platform-team"}
    after_tags = {"Name": "msp-sandbox-app-ec2", "Service": "orders-api", "Owner": "payments-oncall"}
    return {
        "format_version": "1.2",
        "terraform_version": "1.10.5",
        "resource_drift": [
            {
                "address": "aws_instance.app",
                "mode": "managed",
                "type": "aws_instance",
                "name": "app",
                "change": {
                    "actions": ["update"],
                    "before": {**base, "tags": before_tags, "tags_all": before_tags},
                    "after": {**base, "tags": after_tags, "tags_all": after_tags},
                    "before_sensitive": {"user_data": True},
                    "after_sensitive": {"user_data": True},
                },
            }
        ],
        "resource_changes": [
            {
                "address": "aws_instance.app",
                "mode": "managed",
                "type": "aws_instance",
                "name": "app",
                "change": {
                    "actions": ["update"],
                    "before": {**base, "tags": after_tags, "tags_all": after_tags},
                    "after": {**base, "tags": before_tags, "tags_all": before_tags},
                    "before_sensitive": {"user_data": True},
                    "after_sensitive": {"user_data": True},
                },
            }
        ],
        "applyable": True,
        "complete": True,
        "errored": False,
    }


def rds_retention_drift_plan() -> dict[str, Any]:
    base = {
        "id": "msp-sandbox-postgres",
        "engine": "postgres",
        "engine_version": "16.4",
        "instance_class": "db.t4g.micro",
        "vpc_security_group_ids": ["sg-0987654321fedcba0"],
        "username": "mspadmin",
        "password": "SHOULD_ALWAYS_BE_REDACTED",
        "manage_master_user_password": True,
    }
    return {
        "format_version": "1.2",
        "terraform_version": "1.10.5",
        "resource_drift": [
            {
                "address": "aws_db_instance.main",
                "mode": "managed",
                "type": "aws_db_instance",
                "name": "main",
                "change": {
                    "actions": ["update"],
                    "before": {**base, "backup_retention_period": 1, "latest_restorable_time": "2026-11-22T10:00:00Z"},
                    "after": {**base, "backup_retention_period": 7, "latest_restorable_time": "2026-11-22T11:00:00Z"},
                    "before_sensitive": {"password": True},
                    "after_sensitive": {"password": True},
                },
            }
        ],
        "resource_changes": [
            {
                "address": "aws_db_instance.main",
                "mode": "managed",
                "type": "aws_db_instance",
                "name": "main",
                "change": {
                    "actions": ["update"],
                    "before": {**base, "backup_retention_period": 7},
                    "after": {**base, "backup_retention_period": 1},
                    "before_sensitive": {"password": True},
                    "after_sensitive": {"password": True},
                },
            }
        ],
        "applyable": True,
        "complete": True,
        "errored": False,
    }


def combined_demo_plan() -> dict[str, Any]:
    sg = sg_ssh_drift_plan()
    ec2 = ec2_tag_drift_plan()
    rds = rds_retention_drift_plan()
    return {
        "format_version": "1.2",
        "terraform_version": "1.10.5",
        "prior_state": sg["prior_state"],
        "resource_drift": sg["resource_drift"] + ec2["resource_drift"] + rds["resource_drift"],
        "resource_changes": sg["resource_changes"] + ec2["resource_changes"] + rds["resource_changes"],
        "applyable": True,
        "complete": True,
        "errored": False,
    }


def clean_plan() -> dict[str, Any]:
    return {
        "format_version": "1.2",
        "terraform_version": "1.10.5",
        "resource_drift": [],
        "resource_changes": [],
        "applyable": True,
        "complete": True,
        "errored": False,
    }
