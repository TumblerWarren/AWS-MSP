"""Export the three independently deployable sandbox repositories."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[2]
SOURCE = PROJECT / "msp-sandbox-infra" / "infra"
LIFECYCLE_WORKFLOWS = Path(__file__).with_name("split-workflows")


def read(name: str) -> str:
    return (SOURCE / name).read_text(encoding="utf-8")


def blocks(text: str) -> list[str]:
    return [block.strip() for block in text.strip().split("\n}\n")]


def select(text: str, *names: str) -> str:
    result = []
    for block in blocks(text):
        first = block.splitlines()[0]
        if any(first.endswith(f'"{name}" {{') for name in names):
            result.append(block.rstrip("\n}") + "\n}")
    if len(result) != len(names):
        raise ValueError(f"Could not export Terraform definitions for {names}")
    return "\n\n".join(result) + "\n"


def write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")


def export_lifecycle(repo: Path, component: str) -> None:
    for template in LIFECYCLE_WORKFLOWS.glob("*.yml"):
        content = template.read_text(encoding="utf-8")
        content = content.replace("__TARGET_REPOSITORY__", f"msp-{component}")
        content = content.replace("__STATE_KEY__", f"split-sandbox/{component}/terraform.tfstate")
        write(repo / ".github/workflows" / template.name, content)


def export(destination: Path) -> None:
    for component in ("networking", "ec2", "database"):
        repo = destination / f"msp-{component}"
        infra = repo / "infra"
        infra.mkdir(parents=True, exist_ok=False)
        (repo / ".github/workflows").mkdir(parents=True)
        shutil.copytree(PROJECT / "msp-platform/packages/msp_policy/msp_policy", repo / "scripts/msp_policy",
                        ignore=shutil.ignore_patterns("__pycache__"))
        for workflow in ("drift-check.yml", "restore.yml", "pr-plan.yml"):
            content = (PROJECT / ".github/workflows" / workflow).read_text(encoding="utf-8")
            content = content.replace('      - "msp-sandbox-infra/infra/**"\n', "")
            content = content.replace("msp-sandbox-infra/infra", "infra").replace("/msp-sandbox-infra/scripts", "/scripts")
            write(repo / ".github/workflows" / workflow, content)
        export_lifecycle(repo, component)
        write(repo / ".gitignore", ".terraform/\n*.tfstate*\n*.tfplan\n*.tfvars\n*.tfvars.json\n__pycache__/\n*.raw.json\nout/\n")
        versions = read("versions.tf").replace("sandbox/terraform.tfstate", f"split-sandbox/{component}/terraform.tfstate")
        write(infra / "versions.tf", versions.replace('"msp-sandbox-infra"', f'"msp-{component}"'))
        common = ("aws_region", "project_name", "environment")
        if component == "networking":
            write(infra / "network.tf", read("network.tf"))
            write(infra / "security_groups.tf", read("security_groups.tf"))
            names = common + ("vpc_cidr", "allowed_app_cidr")
            outputs = ("vpc_id", "public_subnet_id", "private_subnet_ids", "app_security_group_id", "rds_security_group_id")
        else:
            is_ec2 = component == "ec2"
            names = common + (("ec2_instance_type",) if is_ec2 else ("rds_instance_class", "rds_backup_retention_period"))
            outputs = ("ec2_instance_id",) if is_ec2 else ("rds_instance_id", "rds_endpoint")
            original = read("compute_and_rds.tf")
            resources = original.split('resource "aws_db_subnet_group"', 1)
            compute = resources[0].strip() + "\n" if is_ec2 else 'resource "aws_db_subnet_group"' + resources[1]
            for name in ("private_a", "private_b"):
                compute = compute.replace(f"aws_subnet.{name}.id", f"data.aws_subnet.{name}.id")
            for name in ("app", "rds"):
                compute = compute.replace(f"aws_security_group.{name}.id", f"data.aws_security_group.{name}.id")
            write(infra / f"{component}.tf", compute)
            write(infra / "network.tf", network_lookups(is_ec2))
        write(infra / "variables.tf", select(read("variables.tf"), *names).replace('"msp-sandbox"', '"msp-split-sandbox"'))
        write(infra / "outputs.tf", select(read("outputs.tf"), *outputs))
        write(repo / "README.md", repository_readme(component))


def network_lookups(is_ec2: bool) -> str:
    parts = ['''data "aws_vpc" "network" {
  tags = { Name = "${var.project_name}-vpc" }
}''']
    for name in (("private_a",) if is_ec2 else ("private_a", "private_b")):
        parts.append(f'''data "aws_subnet" "{name}" {{
  vpc_id = data.aws_vpc.network.id
  tags   = {{ Name = "${{var.project_name}}-{name.replace('_', '-')}" }}
}}''')
    group = "app" if is_ec2 else "rds"
    parts.append(f'''data "aws_security_group" "{group}" {{
  vpc_id = data.aws_vpc.network.id
  name   = "${{var.project_name}}-{group}-sg"
}}''')
    return "\n\n".join(parts) + "\n"


def repository_readme(component: str) -> str:
    return f'''# MSP {component.capitalize()} sandbox

Terraform root: `infra/`. State key: `split-sandbox/{component}/terraform.tfstate`.

Use the same AWS account, region, and `project_name` across the three split sandbox repositories. Deploy networking first. EC2 and database look up only the named networking resources in the VPC.

Use **Deploy Sandbox Infrastructure** in GitHub Actions to provision a new sandbox. These roots use a new state key and the `msp-split-sandbox` resource name prefix. Migrating an existing sandbox requires a separate reviewed state move/import.

Set the repository variables `AWS_ACCOUNT_ID`, `TF_STATE_BUCKET`, and `AWS_REGION`, and configure CI AWS credentials. Create a protected `sandbox` GitHub environment, restrict it to `main`, and verify that it enforces human approval before setting `MSP_ENABLE_LIFECYCLE=true` or `MSP_ENABLE_RESTORE=true`. Drift Check publishes redacted reports to the MSP S3 bucket.

Use **Destroy Sandbox Infrastructure** on `main` with the exact confirmation `destroy msp-{component}`. Destroy EC2 and database before networking. The lifecycle workflows use this repository’s state key and check the configured AWS account before running Terraform.
'''


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    export(parser.parse_args().destination)
