# msp-platform

Application repository for the AWS AI Infrastructure Drift Investigation & Reconciliation Platform (MVP 1).

## Structure
- `packages/msp_policy/` — Stdlib-only deterministic Terraform plan parser, redactor, evidence fingerprinter, and remediation policy gate. Vendored into `msp-sandbox-infra/scripts/msp_policy` via `scripts/sync_policy_vendor.ps1`.
- `infra/` — Application infrastructure Terraform: creates the `msp-investigator-readonly` IAM role (`ReadOnlyAccess` + `AWSCloudTrail_ReadOnlyAccess` + Bedrock inference + explicit **Deny** on Secrets Manager, SSM Parameter Store, KMS Decrypt, and the Terraform state S3 bucket).
- `backend/` — FastAPI + SQLModel (SQLite) backend:
  - `app/agents/investigator.py` — **AWS Strands Agents SDK** (`BedrockModel`) mounting official AWS Labs MCP servers (`awslabs.aws-api-mcp-server` in `READ_OPERATIONS_ONLY=true` mode + `awslabs.cloudtrail-mcp-server`) under the read-only STS role. Zero custom agent loop or brittle tool glue.
  - `app/agents/patcher.py` — **Claude Agent SDK** (`claude-agent-sdk`) operating natively on an isolated temporary clone of the Terraform repo using its built-in file tools (`Read`, `Edit`, `Write`, `Glob`, `Grep`) to produce minimal HCL patches for `Update Terraform` PRs.
  - `app/services/orchestrator.py` — End-to-end orchestration: drift ingestion, investigation, fingerprint-bound decisions (`restore` vs `update_terraform`), deterministic policy checks, verification, and audit logging.
- `frontend/` — React + TypeScript + Vite + Tailwind dark developer UI.
- `scripts/` — `simulate_drift.py`, `sync_policy_vendor.ps1`, `destroy.ps1`.

## Drift reports in S3

The Drift Check workflow writes its redacted plan, metadata, and drift summary as one JSON object under `drift-reports/<owner>/<repo>/<run-id>/<attempt>.json`. The platform stack creates a private, encrypted report bucket with a 14-day expiration policy. The ECS task role reads these reports when you click **Sync GitHub**. Older GitHub reports can still be imported while their artifacts are available.

When deploying with the bootstrap OIDC role, apply the updated sandbox bootstrap stack to grant the CI role access to the report bucket. If CI uses AWS access keys, grant their IAM principal the report bucket permissions defined in the bootstrap policy. Run **Deploy Platform AWS Infrastructure** with `host_on_aws_fargate=true` for ECS, using the same AWS account and region as Drift Check. The deploy summary shows the bucket name. Local backend or Docker Compose users can set `MSP_DRIFT_REPORT_BUCKET` in `backend/.env` and use AWS credentials with report read access.

Back up or remove any retained reports before destroying the platform stack. Terraform protects the report bucket from deletion while it contains objects.

## Bedrock model routing

The default `au.anthropic.claude-sonnet-4-6` profile uses Sydney as its Bedrock endpoint and can process requests in Sydney or Melbourne. AWS and CloudTrail tools continue using the platform AWS region. For a custom model, the app uses the platform AWS region unless you set `MSP_BEDROCK_REGION` locally or the platform Terraform `bedrock_region` variable for ECS.

## Repository and workspace restores

**Run Drift Scan** and **Sync GitHub** operate on the registered Terraform repositories. In the Drift Inbox, open a finding and choose **Review workspace restore** to select all the resources you want in one workspace plan. An unselected proposed change blocks the request. GitHub Actions generates the full plan, validates the reviewed account, root, revision, state lineage, state serial, and drift, then displays the proposed actions before deployment approval. **Refresh restore status** reads the apply and independent verification jobs before closing findings.

The first release handles batch **Restore AWS**. **Update Terraform** opens a PR in the finding's repository and continues to require a clean candidate plan. Each registered repository uses one preconfigured Terraform root and state per deployment branch. Workspaces sharing a repository need their own workflow routing before they can be restored independently.

The three split sandbox roots use their own backend keys under `split-sandbox/` and a new `msp-split-sandbox` resource name prefix. Networking owns the VPC, subnets, and security groups. EC2 and database look up the networking resources by name. Run **Deploy Sandbox Infrastructure** for networking first, then EC2 and database. Run **Destroy Sandbox Infrastructure** in reverse dependency order, with the exact confirmation `destroy <repository-name>`. Moving the existing monolithic resources would require a separate state migration with reviewed plans.

### Enable the split repositories

1. Grant each repository's AWS CI identity access to its own Terraform state, its drift report S3 path, and the restore-plan path. The sandbox bootstrap accepts `additional_github_repositories` if you use the shared sandbox role. Configure `AWS_CI_ROLE_ARN`, `AWS_ACCOUNT_ID`, `TF_STATE_BUCKET`, and `AWS_REGION` on the Terraform repositories. Configure the protected `sandbox` environments and verify human approval before setting `MSP_ENABLE_LIFECYCLE=true` for deploy and destroy or `MSP_ENABLE_RESTORE=true` for restore apply.
2. Set the platform repository variable `MSP_TERRAFORM_REPOSITORIES` to `{"TumblerWarren/msp-networking":"main","TumblerWarren/msp-ec2":"main","TumblerWarren/msp-database":"main"}` and deploy the updated platform stack. Give `MSP_GITHUB_PAT` access to the repos it needs to scan and restore. For a local backend, use the same JSON in `MSP_TERRAFORM_REPOSITORIES`.
3. Run and sync a fresh scan before requesting a restore. The plan/apply workflow uses a saved binary plan in private S3 for at most one day, verifies its checksum, and compares the live plan again after approval. The app reads only redacted S3 reports. The existing sandbox repository remains registered through `MSP_GITHUB_REPO`.

To regenerate the starter repositories locally, run `python msp-platform/scripts/export_split_repos.py <empty-destination>` from the platform repository.
