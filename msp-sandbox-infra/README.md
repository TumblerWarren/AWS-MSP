# msp-sandbox-infra

Customer/sandbox AWS infrastructure repository managed by Terraform and monitored by **msp-platform**.

## Resources
- **VPC + Subnets**: 1 public subnet, 2 private subnets, IGW & public route table (`infra/network.tf`)
- **Security Groups**: `app-sg` (HTTPS from VPC CIDR) and `rds-sg` (PostgreSQL 5432 from `app-sg`) (`infra/security_groups.tf`)
- **Compute**: `t3.micro` EC2 instance attached to `app-sg` (`infra/compute_and_rds.tf`)
- **Database**: `db.t4g.micro` PostgreSQL RDS instance attached to `rds-sg` with RDS-managed Secrets Manager password (`infra/compute_and_rds.tf`)

## One-time Setup
1. Bootstrap state bucket & GitHub OIDC CI role (using temporary AWS IAM credentials):
   ```powershell
   cd bootstrap
   terraform init
   terraform apply -var="github_repo=<owner>/msp-sandbox-infra"
   ```
2. Configure GitHub repository settings:
   - **Secret** `AWS_CI_ROLE_ARN` = `ci_role_arn` output from bootstrap
   - **Variable** `TF_STATE_BUCKET` = `state_bucket_name` output from bootstrap
   - **Variable** `AWS_REGION` = `us-east-1`
   - **Environment** `sandbox` with yourself as a required reviewer (gates `restore.yml` apply)
3. Deploy initial sandbox infrastructure:
   ```powershell
   cd ../infra
   terraform init -backend-config="bucket=<state_bucket_name>"
   terraform apply
   ```

## Workflows
- `drift-check.yml` — Runs `terraform plan -refresh-only -json`, redacts sensitive values via `scripts/msp_policy`, and uploads a redacted artifact.
- `restore.yml` — Runs `terraform plan`, evaluates the deterministic `msp_policy` gate (`restore` mode), pauses for `sandbox` environment human approval, and applies the saved plan.
- `pr-plan.yml` — Runs on PRs touching `infra/**`. For `msp/drift-fix-*` branches, enforces `update` mode (plan must show 0 changes, proving code matches live AWS).
