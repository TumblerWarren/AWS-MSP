# MSP — AWS AI Infrastructure Drift Investigation & Reconciliation Platform (MVP 1)

Two repositories live in this workspace, ready to be pushed to GitHub when you are ready:

| Directory | Role |
|---|---|
| [`msp-sandbox-infra/`](./msp-sandbox-infra) | **Infrastructure deployment repo** — Sandbox Terraform (VPC, Subnets, Security Groups, EC2, RDS), AWS bootstrap (state bucket + GitHub OIDC role), vendored `msp_policy`, and GitHub Actions workflows (`drift-check.yml`, `restore.yml`, `pr-plan.yml`). |
| [`msp-platform/`](./msp-platform) | **Application + application-infra repo** — Shared `msp_policy` safety core, platform IAM Terraform (`msp-investigator-readonly` role), FastAPI backend, **AWS Strands** Investigation Agent (with official AWS Labs MCP servers), **Claude Agent SDK** Terraform Patcher, and Greptile-style React UI. |

## Quick Start (Local — Zero AWS/GitHub Needed First)

### 1. Run the Backend
```powershell
cd msp-platform\backend
uv run uvicorn app.main:app --reload --port 8000
```

### 2. Run the Frontend
```powershell
cd msp-platform\frontend
npm run dev
```
Open `http://localhost:5173`, click **Load Demo Drift**, run **Investigate with AI**, and exercise both **Restore AWS** and **Update Terraform** + **Verify**.

### 3. Run the Automated Test Suite
```powershell
cd msp-platform\backend
uv run pytest
```

## Connecting Real AWS & GitHub (When Ready)
1. Push `msp-sandbox-infra/` to a GitHub repo (`<owner>/msp-sandbox-infra`).
2. With temporary AWS IAM keys configured on your machine:
   - Run `terraform apply` in `msp-sandbox-infra/bootstrap` (`-var="github_repo=<owner>/msp-sandbox-infra"`).
   - Run `terraform apply` in `msp-platform/infra` (`-var="state_bucket_arn=<state_bucket_arn>"`) to create the read-only `msp-investigator-readonly` IAM role.
   - Add GitHub repo secrets/vars (`AWS_CI_ROLE_ARN`, `TF_STATE_BUCKET`, `AWS_REGION`) and create a `sandbox` GitHub Environment with yourself as required reviewer.
   - Run `terraform apply` in `msp-sandbox-infra/infra` (`-backend-config="bucket=<state_bucket_name>"`).
3. Copy `msp-platform/backend/.env.example` to `.env` and fill in `MSP_GITHUB_REPO`, `MSP_GITHUB_TOKEN`, and `MSP_INVESTIGATOR_ROLE_ARN`.
4. Introduce real out-of-band drift with:
   ```powershell
   uv --directory msp-platform/backend run python ..\scripts\simulate_drift.py sg-open-ssh --sg-id <sg-id>
   ```
5. Tear down sandbox resources when done to avoid ongoing EC2/RDS charges:
   ```powershell
   powershell -ExecutionPolicy Bypass -File msp-platform\scripts\destroy.ps1 -StateBucket <state_bucket_name>
   ```
