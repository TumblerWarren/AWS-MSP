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
