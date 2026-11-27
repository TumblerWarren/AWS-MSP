export interface AttrChange {
  path: string;
  before: unknown;
  after: unknown;
  added: unknown[];
  removed: unknown[];
}

export interface EvidenceItem {
  source: string;
  timestamp: string | null;
  summary: string;
  raw_ref: string | null;
}

export interface ImpactedResource {
  resource_id: string;
  resource_type: string;
  relationship: string;
  risk: "low" | "medium" | "high" | "critical";
}

export interface InvestigationReport {
  headline: string;
  severity: "low" | "medium" | "high" | "critical";
  summary: string;
  root_cause: string;
  actor: string;
  event_time: string | null;
  event_name: string | null;
  blast_radius_summary: string;
  impacted_resources: ImpactedResource[];
  recommended_action: "restore" | "update_terraform" | "needs_review";
  recommendation_rationale: string;
  confidence: number;
  evidence_timeline: EvidenceItem[];
  open_questions: string[];
}

export interface Investigation {
  id: string;
  finding_id: string;
  status: string;
  engine: string;
  model_id: string;
  mcp_servers: string[];
  report: InvestigationReport | null;
  error: string | null;
  created_at: string;
  completed_at: string | null;
}

export interface PolicyCheck {
  id: string;
  status: "pass" | "fail" | "warn";
  message: string;
  addresses: string[];
}

export interface PolicyResult {
  decision: "allow" | "block";
  mode: string;
  allowed_addresses: string[];
  checks: PolicyCheck[];
  summary: Record<string, number>;
  evaluated_at: string;
}

export interface Remediation {
  id: string;
  finding_id: string;
  direction: "restore" | "update_terraform";
  status: string;
  decided_by: string;
  rationale: string;
  bound_fingerprint: string;
  bound_drift_hash: string;
  correlation_id: string;
  github_run_id: number | null;
  github_run_url: string | null;
  pr_number: number | null;
  pr_url: string | null;
  branch_name: string | null;
  patch_summary: string | null;
  patch_diff: string | null;
  policy_result: PolicyResult | null;
  error: string | null;
  created_at: string;
  updated_at: string;
}

export interface AuditEvent {
  id: string;
  finding_id: string;
  event_type: string;
  actor: string;
  summary: string;
  details: Record<string, unknown>;
  created_at: string;
}

export interface FindingSummary {
  id: string;
  address: string;
  resource_type: string;
  resource_name: string;
  resource_id: string | null;
  drift_kind: string;
  severity: "low" | "medium" | "high" | "critical";
  status: string;
  account_id: string;
  region: string;
  repo: string;
  root_dir: string;
  commit_sha: string | null;
  state_serial: number | null;
  drift_hash: string;
  fingerprint: string;
  changes: AttrChange[];
  restore_actions: string[];
  created_at: string;
  updated_at: string;
  latest_investigation: Investigation | null;
  latest_remediation: Remediation | null;
}

export interface FindingDetail extends FindingSummary {
  redacted_plan: Record<string, unknown>;
  investigations: Investigation[];
  remediations: Remediation[];
  audit_events: AuditEvent[];
}

export interface ModelPreferences {
  investigation: string | null;
  patcher: string | null;
}

export interface PlatformConfig {
  github_configured: boolean;
  github_repo: string;
  aws_region: string;
  aws_credentials_detected: boolean;
  aws_credential_mode?: string;
  investigator_role_configured: boolean;
  investigator_role_arn?: string;
  strands_model_id: string;
  claude_model: string;
  claude_use_bedrock: boolean;
  model_preferences: ModelPreferences;
  bedrock_models: { id: string; label: string }[];
  aws_mcp_enabled: boolean;
}
