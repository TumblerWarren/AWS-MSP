import type { FindingDetail, FindingSummary, ModelPreferences, PlatformConfig, Remediation } from "./types";

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
    ...init,
  });
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      if (body?.detail) detail = typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail);
    } catch {
      // ignore non-json
    }
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

export const api = {
  config: () => req<PlatformConfig>("/api/config"),
  updateModels: (preferences: ModelPreferences) => req<PlatformConfig>("/api/config/models", {
    method: "PUT",
    body: JSON.stringify(preferences),
  }),
  updateCredentials: (payload: {
    aws_access_key_id?: string;
    aws_secret_access_key?: string;
    aws_session_token?: string;
    aws_region?: string;
    investigator_role_arn?: string;
    github_repo?: string;
    github_token?: string;
  }) =>
    req<PlatformConfig>("/api/config/credentials", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  listFindings: () => req<FindingSummary[]>("/api/findings"),
  getFinding: (id: string) => req<FindingDetail>(`/api/findings/${id}`),
  triggerScan: () => req<{ mode: string; correlation_id: string; message: string }>("/api/scans/trigger", {
    method: "POST",
    body: JSON.stringify({}),
  }),
  syncGitHub: () => req<{ synced: boolean; run_id: number; run_url?: string; message: string; findings: FindingSummary[] }>("/api/scans/sync", {
    method: "POST",
  }),
  investigate: (id: string) =>
    req<FindingDetail>(`/api/findings/${id}/investigate`, { method: "POST" }),
  remediateRestore: (id: string, payload: { decided_by: string; rationale: string; expected_fingerprint: string }) =>
    req<FindingDetail>(`/api/findings/${id}/remediate/restore`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  remediateUpdateTerraform: (
    id: string,
    payload: { decided_by: string; rationale: string; expected_fingerprint: string; extra_instructions?: string }
  ) =>
    req<FindingDetail>(`/api/findings/${id}/remediate/update-terraform`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  verify: (id: string, simulateClean = false) =>
    req<FindingDetail>(`/api/findings/${id}/verify`, {
      method: "POST",
      body: JSON.stringify(
        simulateClean
          ? { plan: { format_version: "1.2", terraform_version: "1.10.5", resource_drift: [], resource_changes: [], errored: false } }
          : {}
      ),
    }),
  refreshRemediation: (remId: string) => req<Remediation>(`/api/remediations/${remId}/refresh`),
};
