import type { FindingDetail, FindingSummary, PlatformConfig, Remediation } from "./types";

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
  listFindings: () => req<FindingSummary[]>("/api/findings"),
  getFinding: (id: string) => req<FindingDetail>(`/api/findings/${id}`),
  seedDemo: () => req<{ created: number; findings: FindingSummary[] }>("/api/demo/seed", { method: "POST" }),
  triggerScan: () => req<{ mode: string; correlation_id: string; message: string }>("/api/scans/trigger", {
    method: "POST",
    body: JSON.stringify({}),
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
