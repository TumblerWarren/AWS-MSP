import { useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock,
  ExternalLink,
  GitPullRequest,
  History,
  Loader2,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  User,
  Wrench,
  XCircle,
} from "lucide-react";
import type { FindingDetail, PolicyResult, Remediation } from "../types";
import { DiffView } from "./DiffView";

interface Props {
  finding: FindingDetail;
  busyAction: string | null;
  onInvestigate: () => void;
  onRestore: (rationale: string) => void;
  onUpdateTerraform: (rationale: string) => void;
  onVerify: (simulateClean: boolean) => void;
  githubConfigured: boolean;
}

const sevStyle: Record<string, string> = {
  critical: "border-red-500/40 bg-red-500/10 text-red-300",
  high: "border-orange-500/40 bg-orange-500/10 text-orange-300",
  medium: "border-amber-500/40 bg-amber-500/10 text-amber-300",
  low: "border-zinc-700 bg-zinc-800/60 text-zinc-300",
};

function PolicyGateBox({ policy }: { policy: PolicyResult }) {
  const allowed = policy.decision === "allow";
  return (
    <div className={`rounded-lg border p-3.5 ${allowed ? "border-emerald-500/30 bg-emerald-950/15" : "border-red-500/40 bg-red-950/20"}`}>
      <div className="flex items-center justify-between mb-2.5">
        <div className="flex items-center gap-2 text-xs font-medium">
          {allowed ? (
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
          ) : (
            <ShieldAlert className="w-4 h-4 text-red-400" />
          )}
          <span className={allowed ? "text-emerald-300" : "text-red-300"}>
            Deterministic Policy Gate: {allowed ? "ALLOWED" : "BLOCKED"}
          </span>
          <span className="font-mono text-[11px] text-zinc-400">mode={policy.mode}</span>
        </div>
        <span className="font-mono text-[11px] text-zinc-500">
          +{policy.summary.create ?? 0} ~{policy.summary.update ?? 0} ±{policy.summary.replace ?? 0} -{policy.summary.delete ?? 0}
        </span>
      </div>
      <div className="space-y-1.5">
        {policy.checks.map((chk) => (
          <div key={chk.id} className="flex items-start gap-2 text-xs">
            {chk.status === "pass" && <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />}
            {chk.status === "fail" && <XCircle className="w-3.5 h-3.5 text-red-400 shrink-0 mt-0.5" />}
            {chk.status === "warn" && <AlertTriangle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />}
            <span className="font-mono text-[11px] text-zinc-300 shrink-0">{chk.id}</span>
            <span className="text-zinc-400">{chk.message}</span>
            {chk.addresses.length > 0 && (
              <span className="font-mono text-[11px] text-zinc-300">[{chk.addresses.join(", ")}]</span>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function RemediationCard({ rem }: { rem: Remediation }) {
  return (
    <div className="rounded-lg border border-zinc-800 bg-[#111114] p-4 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          {rem.direction === "restore" ? (
            <RotateCcw className="w-4 h-4 text-amber-400" />
          ) : (
            <GitPullRequest className="w-4 h-4 text-sky-400" />
          )}
          <span className="text-sm font-medium text-zinc-100">
            {rem.direction === "restore" ? "Restore AWS from Terraform" : "Update Terraform (PR)"}
          </span>
          <span className="rounded-full border border-zinc-700 bg-zinc-900 px-2 py-0.5 font-mono text-[11px] text-zinc-300">
            {rem.status}
          </span>
        </div>
        <div className="flex items-center gap-3 text-xs">
          {rem.pr_url && (
            <a
              href={rem.pr_url}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-sky-400 hover:text-sky-300 font-mono"
            >
              PR #{rem.pr_number} <ExternalLink className="w-3 h-3" />
            </a>
          )}
          {rem.github_run_url && (
            <a
              href={rem.github_run_url}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1 text-emerald-400 hover:text-emerald-300 font-mono"
            >
              Actions Run <ExternalLink className="w-3 h-3" />
            </a>
          )}
          {rem.branch_name && (
            <span className="font-mono text-[11px] text-zinc-400">{rem.branch_name}</span>
          )}
        </div>
      </div>

      {rem.rationale && <p className="text-xs text-zinc-400">Rationale: {rem.rationale}</p>}
      {rem.patch_summary && <p className="text-xs text-zinc-300">{rem.patch_summary}</p>}
      {rem.error && (
        <div className="rounded border border-red-500/30 bg-red-950/25 px-3 py-2 text-xs text-red-300 font-mono">
          {rem.error}
        </div>
      )}
      {rem.policy_result && <PolicyGateBox policy={rem.policy_result} />}
      {rem.patch_diff && (
        <div className="rounded-lg border border-zinc-800 bg-[#09090b] overflow-hidden">
          <div className="border-b border-zinc-800 bg-zinc-900/50 px-3 py-1.5 font-mono text-[11px] text-zinc-400">
            Terraform HCL Patch (Claude Agent SDK)
          </div>
          <pre className="p-3 text-xs font-mono overflow-x-auto text-zinc-300 leading-relaxed">
            {rem.patch_diff}
          </pre>
        </div>
      )}
    </div>
  );
}

export function FindingDetailView({
  finding,
  busyAction,
  onInvestigate,
  onRestore,
  onUpdateTerraform,
  onVerify,
  githubConfigured,
}: Props) {
  const [rationale, setRationale] = useState("");
  const [showRaw, setShowRaw] = useState(false);
  const [showAudit, setShowAudit] = useState(true);

  const inv = finding.latest_investigation;
  const report = inv?.report ?? null;

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-4 border-b border-zinc-800/80 pb-5">
        <div className="space-y-1.5">
          <div className="flex items-center gap-2.5 flex-wrap">
            <span className={`rounded border px-2 py-0.5 font-mono text-[11px] uppercase ${sevStyle[finding.severity] ?? sevStyle.medium}`}>
              {finding.severity}
            </span>
            <span className="rounded border border-zinc-800 bg-zinc-900 px-2 py-0.5 font-mono text-[11px] text-zinc-300">
              {finding.status}
            </span>
            <span className="font-mono text-xs text-zinc-500">
              {finding.account_id} · {finding.region}
            </span>
          </div>
          <h1 className="font-mono text-lg font-semibold text-zinc-100 tracking-tight">{finding.address}</h1>
          <div className="flex flex-wrap items-center gap-3 text-xs font-mono text-zinc-400">
            {finding.resource_id && <span>id: {finding.resource_id}</span>}
            {finding.commit_sha && <span>commit: {finding.commit_sha.slice(0, 8)}</span>}
            <span>fp: {finding.fingerprint.slice(0, 12)}</span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={onInvestigate}
            disabled={busyAction !== null}
            className="inline-flex items-center gap-1.5 rounded-md border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-xs font-medium text-emerald-300 hover:bg-emerald-500/20 disabled:opacity-50 cursor-pointer transition"
          >
            {busyAction === "investigate" ? (
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Sparkles className="w-3.5 h-3.5" />
            )}
            {inv ? "Re-run Investigation" : "Investigate with AI"}
          </button>
          {finding.status !== "resolved" && (
            <button
              onClick={() => onVerify(!githubConfigured)}
              disabled={busyAction !== null}
              className="inline-flex items-center gap-1.5 rounded-md border border-zinc-700 bg-zinc-900 px-3 py-1.5 text-xs font-medium text-zinc-200 hover:bg-zinc-800 disabled:opacity-50 cursor-pointer transition"
              title={githubConfigured ? "Dispatch fresh drift-check.yml to verify" : "Verify against a clean plan (local preview)"}
            >
              {busyAction === "verify" ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              )}
              Verify
            </button>
          )}
        </div>
      </div>

      {/* AI Investigation Report */}
      {report ? (
        <section className="rounded-xl border border-zinc-800 bg-[#111114] p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-emerald-400" />
              <h2 className="text-sm font-semibold text-zinc-100">{report.headline}</h2>
            </div>
            <div className="flex items-center gap-2 font-mono text-[11px] text-zinc-400">
              <span>{inv?.engine}</span>
              <span>·</span>
              <span>confidence {Math.round(report.confidence * 100)}%</span>
            </div>
          </div>

          <p className="text-sm text-zinc-300 leading-relaxed">{report.summary}</p>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="rounded-lg border border-zinc-800/80 bg-zinc-950/60 p-3">
              <div className="flex items-center gap-1.5 text-[11px] uppercase tracking-wider text-zinc-500 mb-1">
                <User className="w-3 h-3" /> Actor (CloudTrail)
              </div>
              <div className="font-mono text-xs text-zinc-200 break-all">{report.actor}</div>
              {report.event_name && (
                <div className="font-mono text-[11px] text-zinc-400 mt-1">{report.event_name}</div>
              )}
              {report.event_time && (
                <div className="flex items-center gap-1 font-mono text-[11px] text-zinc-500 mt-0.5">
                  <Clock className="w-3 h-3" /> {report.event_time}
                </div>
              )}
            </div>

            <div className="rounded-lg border border-zinc-800/80 bg-zinc-950/60 p-3">
              <div className="text-[11px] uppercase tracking-wider text-zinc-500 mb-1">Root Cause</div>
              <div className="text-xs text-zinc-300 leading-relaxed">{report.root_cause}</div>
            </div>

            <div className="rounded-lg border border-zinc-800/80 bg-zinc-950/60 p-3">
              <div className="text-[11px] uppercase tracking-wider text-zinc-500 mb-1">AI Recommendation</div>
              <div className="font-mono text-xs text-emerald-300 font-medium mb-1">
                {report.recommended_action === "restore"
                  ? "Restore AWS"
                  : report.recommended_action === "update_terraform"
                  ? "Update Terraform"
                  : "Needs Review"}
              </div>
              <div className="text-xs text-zinc-400 leading-relaxed">{report.recommendation_rationale}</div>
            </div>
          </div>

          <div className="rounded-lg border border-zinc-800/80 bg-zinc-950/50 p-3.5 space-y-2">
            <div className="text-[11px] uppercase tracking-wider text-zinc-500">Blast Radius & Impacted Resources</div>
            <p className="text-xs text-zinc-300">{report.blast_radius_summary}</p>
            {report.impacted_resources.length > 0 && (
              <div className="flex flex-wrap gap-2 pt-1">
                {report.impacted_resources.map((r, i) => (
                  <div
                    key={i}
                    className="rounded border border-zinc-800 bg-zinc-900/70 px-2.5 py-1 text-xs flex items-center gap-2"
                  >
                    <span className="font-mono text-zinc-200">{r.resource_id}</span>
                    <span className="text-zinc-500">{r.resource_type}</span>
                    <span className="text-zinc-400">· {r.relationship}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {report.evidence_timeline.length > 0 && (
            <div className="space-y-1.5">
              <div className="text-[11px] uppercase tracking-wider text-zinc-500">Evidence Collected</div>
              <div className="space-y-1">
                {report.evidence_timeline.map((e, i) => (
                  <div key={i} className="flex items-start gap-2.5 text-xs text-zinc-300 bg-zinc-950/40 rounded px-3 py-1.5 border border-zinc-800/50">
                    <span className="font-mono text-[11px] text-emerald-400 shrink-0">[{e.source}]</span>
                    <span className="flex-1">{e.summary}</span>
                    {e.timestamp && <span className="font-mono text-[11px] text-zinc-500 shrink-0">{e.timestamp}</span>}
                  </div>
                ))}
              </div>
            </div>
          )}
        </section>
      ) : (
        <section className="rounded-xl border border-dashed border-zinc-800 bg-[#111114]/50 p-5 flex items-center justify-between">
          <div>
            <div className="text-sm font-medium text-zinc-200">Not investigated yet</div>
            <p className="text-xs text-zinc-400 mt-0.5">
              Run the Strands AI Investigator (AWS MCP + CloudTrail) to identify who changed this resource and what else is impacted.
            </p>
          </div>
          <button
            onClick={onInvestigate}
            disabled={busyAction !== null}
            className="inline-flex items-center gap-1.5 rounded-md bg-emerald-500 px-3.5 py-2 text-xs font-semibold text-zinc-950 hover:bg-emerald-400 disabled:opacity-50 cursor-pointer transition"
          >
            {busyAction === "investigate" ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Sparkles className="w-3.5 h-3.5" />}
            Investigate Now
          </button>
        </section>
      )}

      {/* Diff */}
      <section className="space-y-2">
        <h3 className="text-xs font-medium uppercase tracking-wider text-zinc-400">Configuration Drift</h3>
        <DiffView changes={finding.changes} />
      </section>

      {/* Engineer Reconciliation Decision (the 2 core choices) */}
      {finding.status !== "resolved" && (
        <section className="rounded-xl border border-zinc-800 bg-[#111114] p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-zinc-100">Reconciliation Decision</h3>
              <p className="text-xs text-zinc-400 mt-0.5">
                Decision binds to evidence fingerprint <code className="text-zinc-300">{finding.fingerprint.slice(0, 12)}</code>. Deterministic CI gate validates every plan.
              </p>
            </div>
          </div>

          <input
            type="text"
            value={rationale}
            onChange={(e) => setRationale(e.target.value)}
            placeholder="Optional rationale for audit log (e.g. 'Unauthorized SSH rule; revert immediately' or 'Intentional owner handoff')"
            className="w-full rounded-md border border-zinc-800 bg-zinc-950 px-3 py-2 text-xs text-zinc-200 placeholder:text-zinc-500 focus:border-zinc-600 focus:outline-none"
          />

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <button
              onClick={() => onRestore(rationale)}
              disabled={busyAction !== null}
              className="group flex items-start gap-3 rounded-lg border border-amber-500/30 bg-amber-500/5 p-3.5 text-left hover:bg-amber-500/10 hover:border-amber-500/50 disabled:opacity-50 cursor-pointer transition"
            >
              <div className="rounded-md bg-amber-500/15 p-2 text-amber-400">
                {busyAction === "restore" ? <Loader2 className="w-4 h-4 animate-spin" /> : <RotateCcw className="w-4 h-4" />}
              </div>
              <div>
                <div className="text-sm font-semibold text-zinc-100">Review workspace restore</div>
                <p className="text-xs text-zinc-400 mt-0.5">
                  Review and select the resources to restore together in one Terraform plan.
                </p>
              </div>
            </button>

            <button
              onClick={() => onUpdateTerraform(rationale)}
              disabled={busyAction !== null}
              className="group flex items-start gap-3 rounded-lg border border-sky-500/30 bg-sky-500/5 p-3.5 text-left hover:bg-sky-500/10 hover:border-sky-500/50 disabled:opacity-50 cursor-pointer transition"
            >
              <div className="rounded-md bg-sky-500/15 p-2 text-sky-400">
                {busyAction === "update" ? <Loader2 className="w-4 h-4 animate-spin" /> : <Wrench className="w-4 h-4" />}
              </div>
              <div>
                <div className="text-sm font-semibold text-zinc-100">Update Terraform</div>
                <p className="text-xs text-zinc-400 mt-0.5">
                  AWS change is intentional. Claude Agent SDK patches HCL and opens a PR whose plan must show 0 changes.
                </p>
              </div>
            </button>
          </div>
        </section>
      )}

      {/* Remediation Runs */}
      {finding.remediations.length > 0 && (
        <section className="space-y-2.5">
          <h3 className="text-xs font-medium uppercase tracking-wider text-zinc-400">Remediation Activity</h3>
          <div className="space-y-3">
            {finding.remediations.map((rem) => (
              <RemediationCard key={rem.id} rem={rem} />
            ))}
          </div>
        </section>
      )}

      {/* Progressive Disclosure: Audit Timeline & Raw Redacted Plan */}
      <section className="space-y-3 pt-2">
        <div className="rounded-lg border border-zinc-800/80 bg-[#111114]">
          <button
            onClick={() => setShowAudit(!showAudit)}
            className="w-full flex items-center justify-between px-4 py-2.5 text-xs font-medium text-zinc-300 hover:bg-zinc-900/50 cursor-pointer"
          >
            <span className="flex items-center gap-2">
              <History className="w-3.5 h-3.5 text-zinc-400" />
              Audit Trail ({finding.audit_events.length})
            </span>
            {showAudit ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
          </button>
          {showAudit && (
            <div className="border-t border-zinc-800/70 divide-y divide-zinc-800/50">
              {finding.audit_events.map((ev) => (
                <div key={ev.id} className="px-4 py-2.5 flex items-start justify-between gap-3 text-xs">
                  <div>
                    <span className="font-mono text-[11px] text-zinc-400 mr-2">{ev.event_type}</span>
                    <span className="text-zinc-200">{ev.summary}</span>
                    <span className="text-zinc-500 ml-2">by {ev.actor}</span>
                  </div>
                  <span className="font-mono text-[11px] text-zinc-500 shrink-0">
                    {new Date(ev.created_at).toLocaleTimeString()}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="rounded-lg border border-zinc-800/80 bg-[#111114]">
          <button
            onClick={() => setShowRaw(!showRaw)}
            className="w-full flex items-center justify-between px-4 py-2.5 text-xs font-medium text-zinc-400 hover:bg-zinc-900/50 cursor-pointer"
          >
            <span>Redacted Terraform Plan Evidence (JSON)</span>
            {showRaw ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
          </button>
          {showRaw && (
            <pre className="border-t border-zinc-800/70 p-4 text-[11px] font-mono text-zinc-400 overflow-x-auto max-h-96">
              {JSON.stringify(finding.redacted_plan, null, 2)}
            </pre>
          )}
        </div>
      </section>
    </div>
  );
}
