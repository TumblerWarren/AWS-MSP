import { useEffect, useState } from "react";
import {
  Activity,
  Bot,
  CheckCircle2,
  Clock,
  ExternalLink,
  Loader2,
  MessageSquareCode,
  Play,
  RefreshCw,
  Terminal,
  Wrench,
  XCircle,
} from "lucide-react";
import type { ModelTrace, ScanProgress } from "../types";

interface Props {
  scans: ScanProgress[];
  traces: ModelTrace[];
  initialFindingFilter?: string | null;
  onRefresh: () => void;
  onTriggerScan: () => void;
  busyAction: string | null;
}

export function ActivityPage({
  scans,
  traces,
  initialFindingFilter,
  onRefresh,
  onTriggerScan,
  busyAction,
}: Props) {
  const [selectedTraceId, setSelectedTraceId] = useState<string | null>(null);
  const [traceTab, setTraceTab] = useState<"prompt" | "reply" | "steps">("prompt");
  const [findingFilter, setFindingFilter] = useState<string>(initialFindingFilter ?? "");

  useEffect(() => {
    if (initialFindingFilter) {
      setFindingFilter(initialFindingFilter);
    }
  }, [initialFindingFilter]);

  const filteredTraces = findingFilter
    ? traces.filter((t) => t.finding_id === findingFilter || t.finding_address.toLowerCase().includes(findingFilter.toLowerCase()))
    : traces;

  const selectedTrace =
    filteredTraces.find((t) => t.id === selectedTraceId) ?? filteredTraces[0] ?? null;

  const activeScan = scans[0] ?? null;

  return (
    <div className="flex-1 overflow-y-auto p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Page Header */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-zinc-800/80 pb-4">
          <div>
            <h1 className="text-base font-semibold text-zinc-100 flex items-center gap-2">
              <Activity className="w-4 h-4 text-emerald-400" />
              Live Activity & AI Model Inspector
            </h1>
            <p className="text-xs text-zinc-400 mt-0.5">
              Real-time drift scan progress, step-by-step execution logs, and exact prompts sent to / replies received from Bedrock models.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onTriggerScan}
              disabled={busyAction !== null}
              className="inline-flex items-center gap-1.5 rounded-md bg-zinc-100 px-3 py-1.5 text-xs font-semibold text-zinc-950 hover:bg-white disabled:opacity-50 cursor-pointer"
            >
              <Play className="w-3 h-3" />
              Run Drift Scan
            </button>
            <button
              type="button"
              onClick={onRefresh}
              className="inline-flex items-center gap-1.5 rounded-md border border-zinc-700 bg-zinc-900 px-2.5 py-1.5 text-xs font-medium text-zinc-200 hover:bg-zinc-800 cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Refresh
            </button>
          </div>
        </div>

        {/* Section 1: Drift Scan Live Progress & What Is Being Done */}
        <section className="rounded-xl border border-zinc-800 bg-[#111114] p-5 space-y-4">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Terminal className="w-4 h-4 text-emerald-400" />
              <h2 className="text-sm font-semibold text-zinc-100">Drift Scan Activity</h2>
            </div>
            {activeScan && (
              <span className="font-mono text-[11px] text-zinc-400">
                {activeScan.correlation_id} · {activeScan.progress_pct}%
              </span>
            )}
          </div>

          {!activeScan ? (
            <div className="rounded-lg border border-dashed border-zinc-800 bg-zinc-950/40 p-6 text-center text-xs text-zinc-400">
              No drift scan has run in this session yet. Click <span className="text-zinc-200 font-medium">Run Drift Scan</span> above to auto-scan and auto-sync all configured Terraform stack folders.
            </div>
          ) : (
            <div className="space-y-4">
              {/* Progress Bar */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-zinc-200 font-medium">{activeScan.message}</span>
                  <span className="font-mono text-zinc-400">
                    {activeScan.completed_count}/{activeScan.total_count} stacks · {activeScan.findings_ingested} finding(s)
                  </span>
                </div>
                <div className="h-2 w-full rounded-full bg-zinc-800 overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all duration-500 ${
                      activeScan.status === "failed"
                        ? "bg-red-500"
                        : activeScan.status === "partial_failure"
                          ? "bg-amber-400"
                          : "bg-emerald-400"
                    }`}
                    style={{ width: `${Math.max(5, Math.min(100, activeScan.progress_pct))}%` }}
                  />
                </div>
              </div>

              {/* Per-stack cards */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                {activeScan.targets.map((t) => (
                  <div
                    key={`${t.repo}:${t.root_dir ?? "default"}`}
                    className="rounded-lg border border-zinc-800 bg-zinc-950/60 p-3.5 space-y-2"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-xs font-semibold text-zinc-100">{t.label}</span>
                      <span className="inline-flex items-center gap-1 font-mono text-[11px] text-zinc-300">
                        {t.status === "synced" && <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />}
                        {t.status === "failed" && <XCircle className="w-3.5 h-3.5 text-red-400" />}
                        {(t.status === "in_progress" || t.status === "syncing") && (
                          <Loader2 className="w-3.5 h-3.5 text-sky-400 animate-spin" />
                        )}
                        {t.status === "queued" && <Clock className="w-3.5 h-3.5 text-zinc-400" />}
                        {t.status}
                      </span>
                    </div>
                    <div className="font-mono text-[11px] text-zinc-500 truncate">{t.root_dir ?? t.repo}</div>
                    <div className="flex items-center justify-between text-[11px] font-mono">
                      <span className="text-zinc-400">
                        {t.status === "synced" ? `${t.findings_count} drift finding(s)` : t.error ?? "Waiting for GitHub Actions..."}
                      </span>
                      {t.run_url && (
                        <a
                          href={t.run_url}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1 text-sky-400 hover:text-sky-300 shrink-0"
                        >
                          #{t.run_number ?? "run"} <ExternalLink className="w-3 h-3" />
                        </a>
                      )}
                    </div>
                  </div>
                ))}
              </div>

              {/* Live Step-by-step Log */}
              <div className="rounded-lg border border-zinc-800/80 bg-[#09090b] overflow-hidden">
                <div className="border-b border-zinc-800/80 bg-zinc-900/40 px-3.5 py-2 text-[11px] font-mono text-zinc-400">
                  Live Scan Step Log (what is being done)
                </div>
                <div className="max-h-48 overflow-y-auto divide-y divide-zinc-900 font-mono text-[11px]">
                  {activeScan.steps.map((step, idx) => (
                    <div key={idx} className="px-3.5 py-1.5 flex items-start gap-3">
                      <span className="text-zinc-500 shrink-0">
                        {new Date(step.time).toLocaleTimeString()}
                      </span>
                      <span className="text-zinc-300">{step.message}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </section>

        {/* Section 2: AI Model Analysis Inspector (Prompt Sent vs Reply Received) */}
        <section className="rounded-xl border border-zinc-800 bg-[#111114] overflow-hidden">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-zinc-800 px-5 py-3.5">
            <div className="flex items-center gap-2">
              <MessageSquareCode className="w-4 h-4 text-sky-400" />
              <h2 className="text-sm font-semibold text-zinc-100">
                AI Model Analysis Traces (Prompts Sent & Replies Received)
              </h2>
              <span className="font-mono text-[11px] text-zinc-500">({filteredTraces.length})</span>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={findingFilter}
                onChange={(e) => setFindingFilter(e.target.value)}
                placeholder="Filter by finding ID or address..."
                className="rounded-md border border-zinc-800 bg-zinc-950 px-2.5 py-1 text-xs font-mono text-zinc-200 placeholder:text-zinc-500 focus:border-zinc-700 focus:outline-none"
              />
              {findingFilter && (
                <button
                  type="button"
                  onClick={() => setFindingFilter("")}
                  className="text-xs text-zinc-400 hover:text-zinc-200 cursor-pointer"
                >
                  clear
                </button>
              )}
            </div>
          </div>

          {filteredTraces.length === 0 ? (
            <div className="p-8 text-center text-xs text-zinc-400">
              No model analysis runs recorded yet. Open a finding in the Drift Inbox and click <span className="text-zinc-200 font-medium">Investigate with AI</span> or <span className="text-zinc-200 font-medium">Update Terraform</span> to inspect the exact prompt sent and reply received.
            </div>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-12 min-h-[460px]">
              {/* Trace List */}
              <div className="lg:col-span-4 border-b lg:border-b-0 lg:border-r border-zinc-800 divide-y divide-zinc-800/70 max-h-[600px] overflow-y-auto">
                {filteredTraces.map((tr) => {
                  const active = selectedTrace?.id === tr.id;
                  return (
                    <button
                      key={tr.id}
                      type="button"
                      onClick={() => setSelectedTraceId(tr.id)}
                      className={`w-full text-left px-4 py-3 space-y-1 transition cursor-pointer ${
                        active ? "bg-zinc-900 border-l-2 border-l-sky-400" : "hover:bg-zinc-900/40"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="inline-flex items-center gap-1.5 font-mono text-[11px] font-medium text-zinc-200">
                          {tr.kind === "investigation" ? (
                            <Bot className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Wrench className="w-3.5 h-3.5 text-sky-400" />
                          )}
                          {tr.kind === "investigation" ? "Investigation" : "TF Patcher"}
                        </span>
                        <span
                          className={`font-mono text-[10px] rounded px-1.5 py-0.5 ${
                            tr.status === "completed"
                              ? "bg-emerald-500/15 text-emerald-300"
                              : tr.status === "failed"
                                ? "bg-red-500/15 text-red-300"
                                : "bg-sky-500/15 text-sky-300"
                          }`}
                        >
                          {tr.status}
                        </span>
                      </div>
                      <div className="font-mono text-xs text-zinc-100 truncate">{tr.finding_address || tr.finding_id}</div>
                      <div className="flex items-center justify-between font-mono text-[10px] text-zinc-500">
                        <span className="truncate">{tr.model_id}</span>
                        <span>{new Date(tr.created_at).toLocaleTimeString()}</span>
                      </div>
                    </button>
                  );
                })}
              </div>

              {/* Trace Detail Inspector */}
              {selectedTrace && (
                <div className="lg:col-span-8 flex flex-col">
                  <div className="border-b border-zinc-800 px-5 py-3 flex flex-wrap items-center justify-between gap-2 bg-zinc-950/40">
                    <div className="space-y-0.5">
                      <div className="font-mono text-xs font-semibold text-zinc-100">
                        {selectedTrace.finding_address} · <span className="text-zinc-400">{selectedTrace.model_id}</span>
                      </div>
                      <div className="font-mono text-[11px] text-zinc-500">
                        engine={selectedTrace.engine} · region={selectedTrace.bedrock_region}
                        {selectedTrace.mcp_servers.length > 0 && ` · mcp=[${selectedTrace.mcp_servers.join(", ")}]`}
                      </div>
                    </div>

                    <div className="flex items-center gap-1 rounded-md border border-zinc-800 bg-zinc-950 p-0.5 font-mono text-[11px]">
                      {(["prompt", "reply", "steps"] as const).map((tab) => (
                        <button
                          key={tab}
                          type="button"
                          onClick={() => setTraceTab(tab)}
                          className={`rounded px-2.5 py-1 capitalize cursor-pointer transition ${
                            traceTab === tab ? "bg-zinc-800 text-zinc-100" : "text-zinc-400 hover:text-zinc-200"
                          }`}
                        >
                          {tab === "prompt"
                            ? "Prompt Sent"
                            : tab === "reply"
                              ? "Reply Received"
                              : `Steps (${selectedTrace.events.length})`}
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="p-5 overflow-y-auto max-h-[540px] space-y-4">
                    {selectedTrace.error && (
                      <div className="rounded-lg border border-red-500/40 bg-red-950/25 p-3 font-mono text-xs text-red-300">
                        Error: {selectedTrace.error}
                      </div>
                    )}

                    {traceTab === "prompt" && (
                      <div className="space-y-4">
                        <div className="rounded-lg border border-zinc-800 bg-[#09090b] overflow-hidden">
                          <div className="border-b border-zinc-800 bg-zinc-900/50 px-3.5 py-1.5 font-mono text-[11px] text-zinc-400">
                            System Prompt Sent to Model
                          </div>
                          <pre className="p-3.5 text-xs font-mono text-zinc-300 whitespace-pre-wrap overflow-x-auto leading-relaxed">
                            {selectedTrace.system_prompt || "(empty)"}
                          </pre>
                        </div>

                        <div className="rounded-lg border border-zinc-800 bg-[#09090b] overflow-hidden">
                          <div className="border-b border-zinc-800 bg-zinc-900/50 px-3.5 py-1.5 font-mono text-[11px] text-zinc-400">
                            User Prompt Sent to Model
                          </div>
                          <pre className="p-3.5 text-xs font-mono text-zinc-200 whitespace-pre-wrap overflow-x-auto leading-relaxed">
                            {selectedTrace.user_prompt || "(empty)"}
                          </pre>
                        </div>
                      </div>
                    )}

                    {traceTab === "reply" && (
                      <div className="rounded-lg border border-zinc-800 bg-[#09090b] overflow-hidden">
                        <div className="border-b border-zinc-800 bg-zinc-900/50 px-3.5 py-1.5 font-mono text-[11px] text-emerald-400">
                          Model Reply Received ({selectedTrace.status})
                        </div>
                        <pre className="p-3.5 text-xs font-mono text-zinc-200 whitespace-pre-wrap overflow-x-auto leading-relaxed">
                          {selectedTrace.reply_text ||
                            (selectedTrace.status === "running"
                              ? "Waiting for model reply..."
                              : "(no reply captured)")}
                        </pre>
                      </div>
                    )}

                    {traceTab === "steps" && (
                      <div className="space-y-2">
                        {selectedTrace.events.length === 0 ? (
                          <div className="text-xs text-zinc-500 font-mono">No intermediate tool/step events recorded.</div>
                        ) : (
                          selectedTrace.events.map((ev, idx) => (
                            <div
                              key={idx}
                              className="rounded-lg border border-zinc-800/80 bg-[#09090b] p-3 font-mono text-xs space-y-1"
                            >
                              <span className="inline-block rounded bg-zinc-800 px-1.5 py-0.5 text-[10px] uppercase text-sky-300">
                                {ev.stage}
                              </span>
                              <pre className="text-zinc-300 whitespace-pre-wrap break-words leading-relaxed">
                                {ev.detail}
                              </pre>
                            </div>
                          ))
                        )}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
