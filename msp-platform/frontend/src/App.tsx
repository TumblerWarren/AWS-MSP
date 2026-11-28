import { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  CheckCircle2,
  Cpu,
  KeyRound,
  MessageSquareCode,
  Play,
  RefreshCw,
  Search,
  Shield,
  Terminal,
  X,
} from "lucide-react";
import { api } from "./api";
import { ActivityPage } from "./components/ActivityPage";
import { FindingDetailView } from "./components/FindingDetail";
import { ScanProgressBar } from "./components/ScanProgressBar";
import type {
  FindingDetail,
  FindingSummary,
  ModelPreferences,
  ModelTrace,
  PlatformConfig,
  ScanProgress,
} from "./types";

const sevDot: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-400",
  medium: "bg-amber-400",
  low: "bg-zinc-500",
};

const modelFields = [
  { key: "investigation", label: "Investigation model" },
  { key: "patcher", label: "Terraform patch model" },
] as const;

function workspaceKey(finding: FindingSummary) {
  return JSON.stringify([finding.repo, finding.root_dir, finding.account_id, finding.region, finding.state_lineage]);
}

export function App() {
  const [config, setConfig] = useState<PlatformConfig | null>(null);
  const [findings, setFindings] = useState<FindingSummary[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<FindingDetail | null>(null);
  const [filter, setFilter] = useState<string>("all");
  const [query, setQuery] = useState("");
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [banner, setBanner] = useState<{ kind: "info" | "error"; text: string } | null>(null);
  const [showCreds, setShowCreds] = useState(false);
  const [modelForm, setModelForm] = useState<ModelPreferences | null>(null);
  const [restoreReview, setRestoreReview] = useState<{ anchor: string; rationale: string; fingerprints: Record<string, string> } | null>(null);
  const [activePage, setActivePage] = useState<"inbox" | "activity">("inbox");
  const [activeScan, setActiveScan] = useState<ScanProgress | null>(null);
  const [scanDismissed, setScanDismissed] = useState(false);
  const [allScans, setAllScans] = useState<ScanProgress[]>([]);
  const [modelTraces, setModelTraces] = useState<ModelTrace[]>([]);
  const [traceFindingFilter, setTraceFindingFilter] = useState<string | null>(null);
  const prevSyncedCount = useRef(0);
  const [credForm, setCredForm] = useState({
    aws_access_key_id: "",
    aws_secret_access_key: "",
    aws_session_token: "",
    aws_region: "ap-south-1",
    investigator_role_arn: "",
    github_token: "",
  });

  async function refreshList(preserveSelection = true) {
    const [cfg, list] = await Promise.all([api.config(), api.listFindings()]);
    setConfig(cfg);
    setFindings(list);
    if (list.length > 0 && (!preserveSelection || !selectedId || !list.some((f) => f.id === selectedId))) {
      setSelectedId(list[0].id);
    }
  }

  async function loadDetail(id: string) {
    const d = await api.getFinding(id);
    setDetail(d);
  }

  async function refreshActivity() {
    const [scans, traces] = await Promise.all([api.listScans(), api.listTraces()]);
    setAllScans(scans);
    setModelTraces(traces);
    if (scans.length > 0) {
      setActiveScan(scans[0]);
    }
  }

  useEffect(() => {
    refreshList(false).catch((err) => setBanner({ kind: "error", text: String(err) }));
    refreshActivity().catch(() => {});
  }, []);

  // Auto-poll active drift scan every 3 seconds and auto-refresh Drift Inbox as stacks finish syncing
  useEffect(() => {
    if (!activeScan || activeScan.status !== "running") return;
    let cancelled = false;
    const poll = async () => {
      try {
        const updated = await api.pollScan(activeScan.correlation_id);
        if (cancelled) return;
        setActiveScan(updated);
        setAllScans((prev) => [updated, ...prev.filter((s) => s.correlation_id !== updated.correlation_id)]);
        const syncedNow = updated.targets.filter((t) => t.status === "synced").length;
        if (syncedNow > prevSyncedCount.current || updated.status !== "running") {
          prevSyncedCount.current = syncedNow;
          await refreshList();
        }
      } catch {
        // transient poll error; next interval will retry
      }
    };
    const timer = window.setInterval(() => {
      void poll();
    }, 3000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [activeScan?.correlation_id, activeScan?.status]);

  // Refresh AI model traces automatically while on the Activity page or when an AI action is busy
  useEffect(() => {
    if (activePage !== "activity" && busyAction !== "investigate" && busyAction !== "update") return;
    void refreshActivity().catch(() => {});
    const timer = window.setInterval(() => {
      void refreshActivity().catch(() => {});
    }, 3000);
    return () => window.clearInterval(timer);
  }, [activePage, busyAction]);

  useEffect(() => {
    if (selectedId) {
      loadDetail(selectedId).catch((err) => setBanner({ kind: "error", text: String(err) }));
    } else {
      setDetail(null);
    }
  }, [selectedId]);

  const filtered = useMemo(() => {
    return findings.filter((f) => {
      if (filter !== "all" && f.status !== filter) return false;
      if (query.trim()) {
        const q = query.toLowerCase();
        return (
          f.address.toLowerCase().includes(q) ||
          (f.resource_id ?? "").toLowerCase().includes(q) ||
          f.resource_type.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [findings, filter, query]);

  async function runAction(name: string, fn: () => Promise<void>) {
    setBusyAction(name);
    setBanner(null);
    try {
      await fn();
    } catch (err) {
      setBanner({ kind: "error", text: err instanceof Error ? err.message : String(err) });
    } finally {
      setBusyAction(null);
    }
  }

  const modelsChanged = config && modelForm && modelFields.some(
    ({ key }) => modelForm[key] !== config.model_preferences[key],
  );
  const groupedFindings = new Map<string, FindingSummary[]>();
  for (const finding of filtered) {
    const key = workspaceKey(finding);
    const group = groupedFindings.get(key);
    if (group) group.push(finding);
    else groupedFindings.set(key, [finding]);
  }
  const reviewing = restoreReview?.anchor === detail?.id ? restoreReview : null;
  const workspaceFindings = detail && reviewing ? findings.filter((finding) => (
    workspaceKey(finding) === workspaceKey(detail) && finding.status !== "resolved" &&
    finding.commit_sha === detail.commit_sha && finding.state_serial === detail.state_serial
  )) : [];
  const checkedFindings = workspaceFindings.filter(({ id }) => reviewing?.fingerprints[id]);
  const staleSelections = reviewing && Object.keys(reviewing.fingerprints).some((id) =>
    !checkedFindings.some((finding) => finding.id === id && finding.fingerprint === reviewing.fingerprints[id]),
  );
  const plannedChanges = (detail?.redacted_plan.resource_changes ?? []) as { address: string; change?: { actions?: string[] } }[];
  const unselectedChanges = plannedChanges.filter(({ address, change }) => (
    change?.actions?.some((action) => action !== "no-op" && action !== "read") &&
    !checkedFindings.some((finding) => finding.address === address)
  ));
  const latestRestore = detail?.latest_remediation;

  return (
    <div className="min-h-screen flex flex-col bg-[#09090b] text-zinc-100">
      {/* Top Navbar */}
      <header className="min-h-13 border-b border-zinc-800/90 bg-[#0b0b0e] flex flex-wrap items-center justify-between gap-x-3 gap-y-2 px-4 py-2 sticky top-0 z-20">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded-md bg-emerald-500/15 border border-emerald-500/40 flex items-center justify-center">
              <Shield className="w-3.5 h-3.5 text-emerald-400" />
            </div>
            <span className="font-semibold text-sm tracking-tight">MSP</span>
            <span className="text-xs text-zinc-500 hidden sm:inline">Drift Investigation & Reconciliation</span>
          </div>

          <nav className="flex items-center gap-1 rounded-md border border-zinc-800 bg-zinc-950 p-0.5 text-xs">
            <button
              type="button"
              onClick={() => setActivePage("inbox")}
              className={`inline-flex items-center gap-1.5 rounded px-2.5 py-1 font-medium cursor-pointer transition ${
                activePage === "inbox" ? "bg-zinc-800 text-zinc-100" : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              <Activity className="w-3.5 h-3.5" />
              Drift Inbox
            </button>
            <button
              type="button"
              onClick={() => {
                setTraceFindingFilter(null);
                setActivePage("activity");
                void refreshActivity().catch(() => {});
              }}
              className={`inline-flex items-center gap-1.5 rounded px-2.5 py-1 font-medium cursor-pointer transition ${
                activePage === "activity" ? "bg-zinc-800 text-zinc-100" : "text-zinc-400 hover:text-zinc-200"
              }`}
            >
              <MessageSquareCode className="w-3.5 h-3.5" />
              Activity & Model Traces
              {(activeScan?.status === "running" || modelTraces.some((t) => t.status === "running")) && (
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              )}
            </button>
          </nav>

          {config && (
            <div className="hidden xl:flex items-center gap-2 pl-3 border-l border-zinc-800 font-mono text-[11px]">
              <span className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 ${config.github_configured ? "border-emerald-500/30 text-emerald-300 bg-emerald-500/5" : "border-zinc-800 text-zinc-400 bg-zinc-900"}`}>
                <span className={`w-1.5 h-1.5 rounded-full ${config.github_configured ? "bg-emerald-400" : "bg-zinc-500"}`} />
                {config.github_configured ? config.github_repo : "GitHub: local mode"}
              </span>
              <span className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 ${config.aws_credentials_detected ? "border-emerald-500/30 text-emerald-300 bg-emerald-500/5" : "border-zinc-800 text-zinc-400 bg-zinc-900"}`}>
                <span className={`w-1.5 h-1.5 rounded-full ${config.aws_credentials_detected ? "bg-emerald-400" : "bg-zinc-500"}`} />
                {config.aws_credentials_detected
                  ? `AWS: ${config.aws_region} (${config.aws_credential_mode === "temporary_session" ? "temp session" : "key/secret"})`
                  : "AWS: offline preview"}
              </span>
            </div>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => {
              if (config) {
                setCredForm((prev) => ({
                  ...prev,
                  aws_region: config.aws_region || "ap-south-1",
                  investigator_role_arn: config.investigator_role_arn || prev.investigator_role_arn,
                }));
              }
              setShowCreds(true);
            }}
            className="inline-flex items-center gap-1.5 rounded-md border border-zinc-700 bg-zinc-900 px-2.5 py-1.5 text-xs font-medium text-zinc-200 hover:bg-zinc-800 cursor-pointer"
          >
            <KeyRound className="w-3.5 h-3.5 text-amber-400" />
            AWS Credentials
          </button>

          <button
            type="button"
            aria-expanded={modelForm !== null}
            aria-controls="model-settings"
            disabled={!config?.model_preferences || busyAction === "models"}
            onClick={() => setModelForm(modelForm ? null : config?.model_preferences ?? null)}
            className="inline-flex items-center gap-1.5 rounded-md border border-zinc-700 bg-zinc-900 px-2.5 py-1.5 text-xs font-medium text-zinc-200 hover:bg-zinc-800 aria-expanded:bg-zinc-800 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-400 disabled:opacity-50 cursor-pointer"
          >
            <Cpu className="w-3.5 h-3.5" aria-hidden="true" />
            AI Models
          </button>

          <button
            onClick={() =>
              runAction("scan", async () => {
                const res = await api.triggerScan();
                prevSyncedCount.current = 0;
                if (res.scan) {
                  setActiveScan(res.scan);
                  setScanDismissed(false);
                  setAllScans((prev) => [res.scan!, ...prev.filter((s) => s.correlation_id !== res.scan!.correlation_id)]);
                }
                await refreshList();
                setBanner({ kind: "info", text: "Drift scan dispatched — auto-polling GitHub Actions & auto-syncing reports..." });
              })
            }
            disabled={busyAction !== null || activeScan?.status === "running"}
            className="inline-flex items-center gap-1.5 rounded-md bg-zinc-100 px-3 py-1.5 text-xs font-semibold text-zinc-950 hover:bg-white disabled:opacity-50 cursor-pointer"
          >
            <Play className="w-3 h-3" />
            {activeScan?.status === "running" ? `Scanning (${activeScan.progress_pct}%)…` : "Run Drift Scan"}
          </button>

          <button
            onClick={() =>
              runAction("sync", async () => {
                const res = await api.syncGitHub();
                await refreshList(false);
                setBanner({ kind: "info", text: res.message });
              })
            }
            disabled={busyAction !== null}
            title="Manually pull the latest completed GitHub Actions drift report(s)"
            className="inline-flex items-center gap-1.5 rounded-md border border-zinc-800 bg-zinc-900 px-2.5 py-1.5 text-xs font-medium text-zinc-300 hover:bg-zinc-800 disabled:opacity-50 cursor-pointer"
          >
            Force Sync
          </button>

          <button
            onClick={() => runAction("refresh", () => refreshList())}
            className="rounded-md border border-zinc-800 p-1.5 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900 cursor-pointer"
            title="Refresh"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${busyAction === "refresh" ? "animate-spin" : ""}`} />
          </button>
        </div>
      </header>

      {banner && (
        <div
          role={banner.kind === "error" ? "alert" : "status"}
          className={`px-4 py-2 text-xs font-mono border-b flex items-center justify-between ${
            banner.kind === "error"
              ? "bg-red-950/30 border-red-500/30 text-red-300"
              : "bg-emerald-950/20 border-emerald-500/30 text-emerald-300"
          }`}
        >
          <span>{banner.text}</span>
          <button onClick={() => setBanner(null)} className="text-zinc-400 hover:text-zinc-200 cursor-pointer">
            dismiss
          </button>
        </div>
      )}

      {config && modelForm && (
        <section id="model-settings" aria-labelledby="model-settings-title" className="border-b border-zinc-800 bg-[#111114] px-4 py-4">
          <form
            className="mx-auto max-w-4xl space-y-4"
            onSubmit={(event) => {
              event.preventDefault();
              if (!modelsChanged || busyAction !== null) return;
              void runAction("models", async () => {
                const updated = await api.updateModels(modelForm);
                setConfig(updated);
                setModelForm(null);
                setBanner({ kind: "info", text: "Model choices saved for new investigations and Terraform patches." });
              });
            }}
          >
            <h2 id="model-settings-title" className="text-sm font-semibold text-zinc-100">AI model settings</h2>
            <div className="grid gap-4 sm:grid-cols-2">
              {modelFields.map(({ key, label }) => {
                const activeId = key === "investigation" ? config.strands_model_id : config.claude_model;
                const activeLabel = config.bedrock_models.find((model) => model.id === activeId)?.label ?? activeId;
                const usesBedrock = key === "investigation" || config.claude_use_bedrock;
                return (
                  <div key={key} className="min-w-0 space-y-1.5">
                    <label htmlFor={`model-${key}`} className="block text-xs font-medium text-zinc-200">{label}</label>
                    <select
                      id={`model-${key}`}
                      aria-describedby={`model-${key}-active`}
                      value={modelForm[key] ?? ""}
                      disabled={!usesBedrock || busyAction === "models"}
                      onChange={(event) => setModelForm({ ...modelForm, [key]: event.target.value || null })}
                      className="w-full rounded-md border border-zinc-700 bg-zinc-950 px-3 py-2 text-sm text-zinc-100 [color-scheme:dark] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-400 disabled:opacity-60"
                    >
                      <option value="">Deployment default</option>
                      {usesBedrock && config.bedrock_models.map((model) => <option key={model.id} value={model.id}>{model.label}</option>)}
                    </select>
                    <p id={`model-${key}-active`} className="break-words text-xs text-zinc-400">
                      {usesBedrock ? `Active model · ${activeLabel}` : `Configured by the deployment · ${activeId}`}
                    </p>
                  </div>
                );
              })}
            </div>
            <div className="flex justify-end gap-2">
              <button type="button" disabled={busyAction === "models"} onClick={() => setModelForm(null)} className="rounded-md border border-zinc-700 px-3 py-1.5 text-xs text-zinc-200 hover:bg-zinc-900 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-400 disabled:opacity-60 cursor-pointer">
                Cancel
              </button>
              <button type="submit" disabled={!modelsChanged || busyAction !== null} className="rounded-md bg-emerald-500 px-3.5 py-1.5 text-xs font-semibold text-zinc-950 hover:bg-emerald-400 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-400 disabled:opacity-50 cursor-pointer">
                {busyAction === "models" ? "Saving…" : "Save models"}
              </button>
            </div>
          </form>
        </section>
      )}

      {activeScan && !scanDismissed && activePage === "inbox" && (
        <ScanProgressBar
          scan={activeScan}
          onOpenActivity={() => {
            setTraceFindingFilter(null);
            setActivePage("activity");
            void refreshActivity().catch(() => {});
          }}
          onDismiss={() => setScanDismissed(true)}
        />
      )}

      {activePage === "activity" ? (
        <ActivityPage
          scans={allScans}
          traces={modelTraces}
          initialFindingFilter={traceFindingFilter}
          busyAction={busyAction}
          onRefresh={() => {
            void refreshActivity().catch(() => {});
          }}
          onTriggerScan={() =>
            runAction("scan", async () => {
              const res = await api.triggerScan();
              prevSyncedCount.current = 0;
              if (res.scan) {
                setActiveScan(res.scan);
                setScanDismissed(false);
                setAllScans((prev) => [res.scan!, ...prev.filter((s) => s.correlation_id !== res.scan!.correlation_id)]);
              }
            })
          }
        />
      ) : (
      /* Workspace: Left Drift Inbox + Right Finding Detail */
      <div className="flex-1 flex flex-col md:flex-row min-h-0">
        <aside className="w-full md:w-80 lg:w-96 max-h-[42vh] md:max-h-none border-b md:border-b-0 md:border-r border-zinc-800/80 bg-[#0b0b0e] flex flex-col shrink-0">
          <div className="p-3 border-b border-zinc-800/80 space-y-2.5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-zinc-200">
                <Activity className="w-3.5 h-3.5 text-emerald-400" />
                Drift Inbox
              </div>
              <span className="font-mono text-[11px] text-zinc-500">{filtered.length} findings</span>
            </div>

            <div className="relative">
              <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-2.5 top-2" />
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Filter by address or resource ID..."
                className="w-full rounded-md border border-zinc-800 bg-zinc-950 pl-8 pr-2.5 py-1.5 text-xs text-zinc-200 placeholder:text-zinc-500 focus:border-zinc-700 focus:outline-none"
              />
            </div>

            <div className="flex items-center gap-1 overflow-x-auto">
              {["all", "open", "investigated", "remediating", "resolved"].map((st) => (
                <button
                  key={st}
                  onClick={() => setFilter(st)}
                  className={`rounded px-2 py-0.5 text-[11px] font-mono capitalize cursor-pointer transition ${
                    filter === st
                      ? "bg-zinc-800 text-zinc-100"
                      : "text-zinc-500 hover:text-zinc-300"
                  }`}
                >
                  {st}
                </button>
              ))}
            </div>
          </div>

          <div className="flex-1 min-h-0 overflow-y-auto divide-y divide-zinc-800/60">
            {filtered.length === 0 ? (
              <div className="p-6 text-center space-y-2">
                <Terminal className="w-6 h-6 text-zinc-600 mx-auto" />
                <div className="text-xs font-medium text-zinc-300">No drift findings</div>
                <p className="text-[11px] text-zinc-500">
                  Click <span className="text-zinc-300">Run Drift Scan</span> to dispatch{" "}
                  <code className="text-zinc-300">drift-check.yml</code>, or{" "}
                  <span className="text-zinc-300">Sync GitHub</span> to pull the latest run.
                </p>
              </div>
            ) : (
              Array.from(groupedFindings.values()).map((group) => (
                <section key={workspaceKey(group[0])} aria-label={`${group[0].repo} ${group[0].root_dir}`}>
                  <h3 className="px-3.5 pt-3 text-xs font-medium text-zinc-300 break-words">{group[0].repo}</h3>
                  <p className="px-3.5 pb-2 text-[11px] text-zinc-400 break-words">
                    {group[0].root_dir} · {group[0].account_id} · {group[0].region}
                  </p>
                  {group.map((f) => {
                const active = f.id === selectedId;
                return (
                  <button
                    key={f.id}
                    onClick={() => setSelectedId(f.id)}
                    className={`w-full text-left px-3.5 py-3 transition cursor-pointer ${
                      active ? "bg-zinc-900/90 border-l-2 border-l-emerald-400" : "hover:bg-zinc-900/40"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className={`w-2 h-2 rounded-full shrink-0 ${sevDot[f.severity] ?? sevDot.medium}`} />
                        <span className="font-mono text-xs font-medium text-zinc-100 truncate">{f.address}</span>
                      </div>
                      {f.status === "resolved" ? (
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                      ) : (
                        <span className="font-mono text-[10px] text-zinc-400 shrink-0">{f.status}</span>
                      )}
                    </div>
                    <div className="flex items-center justify-between text-[11px] font-mono text-zinc-500">
                      <span className="truncate">{f.resource_id ?? f.resource_type}</span>
                      <span>{f.changes.length} diff</span>
                    </div>
                    {f.latest_investigation?.report && (
                      <div className="mt-1.5 text-[11px] text-zinc-400 line-clamp-1">
                        {f.latest_investigation.report.headline}
                      </div>
                    )}
                  </button>
                );
                  })}
                </section>
              ))
            )}
          </div>
        </aside>

        <main className="flex-1 overflow-y-auto">
          {detail ? (
            <>
            {reviewing && (
              <section aria-labelledby="restore-review-title" className="mx-4 mt-4 rounded-xl border border-zinc-800 bg-[#111114] p-4 space-y-3">
                <h2 id="restore-review-title" tabIndex={-1} className="text-sm font-semibold text-zinc-100">Review workspace restore</h2>
                <p className="break-words text-xs text-zinc-400">{detail.repo} · {detail.root_dir} · {detail.account_id} · {detail.region}</p>
                <fieldset className="divide-y divide-zinc-800">
                  <legend className="mb-2 text-xs text-zinc-300">Choose resources to restore in this plan</legend>
                  {workspaceFindings.map((finding) => (
                    <label key={finding.id} className="flex items-start gap-2 py-2 text-xs text-zinc-200">
                      <input type="checkbox" className="accent-emerald-500" checked={Boolean(reviewing.fingerprints[finding.id])}
                        disabled={busyAction !== null}
                        onChange={(event) => {
                          const fingerprints = { ...reviewing.fingerprints };
                          if (event.target.checked) fingerprints[finding.id] = finding.fingerprint;
                          else delete fingerprints[finding.id];
                          setRestoreReview({ ...reviewing, fingerprints });
                        }} />
                      <span className="min-w-0 break-all font-mono">{finding.address}</span>
                    </label>
                  ))}
                </fieldset>
                {unselectedChanges.length > 0 && (
                  <div className="text-xs text-amber-300">
                    <p>The workspace plan would also change these resources:</p>
                    <ul className="mt-1 list-disc space-y-1 pl-4">
                      {unselectedChanges.map(({ address }) => <li key={address} className="break-all font-mono">{address}</li>)}
                    </ul>
                  </div>
                )}
                {!detail.state_lineage && <p className="text-xs text-amber-300">Sync a new scan to capture this workspace’s state identity.</p>}
                {staleSelections && <p role="alert" className="text-xs text-amber-300">The evidence changed. Reopen this review to see the latest findings.</p>}
                <div className="flex flex-wrap justify-end gap-2">
                  <button type="button" onClick={() => setRestoreReview(null)} disabled={busyAction !== null} className="rounded-md border border-zinc-700 px-3 py-1.5 text-xs text-zinc-200">Cancel</button>
                  <button type="button" disabled={busyAction !== null || !config?.github_configured || !detail.state_lineage || checkedFindings.length === 0 || unselectedChanges.length > 0 || !!staleSelections}
                    className="rounded-md bg-emerald-500 px-3 py-1.5 text-xs font-semibold text-zinc-950 disabled:opacity-50"
                    onClick={() => void runAction("restore", async () => {
                      await api.restoreWorkspace({ rationale: reviewing.rationale,
                        selections: checkedFindings.map(({ id }) => ({ finding_id: id, fingerprint: reviewing.fingerprints[id] })) });
                      setRestoreReview(null);
                      await loadDetail(detail.id);
                      await refreshList();
                      setBanner({ kind: "info", text: "Workspace plan requested. Review the plan in GitHub Actions before authorizing apply." });
                    })}>
                    {busyAction === "restore" ? "Requesting plan…" : `Prepare plan (${checkedFindings.length})`}
                  </button>
                </div>
              </section>
            )}
            {latestRestore?.direction === "restore" && latestRestore.correlation_id.startsWith("restore-") &&
              ["running", "awaiting_approval"].includes(latestRestore.status) && (
                <button type="button" disabled={busyAction !== null} className="mx-4 mt-4 rounded-md border border-zinc-700 px-3 py-1.5 text-xs text-zinc-200"
                  onClick={() => void runAction("restore-status", async () => {
                    await api.refreshRemediation(latestRestore.id);
                    await loadDetail(detail.id);
                    await refreshList();
                  })}>Refresh restore status</button>
            )}
            <FindingDetailView
              finding={detail}
              busyAction={busyAction}
              githubConfigured={config?.github_configured ?? false}
              onInvestigate={() =>
                runAction("investigate", async () => {
                  const updated = await api.investigate(detail.id);
                  setDetail(updated);
                  await refreshList();
                })
              }
              onRestore={(rationale) => {
                setRestoreReview({ anchor: detail.id, rationale, fingerprints: { [detail.id]: detail.fingerprint } });
                requestAnimationFrame(() => document.getElementById("restore-review-title")?.focus());
              }}
              onUpdateTerraform={(rationale) =>
                runAction("update", async () => {
                  const updated = await api.remediateUpdateTerraform(detail.id, {
                    decided_by: "engineer",
                    rationale,
                    expected_fingerprint: detail.fingerprint,
                  });
                  setDetail(updated);
                  await refreshList();
                })
              }
              onVerify={(simulateClean) =>
                runAction("verify", async () => {
                  const updated = await api.verify(detail.id, simulateClean);
                  setDetail(updated);
                  await refreshList();
                })
              }
              onInspectTrace={() => {
                setTraceFindingFilter(detail.id);
                setActivePage("activity");
                void refreshActivity().catch(() => {});
              }}
            />
            </>
          ) : (
            <div className="h-full flex items-center justify-center p-8 text-center">
              <div className="max-w-sm space-y-2">
                <Shield className="w-8 h-8 text-zinc-700 mx-auto" />
                <div className="text-sm font-medium text-zinc-300">Select a drift finding</div>
                <p className="text-xs text-zinc-500">
                  Investigate configuration drift with Strands + AWS MCP servers, then choose to Restore AWS or Update Terraform.
                </p>
              </div>
            </div>
          )}
        </main>
      </div>
      )}

      {showCreds && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="w-full max-w-lg rounded-xl border border-zinc-800 bg-[#111114] p-5 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold text-zinc-100">AWS & GitHub Credentials</h2>
                <p className="text-xs text-zinc-400 mt-0.5">
                  Supports static IAM Access Key + Secret Key, or Temporary Session Credentials (+ Session Token).
                </p>
              </div>
              <button onClick={() => setShowCreds(false)} className="text-zinc-400 hover:text-zinc-200 cursor-pointer">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="block text-zinc-400 mb-1 font-mono">AWS_ACCESS_KEY_ID</label>
                <input
                  type="text"
                  value={credForm.aws_access_key_id}
                  onChange={(e) => setCredForm({ ...credForm, aws_access_key_id: e.target.value })}
                  placeholder="AKIA... (permanent) or ASIA... (temporary)"
                  className="w-full rounded border border-zinc-800 bg-zinc-950 px-3 py-1.5 font-mono text-zinc-200"
                />
              </div>

              <div>
                <label className="block text-zinc-400 mb-1 font-mono">AWS_SECRET_ACCESS_KEY</label>
                <input
                  type="password"
                  value={credForm.aws_secret_access_key}
                  onChange={(e) => setCredForm({ ...credForm, aws_secret_access_key: e.target.value })}
                  placeholder="Secret access key"
                  className="w-full rounded border border-zinc-800 bg-zinc-950 px-3 py-1.5 font-mono text-zinc-200"
                />
              </div>

              <div>
                <label className="block text-zinc-400 mb-1 font-mono">
                  AWS_SESSION_TOKEN <span className="text-zinc-500">(optional — leave empty for static IAM keys)</span>
                </label>
                <input
                  type="password"
                  value={credForm.aws_session_token}
                  onChange={(e) => setCredForm({ ...credForm, aws_session_token: e.target.value })}
                  placeholder="Only required for temporary ASIA... credentials"
                  className="w-full rounded border border-zinc-800 bg-zinc-950 px-3 py-1.5 font-mono text-zinc-200"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-zinc-400 mb-1 font-mono">AWS_REGION</label>
                  <input
                    type="text"
                    value={credForm.aws_region}
                    onChange={(e) => setCredForm({ ...credForm, aws_region: e.target.value })}
                    className="w-full rounded border border-zinc-800 bg-zinc-950 px-3 py-1.5 font-mono text-zinc-200"
                  />
                </div>
                <div>
                  <label className="block text-zinc-400 mb-1 font-mono">MSP_GITHUB_TOKEN (optional)</label>
                  <input
                    type="password"
                    value={credForm.github_token}
                    onChange={(e) => setCredForm({ ...credForm, github_token: e.target.value })}
                    placeholder="ghp_... or github_pat_..."
                    className="w-full rounded border border-zinc-800 bg-zinc-950 px-3 py-1.5 font-mono text-zinc-200"
                  />
                </div>
              </div>

              <div>
                <label className="block text-zinc-400 mb-1 font-mono">
                  MSP_INVESTIGATOR_ROLE_ARN <span className="text-zinc-500">(optional)</span>
                </label>
                <input
                  type="text"
                  value={credForm.investigator_role_arn}
                  onChange={(e) => setCredForm({ ...credForm, investigator_role_arn: e.target.value })}
                  placeholder="arn:aws:iam::<account>:role/msp-investigator-readonly"
                  className="w-full rounded border border-zinc-800 bg-zinc-950 px-3 py-1.5 font-mono text-zinc-200"
                />
              </div>
            </div>

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                onClick={() => setShowCreds(false)}
                className="rounded-md border border-zinc-800 px-3 py-1.5 text-xs text-zinc-300 hover:bg-zinc-900 cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={() =>
                  runAction("creds", async () => {
                    const updated = await api.updateCredentials(credForm);
                    setConfig(updated);
                    setShowCreds(false);
                    setBanner({
                      kind: "info",
                      text: `Updated AWS credentials (mode=${updated.aws_credential_mode ?? "configured"}, region=${updated.aws_region}).`,
                    });
                  })
                }
                className="rounded-md bg-emerald-500 px-3.5 py-1.5 text-xs font-semibold text-zinc-950 hover:bg-emerald-400 cursor-pointer"
              >
                Save Credentials
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
