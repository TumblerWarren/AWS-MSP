import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  CheckCircle2,
  Database,
  Play,
  RefreshCw,
  Search,
  Shield,
  Terminal,
} from "lucide-react";
import { api } from "./api";
import { FindingDetailView } from "./components/FindingDetail";
import type { FindingDetail, FindingSummary, PlatformConfig } from "./types";

const sevDot: Record<string, string> = {
  critical: "bg-red-500",
  high: "bg-orange-400",
  medium: "bg-amber-400",
  low: "bg-zinc-500",
};

export function App() {
  const [config, setConfig] = useState<PlatformConfig | null>(null);
  const [findings, setFindings] = useState<FindingSummary[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<FindingDetail | null>(null);
  const [filter, setFilter] = useState<string>("all");
  const [query, setQuery] = useState("");
  const [busyAction, setBusyAction] = useState<string | null>(null);
  const [banner, setBanner] = useState<{ kind: "info" | "error"; text: string } | null>(null);

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

  useEffect(() => {
    refreshList(false).catch((err) => setBanner({ kind: "error", text: String(err) }));
  }, []);

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

  return (
    <div className="min-h-screen flex flex-col bg-[#09090b] text-zinc-100">
      {/* Top Navbar */}
      <header className="h-13 border-b border-zinc-800/90 bg-[#0b0b0e] px-4 flex items-center justify-between gap-4 sticky top-0 z-20">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded-md bg-emerald-500/15 border border-emerald-500/40 flex items-center justify-center">
              <Shield className="w-3.5 h-3.5 text-emerald-400" />
            </div>
            <span className="font-semibold text-sm tracking-tight">MSP</span>
            <span className="text-xs text-zinc-500 hidden sm:inline">Drift Investigation & Reconciliation</span>
          </div>

          {config && (
            <div className="hidden md:flex items-center gap-2 pl-3 border-l border-zinc-800 font-mono text-[11px]">
              <span className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 ${config.github_configured ? "border-emerald-500/30 text-emerald-300 bg-emerald-500/5" : "border-zinc-800 text-zinc-400 bg-zinc-900"}`}>
                <span className={`w-1.5 h-1.5 rounded-full ${config.github_configured ? "bg-emerald-400" : "bg-zinc-500"}`} />
                {config.github_configured ? config.github_repo : "GitHub: local mode"}
              </span>
              <span className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 ${config.aws_credentials_detected ? "border-emerald-500/30 text-emerald-300 bg-emerald-500/5" : "border-zinc-800 text-zinc-400 bg-zinc-900"}`}>
                <span className={`w-1.5 h-1.5 rounded-full ${config.aws_credentials_detected ? "bg-emerald-400" : "bg-zinc-500"}`} />
                {config.aws_credentials_detected ? `AWS: ${config.aws_region}` : "AWS: offline preview"}
              </span>
            </div>
          )}
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() =>
              runAction("seed", async () => {
                const res = await api.seedDemo();
                await refreshList(false);
                setBanner({ kind: "info", text: `Loaded ${res.created} sandbox drift scenario(s) (SG, EC2, RDS).` });
              })
            }
            disabled={busyAction !== null}
            className="inline-flex items-center gap-1.5 rounded-md border border-zinc-700 bg-zinc-900 px-2.5 py-1.5 text-xs font-medium text-zinc-200 hover:bg-zinc-800 disabled:opacity-50 cursor-pointer"
          >
            <Database className="w-3.5 h-3.5 text-zinc-400" />
            Load Demo Drift
          </button>

          <button
            onClick={() =>
              runAction("scan", async () => {
                const res = await api.triggerScan();
                await refreshList();
                setBanner({ kind: "info", text: res.message });
              })
            }
            disabled={busyAction !== null}
            className="inline-flex items-center gap-1.5 rounded-md bg-zinc-100 px-3 py-1.5 text-xs font-semibold text-zinc-950 hover:bg-white disabled:opacity-50 cursor-pointer"
          >
            <Play className="w-3 h-3" />
            Run Drift Scan
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

      {/* Workspace: Left Drift Inbox + Right Finding Detail */}
      <div className="flex-1 flex min-h-0">
        <aside className="w-80 lg:w-96 border-r border-zinc-800/80 bg-[#0b0b0e] flex flex-col shrink-0">
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

          <div className="flex-1 overflow-y-auto divide-y divide-zinc-800/60">
            {filtered.length === 0 ? (
              <div className="p-6 text-center space-y-2">
                <Terminal className="w-6 h-6 text-zinc-600 mx-auto" />
                <div className="text-xs font-medium text-zinc-300">No drift findings</div>
                <p className="text-[11px] text-zinc-500">
                  Click <span className="text-zinc-300">Load Demo Drift</span> to test locally, or{" "}
                  <span className="text-zinc-300">Run Drift Scan</span> once GitHub is connected.
                </p>
              </div>
            ) : (
              filtered.map((f) => {
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
              })
            )}
          </div>
        </aside>

        <main className="flex-1 overflow-y-auto">
          {detail ? (
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
              onRestore={(rationale) =>
                runAction("restore", async () => {
                  const updated = await api.remediateRestore(detail.id, {
                    decided_by: "engineer",
                    rationale,
                    expected_fingerprint: detail.fingerprint,
                  });
                  setDetail(updated);
                  await refreshList();
                })
              }
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
            />
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
    </div>
  );
}

export default App;
