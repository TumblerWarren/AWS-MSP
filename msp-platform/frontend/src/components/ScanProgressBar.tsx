import { CheckCircle2, Clock, ExternalLink, Loader2, Radio, X, XCircle } from "lucide-react";
import type { ScanProgress } from "../types";

interface Props {
  scan: ScanProgress;
  onOpenActivity: () => void;
  onDismiss: () => void;
}

export function ScanProgressBar({ scan, onOpenActivity, onDismiss }: Props) {
  const isRunning = scan.status === "running";
  const isFailed = scan.status === "failed";
  const isPartial = scan.status === "partial_failure";
  const latestStep = scan.steps.length > 0 ? scan.steps[scan.steps.length - 1] : null;

  const barColor = isFailed
    ? "bg-red-500"
    : isPartial
      ? "bg-amber-400"
      : isRunning
        ? "bg-emerald-400"
        : "bg-emerald-500";

  return (
    <div className="border-b border-zinc-800/90 bg-[#0d0d11] px-4 py-3">
      <div className="max-w-7xl mx-auto space-y-2.5">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2.5 min-w-0">
            {isRunning ? (
              <Loader2 className="w-4 h-4 text-emerald-400 animate-spin shrink-0" />
            ) : isFailed ? (
              <XCircle className="w-4 h-4 text-red-400 shrink-0" />
            ) : (
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
            )}
            <div className="min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs font-semibold text-zinc-100">{scan.message}</span>
                <span className="font-mono text-[11px] text-zinc-400">{scan.progress_pct}%</span>
                {isRunning && (
                  <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 font-mono text-[10px] text-emerald-300">
                    <Radio className="w-2.5 h-2.5 animate-pulse" />
                    auto-syncing
                  </span>
                )}
              </div>
              {latestStep && (
                <p className="text-[11px] font-mono text-zinc-400 truncate mt-0.5">
                  {latestStep.message}
                </p>
              )}
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              type="button"
              onClick={onOpenActivity}
              className="rounded-md border border-zinc-700 bg-zinc-900 px-2.5 py-1 text-[11px] font-medium text-zinc-200 hover:bg-zinc-800 cursor-pointer"
            >
              View Live Activity
            </button>
            {!isRunning && (
              <button
                type="button"
                onClick={onDismiss}
                className="rounded p-1 text-zinc-500 hover:text-zinc-200 cursor-pointer"
                title="Dismiss progress card"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        </div>

        {/* Progress Bar */}
        <div className="h-1.5 w-full rounded-full bg-zinc-800 overflow-hidden">
          <div
            className={`h-full rounded-full transition-all duration-500 ${barColor} ${isRunning ? "animate-pulse" : ""}`}
            style={{ width: `${Math.max(5, Math.min(100, scan.progress_pct))}%` }}
          />
        </div>

        {/* Per-stack live pills */}
        <div className="flex flex-wrap items-center gap-2">
          {scan.targets.map((t) => {
            const key = `${t.repo}:${t.root_dir ?? "default"}`;
            const pillStyle =
              t.status === "synced"
                ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-300"
                : t.status === "failed"
                  ? "border-red-500/40 bg-red-500/10 text-red-300"
                  : t.status === "in_progress" || t.status === "syncing"
                    ? "border-sky-500/30 bg-sky-500/10 text-sky-300"
                    : "border-zinc-800 bg-zinc-900 text-zinc-400";
            return (
              <div
                key={key}
                className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-1 font-mono text-[11px] ${pillStyle}`}
              >
                {t.status === "synced" && <CheckCircle2 className="w-3 h-3 shrink-0" />}
                {t.status === "failed" && <XCircle className="w-3 h-3 shrink-0" />}
                {(t.status === "in_progress" || t.status === "syncing") && (
                  <Loader2 className="w-3 h-3 animate-spin shrink-0" />
                )}
                {t.status === "queued" && <Clock className="w-3 h-3 shrink-0" />}
                <span>{t.label}</span>
                <span className="opacity-75">
                  {t.status === "synced"
                    ? `${t.findings_count} drift`
                    : t.status === "in_progress"
                      ? "planning..."
                      : t.status === "syncing"
                        ? "syncing S3..."
                        : t.status}
                </span>
                {t.run_url && (
                  <a
                    href={t.run_url}
                    target="_blank"
                    rel="noreferrer"
                    className="opacity-75 hover:opacity-100 ml-0.5"
                    title={`Open GitHub Actions run #${t.run_number ?? ""}`}
                  >
                    <ExternalLink className="w-3 h-3" />
                  </a>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
