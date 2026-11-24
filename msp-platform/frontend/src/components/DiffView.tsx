import type { AttrChange } from "../types";

function formatVal(val: unknown): string {
  if (val === null || val === undefined) return "null";
  if (typeof val === "string") return JSON.stringify(val);
  if (typeof val === "number" || typeof val === "boolean") return String(val);
  return JSON.stringify(val, null, 2);
}

export function DiffView({ changes }: { changes: AttrChange[] }) {
  if (!changes.length) {
    return (
      <div className="rounded-lg border border-zinc-800 bg-zinc-950/60 px-4 py-3 text-xs text-zinc-400 font-mono">
        Resource deleted out-of-band or no attribute-level diff reported.
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-zinc-800 bg-[#0c0c0f] overflow-hidden">
      <div className="flex items-center justify-between border-b border-zinc-800/80 bg-zinc-900/50 px-3.5 py-2 text-[11px] font-mono text-zinc-400">
        <span>Expected (Terraform) → Actual (Live AWS)</span>
        <span>{changes.length} attribute{changes.length === 1 ? "" : "s"} drifted</span>
      </div>
      <div className="divide-y divide-zinc-800/70">
        {changes.map((c) => {
          const hasListDelta = c.added.length > 0 || c.removed.length > 0;
          return (
            <div key={c.path} className="font-mono text-xs">
              <div className="bg-zinc-900/30 px-3.5 py-1.5 text-zinc-300 font-medium border-b border-zinc-800/50">
                {c.path}
              </div>
              {hasListDelta ? (
                <div className="divide-y divide-zinc-900">
                  {c.removed.map((item, idx) => (
                    <pre
                      key={`rm-${idx}`}
                      className="bg-red-950/25 text-red-300 px-3.5 py-2 overflow-x-auto whitespace-pre-wrap"
                    >
                      - {formatVal(item)}
                    </pre>
                  ))}
                  {c.added.map((item, idx) => (
                    <pre
                      key={`add-${idx}`}
                      className="bg-emerald-950/25 text-emerald-300 px-3.5 py-2 overflow-x-auto whitespace-pre-wrap"
                    >
                      + {formatVal(item)}
                    </pre>
                  ))}
                </div>
              ) : (
                <div className="divide-y divide-zinc-900">
                  <pre className="bg-red-950/25 text-red-300 px-3.5 py-2 overflow-x-auto whitespace-pre-wrap">
                    - {formatVal(c.before)}
                  </pre>
                  <pre className="bg-emerald-950/25 text-emerald-300 px-3.5 py-2 overflow-x-auto whitespace-pre-wrap">
                    + {formatVal(c.after)}
                  </pre>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
