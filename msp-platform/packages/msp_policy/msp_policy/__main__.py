"""CLI used inside CI/CD jobs.

    python -m msp_policy redact --in plan.json --out plan.redacted.json
    python -m msp_policy gate   --plan plan.redacted.json --mode restore --allowed '["a.b"]' --out policy.json
    python -m msp_policy meta   --plan plan.redacted.json --out meta.json --commit $GITHUB_SHA ...
    python -m msp_policy drift  --plan plan.redacted.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from .drift import drift_entries
from .gate import MODES, evaluate, to_markdown
from .plan import load_plan
from .redact import redact_plan


def _write(path: str | None, data: object) -> None:
    text = json.dumps(data, indent=2, default=str)
    if path:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    else:
        print(text)


def _cmd_redact(a: argparse.Namespace) -> int:
    _write(a.out, redact_plan(load_plan(a.inp)))
    return 0


def _cmd_gate(a: argparse.Namespace) -> int:
    allowed = json.loads(a.allowed) if a.allowed else []
    if isinstance(allowed, str):
        allowed = [allowed]
    result = evaluate(
        load_plan(a.plan),
        a.mode,
        allowed,
        expected_drift_hash=a.expected_drift_hash or None,
        expected_commit=a.expected_commit or None,
        actual_commit=a.actual_commit or None,
        allow_create=a.allow_create,
    )
    _write(a.out, result)
    md = to_markdown(result)
    if a.markdown:
        with open(a.markdown, "a", encoding="utf-8") as fh:
            fh.write(md)
    print(md, file=sys.stderr)
    return 0 if result["decision"] == "allow" else 2


def _cmd_meta(a: argparse.Namespace) -> int:
    plan = load_plan(a.plan)
    entries = drift_entries(plan)
    _write(
        a.out,
        {
            "workflow": a.workflow,
            "correlation_id": a.correlation_id,
            "commit_sha": a.commit,
            "ref": a.ref,
            "run_id": a.run_id,
            "root_dir": a.root_dir,
            "account_id": a.account_id,
            "region": a.region,
            "state_serial": int(a.state_serial) if a.state_serial not in (None, "", "null") else None,
            "state_lineage": a.state_lineage or None,
            "terraform_version": plan.get("terraform_version"),
            "drift_count": len(entries),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        },
    )
    return 0


def _cmd_drift(a: argparse.Namespace) -> int:
    _write(a.out, [e.to_dict() for e in drift_entries(load_plan(a.plan))])
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="msp_policy")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("redact")
    r.add_argument("--in", dest="inp", required=True)
    r.add_argument("--out")
    r.set_defaults(fn=_cmd_redact)

    g = sub.add_parser("gate")
    g.add_argument("--plan", required=True)
    g.add_argument("--mode", required=True, choices=MODES)
    g.add_argument("--allowed", default="")
    g.add_argument("--expected-drift-hash", default="")
    g.add_argument("--expected-commit", default="")
    g.add_argument("--actual-commit", default="")
    g.add_argument("--allow-create", action="store_true")
    g.add_argument("--out")
    g.add_argument("--markdown", help="append markdown summary to this file (e.g. $GITHUB_STEP_SUMMARY)")
    g.set_defaults(fn=_cmd_gate)

    m = sub.add_parser("meta")
    m.add_argument("--plan", required=True)
    m.add_argument("--out")
    for flag in ("workflow", "correlation-id", "commit", "ref", "run-id", "root-dir", "account-id",
                 "region", "state-serial", "state-lineage"):
        m.add_argument(f"--{flag}", default=None)
    m.set_defaults(fn=_cmd_meta)

    d = sub.add_parser("drift")
    d.add_argument("--plan", required=True)
    d.add_argument("--out")
    d.set_defaults(fn=_cmd_drift)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
