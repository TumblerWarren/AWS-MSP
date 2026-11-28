"""CI checks for a reviewed restore plan. Raw state and plans stay on the runner."""

from __future__ import annotations

import json
import os
import subprocess
import sys

from typing import Any

from .drift import drift_entries
from .plan import attribute_changes, canonical, load_plan, resource_changes
from .redact import redact_plan


def _check_workspace(verify: bool = False) -> None:
    env = os.environ
    account = subprocess.check_output(["aws", "sts", "get-caller-identity", "--query", "Account", "--output", "text"], text=True).strip()
    state = json.loads(subprocess.check_output(["terraform", "state", "pull"], stderr=subprocess.DEVNULL))
    keys = ("ACCOUNT", "REGION", "ROOT", "COMMIT", "LINEAGE", "SERIAL")
    actual = (account, env["AWS_REGION"], env["TF_WORKING_DIR"], env["GITHUB_SHA"], state.get("lineage") or "", str(state.get("serial", "")))
    expected = tuple(env[f"EXPECTED_{key}"] for key in keys)
    pairs = list(zip(keys, expected, actual))
    checked = pairs[:-1] if verify else pairs
    mismatches = [f"{k} (expected={exp!r}, actual={act!r})" for k, exp, act in checked if exp != act]
    if mismatches:
        raise SystemExit(
            "Workspace, revision, or state changed [" + "; ".join(mismatches) + "]. Sync a fresh scan and review again."
        )
    if not verify:
        head = subprocess.check_output(["git", "ls-remote", "--refs", "origin", env["GITHUB_REF"]], text=True).split()
        if not head or head[0] != env["EXPECTED_COMMIT"]:
            raise SystemExit(
                f"The reviewed Git branch moved (expected={env['EXPECTED_COMMIT']!r}, head={(head[0] if head else None)!r}). "
                "Sync a fresh scan and review again."
            )


def _plan_signature(plan: dict[str, Any]) -> dict[str, Any]:
    """Return a canonical, order-insensitive signature of managed plan changes and drift."""
    if plan.get("errored") or plan.get("complete") is False:
        raise SystemExit("Terraform plan is errored or incomplete.")

    after_unknown_by_addr = {
        entry["address"]: canonical((entry.get("change") or {}).get("after_unknown"))
        for entry in plan.get("resource_changes") or []
        if entry.get("mode", "managed") == "managed" and "address" in entry
    }

    changes = sorted(
        (
            {
                "address": change.address,
                "type": change.type,
                "actions": list(change.actions),
                "action_reason": change.action_reason,
                "changes": sorted(
                    (diff.hash_dict() for diff in attribute_changes(change.type, change.before, change.after)),
                    key=lambda d: d["path"],
                ),
                "after_unknown": after_unknown_by_addr.get(change.address),
            }
            for change in resource_changes(plan)
            if not change.is_noop
        ),
        key=lambda item: item["address"],
    )

    drift = sorted(
        (
            {
                "address": entry.address,
                "type": entry.type,
                "kind": entry.kind,
                "resource_id": entry.resource_id,
                "changes": sorted((diff.hash_dict() for diff in entry.changes), key=lambda d: d["path"]),
            }
            for entry in drift_entries(plan)
        ),
        key=lambda item: item["address"],
    )

    raw_outputs = plan.get("output_changes") or {}
    outputs = {
        name: {
            "actions": list((ch or {}).get("actions") or []),
            "before": canonical((ch or {}).get("before")),
            "after": canonical((ch or {}).get("after")),
            "after_unknown": canonical((ch or {}).get("after_unknown")),
        }
        for name, ch in sorted(raw_outputs.items())
    }

    return {
        "resource_changes": changes,
        "resource_drift": drift,
        "output_changes": outputs,
    }


def _diff_addresses(rev_items: list[dict[str, Any]], fresh_items: list[dict[str, Any]]) -> list[str]:
    rev_map = {item["address"]: item for item in rev_items}
    fresh_map = {item["address"]: item for item in fresh_items}
    return sorted(addr for addr in set(rev_map) | set(fresh_map) if rev_map.get(addr) != fresh_map.get(addr))


def _compare(reviewed_path: str, fresh_path: str) -> None:
    reviewed, fresh = load_plan(reviewed_path), load_plan(fresh_path)
    rev_sig = _plan_signature(reviewed)
    fresh_sig = _plan_signature(fresh)
    if rev_sig != fresh_sig:
        parts: list[str] = []
        for section in ("resource_changes", "resource_drift"):
            if rev_sig[section] != fresh_sig[section]:
                addrs = _diff_addresses(rev_sig[section], fresh_sig[section])
                parts.append(f"{section}: {', '.join(addrs)}" if addrs else section)
        if rev_sig["output_changes"] != fresh_sig["output_changes"]:
            rev_out, fresh_out = rev_sig["output_changes"], fresh_sig["output_changes"]
            names = sorted(k for k in set(rev_out) | set(fresh_out) if rev_out.get(k) != fresh_out.get(k))
            parts.append(f"output_changes: {', '.join(names)}" if names else "output_changes")
        detail = "; ".join(parts)
        raise SystemExit(f"Terraform plan changed after review ({detail}). Prepare a new restore plan.")


def _review(path: str) -> None:
    plan = load_plan(path)
    changes = [change for change in resource_changes(plan) if not change.is_noop]
    selected = set(json.loads(os.environ["ALLOWED_ADDRESSES"]))
    if plan.get("complete") is False or {change.address for change in changes} != selected:
        raise SystemExit("The full plan must contain every reviewed resource and no additional changes.")
    print("\n### Proposed changes\n")
    for change in changes:
        print(f"- {change.address} ({', '.join(change.actions)})")
        for difference in attribute_changes(change.type, change.before, change.after):
            evidence = json.dumps(difference.hash_dict(), ensure_ascii=True).replace("`", "\\u0060").replace("<", "\\u003c")
            print(f"  - `{evidence}`")


def _verify(path: str) -> None:
    _check_workspace(verify=True)
    targets = set(json.loads(os.environ["ALLOWED_ADDRESSES"]))
    plan = redact_plan(load_plan(path))
    unresolved = targets & (
        {entry.address for entry in drift_entries(plan)}
        | {entry.address for entry in resource_changes(plan) if not entry.is_noop}
    )
    if plan.get("errored") or plan.get("complete") is False or unresolved:
        raise SystemExit("Verification still sees drift or planned changes on: " + ", ".join(sorted(unresolved)))
    print("Verified restored resources: " + ", ".join(sorted(targets)))


if __name__ == "__main__":
    command, *args = sys.argv[1:]
    {"check": _check_workspace, "compare": _compare, "review": _review, "verify": _verify}[command](*args)
