"""CI checks for a reviewed restore plan. Raw state and plans stay on the runner."""

from __future__ import annotations

import json
import os
import subprocess
import sys

from .drift import drift_entries
from .plan import attribute_changes, load_plan, resource_changes
from .redact import redact_plan


def _check_workspace(verify: bool = False) -> None:
    env = os.environ
    account = subprocess.check_output(["aws", "sts", "get-caller-identity", "--query", "Account", "--output", "text"], text=True).strip()
    state = json.loads(subprocess.check_output(["terraform", "state", "pull"], stderr=subprocess.DEVNULL))
    actual = (account, env["AWS_REGION"], env["TF_WORKING_DIR"], env["GITHUB_SHA"], state.get("lineage"), str(state.get("serial")))
    expected = tuple(env[f"EXPECTED_{key}"] for key in ("ACCOUNT", "REGION", "ROOT", "COMMIT", "LINEAGE", "SERIAL"))
    matches = actual[:-1] == expected[:-1] if verify else actual == expected
    if not matches:
        raise SystemExit("Workspace, revision, or state changed. Sync a fresh scan and review again.")
    if not verify:
        head = subprocess.check_output(["git", "ls-remote", "--refs", "origin", env["GITHUB_REF"]], text=True).split()
        if not head or head[0] != env["EXPECTED_COMMIT"]:
            raise SystemExit("The reviewed Git branch moved. Sync a fresh scan and review again.")


def _compare(reviewed_path: str, fresh_path: str) -> None:
    reviewed, fresh = load_plan(reviewed_path), load_plan(fresh_path)
    for plan in (reviewed, fresh):
        plan.pop("timestamp", None)
    if reviewed != fresh:
        raise SystemExit("Terraform plan changed after review. Prepare a new restore plan.")


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
