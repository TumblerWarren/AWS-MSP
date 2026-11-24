"""Deterministic remediation policy gate.

AI investigates and prepares; this module validates. It is evaluated inside the
authorised CI/CD job against the authoritative plan, and again by the platform.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

from .drift import drift_hash
from .plan import resource_changes

MODES = ("restore", "update", "apply", "verify")

# Never destroy or replace these, regardless of mode.
PROTECTED_TYPES = frozenset(
    {
        "aws_db_instance",
        "aws_rds_cluster",
        "aws_db_subnet_group",
        "aws_vpc",
        "aws_subnet",
    }
)


@dataclass
class Check:
    id: str
    status: str  # pass | fail | warn
    message: str
    addresses: list[str] = field(default_factory=list)


def evaluate(
    plan: dict[str, Any],
    mode: str,
    allowed: Iterable[str] = (),
    *,
    expected_drift_hash: str | None = None,
    expected_commit: str | None = None,
    actual_commit: str | None = None,
    allow_create: bool = False,
) -> dict[str, Any]:
    if mode not in MODES:
        raise ValueError(f"unknown mode {mode!r}; expected one of {MODES}")
    allowed_set = set(allowed)
    checks: list[Check] = []

    # 1. Plan integrity
    if plan.get("errored"):
        checks.append(Check("PLAN_VALID", "fail", "Terraform reported an errored plan."))
    else:
        checks.append(Check("PLAN_VALID", "pass", "Plan completed without errors."))
    if not plan.get("msp_redacted"):
        checks.append(Check("PLAN_REDACTED", "warn", "Plan was not redacted before evaluation."))

    all_changes = resource_changes(plan)
    changes = [c for c in all_changes if not c.is_noop]

    # 2. Global protections
    destructive = [c.address for c in changes if (c.is_delete or c.is_replace) and c.type in PROTECTED_TYPES]
    if destructive:
        checks.append(Check("PROTECTED_RESOURCES", "fail",
                            "Plan would delete or replace protected resources.", destructive))
    else:
        checks.append(Check("PROTECTED_RESOURCES", "pass", "No protected resource is deleted or replaced."))

    # 3. Mode specific scope rules
    if mode == "restore":
        if not allowed_set:
            checks.append(Check("SCOPE_DEFINED", "fail", "Restore requires an explicit list of allowed addresses."))
        out_of_scope = [c.address for c in changes if c.address not in allowed_set]
        checks.append(
            Check("SCOPE", "fail", "Plan changes resources outside the approved scope (blast radius).", out_of_scope)
            if out_of_scope
            else Check("SCOPE", "pass", "Every change is within the approved scope.")
        )
        in_scope = [c for c in changes if c.address in allowed_set]
        replaces = [c.address for c in in_scope if c.is_replace]
        deletes = [c.address for c in in_scope if c.is_delete]
        creates = [c.address for c in in_scope if c.is_create]
        checks.append(Check("NO_REPLACEMENT", "fail" if replaces else "pass",
                            "Restore would replace resources." if replaces else "No replacements.", replaces))
        checks.append(Check("NO_DELETION", "fail" if deletes else "pass",
                            "Restore would delete resources." if deletes else "No deletions.", deletes))
        if creates and not allow_create:
            checks.append(Check("NO_CREATION", "fail", "Restore would create resources (not enabled).", creates))
        changed = {c.address for c in changes}
        nothing = sorted(a for a in allowed_set if a not in changed)
        if nothing:
            checks.append(Check("RESTORE_EFFECTIVE", "warn",
                                "No change planned for some approved addresses (already restored?).", nothing))
    elif mode in ("update", "verify"):
        addrs = [c.address for c in changes]
        checks.append(
            Check("NO_CHANGES", "fail", "Terraform still plans changes; code does not match live AWS.", addrs)
            if addrs
            else Check("NO_CHANGES", "pass", "Plan shows no changes: Terraform matches live AWS.")
        )
    elif mode == "apply":
        risky = [c.address for c in changes if c.is_delete or c.is_replace]
        if risky:
            checks.append(Check("DESTRUCTIVE_CHANGES", "warn", "Plan deletes or replaces resources.", risky))

    # 4. Stale evidence
    if expected_commit:
        if actual_commit and actual_commit != expected_commit:
            checks.append(Check("STALE_COMMIT", "fail",
                                f"Terraform commit changed since the decision ({expected_commit[:8]} -> {actual_commit[:8]})."))
        else:
            checks.append(Check("STALE_COMMIT", "pass", "Terraform commit matches the approved evidence."))
    actual_hash = None
    if expected_drift_hash:
        actual_hash = drift_hash(plan, allowed_set)
        if actual_hash != expected_drift_hash:
            checks.append(Check("STALE_EVIDENCE", "fail",
                                "Live drift differs from the evidence the engineer approved.", sorted(allowed_set)))
        else:
            checks.append(Check("STALE_EVIDENCE", "pass", "Live drift matches the approved evidence."))

    summary = {"create": 0, "update": 0, "delete": 0, "replace": 0, "no-op": 0}
    for c in all_changes:
        summary[c.kind if c.kind in summary else "no-op"] += 1

    decision = "block" if any(c.status == "fail" for c in checks) else "allow"
    return {
        "decision": decision,
        "mode": mode,
        "allowed_addresses": sorted(allowed_set),
        "checks": [asdict(c) for c in checks],
        "summary": summary,
        "changes": [{"address": c.address, "type": c.type, "actions": list(c.actions)} for c in changes],
        "drift_hash": actual_hash,
        "terraform_version": plan.get("terraform_version"),
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
    }


def to_markdown(result: dict[str, Any]) -> str:
    icon = {"pass": "✅", "fail": "❌", "warn": "⚠️"}
    verdict = "ALLOWED" if result["decision"] == "allow" else "BLOCKED"
    s = result["summary"]
    lines = [
        f"### MSP policy gate: **{verdict}** (mode `{result['mode']}`)",
        "",
        f"Plan: {s['create']} to create, {s['update']} to update, {s['replace']} to replace, {s['delete']} to delete.",
        "",
        "| Check | Result | Detail |",
        "|---|---|---|",
    ]
    for c in result["checks"]:
        addrs = ", ".join(f"`{a}`" for a in c["addresses"])
        detail = c["message"] + (f" {addrs}" if addrs else "")
        lines.append(f"| `{c['id']}` | {icon.get(c['status'], c['status'])} | {detail} |")
    return "\n".join(lines) + "\n"
