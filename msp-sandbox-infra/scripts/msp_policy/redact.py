"""Plan redaction: nothing sensitive may leave CI or reach an AI agent."""

from __future__ import annotations

import copy
import re
from typing import Any

REDACTED = "(sensitive)"

SENSITIVE_KEY_RE = re.compile(
    r"(password|passwd|secret|token|private_key|access_key|credential|user_data|connection_string)",
    re.IGNORECASE,
)

# Only these top-level plan keys survive redaction. prior_state, planned_values,
# configuration and variables are dropped entirely (they can carry raw values).
KEPT_KEYS = (
    "format_version",
    "terraform_version",
    "resource_drift",
    "resource_changes",
    "relevant_attributes",
    "output_changes",
    "applyable",
    "complete",
    "errored",
    "timestamp",
)


def _apply_mask(value: Any, mask: Any) -> Any:
    if mask is True:
        return None if value is None else REDACTED
    if isinstance(value, dict) and isinstance(mask, dict):
        return {k: _apply_mask(v, mask.get(k, False)) for k, v in value.items()}
    if isinstance(value, list) and isinstance(mask, list):
        return [_apply_mask(v, mask[i] if i < len(mask) else False) for i, v in enumerate(value)]
    return value


def _scrub_keys(value: Any) -> Any:
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if (
                SENSITIVE_KEY_RE.search(str(k))
                and not isinstance(v, bool)
                and v not in (None, "", [], {})
                and not str(k).endswith(("_arn", "_on_change"))
                and not str(k).startswith("manage_")
            ):
                out[k] = REDACTED
            else:
                out[k] = _scrub_keys(v)
        return out
    if isinstance(value, list):
        return [_scrub_keys(v) for v in value]
    return value


def _redact_change(change: dict[str, Any]) -> dict[str, Any]:
    change = dict(change)
    for side in ("before", "after"):
        if side in change:
            masked = _apply_mask(change.get(side), change.get(f"{side}_sensitive", False))
            change[side] = _scrub_keys(masked)
    return change


def redact_plan(plan: dict[str, Any]) -> dict[str, Any]:
    plan = copy.deepcopy(plan)
    out: dict[str, Any] = {k: plan[k] for k in KEPT_KEYS if k in plan}
    for key in ("resource_drift", "resource_changes"):
        out[key] = [
            {**entry, "change": _redact_change(entry.get("change") or {})}
            for entry in out.get(key) or []
        ]
    if "output_changes" in out:
        out["output_changes"] = {
            name: _redact_change(ch) for name, ch in (out["output_changes"] or {}).items()
        }
    out["msp_redacted"] = True
    return out


def contains_unredacted_secret(obj: Any, needles: list[str]) -> bool:
    """Test helper: True if any raw needle value appears anywhere in obj."""
    if isinstance(obj, dict):
        return any(contains_unredacted_secret(v, needles) for v in obj.values())
    if isinstance(obj, list):
        return any(contains_unredacted_secret(v, needles) for v in obj)
    return isinstance(obj, str) and any(n in obj for n in needles)
