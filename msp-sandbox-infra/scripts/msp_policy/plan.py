"""Terraform plan JSON parsing and attribute diffing.

Stdlib-only on purpose: this package is vendored into IaC repositories and runs
inside CI/CD as the deterministic policy gate.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Attributes that change on their own and must never be reported as drift.
VOLATILE_ATTRIBUTES: dict[str, frozenset[str]] = {
    "*": frozenset({"timeouts"}),
    "aws_db_instance": frozenset({"latest_restorable_time", "engine_version_actual", "replicas", "status"}),
    "aws_instance": frozenset({"instance_state"}),
}

_EMPTY = (None, "", [], {})


def load_plan(path: str | Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def canonical(value: Any) -> Any:
    """Return an order-insensitive canonical form for comparison/hashing."""
    if isinstance(value, dict):
        return {k: canonical(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        items = [canonical(v) for v in value]
        try:
            return sorted(items, key=lambda v: json.dumps(v, sort_keys=True, default=str))
        except TypeError:  # pragma: no cover - defensive
            return items
    return value


def _is_empty(value: Any) -> bool:
    return any(value == e and type(value) is type(e) for e in _EMPTY if e is not None) or value is None


def _equal(a: Any, b: Any) -> bool:
    if _is_empty(a) and _is_empty(b):
        return True
    return canonical(a) == canonical(b)


@dataclass(frozen=True)
class AttrChange:
    path: str
    before: Any
    after: Any
    added: list[Any] = field(default_factory=list)
    removed: list[Any] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "before": self.before,
            "after": self.after,
            "added": self.added,
            "removed": self.removed,
        }

    def hash_dict(self) -> dict[str, Any]:
        return {"path": self.path, "before": canonical(self.before), "after": canonical(self.after)}


def _list_delta(before: list[Any] | None, after: list[Any] | None) -> tuple[list[Any], list[Any]]:
    b = before or []
    a = after or []
    bk = [json.dumps(canonical(x), sort_keys=True, default=str) for x in b]
    ak = [json.dumps(canonical(x), sort_keys=True, default=str) for x in a]
    added = [x for x, k in zip(a, ak) if k not in bk]
    removed = [x for x, k in zip(b, bk) if k not in ak]
    return added, removed


def diff_values(before: Any, after: Any, path: str = "") -> list[AttrChange]:
    if isinstance(before, dict) and isinstance(after, dict):
        out: list[AttrChange] = []
        for key in sorted(set(before) | set(after)):
            sub = f"{path}.{key}" if path else str(key)
            out.extend(diff_values(before.get(key), after.get(key), sub))
        return out
    if _equal(before, after):
        return []
    if isinstance(before, list) or isinstance(after, list):
        added, removed = _list_delta(before if isinstance(before, list) else None,
                                     after if isinstance(after, list) else None)
        return [AttrChange(path, before, after, added, removed)]
    return [AttrChange(path, before, after)]


def attribute_changes(resource_type: str, before: Any, after: Any) -> list[AttrChange]:
    """Diff two resource objects, dropping volatile attributes and tags_all duplicates."""
    ignored = VOLATILE_ATTRIBUTES["*"] | VOLATILE_ATTRIBUTES.get(resource_type, frozenset())
    changes = [
        c for c in diff_values(before or {}, after or {})
        if c.path.split(".", 1)[0] not in ignored
    ]
    tag_changes = {c.path.split(".", 1)[1]: c for c in changes if c.path.startswith("tags.")}
    result = []
    for c in changes:
        if c.path.startswith("tags_all."):
            key = c.path.split(".", 1)[1]
            twin = tag_changes.get(key)
            if twin is not None and _equal(twin.before, c.before) and _equal(twin.after, c.after):
                continue
        result.append(c)
    return result


@dataclass(frozen=True)
class ResourceChange:
    address: str
    type: str
    name: str
    mode: str
    module_address: str | None
    actions: tuple[str, ...]
    before: Any
    after: Any
    action_reason: str | None = None

    @property
    def is_noop(self) -> bool:
        return set(self.actions) <= {"no-op", "read"}

    @property
    def is_replace(self) -> bool:
        return "delete" in self.actions and "create" in self.actions

    @property
    def is_delete(self) -> bool:
        return self.actions == ("delete",)

    @property
    def is_create(self) -> bool:
        return self.actions == ("create",)

    @property
    def is_update(self) -> bool:
        return self.actions == ("update",)

    @property
    def kind(self) -> str:
        if self.is_noop:
            return "no-op"
        if self.is_replace:
            return "replace"
        return self.actions[0]

    @property
    def resource_id(self) -> str | None:
        for obj in (self.before, self.after):
            if isinstance(obj, dict) and isinstance(obj.get("id"), str):
                return obj["id"]
        return None


def _parse(entry: dict[str, Any]) -> ResourceChange:
    change = entry.get("change") or {}
    return ResourceChange(
        address=entry["address"],
        type=entry.get("type", ""),
        name=entry.get("name", ""),
        mode=entry.get("mode", "managed"),
        module_address=entry.get("module_address"),
        actions=tuple(change.get("actions") or ("no-op",)),
        before=change.get("before"),
        after=change.get("after"),
        action_reason=entry.get("action_reason"),
    )


def resource_changes(plan: dict[str, Any]) -> list[ResourceChange]:
    return [_parse(e) for e in plan.get("resource_changes") or [] if e.get("mode", "managed") == "managed"]


def resource_drift(plan: dict[str, Any]) -> list[ResourceChange]:
    return [_parse(e) for e in plan.get("resource_drift") or [] if e.get("mode", "managed") == "managed"]
