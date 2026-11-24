"""Drift extraction and evidence hashing."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from .plan import AttrChange, ResourceChange, attribute_changes, resource_changes, resource_drift


@dataclass
class DriftEntry:
    address: str
    type: str
    name: str
    module_address: str | None
    kind: str  # "modified" | "deleted"
    resource_id: str | None
    changes: list[AttrChange] = field(default_factory=list)
    restore_actions: tuple[str, ...] | None = None
    restore_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "type": self.type,
            "name": self.name,
            "module_address": self.module_address,
            "kind": self.kind,
            "resource_id": self.resource_id,
            "changes": [c.to_dict() for c in self.changes],
            "restore_actions": list(self.restore_actions) if self.restore_actions else None,
            "restore_reason": self.restore_reason,
        }


def drift_entries(plan: dict[str, Any]) -> list[DriftEntry]:
    pending: dict[str, ResourceChange] = {c.address: c for c in resource_changes(plan)}
    out: list[DriftEntry] = []
    for d in resource_drift(plan):
        restore = pending.get(d.address)
        if d.is_delete or (d.before is not None and d.after is None):
            kind, changes = "deleted", []
        else:
            kind, changes = "modified", attribute_changes(d.type, d.before, d.after)
            if not changes:
                continue  # volatile noise only
        out.append(
            DriftEntry(
                address=d.address,
                type=d.type,
                name=d.name,
                module_address=d.module_address,
                kind=kind,
                resource_id=d.resource_id,
                changes=changes,
                restore_actions=restore.actions if restore else None,
                restore_reason=restore.action_reason if restore else None,
            )
        )
    return out


def drift_hash(plan: dict[str, Any], addresses: Iterable[str]) -> str:
    """Stable hash of the drift observed for the given addresses.

    Used to bind an engineer's decision to the exact evidence they reviewed: the
    CI gate recomputes this from a fresh plan and blocks when it differs.
    """
    by_addr = {e.address: e for e in drift_entries(plan)}
    payload = []
    for address in sorted(set(addresses)):
        entry = by_addr.get(address)
        payload.append(
            {
                "address": address,
                "kind": entry.kind if entry else None,
                "changes": sorted((c.hash_dict() for c in entry.changes), key=lambda c: c["path"]) if entry else [],
            }
        )
    blob = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def fingerprint(*, commit_sha: str | None, state_serial: Any, state_lineage: str | None,
                address: str, drift_digest: str) -> str:
    blob = json.dumps(
        {
            "commit": commit_sha,
            "serial": state_serial,
            "lineage": state_lineage,
            "address": address,
            "drift": drift_digest,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()
