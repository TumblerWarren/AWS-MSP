"""Exhaustive unit & negative-safety tests for msp_policy (plan, drift, redaction, gate)."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

from msp_policy import (
    REDACTED,
    drift_entries,
    drift_hash,
    evaluate,
    fingerprint,
    redact_plan,
    to_markdown,
)
from msp_policy.redact import contains_unredacted_secret

from app.demo_fixtures import (
    clean_plan,
    combined_demo_plan,
    ec2_tag_drift_plan,
    rds_retention_drift_plan,
    sg_ssh_drift_plan,
)


def test_redaction_strips_prior_state_and_secrets():
    raw = combined_demo_plan()
    redacted = redact_plan(raw)

    assert redacted["msp_redacted"] is True
    assert "prior_state" not in redacted
    assert not contains_unredacted_secret(
        redacted,
        ["SUPER_SECRET_DB_PASSWORD_123", "sensitive-bootstrap-token-xyz", "SHOULD_ALWAYS_BE_REDACTED"],
    )

    # Sensitive fields are replaced with REDACTED marker, while non-sensitive metadata survives
    rds_drift = next(d for d in redacted["resource_drift"] if d["address"] == "aws_db_instance.main")
    assert rds_drift["change"]["before"]["password"] == REDACTED
    assert rds_drift["change"]["before"]["manage_master_user_password"] is True
    assert rds_drift["change"]["before"]["backup_retention_period"] == 1
    assert rds_drift["change"]["after"]["backup_retention_period"] == 7


def test_drift_extraction_filters_volatile_and_tags_all_duplicates():
    redacted = redact_plan(combined_demo_plan())
    entries = {e.address: e for e in drift_entries(redacted)}
    assert set(entries) == {"aws_security_group.app", "aws_instance.app", "aws_db_instance.main"}

    # EC2 tags_all.Owner should be deduplicated against tags.Owner
    ec2_paths = [c.path for c in entries["aws_instance.app"].changes]
    assert ec2_paths == ["tags.Owner"]

    # RDS latest_restorable_time is volatile and must not show up as drift
    rds_paths = [c.path for c in entries["aws_db_instance.main"].changes]
    assert rds_paths == ["backup_retention_period"]


def test_drift_hash_is_order_insensitive_and_sensitive_to_real_changes():
    p1 = redact_plan(sg_ssh_drift_plan())
    p2 = copy.deepcopy(p1)
    # Reverse ingress order in p2 -> canonical drift_hash must still match
    p2["resource_drift"][0]["change"]["after"]["ingress"].reverse()
    assert drift_hash(p1, ["aws_security_group.app"]) == drift_hash(p2, ["aws_security_group.app"])

    # Mutate port 22 -> 2222 -> drift_hash must change (stale evidence detection)
    p3 = copy.deepcopy(p1)
    p3["resource_drift"][0]["change"]["after"]["ingress"][1]["from_port"] = 2222
    assert drift_hash(p1, ["aws_security_group.app"]) != drift_hash(p3, ["aws_security_group.app"])


def test_policy_gate_allows_in_scope_restore():
    plan = redact_plan(sg_ssh_drift_plan())
    dh = drift_hash(plan, ["aws_security_group.app"])
    res = evaluate(
        plan,
        mode="restore",
        allowed=["aws_security_group.app"],
        expected_drift_hash=dh,
        expected_commit="abc12345",
        actual_commit="abc12345",
    )
    assert res["decision"] == "allow"
    md = to_markdown(res)
    assert "ALLOWED" in md


def test_policy_gate_blocks_out_of_scope_blast_radius():
    # Combined plan changes SG + EC2 + RDS, but engineer only approved SG
    plan = redact_plan(combined_demo_plan())
    res = evaluate(plan, mode="restore", allowed=["aws_security_group.app"])
    assert res["decision"] == "block"
    scope = next(c for c in res["checks"] if c["id"] == "SCOPE")
    assert scope["status"] == "fail"
    assert "aws_instance.app" in scope["addresses"]
    assert "aws_db_instance.main" in scope["addresses"]


def test_policy_gate_blocks_rds_replacement_even_if_in_scope():
    plan = redact_plan(rds_retention_drift_plan())
    plan["resource_changes"][0]["change"]["actions"] = ["delete", "create"]
    res = evaluate(plan, mode="restore", allowed=["aws_db_instance.main"])
    assert res["decision"] == "block"
    failed_ids = {c["id"] for c in res["checks"] if c["status"] == "fail"}
    assert "PROTECTED_RESOURCES" in failed_ids
    assert "NO_REPLACEMENT" in failed_ids


def test_policy_gate_blocks_stale_evidence_and_stale_commit():
    plan = redact_plan(sg_ssh_drift_plan())
    res = evaluate(
        plan,
        mode="restore",
        allowed=["aws_security_group.app"],
        expected_drift_hash="0" * 64,
        expected_commit="oldsha111",
        actual_commit="newsha222",
    )
    assert res["decision"] == "block"
    failed_ids = {c["id"] for c in res["checks"] if c["status"] == "fail"}
    assert "STALE_EVIDENCE" in failed_ids
    assert "STALE_COMMIT" in failed_ids


def test_policy_gate_update_mode_requires_zero_changes():
    dirty = redact_plan(ec2_tag_drift_plan())
    assert evaluate(dirty, mode="update")["decision"] == "block"

    clean = redact_plan(clean_plan())
    assert evaluate(clean, mode="update")["decision"] == "allow"
    assert evaluate(clean, mode="verify")["decision"] == "allow"


def test_fingerprint_changes_when_state_serial_or_commit_changes():
    fp1 = fingerprint(commit_sha="aaa", state_serial=4, state_lineage="lin", address="a.b", drift_digest="h1")
    fp2 = fingerprint(commit_sha="aaa", state_serial=5, state_lineage="lin", address="a.b", drift_digest="h1")
    fp3 = fingerprint(commit_sha="bbb", state_serial=4, state_lineage="lin", address="a.b", drift_digest="h1")
    assert len({fp1, fp2, fp3}) == 3


def test_cli_redact_and_gate_exit_codes(tmp_path: Path):
    raw_file = tmp_path / "raw.json"
    red_file = tmp_path / "red.json"
    pol_file = tmp_path / "pol.json"
    raw_file.write_text(json.dumps(sg_ssh_drift_plan()), encoding="utf-8")

    r1 = subprocess.run(
        [sys.executable, "-m", "msp_policy", "redact", "--in", str(raw_file), "--out", str(red_file)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert r1.returncode == 0

    # Allowed restore -> exit 0
    r2 = subprocess.run(
        [
            sys.executable, "-m", "msp_policy", "gate",
            "--plan", str(red_file),
            "--mode", "restore",
            "--allowed", '["aws_security_group.app"]',
            "--out", str(pol_file),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert r2.returncode == 0

    # Blocked restore (wrong scope) -> exit 2
    r3 = subprocess.run(
        [
            sys.executable, "-m", "msp_policy", "gate",
            "--plan", str(red_file),
            "--mode", "restore",
            "--allowed", '["aws_instance.app"]',
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert r3.returncode == 2
