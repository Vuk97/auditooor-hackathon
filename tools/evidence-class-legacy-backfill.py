#!/usr/bin/env python3
"""Backfill legacy ``evidence_class`` fields on bounded PR560 artifacts.

This is a one-time migration helper for old local artifacts whose current
producers either no longer exist or no longer overwrite the stale files.  It is
intentionally conservative: it only stamps known legacy artifact families and
never promotes advisory rows to proof.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.evidence_class_legacy_backfill.v1"
PROVIDER_CLOSURE_GLOB = ".audit_logs/pr560_worker_*/provider_local_verification_closure.json"
EXECUTION_OUTCOME_GLOB = ".auditooor/execution_proof_outcomes/*.json"
LIVE_TRIAGE_GLOB = ".audit_logs/pr560_worker_*/live_provider_result_triage.json"
SCANNER_AUTONOMY_EXECUTION_GLOB = ".auditooor/scanner_autonomy_execution.json"
GENERATED = "generated_hypothesis"
SCAFFOLDED = "scaffolded_unverified"
PROVIDER_BOUNDARY = (
    "Provider/local verification closure is advisory source-review evidence only; "
    "it is not exploit proof."
)
LIVE_TRIAGE_BOUNDARY = (
    "Live provider result triage is advisory provider-output classification only; "
    "it is not detector, PoC, severity, or submission proof."
)
EXECUTION_BOUNDARY = (
    "Command readiness is not exploit proof. Count proof only from "
    "poc_execution/**/execution_manifest.json with final_result=proved, "
    "impact_assertion=exploit_impact, evidence_class=executed_with_manifest, "
    "and a structured commands_attempted row with status=pass and exit_code=0."
)
SCANNER_AUTONOMY_BOUNDARY = (
    "Scanner autonomy execution rows are detector/scanner accounting only. "
    "Terminal blocker state is not a canonical evidence_class and does not prove exploit impact."
)


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"[evidence-class-legacy-backfill] ERR missing: {path}") from None
    except json.JSONDecodeError as exc:
        raise SystemExit(f"[evidence-class-legacy-backfill] ERR invalid JSON in {path}: {exc}") from None


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def set_if_changed(row: dict[str, Any], key: str, value: Any) -> bool:
    if row.get(key) == value:
        return False
    row[key] = value
    return True


def set_missing_evidence_class(row: dict[str, Any], evidence_class: str) -> bool:
    if isinstance(row.get("evidence_class"), str):
        return False
    row["evidence_class"] = evidence_class
    return True


def normalize_advisory_row(row: dict[str, Any], evidence_class: str, boundary: str) -> bool:
    changed = set_missing_evidence_class(row, evidence_class)
    changed = set_if_changed(row, "submit_ready", False) or changed
    changed = set_if_changed(row, "promotion_allowed", False) or changed
    changed = set_if_changed(row, "promotion_authority", False) or changed
    changed = set_if_changed(row, "submission_posture", "NOT_SUBMIT_READY") or changed
    changed = set_if_changed(row, "proof_boundary", boundary) or changed
    return changed


def normalize_payload_header(payload: dict[str, Any], evidence_class: str, boundary: str) -> bool:
    changed = set_missing_evidence_class(payload, evidence_class)
    changed = set_if_changed(payload, "submit_ready", False) or changed
    changed = set_if_changed(payload, "promotion_allowed", False) or changed
    changed = set_if_changed(payload, "promotion_authority", False) or changed
    changed = set_if_changed(payload, "submission_posture", "NOT_SUBMIT_READY") or changed
    changed = set_if_changed(payload, "proof_boundary", boundary) or changed
    changed = set_if_changed(payload, "legacy_backfill_schema", SCHEMA) or changed
    return changed


def stamp_provider_closure(path: Path, *, dry_run: bool = False) -> dict[str, Any]:
    payload = read_json(path)
    if not isinstance(payload, dict):
        return {"path": str(path), "family": "provider_local_verification_closure", "rows_seen": 0, "rows_changed": 0, "skipped": "not_object"}
    rows = payload.get("rows")
    if not isinstance(rows, list):
        return {"path": str(path), "family": "provider_local_verification_closure", "rows_seen": 0, "rows_changed": 0, "skipped": "missing_rows"}

    rows_changed = 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        if normalize_advisory_row(row, GENERATED, PROVIDER_BOUNDARY):
            rows_changed += 1

    artifact_changed = normalize_payload_header(payload, GENERATED, PROVIDER_BOUNDARY)
    artifact_changed = set_if_changed(
        payload,
        "legacy_backfill_note",
        "Stamped advisory provider-local closure rows as generated_hypothesis; no proof semantics were promoted.",
    ) or artifact_changed
    if (rows_changed or artifact_changed) and not dry_run:
        write_json(path, payload)
    return {
        "path": str(path),
        "family": "provider_local_verification_closure",
        "rows_seen": len(rows),
        "rows_changed": rows_changed,
        "artifact_changed": bool(rows_changed or artifact_changed),
        "evidence_class": GENERATED,
        "submit_ready": False,
        "promotion_allowed": False,
        "promotion_authority": False,
    }


def stamp_execution_outcome(path: Path, *, dry_run: bool = False) -> dict[str, Any]:
    payload = read_json(path)
    if not isinstance(payload, dict):
        return {"path": str(path), "family": "execution_proof_outcomes", "rows_seen": 0, "rows_changed": 0, "skipped": "not_object"}
    legacy_missing = not isinstance(payload.get("evidence_class"), str)
    changed = set_missing_evidence_class(payload, SCAFFOLDED)
    changed = set_if_changed(payload, "submit_ready", False) or changed
    changed = set_if_changed(payload, "proof_boundary", EXECUTION_BOUNDARY) or changed
    if legacy_missing or changed:
        changed = set_if_changed(payload, "legacy_backfill_schema", SCHEMA) or changed
        changed = set_if_changed(
            payload,
            "legacy_backfill_note",
            "Stamped stale execution-proof outcome as scaffolded_unverified, matching the current execution-proof task runner ceiling.",
        ) or changed
    if changed and not dry_run:
        write_json(path, payload)
    return {
        "path": str(path),
        "family": "execution_proof_outcomes",
        "rows_seen": 1,
        "rows_changed": 1 if changed else 0,
        "artifact_changed": bool(changed),
        "evidence_class": SCAFFOLDED,
        "submit_ready": False,
    }


def stamp_live_triage(path: Path, *, dry_run: bool = False) -> dict[str, Any]:
    payload = read_json(path)
    if not isinstance(payload, dict):
        return {"path": str(path), "family": "live_provider_result_triage", "rows_seen": 0, "rows_changed": 0, "skipped": "not_object"}
    rows = payload.get("rows")
    if not isinstance(rows, list):
        return {"path": str(path), "family": "live_provider_result_triage", "rows_seen": 0, "rows_changed": 0, "skipped": "missing_rows"}

    rows_changed = 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        if normalize_advisory_row(row, GENERATED, LIVE_TRIAGE_BOUNDARY):
            rows_changed += 1
    artifact_changed = normalize_payload_header(payload, GENERATED, LIVE_TRIAGE_BOUNDARY)
    artifact_changed = set_if_changed(
        payload,
        "legacy_backfill_note",
        "Stamped live provider triage rows as generated_hypothesis; no provider output was promoted to proof.",
    ) or artifact_changed
    if (rows_changed or artifact_changed) and not dry_run:
        write_json(path, payload)
    return {
        "path": str(path),
        "family": "live_provider_result_triage",
        "rows_seen": len(rows),
        "rows_changed": rows_changed,
        "artifact_changed": bool(rows_changed or artifact_changed),
        "evidence_class": GENERATED,
        "submit_ready": False,
        "promotion_allowed": False,
        "promotion_authority": False,
    }


def stamp_scanner_autonomy_execution(path: Path, *, dry_run: bool = False) -> dict[str, Any]:
    payload = read_json(path)
    if not isinstance(payload, dict):
        return {"path": str(path), "family": "scanner_autonomy_execution", "rows_seen": 0, "rows_changed": 0, "skipped": "not_object"}
    rows = payload.get("rows")
    if not isinstance(rows, list):
        return {"path": str(path), "family": "scanner_autonomy_execution", "rows_seen": 0, "rows_changed": 0, "skipped": "missing_rows"}

    rows_changed = 0
    for row in rows:
        if not isinstance(row, dict):
            continue
        row_changed = False
        previous = row.get("evidence_class")
        needs_canonicalization = previous == "terminal_blocker" or not isinstance(previous, str)
        unsafe_flags = (
            row.get("submit_ready") is True
            or row.get("promotion_allowed") is True
            or row.get("promotion_authority") is True
            or row.get("submission_posture") == "SUBMIT_READY"
        )
        if not needs_canonicalization and not unsafe_flags:
            continue
        if previous == "terminal_blocker" or not isinstance(previous, str):
            row["evidence_class"] = SCAFFOLDED
            row_changed = True
            if previous:
                row_changed = set_if_changed(row, "terminal_evidence_status", str(previous)) or row_changed
        if str(row.get("status") or "").startswith("terminal_"):
            row_changed = set_if_changed(row, "terminal_evidence_status", "terminal_blocker") or row_changed
        row_changed = set_if_changed(row, "submit_ready", False) or row_changed
        row_changed = set_if_changed(row, "promotion_allowed", False) or row_changed
        row_changed = set_if_changed(row, "promotion_authority", False) or row_changed
        row_changed = set_if_changed(row, "submission_posture", "NOT_SUBMIT_READY") or row_changed
        row_changed = set_if_changed(row, "proof_boundary", SCANNER_AUTONOMY_BOUNDARY) or row_changed
        if row_changed:
            rows_changed += 1

    artifact_changed = False
    if rows_changed:
        artifact_changed = set_if_changed(payload, "legacy_backfill_schema", SCHEMA) or artifact_changed
        artifact_changed = set_if_changed(
            payload,
            "legacy_backfill_note",
            "Canonicalized scanner-autonomy terminal blocker rows to scaffolded_unverified; terminal blocker state remains separate.",
        ) or artifact_changed
    if (rows_changed or artifact_changed) and not dry_run:
        write_json(path, payload)
    return {
        "path": str(path),
        "family": "scanner_autonomy_execution",
        "rows_seen": len(rows),
        "rows_changed": rows_changed,
        "artifact_changed": bool(rows_changed or artifact_changed),
        "evidence_class": SCAFFOLDED,
        "submit_ready": False,
        "promotion_allowed": False,
        "promotion_authority": False,
    }


def run(workspace: Path, *, dry_run: bool = False) -> dict[str, Any]:
    provider_results = [
        stamp_provider_closure(path, dry_run=dry_run)
        for path in sorted(workspace.glob(PROVIDER_CLOSURE_GLOB))
        if path.is_file()
    ]
    outcome_results = [
        stamp_execution_outcome(path, dry_run=dry_run)
        for path in sorted(workspace.glob(EXECUTION_OUTCOME_GLOB))
        if path.is_file()
    ]
    triage_results = [
        stamp_live_triage(path, dry_run=dry_run)
        for path in sorted(workspace.glob(LIVE_TRIAGE_GLOB))
        if path.is_file()
    ]
    scanner_results = [
        stamp_scanner_autonomy_execution(path, dry_run=dry_run)
        for path in sorted(workspace.glob(SCANNER_AUTONOMY_EXECUTION_GLOB))
        if path.is_file()
    ]
    results = provider_results + outcome_results + triage_results + scanner_results
    return {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "dry_run": dry_run,
        "artifact_families": {
            "provider_local_verification_closure": PROVIDER_CLOSURE_GLOB,
            "execution_proof_outcomes": EXECUTION_OUTCOME_GLOB,
            "live_provider_result_triage": LIVE_TRIAGE_GLOB,
            "scanner_autonomy_execution": SCANNER_AUTONOMY_EXECUTION_GLOB,
        },
        "changed_artifacts": [
            row
            for row in results
            if row.get("artifact_changed") or int(row.get("rows_changed") or 0) > 0
        ],
        "results": results,
        "rows_seen": sum(int(row.get("rows_seen") or 0) for row in results),
        "rows_changed": sum(int(row.get("rows_changed") or 0) for row in results),
        "artifacts_changed": sum(1 for row in results if row.get("artifact_changed") or int(row.get("rows_changed") or 0) > 0),
        "proof_semantics": "No row is promoted above generated_hypothesis/scaffolded_unverified; submit_ready, promotion_allowed, and promotion_authority are forced false where present.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--out-json", type=Path, default=Path(".auditooor/evidence_class_legacy_backfill_em.json"))
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        raise SystemExit(f"[evidence-class-legacy-backfill] ERR workspace not found: {workspace}")
    payload = run(workspace, dry_run=args.dry_run)
    out = args.out_json
    if not out.is_absolute():
        out = workspace / out
    write_json(out, payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
