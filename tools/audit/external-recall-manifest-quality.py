#!/usr/bin/env python3
"""Dry-run quality gate for external recall manifests.

The recall scoreboard intentionally keeps simple scoring semantics: every
manifest row is treated as a known-vulnerable holdout. This checker is the
pre-scoreboard / pre-prioritizer guard that asks whether each external row is
actually eligible to create a detector gap.

It does not edit manifests and does not change scoreboard output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.external_recall_manifest_quality.v1"
MANIFEST_SCHEMA = "auditooor.external_recall_samples.v1"

VULNERABLE_STATES = {
    "known_vulnerable",
    "pre_fix",
    "unfixed_vulnerable",
    "vulnerable",
}
DISQUALIFYING_STATES = {
    "clean",
    "fixed",
    "not_a_bug",
    "out_of_class",
    "patched",
    "post_fix",
}
UNKNOWN_STATES = {
    "",
    "needs_validation",
    "unknown",
    "unvalidated",
}

EVIDENCE_FIELDS = {
    "advisory_url",
    "audit_report_url",
    "finding_ref",
    "fix_commit",
    "proof_ref",
    "report_url",
    "source_snapshot",
    "source_snapshot_ref",
    "validated_by",
    "vulnerable_commit",
}


def _normalize_state(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() not in {"", "0", "false", "no", "none", "null"}


def _load_manifest(path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, [f"manifest_parse_error: {exc}"]
    if not isinstance(payload, dict):
        return None, ["manifest_shape_error: manifest must be a JSON object"]
    errors: list[str] = []
    if payload.get("schema") != MANIFEST_SCHEMA:
        errors.append(f"schema must be {MANIFEST_SCHEMA}")
    if not isinstance(payload.get("samples"), list):
        errors.append("samples must be a list")
    return payload, errors


def _has_evidence(row: dict[str, Any]) -> bool:
    for field in EVIDENCE_FIELDS:
        if _truthy(row.get(field)):
            return True
    refs = row.get("source_refs") or row.get("evidence_refs")
    if isinstance(refs, list) and any(_truthy(item) for item in refs):
        return True
    return False


def evaluate_row(row: dict[str, Any], idx: int) -> dict[str, Any]:
    sample_id = str(row.get("id") or row.get("slug") or f"sample-{idx}").strip()
    source_state = _normalize_state(
        row.get("source_state")
        or row.get("vulnerability_state")
        or row.get("validation_state")
    )
    validated_vulnerable = _truthy(row.get("validated_vulnerable"))
    has_evidence = _has_evidence(row)
    reasons: list[str] = []
    required_actions: list[str] = []

    if source_state in DISQUALIFYING_STATES:
        quality_state = "disqualified_source_state"
        eligible = False
        reasons.append(f"source_state={source_state}")
        required_actions.append("remove from external recall gap scoring or replace with a vulnerable pre-fix snapshot")
    elif validated_vulnerable or source_state in VULNERABLE_STATES:
        if has_evidence:
            quality_state = "gap_eligible"
            eligible = True
            reasons.append("validated vulnerable source state with evidence")
        else:
            quality_state = "needs_source_state_validation"
            eligible = False
            reasons.append("vulnerable state is asserted but no source-state evidence field is present")
            required_actions.append("add finding/source snapshot evidence before using this row for gap prioritization")
    elif source_state in UNKNOWN_STATES:
        quality_state = "needs_source_state_validation"
        eligible = False
        reasons.append("missing or unknown source_state")
        required_actions.append("confirm vulnerable pre-fix, fixed/post-fix, or out-of-class source state")
    else:
        quality_state = "needs_source_state_validation"
        eligible = False
        reasons.append(f"unrecognized source_state={source_state}")
        required_actions.append("normalize source_state to vulnerable/pre_fix/fixed/out_of_class before gap prioritization")

    if not str(row.get("attack_class") or "").strip():
        eligible = False
        reasons.append("missing attack_class")
        required_actions.append("set attack_class before scoring recall")

    return {
        "id": sample_id,
        "path": str(row.get("path") or row.get("vuln_path") or "").strip(),
        "attack_class": str(row.get("attack_class") or "").strip(),
        "source": str(row.get("source") or "").strip(),
        "source_state": source_state or "unknown",
        "quality_state": quality_state,
        "gap_prioritization_eligible": eligible,
        "reasons": reasons,
        "required_actions": required_actions,
    }


def evaluate_manifest(path: Path) -> dict[str, Any]:
    manifest_path = path.expanduser().resolve()
    manifest_sha256 = ""
    manifest_mtime_utc = ""
    try:
        manifest_bytes = manifest_path.read_bytes()
        manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
        manifest_mtime_utc = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(manifest_path.stat().st_mtime)
        )
    except OSError:
        pass
    payload, manifest_errors = _load_manifest(manifest_path)
    rows: list[dict[str, Any]] = []
    raw_samples = payload.get("samples", []) if isinstance(payload, dict) else []
    if isinstance(raw_samples, list):
        for idx, row in enumerate(raw_samples, 1):
            if isinstance(row, dict):
                rows.append(evaluate_row(row, idx))
            else:
                rows.append(
                    {
                        "id": f"sample-{idx}",
                        "path": "",
                        "attack_class": "",
                        "source": "",
                        "source_state": "unknown",
                        "quality_state": "needs_source_state_validation",
                        "gap_prioritization_eligible": False,
                        "reasons": ["sample row is not an object"],
                        "required_actions": ["fix manifest row shape before scoring recall"],
                    }
                )

    gap_eligible = sum(1 for row in rows if row["gap_prioritization_eligible"])
    disqualified = sum(1 for row in rows if row["quality_state"] == "disqualified_source_state")
    validation_required = sum(
        1 for row in rows if row["quality_state"] == "needs_source_state_validation"
    )
    blockers = len(manifest_errors) + disqualified + validation_required
    generated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return {
        "schema": SCHEMA,
        "generated_at": generated_at,
        "manifest_path": str(manifest_path),
        "manifest_sha256": manifest_sha256,
        "manifest_mtime_utc": manifest_mtime_utc,
        "manifest_errors": manifest_errors,
        "summary": {
            "sample_count": len(rows),
            "gap_eligible": gap_eligible,
            "needs_source_state_validation": validation_required,
            "disqualified_source_state": disqualified,
            "blockers": blockers,
        },
        "rows": rows,
        "policy": (
            "Only rows with validated vulnerable/pre-fix source state and an "
            "evidence reference should be promoted into P0 detector-gap "
            "prioritization. Fixed, clean, post-fix, or out-of-class rows are "
            "measurement-quality blockers, not detector gaps."
        ),
    }


def build_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    lines = [
        "# External Recall Manifest Quality Gate",
        "",
        f"Generated: {payload['generated_at']}",
        f"Schema: `{payload['schema']}`",
        f"Manifest: `{payload['manifest_path']}`",
        "",
        "## Summary",
        "",
        "| Metric | Count |",
        "|--------|------:|",
        f"| samples | {summary['sample_count']} |",
        f"| gap eligible | {summary['gap_eligible']} |",
        f"| needs source-state validation | {summary['needs_source_state_validation']} |",
        f"| disqualified source state | {summary['disqualified_source_state']} |",
        f"| blockers before P0 gap prioritization | {summary['blockers']} |",
        "",
        "## Policy",
        "",
        payload["policy"],
        "",
    ]
    if payload.get("manifest_errors"):
        lines.extend(["## Manifest Errors", ""])
        for err in payload["manifest_errors"]:
            lines.append(f"- {err}")
        lines.append("")

    lines.extend(
        [
            "## Rows",
            "",
            "| eligible | quality_state | source_state | attack_class | id | reason |",
            "|---------:|---------------|--------------|--------------|----|--------|",
        ]
    )
    for row in payload["rows"]:
        reason = "; ".join(row["reasons"])
        lines.append(
            f"| {'yes' if row['gap_prioritization_eligible'] else 'no'} "
            f"| {row['quality_state']} | {row['source_state']} "
            f"| {row['attack_class']} | {row['id']} | {reason} |"
        )
    lines.append("")
    return "\n".join(lines)


def _print_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("manifest")
    parser.add_argument("--out-json", default="")
    parser.add_argument("--out-md", default="")
    parser.add_argument("--json", action="store_true", help="print JSON payload to stdout")
    parser.add_argument(
        "--warn-only",
        action="store_true",
        help="always exit 0 even when rows are not gap-eligible",
    )
    args = parser.parse_args(argv)

    payload = evaluate_manifest(Path(args.manifest))
    if args.out_json:
        out_json = Path(args.out_json)
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.out_md:
        out_md = Path(args.out_md)
        out_md.parent.mkdir(parents=True, exist_ok=True)
        out_md.write_text(build_markdown(payload), encoding="utf-8")

    if args.json:
        _print_json(payload)
    else:
        summary = payload["summary"]
        status = "pass" if summary["blockers"] == 0 else "needs-validation"
        print(
            f"[{status}] {payload['manifest_path']} "
            f"eligible={summary['gap_eligible']} blockers={summary['blockers']}"
        )
        if args.out_md:
            print(f"[md] {Path(args.out_md).expanduser().resolve()}")
        if args.out_json:
            print(f"[json] {Path(args.out_json).expanduser().resolve()}")

    if args.warn_only:
        return 0
    return 0 if payload["summary"]["blockers"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
