#!/usr/bin/env python3
"""Stage uncovered Go/Cosmos audit-text corpus inputs for review.

This is deliberately a staging wrapper: it discovers uncovered Go/Cosmos
candidate sources via ``hackerman-go-cosmos-inventory.py`` and emits records to
an operator-selected staging directory, not the live Hackerman tag corpus.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAG_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_REFERENCE_ROOT = REPO_ROOT
DEFAULT_OUT_DIR = Path("/private/tmp/hackerman-go-cosmos-stage")
STAGE_SCHEMA_VERSION = "auditooor.hackerman_go_cosmos_stage_imports.v1"
GO_COSMOS_PROMOTION_HINTS = (
    "cosmos",
    "cosmos-sdk",
    "cosmos sdk",
    "cometbft",
    "tendermint",
    "iavl",
    "msgserver",
    "keeper",
    "validatebasic",
    "prepareproposal",
    "processproposal",
    "extendvote",
    "finalizeblock",
    "beginblocker",
    "endblocker",
    "antehandler",
    "module account",
    "x/bank",
    "x/gov",
    "x/clob",
    "dydx",
    "dydxprotocol/v4-chain",
    "slinky",
    "ibc",
)


def _load_tool(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_INVENTORY = _load_tool(
    REPO_ROOT / "tools" / "hackerman-go-cosmos-inventory.py",
    "_hackerman_go_cosmos_inventory_for_stage_imports",
)
_PRIOR_AUDIT_ETL = _load_tool(
    REPO_ROOT / "tools" / "hackerman-etl-from-prior-audits.py",
    "_hackerman_etl_from_prior_audits_for_go_cosmos_stage",
)
_VALIDATOR = _load_tool(
    REPO_ROOT / "tools" / "hackerman-record-validate.py",
    "_hackerman_record_validate_for_go_cosmos_stage",
)


def _resolve_path(path_text: str) -> Path:
    path = Path(path_text).expanduser()
    if path.is_absolute():
        return path.resolve()
    return (REPO_ROOT / path).resolve()


def select_source_files(
    report: dict[str, Any],
    *,
    source_families: set[str],
    limit: int | None,
    explicit_source_files: list[str],
) -> list[Path]:
    if explicit_source_files:
        selected = [_resolve_path(item) for item in explicit_source_files]
    else:
        selected = []
        seen: set[str] = set()
        ranked_items = report.get("candidate_import_targets") or report.get("local_inputs", [])
        for item in ranked_items:
            if item.get("covered"):
                continue
            if str(item.get("source_family") or "") not in source_families:
                continue
            source_path = str(item.get("source_path") or "")
            if not source_path or source_path in seen:
                continue
            seen.add(source_path)
            selected.append(_resolve_path(source_path))
            if limit is not None and len(selected) >= limit:
                break
    if limit is not None:
        selected = selected[:limit]
    return selected


def validate_stage(out_dir: Path) -> dict[str, int]:
    return validate_paths(sorted(out_dir.glob("*.yaml")))


def validate_paths(paths: list[Path]) -> dict[str, int]:
    schema = _VALIDATOR.load_schema()
    counts = {"valid": 0, "invalid": 0, "skipped": 0}
    for path in paths:
        if not path.exists():
            counts["skipped"] += 1
            continue
        status, _errors = _VALIDATOR.validate_file(path, schema)
        counts[status] += 1
    return counts


def _validation_statuses(paths: list[Path]) -> dict[str, str]:
    schema = _VALIDATOR.load_schema()
    statuses: dict[str, str] = {}
    for path in paths:
        if not path.exists():
            statuses[str(path)] = "dry_run"
            continue
        status, _errors = _VALIDATOR.validate_file(path, schema)
        statuses[str(path)] = status
    return statuses


def _source_ref_path(source_ref: str) -> str:
    if source_ref.startswith("corpus-txt:"):
        body = source_ref.removeprefix("corpus-txt:")
        return body.rsplit(":L", 1)[0]
    if source_ref.startswith("prior-audit:"):
        parts = source_ref.split(":", 2)
        if len(parts) == 3:
            return parts[2].rsplit(":L", 1)[0]
    return source_ref


def _record_blob(record: dict[str, object]) -> str:
    fields = [
        "record_id",
        "source_audit_ref",
        "target_repo",
        "target_domain",
        "target_component",
        "bug_class",
        "attack_class",
        "impact_class",
        "fix_pattern",
    ]
    parts = [str(record.get(field) or "") for field in fields]
    function_shape = record.get("function_shape")
    if isinstance(function_shape, dict):
        parts.append(str(function_shape.get("raw_signature") or ""))
        parts.extend(str(item) for item in function_shape.get("shape_tags") or [])
    for field in ("attacker_preconditions", "attacker_action_sequence"):
        value = record.get(field)
        if isinstance(value, list):
            parts.extend(str(item) for item in value)
        else:
            parts.append(str(value or ""))
    return " ".join(parts).lower()


def is_go_cosmos_promotion_candidate(record: dict[str, object]) -> bool:
    if record.get("target_language") != "go":
        return False
    blob = _record_blob(record)
    return any(term in blob for term in GO_COSMOS_PROMOTION_HINTS)


def split_stage_records(
    records: list[dict[str, object]], *, include_cross_language_context: bool
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    if include_cross_language_context:
        return list(records), []
    stage_records: list[dict[str, object]] = []
    context_records: list[dict[str, object]] = []
    for record in records:
        if is_go_cosmos_promotion_candidate(record):
            stage_records.append(record)
        else:
            context_records.append(record)
    return stage_records, context_records


def _review_flags(record: dict[str, object], path: Path, validation_status: str) -> list[str]:
    flags: list[str] = []
    if validation_status != "valid":
        flags.append(f"validation_{validation_status}")
    if record.get("target_language") != "go":
        flags.append("cross_language_not_go")
    if record.get("target_repo") == "unknown":
        flags.append("unknown_target_repo")
    source_ref = str(record.get("source_audit_ref") or "")
    if ":L1:S1" in source_ref:
        flags.append("line1_segment_review")
    raw_signature = ""
    function_shape = record.get("function_shape")
    if isinstance(function_shape, dict):
        raw_signature = str(function_shape.get("raw_signature") or "")
    if raw_signature.startswith("function-name-hint:"):
        flags.append("function_name_hint")
    if str(record.get("fix_pattern") or "").strip().lower().rstrip(":") in {
        "recommendation",
        "recommendations",
        "mitigation",
        "mitigations",
    }:
        flags.append("heading_only_fix_pattern")
    if not path.exists():
        flags.append("file_not_written")
    return flags


def _context_flags(record: dict[str, object]) -> list[str]:
    flags: list[str] = []
    if record.get("target_language") != "go":
        flags.append("cross_language_not_go")
    elif not is_go_cosmos_promotion_candidate(record):
        flags.append("not_go_cosmos_scoped")
    if record.get("target_repo") == "unknown":
        flags.append("unknown_target_repo")
    source_ref = str(record.get("source_audit_ref") or "")
    if ":L1:S1" in source_ref:
        flags.append("line1_segment_review")
    raw_signature = ""
    function_shape = record.get("function_shape")
    if isinstance(function_shape, dict):
        raw_signature = str(function_shape.get("raw_signature") or "")
    if raw_signature.startswith("function-name-hint:"):
        flags.append("function_name_hint")
    if str(record.get("fix_pattern") or "").strip().lower().rstrip(":") in {
        "recommendation",
        "recommendations",
        "mitigation",
        "mitigations",
    }:
        flags.append("heading_only_fix_pattern")
    return flags


def build_context_manifest(records: list[dict[str, object]]) -> list[dict[str, object]]:
    manifest: list[dict[str, object]] = []
    for record in records:
        manifest.append(
            {
                "record_id": record.get("record_id"),
                "source_audit_ref": record.get("source_audit_ref"),
                "source_path": _source_ref_path(str(record.get("source_audit_ref") or "")),
                "review_status": "context_only_not_promoted",
                "review_flags": _context_flags(record),
                "target_language": record.get("target_language"),
                "target_repo": record.get("target_repo"),
                "target_component": record.get("target_component"),
                "severity_at_finding": record.get("severity_at_finding"),
                "bug_class": record.get("bug_class"),
                "attack_class": record.get("attack_class"),
                "impact_class": record.get("impact_class"),
                "fix_pattern": record.get("fix_pattern"),
            }
        )
    return manifest


def build_record_manifest(records: list[dict[str, object]], paths: list[Path]) -> list[dict[str, object]]:
    statuses = _validation_statuses(paths)
    manifest: list[dict[str, object]] = []
    for record, path in zip(records, paths):
        validation_status = statuses.get(str(path), "missing")
        flags = _review_flags(record, path, validation_status)
        if validation_status != "valid":
            review_status = "blocked"
        elif flags:
            review_status = "needs_source_review"
        else:
            review_status = "promotable_after_source_review"
        manifest.append(
            {
                "record_id": record.get("record_id"),
                "source_audit_ref": record.get("source_audit_ref"),
                "source_path": _source_ref_path(str(record.get("source_audit_ref") or "")),
                "yaml_path": str(path),
                "validation_status": validation_status,
                "promotion_ready": validation_status == "valid" and not flags,
                "review_status": review_status,
                "review_flags": flags,
                "target_language": record.get("target_language"),
                "target_repo": record.get("target_repo"),
                "target_component": record.get("target_component"),
                "severity_at_finding": record.get("severity_at_finding"),
                "bug_class": record.get("bug_class"),
                "attack_class": record.get("attack_class"),
                "impact_class": record.get("impact_class"),
                "fix_pattern": record.get("fix_pattern"),
            }
        )
    return manifest


def _review_counts(*manifests: list[dict[str, object]]) -> dict[str, Any]:
    status_counts: Counter[str] = Counter()
    flag_counts: Counter[str] = Counter()
    for manifest in manifests:
        for row in manifest:
            status = str(row.get("review_status") or "unknown")
            status_counts[status] += 1
            flags = row.get("review_flags")
            if isinstance(flags, list):
                flag_counts.update(str(flag) for flag in flags)
    return {
        "review_status_counts": dict(sorted(status_counts.items())),
        "review_flag_counts": dict(sorted(flag_counts.items())),
    }


def stage_imports(args: argparse.Namespace) -> dict[str, Any]:
    tag_dir = Path(args.tag_dir).expanduser().resolve()
    reference_root = Path(args.reference_root).expanduser().resolve()
    out_dir = Path(args.out_dir).expanduser().resolve()
    inventory_args = type(
        "InventoryArgs",
        (),
        {
            "tag_dir": str(tag_dir),
            "reference_root": str(reference_root),
        },
    )()
    report = _INVENTORY.summarize(inventory_args)
    source_families = set(args.source_family or ["audit-text-corpus"])
    source_files = select_source_files(
        report,
        source_families=source_families,
        limit=args.limit,
        explicit_source_files=args.source_file,
    )

    raw_records, counters = _PRIOR_AUDIT_ETL.extract_records([], None, source_files=source_files)
    records, context_records = split_stage_records(
        raw_records,
        include_cross_language_context=args.include_cross_language_context,
    )
    paths = _PRIOR_AUDIT_ETL.write_records(records, out_dir, args.dry_run)
    validation = {"valid": 0, "invalid": 0, "skipped": 0}
    if not args.dry_run:
        validation = validate_paths(paths)
    record_manifest = build_record_manifest(records, paths)
    context_record_manifest = build_context_manifest(context_records)
    review_counts = _review_counts(record_manifest, context_record_manifest)
    promotion_ready_records = sum(1 for row in record_manifest if row.get("promotion_ready"))
    emitted_review_blocked_records = len(record_manifest) - promotion_ready_records

    summary = {
        "schema_version": STAGE_SCHEMA_VERSION,
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "tag_dir": str(tag_dir),
        "reference_root": str(reference_root),
        "out_dir": str(out_dir),
        "dry_run": args.dry_run,
        "source_families": sorted(source_families),
        "source_files_selected": [str(path) for path in source_files],
        "include_cross_language_context": args.include_cross_language_context,
        "documents_scanned": counters["documents_scanned"],
        "documents_with_text": counters["documents_with_text"],
        "documents_skipped": counters["documents_skipped"],
        "segments_seen": counters["segments_seen"],
        "raw_records_extracted": len(raw_records),
        "context_records_filtered": len(context_records),
        "records_emitted": len(records),
        "files": [str(path) for path in paths],
        "validation": validation,
        "record_manifest": record_manifest,
        "context_record_manifest": context_record_manifest,
        "promotion_ready_records": promotion_ready_records,
        "emitted_review_blocked_records": emitted_review_blocked_records,
        "review_status_counts": review_counts["review_status_counts"],
        "review_flag_counts": review_counts["review_flag_counts"],
        "inventory_errors": report.get("errors", []),
    }
    if args.stage_artifact_out:
        stage_path = Path(args.stage_artifact_out).expanduser().resolve()
    else:
        stage_path = out_dir / "stage_imports.json"
    if not args.dry_run:
        stage_path.parent.mkdir(parents=True, exist_ok=True)
        stage_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        summary["stage_artifact_out"] = str(stage_path)
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag-dir", default=str(DEFAULT_TAG_DIR))
    parser.add_argument("--reference-root", default=str(DEFAULT_REFERENCE_ROOT))
    parser.add_argument("--out-dir", default=str(DEFAULT_OUT_DIR))
    parser.add_argument(
        "--source-family",
        action="append",
        choices=("audit-text-corpus", "prior-audit"),
        help="Source family to stage from inventory; defaults to audit-text-corpus.",
    )
    parser.add_argument("--source-file", action="append", default=[], help="Explicit source file; repeatable.")
    parser.add_argument("--limit", type=int, default=20, help="Maximum source files to stage.")
    parser.add_argument("--stage-artifact-out", help="Optional JSON stage artifact path.")
    parser.add_argument(
        "--include-cross-language-context",
        action="store_true",
        help="Write cross-language context rows too; by default they stay only in context_record_manifest.",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json-summary", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.limit is not None and args.limit < 0:
        print("--limit must be non-negative", file=sys.stderr)
        return 2
    summary = stage_imports(args)
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman Go/Cosmos stage imports: "
            f"sources={len(summary['source_files_selected'])} "
            f"records={summary['records_emitted']} "
            f"promotion_ready={summary['promotion_ready_records']} "
            f"review_blocked={summary['emitted_review_blocked_records']} "
            f"context_only={summary['context_records_filtered']} "
            f"valid={summary['validation']['valid']} "
            f"invalid={summary['validation']['invalid']} "
            f"dry_run={summary['dry_run']} "
            f"out_dir={summary['out_dir']}"
        )
    return 0 if summary["validation"]["invalid"] == 0 and not summary["inventory_errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
