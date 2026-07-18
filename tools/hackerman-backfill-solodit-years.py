#!/usr/bin/env python3
"""Backfill Solodit hackerman_record years from local source spec metadata.

The original Solodit ETL used ``year: 2000`` as an unknown-year sentinel.
This tool performs a narrow in-place correction: for live hackerman tag YAMLs
whose source points back to a local Solodit spec, update only the ``year`` line
when that source spec proves a real date/year from explicit source-date fields.
Filename/path/title/description slug dates are reported as unsafe hints but are
never used as authoritative backfill evidence.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAG_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_INDEX_DIR = REPO_ROOT / "audit" / "corpus_tags" / "index"
DEFAULT_REFERENCE_DIR = REPO_ROOT / "reference"
DEFAULT_CANDIDATES_PATH = REPO_ROOT / ".auditooor" / "year-backfill-candidates.jsonl"


def _load_tool(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_ETL = _load_tool(
    REPO_ROOT / "tools" / "hackerman-etl-from-solodit-specs.py",
    "_hackerman_etl_from_solodit_specs_for_year_backfill",
)
_VALIDATOR = _load_tool(
    REPO_ROOT / "tools" / "hackerman-record-validate.py",
    "_hackerman_record_validate_for_year_backfill",
)


SAFE_DATE_FIELDS = (
    "audit_date",
    "auditDate",
    "audit_year",
    "year",
    "source_date",
    "reported_date",
    "reportedDate",
    "report_date",
    "reportDate",
    "published_at",
    "publishedAt",
    "published_date",
    "publishedDate",
    "created_at",
    "createdAt",
    "updated_at",
    "updatedAt",
    "date",
)

UNSAFE_HINT_FIELDS = (
    "solodit_slug",
    "source",
    "source_url",
    "protocol",
    "wiki_title",
    "title",
    "wiki_description",
    "description",
    "wiki_exploit_scenario",
    "exploit_precondition",
    "wiki_recommendation",
    "suggested_remediation",
    "solodit_id",
    "source_id",
)

UNSAFE_DSL_HINT_FIELDS = (
    "source_url",
    "protocol",
)
# Intentionally excludes the DSL `source` field: rows like
# `solodit-2026-04-cycle45-*` describe our import cycle, not audit provenance.


def _source_spec_ref(source_audit_ref: object) -> tuple[Path | None, str]:
    text = str(source_audit_ref or "")
    if not text.startswith("solodit-spec:"):
        return None, ""
    body = text.removeprefix("solodit-spec:")
    if ":" not in body:
        return None, ""
    path_text, source_id = body.rsplit(":", 1)
    if not path_text:
        return None, source_id.strip()
    path = Path(path_text)
    if not path.is_absolute():
        path = REPO_ROOT / path
    return path, source_id.strip()


def _source_spec_path(source_audit_ref: object) -> Path | None:
    path, _source_id = _source_spec_ref(source_audit_ref)
    return path


def _load_source_spec(spec_path: Path) -> tuple[dict[str, Any] | None, str | None]:
    if not spec_path.exists():
        return None, "source_spec_missing"
    data = _ETL.load_yaml(spec_path)
    if not isinstance(data, dict):
        return None, "source_spec_not_mapping"
    return data, None


def _iter_safe_date_evidence(data: dict[str, Any]) -> list[tuple[str, object]]:
    return [(key, data.get(key)) for key in SAFE_DATE_FIELDS]


def _safe_date_field_counts(data: dict[str, Any] | None) -> dict[str, int]:
    if data is None:
        return {}
    return {
        field: 1
        for field, value in _iter_safe_date_evidence(data)
        if str(value or "").strip()
    }


def _iter_unsafe_date_hints(data: dict[str, Any], spec_path: Path) -> list[tuple[str, object]]:
    hints: list[tuple[str, object]] = [(key, data.get(key)) for key in UNSAFE_HINT_FIELDS]
    hints.append(("spec_path.stem", spec_path.stem))
    return hints


def _collect_explicit_year_evidence(
    data: dict[str, Any],
    *,
    field_prefix: str = "",
    include_values: bool = True,
) -> list[dict[str, object]]:
    evidence_rows: list[dict[str, object]] = []
    for field, value in _iter_safe_date_evidence(data):
        year = _ETL.extract_year_from_slug(value)
        if year is None:
            continue
        row: dict[str, object] = {
            "field": f"{field_prefix}{field}",
            "year": year,
        }
        if include_values:
            row["value"] = str(value).strip()
        evidence_rows.append(row)
    return evidence_rows


def _summarize_conflicting_year_evidence(
    evidence_rows: list[dict[str, object]],
) -> list[dict[str, object]]:
    grouped: dict[int, dict[str, list[str]]] = {}
    for row in evidence_rows:
        year = int(row["year"])
        bucket = grouped.setdefault(year, {"fields": [], "sources": [], "values": []})
        field = str(row.get("field") or "").strip()
        source = str(row.get("source") or "").strip()
        value = str(row.get("value") or "").strip()
        if field and field not in bucket["fields"]:
            bucket["fields"].append(field)
        if source and source not in bucket["sources"]:
            bucket["sources"].append(source)
        if value and value not in bucket["values"]:
            bucket["values"].append(value)
    summary: list[dict[str, object]] = []
    for year in sorted(grouped):
        bucket = grouped[year]
        row: dict[str, object] = {
            "year": year,
            "fields": bucket["fields"][:8],
        }
        if bucket["sources"]:
            row["sources"] = bucket["sources"][:8]
        if bucket["values"]:
            row["values"] = bucket["values"][:8]
        summary.append(row)
    return summary[:8]


def _resolve_explicit_year_evidence(
    evidence_rows: list[dict[str, object]],
    *,
    empty_reason: str,
    conflict_reason: str,
) -> tuple[int | None, str, list[dict[str, object]]]:
    if not evidence_rows:
        return None, empty_reason, []
    years = {int(row["year"]) for row in evidence_rows}
    if len(years) > 1:
        return None, conflict_reason, _summarize_conflicting_year_evidence(evidence_rows)
    chosen = evidence_rows[0]
    return int(chosen["year"]), str(chosen["field"]), []


def _extract_year_from_spec_data(
    data: dict[str, Any],
    spec_path: Path,
) -> tuple[int | None, str, list[dict[str, object]]]:
    del spec_path
    evidence_rows = _collect_explicit_year_evidence(data)
    return _resolve_explicit_year_evidence(
        evidence_rows,
        empty_reason="no_source_date_evidence",
        conflict_reason="conflicting_source_date_evidence",
    )


def _collect_unsafe_year_hints(data: dict[str, Any] | None, spec_path: Path | None) -> list[dict[str, object]]:
    if data is None or spec_path is None:
        return []
    hints: list[dict[str, object]] = []
    for field, value in _iter_unsafe_date_hints(data, spec_path):
        year = _ETL.extract_year_from_slug(value)
        if year is None:
            continue
        hints.append(
            {
                "field": field,
                "year": year,
                "classification": "unsafe_non_authoritative",
            }
        )
    return hints[:8]


def _extract_year_from_spec(spec_path: Path) -> tuple[int | None, str, list[dict[str, object]]]:
    data, error = _load_source_spec(spec_path)
    if data is None:
        return None, str(error), []
    return _extract_year_from_spec_data(data, spec_path)


def _identifier_candidates(*values: object) -> set[str]:
    candidates: set[str] = set()
    for value in values:
        text = str(value or "").strip().strip("'\"")
        if not text:
            continue
        candidates.add(text.lower())
        if text.startswith("solodit-spec:") and ":" in text:
            candidates.add(text.rsplit(":", 1)[1].strip().lower())
        for match in re.finditer(r"\b[Ss]olodit\s*#\s*([A-Za-z0-9._-]+)", text):
            candidates.add(match.group(1).lower())
    return {candidate for candidate in candidates if candidate}


def _source_match_ids(
    record: dict[str, Any],
    source_data: dict[str, Any] | None,
    source_ref_id: str,
) -> set[str]:
    source_data = source_data or {}
    return _identifier_candidates(
        record.get("source_audit_ref"),
        source_ref_id,
        source_data.get("solodit_id"),
        source_data.get("source_id"),
        source_data.get("source_audit_ref"),
    )


def _dsl_match_ids(data: dict[str, Any]) -> set[str]:
    return _identifier_candidates(
        data.get("solodit_id"),
        data.get("source_id"),
        data.get("source_audit_ref"),
    )


def _extract_year_from_dsl(data: dict[str, Any]) -> tuple[int | None, str, list[dict[str, object]]]:
    evidence_rows = _collect_explicit_year_evidence(data, field_prefix="dsl.")
    return _resolve_explicit_year_evidence(
        evidence_rows,
        empty_reason="dsl_no_source_date_evidence",
        conflict_reason="dsl_conflicting_source_date_evidence",
    )


def _collect_dsl_unsafe_year_hints(data: dict[str, Any]) -> list[dict[str, object]]:
    hints: list[dict[str, object]] = []
    for field in UNSAFE_DSL_HINT_FIELDS:
        year = _ETL.extract_year_from_slug(data.get(field))
        if year is None:
            continue
        hints.append(
            {
                "field": f"dsl.{field}",
                "year": year,
                "classification": "unsafe_non_authoritative",
            }
        )
    return hints[:8]


def _build_dsl_year_index(reference_dir: Path) -> dict[str, list[dict[str, object]]]:
    index: dict[str, list[dict[str, object]]] = {}
    for dsl_path in sorted(reference_dir.glob("patterns.dsl.r94_solodit_*/*.yaml")):
        try:
            data = _ETL.load_yaml(dsl_path)
        except Exception:  # noqa: BLE001
            continue
        if not isinstance(data, dict):
            continue
        year, evidence, conflicting_evidence = _extract_year_from_dsl(data)
        if year is None and not conflicting_evidence:
            continue
        try:
            source = dsl_path.relative_to(REPO_ROOT).as_posix()
        except ValueError:
            source = dsl_path.as_posix()
        if year is None:
            entry: dict[str, object] = {
                "kind": "conflict",
                "reason": evidence,
                "source": source,
                "conflicting_evidence": [
                    {
                        **row,
                        "source": source,
                    }
                    for row in conflicting_evidence
                ],
            }
        else:
            entry = {
                "kind": "year",
                "year": year,
                "evidence": evidence,
                "source": source,
            }
        for identifier in _dsl_match_ids(data):
            index.setdefault(identifier, []).append(dict(entry))
    return index


def _build_dsl_unsafe_hint_index(reference_dir: Path) -> dict[str, list[dict[str, object]]]:
    index: dict[str, list[dict[str, object]]] = {}
    for dsl_path in sorted(reference_dir.glob("patterns.dsl.r94_solodit_*/*.yaml")):
        try:
            data = _ETL.load_yaml(dsl_path)
        except Exception:  # noqa: BLE001
            continue
        if not isinstance(data, dict):
            continue
        hints = _collect_dsl_unsafe_year_hints(data)
        if not hints:
            continue
        try:
            source = dsl_path.relative_to(REPO_ROOT).as_posix()
        except ValueError:
            source = dsl_path.as_posix()
        for hint in hints:
            hint = dict(hint)
            hint["source"] = source
            for identifier in _dsl_match_ids(data):
                index.setdefault(identifier, []).append(hint)
    return index


def _extract_year_from_matching_dsl(
    match_ids: set[str],
    dsl_year_index: dict[str, list[dict[str, object]]],
) -> tuple[int | None, str, list[dict[str, object]]]:
    entries: list[dict[str, object]] = []
    seen: set[tuple[object, object, object, object]] = set()
    for identifier in sorted(match_ids):
        for entry in dsl_year_index.get(identifier, []):
            key = (
                entry.get("kind"),
                entry.get("source"),
                entry.get("evidence") or entry.get("reason"),
                entry.get("year"),
            )
            if key in seen:
                continue
            seen.add(key)
            entries.append(dict(entry))
    if not entries:
        return None, "no_source_date_evidence", []
    conflict_rows: list[dict[str, object]] = []
    resolved_rows: list[dict[str, object]] = []
    for entry in entries:
        if entry.get("kind") == "conflict":
            for row in entry.get("conflicting_evidence", []):
                if isinstance(row, dict):
                    conflict_rows.append(dict(row))
            continue
        resolved_rows.append(
            {
                "field": entry.get("evidence"),
                "year": entry.get("year"),
                "source": entry.get("source"),
            }
        )
    years = {int(row["year"]) for row in resolved_rows if row.get("year") is not None}
    if conflict_rows or len(years) > 1:
        return (
            None,
            "dsl_conflicting_source_date_evidence",
            _summarize_conflicting_year_evidence(conflict_rows + resolved_rows),
        )
    if not resolved_rows:
        return None, "no_source_date_evidence", []
    chosen = resolved_rows[0]
    return int(chosen["year"]), f"{chosen['field']}:{chosen['source']}", []


def _unsafe_hints_from_matching_dsl(
    match_ids: set[str],
    dsl_hint_index: dict[str, list[dict[str, object]]],
) -> list[dict[str, object]]:
    hints: list[dict[str, object]] = []
    seen: set[tuple[object, object, object]] = set()
    for identifier in sorted(match_ids):
        for hint in dsl_hint_index.get(identifier, []):
            key = (hint.get("field"), hint.get("year"), hint.get("source"))
            if key in seen:
                continue
            seen.add(key)
            hints.append(dict(hint))
            if len(hints) >= 8:
                return hints
    return hints


def _bump(counter: dict[str, int], key: object, amount: int = 1) -> None:
    text = str(key or "").strip()
    if not text:
        return
    counter[text] = counter.get(text, 0) + amount


def _status_message(summary: dict[str, Any]) -> str:
    if summary["errors"]:
        return "completed_with_errors"
    if summary["updated"]:
        return "safe_source_date_candidates_found"
    if summary["sentinel_solodit_records"]:
        return (
            "intentionally_unresolved_no_safe_source_date_candidates; "
            "year=2000 remains the unknown-year sentinel, not a failed parse"
        )
    return "no_solodit_unknown_year_sentinel_records"


YEAR_SENTINEL_RE = re.compile(r"^year:\s+2000\s*$", re.MULTILINE)


def _replace_year_line(tag_path: Path, year: int) -> bool:
    text = tag_path.read_text(encoding="utf-8")
    updated, count = YEAR_SENTINEL_RE.subn(f"year: {year}", text, count=1)
    if count != 1:
        return False
    tag_path.write_text(updated, encoding="utf-8")
    return True


def backfill_years(
    tag_dir: Path,
    *,
    dry_run: bool = False,
    reference_dir: Path = DEFAULT_REFERENCE_DIR,
    candidates_path: Path | None = None,
) -> dict[str, Any]:
    dsl_year_index = _build_dsl_year_index(reference_dir)
    dsl_hint_index = _build_dsl_unsafe_hint_index(reference_dir)
    scanned = 0
    sentinel = 0
    updated = 0
    unresolved = 0
    unsafe_hint_records = 0
    skipped = 0
    unresolved_reason_counts: dict[str, int] = {}
    errors: list[str] = []
    examples: list[dict[str, object]] = []
    unresolved_examples: list[dict[str, object]] = []
    unsafe_hint_examples: list[dict[str, object]] = []
    conflicting_source_date_examples: list[dict[str, object]] = []
    candidate_rows: list[dict[str, object]] = []
    safe_source_date_field_counts: dict[str, int] = {}
    candidate_evidence_counts: dict[str, int] = {}
    unsafe_hint_field_counts: dict[str, int] = {}
    conflicting_source_date_field_counts: dict[str, int] = {}
    records_with_safe_source_date_fields = 0
    conflicting_source_date_records = 0

    if candidates_path is not None:
        candidates_path.parent.mkdir(parents=True, exist_ok=True)
        # Truncate prior dry-run output so the JSONL only reflects this invocation.
        try:
            candidates_path.write_text("", encoding="utf-8")
        except OSError as exc:
            errors.append(f"{candidates_path}: write error: {exc}")

    for tag_path in sorted(tag_dir.glob("*.yaml")):
        scanned += 1
        try:
            record = _VALIDATOR.load_yaml(tag_path)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{tag_path}: YAML parse error: {exc}")
            continue
        if not _VALIDATOR.is_hackerman_record(record):
            skipped += 1
            continue
        errs = _VALIDATOR.validate_doc(record)
        if errs:
            errors.extend(f"{tag_path}: {err}" for err in errs)
            continue
        if not str(record.get("source_audit_ref") or "").startswith("solodit-spec:"):
            skipped += 1
            continue
        if record.get("year") != 2000:
            skipped += 1
            continue
        sentinel += 1
        spec_path, source_ref_id = _source_spec_ref(record.get("source_audit_ref"))
        source_data: dict[str, Any] | None = None
        conflicting_evidence: list[dict[str, object]] = []
        if spec_path:
            source_data, source_error = _load_source_spec(spec_path)
            if source_data is None:
                year, evidence = None, str(source_error)
            else:
                per_record_safe_counts = _safe_date_field_counts(source_data)
                if per_record_safe_counts:
                    records_with_safe_source_date_fields += 1
                    for field, count in per_record_safe_counts.items():
                        _bump(safe_source_date_field_counts, field, count)
                year, evidence, conflicting_evidence = _extract_year_from_spec_data(source_data, spec_path)
        else:
            year, evidence = None, "source_ref_unparseable"
        match_ids = _source_match_ids(record, source_data, source_ref_id)
        unsafe_hints = _collect_unsafe_year_hints(source_data, spec_path)
        unsafe_hints.extend(_unsafe_hints_from_matching_dsl(match_ids, dsl_hint_index))
        if unsafe_hints:
            unsafe_hint_records += 1
            for hint in unsafe_hints:
                _bump(unsafe_hint_field_counts, hint.get("field"))
            if len(unsafe_hint_examples) < 8:
                unsafe_hint_examples.append(
                    {
                        "tag_file": tag_path.name,
                        "source_audit_ref": record.get("source_audit_ref"),
                        "unsafe_hints": unsafe_hints[:4],
                    }
                )
        if year is None and evidence != "conflicting_source_date_evidence":
            dsl_year, dsl_evidence, dsl_conflicting_evidence = _extract_year_from_matching_dsl(
                match_ids,
                dsl_year_index,
            )
            if dsl_year is not None:
                year, evidence = dsl_year, dsl_evidence
            elif dsl_evidence != "no_source_date_evidence":
                evidence = dsl_evidence
                conflicting_evidence = dsl_conflicting_evidence
        if year is None:
            unresolved += 1
            unresolved_reason_counts[evidence] = unresolved_reason_counts.get(evidence, 0) + 1
            if evidence in {"conflicting_source_date_evidence", "dsl_conflicting_source_date_evidence"}:
                conflicting_source_date_records += 1
                for row in conflicting_evidence:
                    for field in row.get("fields", []):
                        _bump(conflicting_source_date_field_counts, field)
                if len(conflicting_source_date_examples) < 8:
                    conflicting_source_date_examples.append(
                        {
                            "tag_file": tag_path.name,
                            "source_audit_ref": record.get("source_audit_ref"),
                            "reason": evidence,
                            "conflicting_evidence": conflicting_evidence[:4],
                        }
                    )
            if len(unresolved_examples) < 8:
                example = {
                    "tag_file": tag_path.name,
                    "source_audit_ref": record.get("source_audit_ref"),
                    "reason": evidence,
                    "unsafe_hints": unsafe_hints[:4],
                }
                if conflicting_evidence:
                    example["conflicting_evidence"] = conflicting_evidence[:4]
                unresolved_examples.append(example)
            continue
        if not dry_run:
            if not _replace_year_line(tag_path, year):
                errors.append(f"{tag_path}: expected one 'year: 2000' line")
                continue
        updated += 1
        _bump(candidate_evidence_counts, evidence)
        candidate_row = {
            "schema": "auditooor.hackerman_backfill_solodit_years_candidate.v1",
            "tag_file": tag_path.name,
            "record_id": record.get("record_id"),
            "old_year": 2000,
            "new_year": year,
            "evidence": evidence,
            "source_audit_ref": record.get("source_audit_ref"),
            "source_spec": str(spec_path.relative_to(REPO_ROOT)) if spec_path else "",
            "unsafe_hints_observed": unsafe_hints,
        }
        candidate_rows.append(candidate_row)
        if len(examples) < 8:
            examples.append(
                {
                    "tag_file": tag_path.name,
                    "year": year,
                    "evidence": evidence,
                    "source_spec": str(spec_path.relative_to(REPO_ROOT)) if spec_path else "",
                }
            )

    if candidates_path is not None:
        try:
            with candidates_path.open("w", encoding="utf-8") as fh:
                for row in candidate_rows:
                    fh.write(json.dumps(row, sort_keys=True) + "\n")
        except OSError as exc:
            errors.append(f"{candidates_path}: write error: {exc}")

    summary: dict[str, Any] = {
        "schema": "auditooor.hackerman_backfill_solodit_years.v1",
        "tag_dir": str(tag_dir),
        "dry_run": dry_run,
        "scanned_files": scanned,
        "skipped": skipped,
        "sentinel_solodit_records": sentinel,
        "updated": updated,
        "unresolved": unresolved,
        "unsafe_hint_records": unsafe_hint_records,
        "records_with_safe_source_date_fields": records_with_safe_source_date_fields,
        "conflicting_source_date_records": conflicting_source_date_records,
        "safe_source_date_field_counts": safe_source_date_field_counts,
        "candidate_evidence_counts": candidate_evidence_counts,
        "unsafe_hint_field_counts": unsafe_hint_field_counts,
        "conflicting_source_date_field_counts": conflicting_source_date_field_counts,
        "unresolved_reason_counts": unresolved_reason_counts,
        "examples": examples,
        "unresolved_examples": unresolved_examples,
        "unsafe_hint_examples": unsafe_hint_examples,
        "conflicting_source_date_examples": conflicting_source_date_examples,
        "errors": errors,
        "candidates_path": str(candidates_path) if candidates_path is not None else "",
        "candidates_written": len(candidate_rows),
    }
    summary["status_message"] = _status_message(summary)
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag-dir", default=str(DEFAULT_TAG_DIR))
    parser.add_argument("--index-dir", default=str(DEFAULT_INDEX_DIR))
    parser.add_argument("--reference-dir", default=str(DEFAULT_REFERENCE_DIR))
    parser.add_argument("--candidates-path", default=str(DEFAULT_CANDIDATES_PATH))
    parser.add_argument("--apply", action="store_true", help="Alias for default mutate-mode (compat with reclassify CLI).")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--rebuild-index", action="store_true")
    parser.add_argument("--json-summary", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    tag_dir = Path(args.tag_dir).expanduser().resolve()
    candidates_path = Path(args.candidates_path).expanduser().resolve()
    summary = backfill_years(
        tag_dir,
        dry_run=args.dry_run,
        reference_dir=Path(args.reference_dir).expanduser().resolve(),
        candidates_path=candidates_path,
    )
    if summary["errors"]:
        for error in summary["errors"]:
            print(error, file=sys.stderr)
    if args.rebuild_index and not args.dry_run and not summary["errors"]:
        index_tool = _load_tool(
            REPO_ROOT / "tools" / "hackerman-index-build.py",
            "_hackerman_index_build_for_year_backfill",
        )
        summary["index_counts"] = index_tool.build_indices(
            tag_dir,
            Path(args.index_dir).expanduser().resolve(),
            preserve_existing=True,
        )
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "hackerman Solodit year backfill: "
            f"sentinel={summary['sentinel_solodit_records']} "
            f"updated={summary['updated']} unresolved={summary['unresolved']} "
            f"errors={len(summary['errors'])}"
        )
    return 0 if not summary["errors"] else 1


if __name__ == "__main__":
    sys.exit(main())
