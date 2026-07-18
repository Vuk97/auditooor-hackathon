#!/usr/bin/env python3
"""Build a no-guessing Solodit date enrichment queue.

``hackerman-backfill-solodit-years.py`` is intentionally conservative: it only
mutates ``year: 2000`` when local specs contain explicit date fields. This tool
is the next step for records that do not have those fields yet. It emits a
bounded JSONL queue for provider/manual/web enrichment, preserving unsafe
date-looking hints as hints only.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TAG_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_OUT = REPO_ROOT / "reports" / "solodit_date_enrichment_queue.jsonl"
DEFAULT_SUMMARY = REPO_ROOT / "reports" / "solodit_date_enrichment_queue_summary.json"
BACKFILL_TOOL = REPO_ROOT / "tools" / "hackerman-backfill-solodit-years.py"

DATE_RE = re.compile(r"(?<!\d)(19|20)\d{2}[-_/](0[1-9]|1[0-2])[-_/]([0-2]\d|3[01])(?!\d)")
YEAR_RE = re.compile(r"(?<!\d)(19|20)\d{2}(?!\d)")


def _load_tool(path: Path, name: str) -> Any:
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_BACKFILL = _load_tool(BACKFILL_TOOL, "_solodit_date_enrichment_backfill")
_ETL = _BACKFILL._ETL
_VALIDATOR = _BACKFILL._VALIDATOR


HINT_FIELDS = (
    "source",
    "source_url",
    "protocol",
    "wiki_title",
    "title",
    "wiki_description",
    "description",
    "solodit_slug",
)


def _safe_rel(path: Path) -> str:
    try:
        return path.resolve(strict=False).relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _date_hints(field: str, value: object) -> list[dict[str, object]]:
    text = str(value or "").strip()
    if not text:
        return []
    hints: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for match in DATE_RE.finditer(text):
        raw = match.group(0)
        key = ("date", raw)
        if key in seen:
            continue
        seen.add(key)
        hints.append(
            {
                "field": field,
                "raw": raw,
                "kind": "date_like_hint",
                "year": int(raw[:4]),
                "classification": "unsafe_hint_only",
                "reason": "date-looking text is not explicit source-date metadata",
            }
        )
    for match in YEAR_RE.finditer(text):
        raw = match.group(0)
        key = ("year", raw)
        if key in seen:
            continue
        seen.add(key)
        hints.append(
            {
                "field": field,
                "raw": raw,
                "kind": "year_like_hint",
                "year": int(raw),
                "classification": "unsafe_hint_only",
                "reason": "year-looking text is not explicit source-date metadata",
            }
        )
    return hints[:8]


def _unsafe_hints(source_data: dict[str, Any] | None, spec_path: Path | None) -> list[dict[str, object]]:
    if source_data is None:
        return []
    hints: list[dict[str, object]] = []
    for field in HINT_FIELDS:
        hints.extend(_date_hints(field, source_data.get(field)))
        if len(hints) >= 8:
            break
    if len(hints) < 8 and spec_path is not None:
        hints.extend(_date_hints("spec_path.stem", spec_path.stem))
    return hints[:8]


def _source_label(source_data: dict[str, Any] | None) -> str:
    if not source_data:
        return ""
    return str(source_data.get("source") or source_data.get("source_url") or "").strip()


def _queue_row(
    tag_path: Path,
    record: dict[str, Any],
    *,
    spec_path: Path | None,
    source_ref_id: str,
    source_data: dict[str, Any] | None,
    source_error: str | None,
) -> dict[str, object]:
    record_id = str(record.get("record_id") or tag_path.stem)
    source_label = _source_label(source_data)
    queue_id = "solodit-date-" + _sha(record_id + "|" + str(record.get("source_audit_ref") or ""))[:16]
    safe_field_counts = _BACKFILL._safe_date_field_counts(source_data)
    hints = _unsafe_hints(source_data, spec_path)
    status = "needs_explicit_source_date"
    if source_error:
        status = source_error
    elif safe_field_counts:
        status = "local_safe_date_fields_present_run_backfill"
    return {
        "schema": "auditooor.solodit_date_enrichment_queue.row.v1",
        "queue_id": queue_id,
        "status": status,
        "record_id": record_id,
        "tag_file": _safe_rel(tag_path),
        "source_audit_ref": record.get("source_audit_ref"),
        "solodit_id": source_ref_id,
        "source_spec": _safe_rel(spec_path) if spec_path else "",
        "source_label": source_label,
        "target_language": record.get("target_language"),
        "attack_class": record.get("attack_class"),
        "bug_class": record.get("bug_class"),
        "severity_at_finding": record.get("severity_at_finding"),
        "safe_date_fields_present": safe_field_counts,
        "unsafe_date_hints": hints,
        "lookup_terms": [
            term
            for term in (
                f"Solodit #{source_ref_id}" if source_ref_id else "",
                source_label,
                str(record.get("target_repo") or ""),
            )
            if term
        ],
        "candidate_urls_unverified": [
            f"https://solodit.cyfrin.io/issues/{source_ref_id}" if source_ref_id else "",
            f"https://solodit.xyz/issues/{source_ref_id}" if source_ref_id else "",
        ],
        "accepted_evidence_required": [
            "explicit source-date field on the Solodit page or API response",
            "explicit date on the linked primary audit report",
            "explicit publication/report date from primary vendor/auditor metadata",
        ],
        "rejection_rules": [
            "do not mutate from source/title/path/filename/date-looking hints",
            "do not infer from Solodit id, import cycle, filesystem mtime, or current date",
            "do not accept year-only values unless the primary source explicitly exposes only year precision",
        ],
    }


def build_queue(
    tag_dir: Path,
    *,
    limit: int | None = None,
    status_filter: str = "needs_explicit_source_date",
) -> tuple[list[dict[str, object]], dict[str, object]]:
    rows: list[dict[str, object]] = []
    scanned = skipped = errors = 0
    status_counts: dict[str, int] = {}
    hint_field_counts: dict[str, int] = {}
    for tag_path in sorted(tag_dir.glob("*.yaml")):
        scanned += 1
        try:
            record = _VALIDATOR.load_yaml(tag_path)
        except Exception:  # noqa: BLE001
            errors += 1
            continue
        if not _VALIDATOR.is_hackerman_record(record):
            skipped += 1
            continue
        if record.get("year") != 2000:
            skipped += 1
            continue
        if not str(record.get("source_audit_ref") or "").startswith("solodit-spec:"):
            skipped += 1
            continue
        spec_path, source_ref_id = _BACKFILL._source_spec_ref(record.get("source_audit_ref"))
        source_data = None
        source_error = None
        if spec_path:
            source_data, source_error = _BACKFILL._load_source_spec(spec_path)
        else:
            source_error = "source_ref_unparseable"
        row = _queue_row(
            tag_path,
            record,
            spec_path=spec_path,
            source_ref_id=source_ref_id,
            source_data=source_data,
            source_error=source_error,
        )
        status = str(row["status"])
        status_counts[status] = status_counts.get(status, 0) + 1
        for hint in row["unsafe_date_hints"]:  # type: ignore[index]
            if isinstance(hint, dict):
                field = str(hint.get("field") or "")
                hint_field_counts[field] = hint_field_counts.get(field, 0) + 1
        if status_filter != "all" and status != status_filter:
            continue
        rows.append(row)
        if limit is not None and len(rows) >= limit:
            break
    summary: dict[str, object] = {
        "schema": "auditooor.solodit_date_enrichment_queue.summary.v1",
        "tag_dir": str(tag_dir),
        "scanned_files": scanned,
        "skipped": skipped,
        "errors": errors,
        "rows": len(rows),
        "status_filter": status_filter,
        "status_counts": status_counts,
        "unsafe_hint_field_counts": hint_field_counts,
        "advisory_only": True,
        "mutation_performed": False,
    }
    return rows, summary


def write_outputs(rows: list[dict[str, object]], summary: dict[str, object], out: Path, summary_out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    summary_out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
    summary_out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag-dir", type=Path, default=DEFAULT_TAG_DIR)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--summary-out", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--limit", type=int)
    parser.add_argument("--status-filter", choices=("needs_explicit_source_date", "local_safe_date_fields_present_run_backfill", "all"), default="needs_explicit_source_date")
    parser.add_argument("--json-summary", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    rows, summary = build_queue(
        args.tag_dir.expanduser().resolve(),
        limit=args.limit,
        status_filter=args.status_filter,
    )
    write_outputs(rows, summary, args.out.expanduser().resolve(), args.summary_out.expanduser().resolve())
    if args.json_summary:
        print(json.dumps(summary, sort_keys=True))
    else:
        print(
            "solodit date enrichment queue: "
            f"rows={summary['rows']} scanned={summary['scanned_files']} "
            f"errors={summary['errors']} out={args.out}"
        )
    return 0 if int(summary["errors"]) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
