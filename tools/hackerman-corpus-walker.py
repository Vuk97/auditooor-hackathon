#!/usr/bin/env python3
"""Shared recursive corpus walker - coverage report and enumeration tool.

B7 (V3 plan): All hunter-facing sidecars share `iter_corpus_record_paths`
from `hackerman_query_common`. This standalone tool surfaces the walker's
output as a human-readable coverage report and a machine-readable JSON
inventory, so operators can verify before/after coverage counts without
rebuilding any sidecar.

Usage:
    python3 tools/hackerman-corpus-walker.py                  # text summary
    python3 tools/hackerman-corpus-walker.py --json           # JSON output
    python3 tools/hackerman-corpus-walker.py --compare-sidecar audit/corpus_tags/derived/exploit_predicates.manifest.json
    python3 tools/hackerman-corpus-walker.py --include-excluded  # quarantine too
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from hackerman_query_common import (  # noqa: E402
    DEFAULT_TAGS_DIR,
    corpus_content_fingerprint,
    iter_corpus_record_paths,
    utc_now,
    yaml_load,
)

SCHEMA_VERSION = "auditooor.hackerman_corpus_walker_report.v1"
ACTIVE_RECORD_SCHEMAS = frozenset({
    "auditooor.hackerman_record.v1",
    "auditooor.hackerman_record.v1.1",
    "auditooor.darknavy_web3_record.v1",
})


def _try_load_record(path: Path) -> dict[str, Any] | None:
    try:
        if path.suffix == ".json":
            doc = json.loads(path.read_text(encoding="utf-8"))
        else:
            doc = yaml_load(path.read_text(encoding="utf-8"))
        return doc if isinstance(doc, dict) else None
    except Exception:
        return None


def _file_kind(path: Path) -> str:
    """Return a short string describing how this file was reached by the walker."""
    name = path.name
    if name == "record.yaml":
        return "nested-record.yaml"
    if name == "record.json":
        return "nested-record.json"
    if name.endswith(".yml"):
        return "flat.yml"
    return "flat.yaml"


def walk_corpus(
    tag_dir: Path,
    *,
    include_excluded: bool = False,
) -> dict[str, Any]:
    """Enumerate all canonical corpus record files and return a coverage dict."""
    items = list(iter_corpus_record_paths(tag_dir, include_excluded=include_excluded))
    fingerprint, _ = corpus_content_fingerprint(tag_dir, recursive=True)

    by_kind: Counter[str] = Counter()
    by_schema: Counter[str] = Counter()
    by_top_level: Counter[str] = Counter()
    active_count = 0
    load_errors = 0
    non_record_schema = 0

    for item in items:
        kind = _file_kind(item.path)
        by_kind[kind] += 1
        top = item.relative_path.split("/", 1)[0] if "/" in item.relative_path else "."
        doc = _try_load_record(item.path)
        if doc is None:
            load_errors += 1
            continue
        schema = str(doc.get("schema_version") or doc.get("schema") or "")
        if schema:
            by_schema[schema] += 1
        if schema in ACTIVE_RECORD_SCHEMAS:
            active_count += 1
            by_top_level[top] += 1
        else:
            non_record_schema += 1

    return {
        "schema_version": SCHEMA_VERSION,
        "tag_dir": str(tag_dir),
        "generated_at_utc": utc_now(),
        "corpus_fingerprint": fingerprint,
        "include_excluded": include_excluded,
        "canonical_record_files": len(items),
        "active_records": active_count,
        "load_errors": load_errors,
        "non_record_schema_files": non_record_schema,
        "files_by_kind": dict(sorted(by_kind.items())),
        "active_records_by_schema": dict(sorted(by_schema.items())),
        "active_records_by_top_level": dict(sorted(by_top_level.items())),
    }


def compare_with_sidecar(
    walker_report: dict[str, Any],
    sidecar_path: Path,
) -> dict[str, Any]:
    """Compare walker canonical file count against a built sidecar's meta."""
    canonical = int(walker_report.get("canonical_record_files") or 0)
    meta_corpus_file_count = 0
    emitted = 0
    layout = "unknown"
    shard_count = 0

    manifest_path = sidecar_path.with_name(f"{sidecar_path.stem}.manifest.json")
    if manifest_path.is_file():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            meta_corpus_file_count = int(manifest.get("corpus_file_count") or 0)
            emitted = int(manifest.get("records_emitted") or 0)
            layout = str(manifest.get("sidecar_layout") or "sharded-jsonl")
            shard_count = int(manifest.get("shard_count") or 0)
        except Exception:
            pass
    elif sidecar_path.is_file():
        try:
            with sidecar_path.open("r", encoding="utf-8") as fh:
                first_line = fh.readline()
            meta = json.loads(first_line)
            meta_corpus_file_count = int(meta.get("corpus_file_count") or 0)
            emitted = int(
                meta.get("records_emitted")
                or meta.get("records_loaded")
                or 0
            )
            layout = "jsonl"
        except Exception:
            pass

    coverage_ratio = (
        meta_corpus_file_count / canonical if canonical else 0.0
    )
    return {
        "sidecar_path": str(sidecar_path),
        "sidecar_layout": layout,
        "shard_count": shard_count,
        "sidecar_meta_corpus_file_count": meta_corpus_file_count,
        "sidecar_records_emitted": emitted,
        "walker_canonical_record_files": canonical,
        "sidecar_file_coverage_ratio": round(coverage_ratio, 6),
        "coverage_ok": coverage_ratio >= 0.98,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag-dir", default=str(DEFAULT_TAGS_DIR))
    parser.add_argument(
        "--include-excluded",
        action="store_true",
        help="Include quarantine and deprecated subtrees in the count.",
    )
    parser.add_argument(
        "--compare-sidecar",
        default=None,
        metavar="PATH",
        help="Path to a sidecar .jsonl or manifest .json to compare coverage against.",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    args = parser.parse_args(argv)

    tag_dir = Path(args.tag_dir).expanduser().resolve()
    if not tag_dir.is_dir():
        print(f"tag dir not found: {tag_dir}", file=sys.stderr)
        return 2

    report = walk_corpus(tag_dir, include_excluded=args.include_excluded)

    if args.compare_sidecar:
        comparison = compare_with_sidecar(report, Path(args.compare_sidecar).expanduser().resolve())
        report["sidecar_comparison"] = comparison

    if args.json:
        print(json.dumps(report, sort_keys=True))
        return 0

    canonical = report["canonical_record_files"]
    active = report["active_records"]
    errors = report["load_errors"]
    non_rec = report["non_record_schema_files"]
    print(f"Corpus walker report ({tag_dir})")
    print(f"  canonical record files : {canonical:,}")
    print(f"  active records         : {active:,}")
    print(f"  non-record schema files: {non_rec:,}")
    print(f"  load errors            : {errors:,}")
    print()
    print("Files by kind:")
    for kind, count in sorted(report["files_by_kind"].items(), key=lambda x: -x[1]):
        print(f"  {kind:<30} {count:,}")
    print()
    print("Active records by schema:")
    for schema, count in sorted(report["active_records_by_schema"].items(), key=lambda x: -x[1]):
        print(f"  {schema:<55} {count:,}")
    print()
    print(f"Top-level subtrees with active records: {len(report['active_records_by_top_level'])}")

    cmp = report.get("sidecar_comparison")
    if cmp:
        print()
        print("Sidecar comparison:")
        print(f"  path           : {cmp['sidecar_path']}")
        print(f"  layout         : {cmp['sidecar_layout']}")
        print(f"  shard_count    : {cmp['shard_count']}")
        print(f"  records_emitted: {cmp['sidecar_records_emitted']:,}")
        print(f"  file_coverage  : {cmp['sidecar_file_coverage_ratio']:.4f} ({'OK' if cmp['coverage_ok'] else 'BELOW 98%'})")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
