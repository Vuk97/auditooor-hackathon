#!/usr/bin/env python3
"""Predicate parity probe: walker-mode vs index-mode for hackerman corpus.

Spec: docs/WAVE2_INDEX_COVERAGE_EXTENSION_SPEC_2026-05-16.md §6.3.

For each canonical predicate listed in §6.3, walks the corpus tree directly
(mirroring the post-extension ``hackerman-index-build.py:load_records``
walker shape) and compares the result count against the corresponding row
count in the derived ``audit/corpus_tags/index/by_*.jsonl`` files.

Verdict:
- ``pass-walker-index-parity`` if every probed predicate matches within
  ``--tolerance`` percent (default 0.5%).
- ``fail-walker-index-parity`` otherwise; the failing rows are emitted to
  stderr for triage.

Exit codes: 0 = pass, 1 = fail, 2 = setup error.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TAG_DIR = REPO_ROOT / "audit" / "corpus_tags" / "tags"
DEFAULT_INDEX_DIR = REPO_ROOT / "audit" / "corpus_tags" / "index"
EXCLUDED_SUBTREE_PREFIXES = ("_QUARANTINE_", "_deprecated")

# Canonical predicate set per spec §6.3.
PREDICATES = [
    ("attack_class", "reentrancy", "by_attack_class"),
    ("attack_class", "oracle-manipulation", "by_attack_class"),
    ("attack_class", "access-control", "by_attack_class"),
    ("target_language", "solidity", "by_language"),
    ("target_language", "vyper", "by_language"),
    ("target_language", "rust", "by_language"),
    ("severity_at_finding", "critical", "by_severity"),
    ("bug_class", "integer-overflow", "by_bug_class"),
    ("target_domain", "dex", "by_target_domain"),
    ("target_domain", "lending", "by_target_domain"),
]


def _is_excluded(path: Path, tag_dir: Path) -> bool:
    try:
        rel = path.relative_to(tag_dir)
    except ValueError:
        return False
    if not rel.parts:
        return False
    return rel.parts[0].startswith(EXCLUDED_SUBTREE_PREFIXES)


def iter_walker_records(tag_dir: Path) -> Iterable[dict]:
    structured = sorted(tag_dir.rglob("record.yaml"))
    flat = [
        p
        for p in sorted(list(tag_dir.rglob("*.yaml")) + list(tag_dir.rglob("*.yml")))
        if p.name != "record.yaml"
    ]
    for p in structured + flat:
        if _is_excluded(p, tag_dir):
            continue
        try:
            doc = yaml.safe_load(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(doc, dict):
            continue
        if doc.get("schema_version") != "auditooor.hackerman_record.v1":
            continue
        yield doc


def index_count(index_dir: Path, name: str, key: str) -> int:
    path = index_dir / f"{name}.jsonl"
    if not path.exists():
        return 0
    c = 0
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("key") == key:
                c += 1
    return c


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag-dir", default=str(DEFAULT_TAG_DIR))
    parser.add_argument("--index-dir", default=str(DEFAULT_INDEX_DIR))
    parser.add_argument(
        "--tolerance",
        type=float,
        default=0.5,
        help="Acceptance tolerance in percent (default 0.5).",
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    tag_dir = Path(args.tag_dir)
    index_dir = Path(args.index_dir)
    if not tag_dir.is_dir():
        print(f"hackerman-index-walker-parity-check: tag dir missing: {tag_dir}", file=sys.stderr)
        return 2
    if not index_dir.is_dir():
        print(f"hackerman-index-walker-parity-check: index dir missing: {index_dir}", file=sys.stderr)
        return 2

    walker_counters: dict[str, Counter] = {}
    for field in {field for field, _, _ in PREDICATES}:
        walker_counters[field] = Counter()

    distinct_fields = {field for field, _, _ in PREDICATES}
    for rec in iter_walker_records(tag_dir):
        for field in distinct_fields:
            walker_counters[field][str(rec.get(field) or "")] += 1

    rows = []
    all_pass = True
    for field, key, index_name in PREDICATES:
        walker_n = walker_counters[field].get(key, 0)
        index_n = index_count(index_dir, index_name, key)
        if walker_n == 0 and index_n == 0:
            diff_pct = 0.0
        elif walker_n == 0:
            diff_pct = 100.0
        else:
            diff_pct = abs(index_n - walker_n) / walker_n * 100.0
        ok = diff_pct <= args.tolerance
        all_pass = all_pass and ok
        rows.append(
            {
                "predicate": f"{field}={key}",
                "index_name": index_name,
                "walker_count": walker_n,
                "index_count": index_n,
                "diff_percent": round(diff_pct, 6),
                "verdict": "pass" if ok else "fail",
            }
        )

    verdict = "pass-walker-index-parity" if all_pass else "fail-walker-index-parity"
    payload = {
        "verdict": verdict,
        "tolerance_percent": args.tolerance,
        "rows": rows,
    }
    if args.json:
        print(json.dumps(payload, sort_keys=True, indent=2))
    else:
        print(f"verdict: {verdict}")
        print(f"tolerance: ±{args.tolerance}%")
        print()
        print(f"{'Predicate':45s} {'Walker':>8s} {'Index':>8s} {'Diff%':>8s} {'OK':>6s}")
        for row in rows:
            print(
                f"{row['predicate']:45s} {row['walker_count']:>8d} {row['index_count']:>8d} "
                f"{row['diff_percent']:>7.3f}% {row['verdict']:>6s}"
            )
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
