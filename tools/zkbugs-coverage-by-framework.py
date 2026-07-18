#!/usr/bin/env python3
"""zkbugs-coverage-by-framework.py — print ZK framework coverage table.

Wave-6 Track K-zkBugs step K-Z.10f. Shows gap between corpus size per
ZK framework and the number of detectors shipped for that framework.

Usage:
    python3 tools/zkbugs-coverage-by-framework.py
    make zkbugs-coverage-by-framework

Run after `make zkbugs-ingest-all` to get accurate corpus counts.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

INDEX_PATHS = [
    ROOT / "audit" / "zkbugs" / "0xparc_index.json",
    ROOT / ".audit_logs" / "zkbugs_farming" / "zkbugs_index.json",
    Path("/Users/wolf/audits/base-azul/.audit_logs/zkbugs_farming/zkbugs_index.json"),
]

FRAMEWORKS = [
    "circom",
    "halo2",
    "plonky2",
    "plonky3",
    "noir",
    "cairo",
    "bellperson",
    "arkworks",
    "gnark",
    "risc0",
    "pil",
    "other",
]


def count_detectors(det_root: Path) -> dict[str, int]:
    """Count .py detector files (excluding _private) per framework wave dir."""
    out: dict[str, int] = {}
    for fw in FRAMEWORKS:
        wave_dirs = list(det_root.glob(f"{fw}_wave*"))
        total = sum(
            len([p for p in d.glob("*.py") if not p.stem.startswith("_")])
            for d in wave_dirs
        )
        out[fw] = total
    return out


def count_corpus(index_paths: list[Path]) -> dict[str, int]:
    """Count records per framework across all loaded index files."""
    counts: dict[str, int] = {f: 0 for f in FRAMEWORKS}
    for p in index_paths:
        if not p.exists():
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception as exc:
            sys.stderr.write(f"[zkbugs-coverage] warn: could not load {p}: {exc}\n")
            continue
        records = data.get("records") or data.get("bugs") or []
        for r in records:
            dsl = (
                r.get("dsl") or r.get("framework") or r.get("language") or ""
            ).lower()
            matched = False
            for key in FRAMEWORKS[:-1]:  # skip "other"
                if key in dsl:
                    counts[key] += 1
                    matched = True
                    break
            if not matched:
                counts["other"] += 1
    return counts


def main() -> None:
    det_root = ROOT / "detectors"
    detector_counts = count_detectors(det_root)
    corpus_counts = count_corpus(INDEX_PATHS)

    # Sorted by corpus count descending, other at bottom
    sorted_fws = sorted(FRAMEWORKS[:-1], key=lambda x: -corpus_counts[x])

    print("Framework    | Bugs in corpus | Detectors shipped")
    print("-" * 52)
    for fw in sorted_fws:
        print(
            f"{fw:12} | {corpus_counts[fw]:14} | {detector_counts.get(fw, 0)}"
        )
    print(f'{"other":12} | {corpus_counts["other"]:14} | -')


if __name__ == "__main__":
    main()
