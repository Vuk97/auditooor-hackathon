#!/usr/bin/env python3
"""wirer-output-diversity-check.py — refuse a wire pass when output predicates
collapse to a single fixture-distinguishing trick.

Background (2026-05-04 incident):
  fp_repair_v2 wire pass produced 162 smoke-passing "refined" YAMLs. Manual
  inspection found 91/91 newly-emitted YAMLs regressed to the same trick:

      match:
        - function.name_matches: "<target>"
        - function.body_not_contains_regex: "require\\s*\\("
        - function.not_slither_synthetic: true
        - function.not_in_skip_list: true

  This predicate distinguishes the FIXTURE SHAPE (vulnerable=no-require,
  clean=has-require), not the BUG CLASS. Smoke passes; the detector is fake.

  Mitigation: this tool. Run AFTER a wirer emits its YAMLs but BEFORE
  inventory-bulk-promote runs. Refuses promotion if predicate diversity is
  too low.

Usage:
  # Stand-alone (post-wire):
  python3 tools/wirer-output-diversity-check.py \\
    --emitted-yaml-dir reference/patterns.dsl/ \\
    --emitted-since '<ISO timestamp the wirer started>' \\
    [--max-share 0.3] \\
    [--min-cohort 5]

  # Or pass an explicit list of YAMLs:
  python3 tools/wirer-output-diversity-check.py \\
    --yaml-list /tmp/emitted_yamls.txt \\
    [--max-share 0.3]

  # Strict-mode (block promotion if any cluster exceeds threshold):
  python3 tools/wirer-output-diversity-check.py ... --strict

Exit codes:
  0  diversity OK
  1  diversity violation (cluster exceeds --max-share); promotion should be refused
  2  bad input

Algorithm:
  1. Read each emitted YAML's `match:` block.
  2. Canonicalize predicates: drop scope-keys (`function.name_matches`,
     `function.not_slither_synthetic`, `function.not_in_skip_list`),
     keeping the SEMANTIC predicate keys (the actual bug-class signals).
  3. Hash the remaining sorted-tuple of (key, value) pairs.
  4. Count cohort sizes by hash.
  5. If any cohort > max_share * total: VIOLATION.
  6. If --min-cohort given, ignore cohorts below that size threshold (small
     cohorts are noise, not regressions).

This is a heuristic. It catches the SPECIFIC failure mode where an LLM
collapses to a single trick. It does NOT catch:
  - Subtle FPs where each detector's predicate is unique but wrong.
  - Drift where the LLM regresses to N tricks with N small (still each
    a fake but no single dominant cluster).

Use alongside (not instead of) random-sample audits and strict-smoke.
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple

try:
    import yaml  # type: ignore
except ImportError:
    print("PyYAML required: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

REPO = Path(__file__).resolve().parents[1]

# Predicate keys that are scope-only — they carry no semantic bug-class signal.
# A predicate composed ONLY of these is shape-distinguishing, not bug-class.
SCOPE_ONLY_KEYS = {
    "function.name_matches",
    "function.name_equals",
    "function.kind",
    "function.visibility",
    "function.not_slither_synthetic",
    "function.not_in_skip_list",
    "function.is_external",
    "function.is_public",
    "function.is_internal",
    "function.is_private",
    "contract.name_matches",
    "contract.name_equals",
    "file.path_matches",
}


def canonicalize_match_block(match_block) -> Tuple[Tuple[str, str], ...]:
    """Reduce a YAML `match:` block to a hashable canonical form, semantic-only."""
    if not match_block:
        return ()
    pairs = []
    if isinstance(match_block, list):
        for entry in match_block:
            if isinstance(entry, dict):
                for k, v in entry.items():
                    if k in SCOPE_ONLY_KEYS:
                        continue  # drop scope-only
                    pairs.append((str(k), str(v)))
            elif isinstance(entry, str):
                pairs.append(("__bare_str__", entry))
    elif isinstance(match_block, dict):
        for k, v in match_block.items():
            if k in SCOPE_ONLY_KEYS:
                continue
            pairs.append((str(k), str(v)))
    return tuple(sorted(pairs))


def hash_predicate(canonical: Tuple[Tuple[str, str], ...]) -> str:
    h = hashlib.sha256()
    h.update(repr(canonical).encode())
    return h.hexdigest()[:16]


def load_yaml_match(path: Path) -> Tuple[Tuple[str, str], ...] | None:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return None
        return canonicalize_match_block(data.get("match"))
    except Exception:
        return None


def collect_yamls(args: argparse.Namespace) -> List[Path]:
    if args.yaml_list:
        with open(args.yaml_list, "r", encoding="utf-8") as f:
            return [Path(line.strip()) for line in f if line.strip()]
    if args.emitted_yaml_dir and args.emitted_since:
        cutoff = datetime.datetime.fromisoformat(args.emitted_since.replace("Z", "+00:00"))
        if cutoff.tzinfo is None:
            cutoff = cutoff.replace(tzinfo=datetime.timezone.utc)
        out: List[Path] = []
        for yaml_path in Path(args.emitted_yaml_dir).glob("*.yaml"):
            mtime = datetime.datetime.fromtimestamp(yaml_path.stat().st_mtime, tz=datetime.timezone.utc)
            if mtime >= cutoff:
                out.append(yaml_path)
        return out
    return []


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--emitted-yaml-dir", help="directory of YAML files (e.g. reference/patterns.dsl/)")
    ap.add_argument("--emitted-since", help="ISO timestamp; only yamls mtime >= this are checked")
    ap.add_argument("--yaml-list", help="path to a file containing one YAML path per line (alternative to --emitted-yaml-dir)")
    ap.add_argument("--max-share", type=float, default=0.30,
                    help="max share of one canonical predicate (default 0.30 = 30 percent)")
    ap.add_argument("--min-cohort", type=int, default=5,
                    help="ignore cohorts smaller than this (default 5)")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 on first violation (default behavior already does this)")
    ap.add_argument("--json-out", help="optional path to write the diversity report JSON")
    args = ap.parse_args()

    yamls = collect_yamls(args)
    if not yamls:
        print("[diversity-check] no YAMLs to check (need --yaml-list or --emitted-yaml-dir + --emitted-since)", file=sys.stderr)
        return 2

    cohorts: Dict[str, List[str]] = {}
    canonicals: Dict[str, Tuple[Tuple[str, str], ...]] = {}
    skipped: List[str] = []

    for yaml_path in yamls:
        canonical = load_yaml_match(yaml_path)
        if canonical is None or len(canonical) == 0:
            skipped.append(str(yaml_path))
            continue
        h = hash_predicate(canonical)
        cohorts.setdefault(h, []).append(str(yaml_path))
        canonicals[h] = canonical

    total = sum(len(v) for v in cohorts.values())
    if total == 0:
        print("[diversity-check] no parseable YAMLs", file=sys.stderr)
        return 2

    violations: List[Dict] = []
    for h, members in sorted(cohorts.items(), key=lambda x: -len(x[1])):
        share = len(members) / total
        if len(members) >= args.min_cohort and share > args.max_share:
            violations.append({
                "predicate_hash": h,
                "cohort_size": len(members),
                "share": round(share, 4),
                "canonical_predicate": [list(p) for p in canonicals[h]],
                "sample_members": members[:5],
            })

    report = {
        "schema": "auditooor.wirer_output_diversity.v1",
        "ran_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "total_checked": total,
        "skipped_count": len(skipped),
        "cohort_count": len(cohorts),
        "max_share_threshold": args.max_share,
        "min_cohort_threshold": args.min_cohort,
        "violations": violations,
        "passes": len(violations) == 0,
    }

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(report, indent=2))

    print(f"[diversity-check] checked {total} yamls, {len(cohorts)} distinct predicate cohorts")
    print(f"  max_share = {args.max_share}, min_cohort = {args.min_cohort}")
    if violations:
        print(f"  ❌ {len(violations)} violations:")
        for v in violations:
            print(f"    cohort {v['predicate_hash']}: {v['cohort_size']} members ({v['share']:.1%})")
            for p in v["canonical_predicate"][:3]:
                print(f"      - {p[0]}: {p[1][:80]}")
            print(f"      sample: {', '.join(Path(m).name for m in v['sample_members'])}")
        print()
        print("  → Promotion should be REFUSED. Predicate cohort exceeds diversity threshold.")
        return 1
    print("  ✅ diversity OK. No predicate cohort exceeds threshold.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
