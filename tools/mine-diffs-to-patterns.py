#!/usr/bin/env python3
"""
mine-diffs-to-patterns.py — turn scraped diff corpus into DSL pattern candidates.

The R35 diff-scraper produced 3,219 real vuln/clean Solidity pairs in
patterns/fixtures/auto/. Until R37 they were used only for CI. This tool
mines them for PATTERN candidates: for each fix-commit diff, extract the
core transformation (what lines were ADDED that eliminate the bug) and
emit a draft DSL pattern YAML that encodes that transformation.

Usage:
    python3 tools/mine-diffs-to-patterns.py                 # print top-20 candidates
    python3 tools/mine-diffs-to-patterns.py --limit 100     # mine first N diffs
    python3 tools/mine-diffs-to-patterns.py --emit <dir>    # write draft YAMLs

Design note: this is an APPROXIMATION — the emitted YAMLs are drafts that
require human / agent review before landing in `reference/patterns.dsl/`.
The script classifies each diff by common fix-shape (e.g., "added require()",
"added nonReentrant", "changed uint256 to uint248", "reordered calls") and
emits a pattern matching the PRE-fix shape.
"""

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIFFS = ROOT / "patterns" / "fixtures" / "auto"

# Shape classifiers: (regex, class-tag)
FIX_SHAPES = [
    (re.compile(r"^\+\s*require\s*\("), "added-require"),
    (re.compile(r"^\+.*nonReentrant"), "added-nonreentrant"),
    (re.compile(r"^\+.*onlyRole|^\+.*onlyOwner"), "added-access-control"),
    (re.compile(r"^\+.*SafeERC20|^\+.*safeTransfer"), "added-safe-transfer"),
    (re.compile(r"^\+.*whenNotPaused"), "added-pause-check"),
    (re.compile(r"^\-.*\babi\.encodePacked\b.*\+.*\babi\.encode\b"), "encodePacked-to-encode"),
    (re.compile(r"^\+.*uint(8|16|32|64|128|248)"), "downsize-uint"),
    (re.compile(r"^\+.*block\.timestamp.*[<>]=?"), "added-timestamp-check"),
    (re.compile(r"^\+.*!=\s*address\(0\)|^\+.*==\s*address\(0\)"), "added-zero-address-check"),
    (re.compile(r"^\+.*slippage|^\+.*minOut|^\+.*minAmount"), "added-slippage-guard"),
    (re.compile(r"^\+.*deadline"), "added-deadline"),
    (re.compile(r"^\+.*chainid|^\+.*block\.chainid"), "added-chainid-binding"),
    (re.compile(r"^\-.*ecrecover"), "removed-raw-ecrecover"),
    (re.compile(r"^\+.*accrueInterest|^\+.*_accrue"), "added-accrue-first"),
    (re.compile(r"^\+.*_disableInitializers"), "added-disable-initializers"),
    (re.compile(r"^\-.*delegatecall"), "removed-delegatecall"),
    (re.compile(r"^\+.*mulDiv|^\+.*FullMath"), "added-mulDiv-math"),
]


def classify_diff(path: Path):
    """Return dict: counts of each fix-shape in this diff."""
    tags = Counter()
    try:
        text = path.read_text(errors="ignore")
    except Exception:
        return tags
    for line in text.splitlines():
        for rx, tag in FIX_SHAPES:
            if rx.search(line):
                tags[tag] += 1
    return tags


def find_diffs(limit=0):
    diffs = sorted(DIFFS.glob("finding_*.diff"))
    if limit:
        diffs = diffs[:limit]
    return diffs


def mine_all(limit=0):
    tag_counts = Counter()
    per_diff = {}
    for d in find_diffs(limit):
        tags = classify_diff(d)
        if not tags:
            continue
        per_diff[d.stem] = tags
        for t, c in tags.items():
            tag_counts[t] += c
    return per_diff, tag_counts


def emit_draft_yaml(tag, example_ids, out_dir: Path):
    """Emit a draft pattern YAML for a given fix-shape class."""
    slug = f"auto-mined-{tag}"
    yaml_path = out_dir / f"{slug}.yaml"
    # Shape-specific pattern templates (minimal — human/agent refines)
    if tag == "added-require":
        match_block = '  - function.body_not_contains_regex: "require\\\\s*\\\\("'
    elif tag == "added-nonreentrant":
        match_block = '  - function.has_modifier:\n      includes: ["nonReentrant"]\n      negate: true'
    elif tag == "added-zero-address-check":
        match_block = '  - function.body_not_contains_regex: "!=\\\\s*address\\\\(0\\\\)"'
    elif tag == "added-slippage-guard":
        match_block = '  - function.body_not_contains_regex: "minOut|minAmount|slippage"'
    elif tag == "added-deadline":
        match_block = '  - function.body_not_contains_regex: "deadline|expir"'
    elif tag == "encodePacked-to-encode":
        match_block = '  - function.body_contains_regex: "abi\\\\.encodePacked\\\\("'
    elif tag == "downsize-uint":
        match_block = '  - function.body_contains_regex: "uint(8|16|32|64|128|248)"'
    elif tag == "added-accrue-first":
        match_block = '  - function.body_not_contains_regex: "accrueInterest|_accrue"'
    else:
        match_block = '  - function.kind: external_or_public'

    yaml = f"""# Auto-mined draft pattern — fix-shape: {tag}
# Seeded from {len(example_ids)} real fix-commit diff(s) in patterns/fixtures/auto/
# Example findings: {', '.join(example_ids[:5])}
# REVIEW REQUIRED before landing in reference/patterns.dsl/
pattern: {slug}
source: auto-mined-from-diffs
severity: MEDIUM
confidence: LOW

preconditions:
  - contract.has_function_matching: ".*"

match:
  - function.kind: external_or_public
{match_block}

fixtures:
  vuln: patterns/fixtures/auto/finding_{example_ids[0].replace('finding_','')}__*.vuln.sol
  clean: patterns/fixtures/auto/finding_{example_ids[0].replace('finding_','')}__*.clean.sol

help: "Auto-mined candidate: functions lacking the fix introduced by {len(example_ids)} real fix-commits classified as {tag}."
wiki_title: "Auto-mined pattern: {tag}"
wiki_description: "This pattern was auto-seeded from {len(example_ids)} real vuln/fix diff pairs. Review the shape and refine preconditions before promoting to Tier-E."
wiki_exploit_scenario: "See source diffs for the concrete exploit class."
wiki_recommendation: "Apply the fix-shape '{tag}' — review example diffs for exact form."
"""
    yaml_path.write_text(yaml)
    return yaml_path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--emit", type=str, default="", help="emit draft YAMLs to this dir")
    ap.add_argument("--top", type=int, default=20)
    args = ap.parse_args()

    per_diff, counts = mine_all(args.limit)
    print(f"[mine] processed {len(per_diff)} diffs, {len(counts)} shape-classes found")
    print()
    print("Top fix-shapes:")
    for tag, n in counts.most_common(args.top):
        examples = [fid for fid, t in per_diff.items() if tag in t][:3]
        print(f"  {n:>5}  {tag:<32}  examples: {', '.join(examples)}")

    if args.emit:
        out_dir = Path(args.emit)
        out_dir.mkdir(parents=True, exist_ok=True)
        # Group by tag
        by_tag = {}
        for fid, tags in per_diff.items():
            for t in tags:
                by_tag.setdefault(t, []).append(fid)
        emitted = 0
        for tag, fids in by_tag.items():
            if len(fids) < 3:  # skip rare shapes
                continue
            p = emit_draft_yaml(tag, fids, out_dir)
            emitted += 1
            print(f"  [emit] {tag}: {len(fids)} examples → {p.name}")
        print(f"\n[mine] emitted {emitted} draft YAMLs to {out_dir}")


if __name__ == "__main__":
    main()
