#!/usr/bin/env python3
"""Walk agent_briefs/*.md and report R39 attack_class anchor coverage.

Per Lane YYYY of V3 closeout iter15 (iter14 RRRR META-1 dogfood recommendation),
each brief under `agent_briefs/*.md` should carry a `## Suggested attack_class
(R39 anchor)` section that anchors workers to a canonical (or supported-non-
canonical) attack_class at brief-consumption time, instead of letting the worker
silently invent an orphan class that R39 (Check #74) then rejects at submission
time.

This tool walks `agent_briefs/*.md` and reports:
  - total briefs
  - briefs WITH the R39 section
  - briefs WITHOUT the R39 section
  - briefs WITH the `<!-- TODO: classify (R39) -->` marker (acknowledged gap)
  - percentage R39-anchored (section present AND no TODO marker)

Exit code:
  - 0 if all briefs are either anchored or acknowledged-TODO
  - 1 if any brief lacks the section entirely (silent gap)

Verbose mode (`--verbose`) lists each brief and its status.

JSON mode (`--json`) emits the report as JSON for tooling integration.

Schema: auditooor.agent_briefs_r39_coverage.v1
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, List, Tuple

SECTION_HEADER = "## Suggested attack_class (R39 anchor)"
SECTION_BEGIN = "<!-- r39-anchor-section: begin -->"
SECTION_END = "<!-- r39-anchor-section: end -->"
TODO_MARKER = "<!-- TODO: classify (R39) -->"

DEFAULT_BRIEFS_DIR = "agent_briefs"

# Status values
STATUS_ANCHORED = "anchored"          # section present, no TODO
STATUS_TODO = "acknowledged-todo"     # section present, TODO marker
STATUS_MISSING = "missing-section"    # no section at all


def classify_brief(content: str) -> str:
    """Return STATUS_* for a single brief's raw content."""
    has_begin = SECTION_BEGIN in content
    has_end = SECTION_END in content
    has_header = SECTION_HEADER in content
    section_present = (has_begin and has_end) or has_header
    if not section_present:
        return STATUS_MISSING
    if TODO_MARKER in content:
        return STATUS_TODO
    return STATUS_ANCHORED


def walk_briefs(briefs_dir: str) -> List[Tuple[str, str]]:
    """Return list of (filename, status) for every .md under briefs_dir."""
    if not os.path.isdir(briefs_dir):
        return []
    out = []
    for fname in sorted(os.listdir(briefs_dir)):
        if not fname.endswith(".md"):
            continue
        path = os.path.join(briefs_dir, fname)
        if not os.path.isfile(path):
            continue
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        out.append((fname, classify_brief(content)))
    return out


def build_report(rows: List[Tuple[str, str]]) -> Dict:
    total = len(rows)
    anchored = [f for f, s in rows if s == STATUS_ANCHORED]
    todo = [f for f, s in rows if s == STATUS_TODO]
    missing = [f for f, s in rows if s == STATUS_MISSING]
    pct = (len(anchored) / total * 100.0) if total > 0 else 0.0
    return {
        "schema": "auditooor.agent_briefs_r39_coverage.v1",
        "total_briefs": total,
        "anchored_count": len(anchored),
        "todo_count": len(todo),
        "missing_count": len(missing),
        "anchored_pct": round(pct, 2),
        "anchored_briefs": anchored,
        "todo_briefs": todo,
        "missing_briefs": missing,
        "exit_status": "fail-missing-section" if missing else "pass",
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Walk agent_briefs/*.md and report R39 attack_class anchor coverage."
    )
    parser.add_argument(
        "--briefs-dir",
        default=DEFAULT_BRIEFS_DIR,
        help=f"Directory containing brief .md files (default: {DEFAULT_BRIEFS_DIR})",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit report as JSON for tooling integration",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="List each brief and its status",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail if ANY brief lacks a section, regardless of TODO acknowledgement",
    )
    args = parser.parse_args()

    rows = walk_briefs(args.briefs_dir)
    report = build_report(rows)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"R39 attack_class anchor coverage report")
        print(f"  briefs dir:      {args.briefs_dir}")
        print(f"  total briefs:    {report['total_briefs']}")
        print(f"  anchored:        {report['anchored_count']}")
        print(f"  acknowledged TODO: {report['todo_count']}")
        print(f"  missing section: {report['missing_count']}")
        print(f"  coverage (anchored): {report['anchored_pct']}%")
        if args.verbose:
            print()
            for fname, status in rows:
                print(f"  [{status:18s}] {fname}")
        if report["missing_briefs"]:
            print()
            print("Briefs missing R39 anchor section:")
            for f in report["missing_briefs"]:
                print(f"  - {f}")

    # Exit code: fail iff missing-section present, or --strict and any non-anchored
    if report["missing_count"] > 0:
        return 1
    if args.strict and report["todo_count"] > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
