#!/usr/bin/env python3
"""hunt-reporter.py - Print a hunter-friendly top-N candidate list from LIVE_TARGET_REPORT.md.

Usage:
    python3 tools/hunt-reporter.py --report <path/to/LIVE_TARGET_REPORT.md> [--top-n 10]

Schema: auditooor.hunt_reporter.v1
"""

import argparse
import re
import sys


def parse_report(report_path: str, top_n: int) -> int:
    """Parse LIVE_TARGET_REPORT.md and print top-N candidates. Returns exit code."""
    try:
        with open(report_path) as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[hunt-reporter] ERR {report_path} not found", file=sys.stderr)
        return 1

    # Extract table rows from the Hunt prioritization section
    in_table = False
    rows = []
    for line in content.splitlines():
        # Table header detection
        if "| rank |" in line or "| rank|" in line:
            in_table = True
            continue
        # Separator row
        if in_table and line.startswith("|") and re.match(r"^\|[-: |]+\|", line):
            continue
        # Data row - preserve empty cells to keep column alignment
        if in_table and line.startswith("|"):
            # Split by | and strip, keeping empty strings for empty cells
            raw_parts = line.split("|")
            # Remove first and last (artifact of leading/trailing |)
            parts = [p.strip() for p in raw_parts[1:-1]]
            if len(parts) >= 5:
                rows.append(parts)
        elif in_table and line.startswith("#"):
            # New section header - stop parsing
            break
        elif in_table and not line.startswith("|") and line.strip() != "":
            break

    count = 0
    for row in rows:
        if count >= top_n:
            break
        try:
            rank = row[0]
            score = row[1]
            # comp at index 2, priority at index 3, file:line at index 4
            priority = row[3] if len(row) > 3 else ""
            file_loc = row[4] if len(row) > 4 else ""
            cluster = row[5] if len(row) > 5 else ""
            p1_tier = row[6] if len(row) > 6 else ""
            p1 = row[7] if len(row) > 7 else ""

            # Shorten file path for readability
            file_short = re.sub(r".*/audits/[^/]+/", "<ws>/", file_loc)
            file_short = re.sub(r"`", "", file_short)
            cluster_short = cluster.strip("`")
            p1_short = p1[:50] + "..." if len(p1) > 50 else p1

            print(f"  {rank:>3}. [{priority:<22}] {file_short}")
            print(f"       cluster={cluster_short}  score={score}  p1-tier={p1_tier}")
            if p1_short:
                print(f"       invariants: {p1_short}")
            print()
            count += 1
        except (IndexError, ValueError):
            continue

    if count == 0:
        print("  (no candidates found in LIVE_TARGET_REPORT.md - run 'make audit' first)")

    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Print hunter-friendly top-N candidate list from LIVE_TARGET_REPORT.md"
    )
    parser.add_argument("--report", required=True, help="Path to LIVE_TARGET_REPORT.md")
    parser.add_argument("--top-n", type=int, default=10, help="Number of candidates to show (default: 10)")
    args = parser.parse_args()

    sys.exit(parse_report(args.report, args.top_n))


if __name__ == "__main__":
    main()
