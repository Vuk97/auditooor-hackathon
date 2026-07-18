#!/usr/bin/env python3
"""reweight-diff.py — PR 112 before/after prioritization dashboard.

Consumes a post-reweight `swarm/mining_priorities.json` (as produced by
`tools/mining-prioritizer.py --out ...`) and emits a Markdown table
showing the top-N angles sorted by post-reweight score, with a column
for the delta vs pre-reweight plus the reweight rationale lines.

Also supports appending the resulting section to
`docs/OUTCOME_TELEMETRY.md` via `--append-dashboard`.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List


DASHBOARD_MARKER = "<!-- PR112:outcome-reweight -->"


def _rank_rows(entries: List[Dict[str, Any]], top: int) -> List[Dict[str, Any]]:
    rows = []
    for e in entries:
        post = float(e.get("score", 0.0))
        pre = float(e.get("pre_reweight_score", post))
        rows.append({**e, "score": post, "pre_reweight_score": pre})
    rows.sort(key=lambda r: r["score"], reverse=True)
    return rows[:top]


def render_section(priorities: List[Dict[str, Any]], top: int = 10) -> str:
    rows = _rank_rows(priorities, top)
    if not rows:
        return (
            f"{DASHBOARD_MARKER}\n"
            "## Outcome-driven reweighting\n\n"
            "_No prioritized angles available._\n"
        )

    lines = [
        DASHBOARD_MARKER,
        "## Outcome-driven reweighting",
        "",
        "Before/after view of PR 112 reweighting. Classes with paid outcomes float "
        "up; duplicate-heavy classes sink.",
        "",
        "| Rank | ID | Severity | Pre | Post | Δ | Title |",
        "|---:|---|---|---:|---:|---:|---|",
    ]
    for i, r in enumerate(rows, 1):
        pre = r["pre_reweight_score"]
        post = r["score"]
        delta = post - pre
        title = str(r.get("title", "")).replace("|", "\\|")
        lines.append(
            f"| {i} | {r.get('id', '?')} | {r.get('severity', '?')} | "
            f"{pre:+.2f} | {post:+.2f} | {delta:+.2f} | {title} |"
        )

    # Rationale block.
    any_rationale = any(r.get("reweight_rationale") for r in rows)
    if any_rationale:
        lines.extend(["", "### Reweight rationale", ""])
        for i, r in enumerate(rows, 1):
            rat = r.get("reweight_rationale") or []
            if not rat:
                continue
            lines.append(f"- **#{i} {r.get('id', '?')}** — {r.get('title', '')[:80]}")
            for line in rat:
                lines.append(f"  - {line}")

    return "\n".join(lines) + "\n"


def _strip_existing(dashboard: str) -> str:
    if DASHBOARD_MARKER not in dashboard:
        return dashboard.rstrip() + "\n"
    idx = dashboard.index(DASHBOARD_MARKER)
    return dashboard[:idx].rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Render PR 112 before/after reweighting dashboard."
    )
    parser.add_argument(
        "priorities_path",
        help="Path to swarm/mining_priorities.json emitted by mining-prioritizer.py --out.",
    )
    parser.add_argument("--top", type=int, default=10)
    parser.add_argument(
        "--append-dashboard",
        default=None,
        help="If set, append the section to the given dashboard file "
        "(replacing any previous PR 112 block).",
    )
    parser.add_argument("--out", default=None, help="Write section to this file.")
    args = parser.parse_args()

    path = Path(args.priorities_path).expanduser().resolve()
    if not path.exists():
        print(f"[reweight-diff] missing priorities file: {path}", file=sys.stderr)
        return 1
    try:
        priorities = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        print(f"[reweight-diff] cannot parse priorities: {exc}", file=sys.stderr)
        return 1
    if not isinstance(priorities, list):
        print("[reweight-diff] expected a JSON array of priorities", file=sys.stderr)
        return 1

    section = render_section(priorities, top=args.top)

    if args.append_dashboard:
        dashboard_path = Path(args.append_dashboard).expanduser().resolve()
        existing = dashboard_path.read_text() if dashboard_path.exists() else ""
        stripped = _strip_existing(existing)
        dashboard_path.write_text(stripped + "\n" + section)
        print(f"[reweight-diff] appended section to {dashboard_path}")

    if args.out:
        Path(args.out).expanduser().resolve().write_text(section)

    if not args.out and not args.append_dashboard:
        print(section, end="")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
