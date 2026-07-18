#!/usr/bin/env python3
"""queue-next.py — Master Perpetual Queue CLI.

Read-only by default. Surfaces the next-best N rows the orchestrator should
dispatch from `.auditooor/master_perpetual_queue.json`.

Examples:
    python3 tools/queue-next.py
    python3 tools/queue-next.py --tier 4
    python3 tools/queue-next.py --priority P0
    python3 tools/queue-next.py --update T1-PRIORITY-1 --status progressed
    python3 tools/queue-next.py --json

The selector preserves canonical priority ordering (P0 > P1 > P2 > P3) and
breaks ties with effort (XS < S < M < L < XL — quick wins first within tier).
The default N=5 selector additionally enforces non-overlapping tier coverage
so the orchestrator does not stack 5 Tier-1 rows in a single dispatch.

Schema: auditooor.master_perpetual_queue.v1.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_QUEUE_PATH = REPO_ROOT / ".auditooor" / "master_perpetual_queue.json"

PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
EFFORT_ORDER = {"XS": 0, "S": 1, "M": 2, "L": 3, "XL": 4}
VALID_STATUSES = {"open", "progressed", "partially_resolved", "blocked", "closed"}


def load_queue(path: Path) -> dict[str, Any]:
    if not path.exists():
        sys.stderr.write(f"queue-next: queue manifest not found at {path}\n")
        sys.exit(2)
    with path.open() as fh:
        data = json.load(fh)
    if data.get("schema") != "auditooor.master_perpetual_queue.v1":
        sys.stderr.write(
            f"queue-next: unexpected schema {data.get('schema')!r}; "
            "expected auditooor.master_perpetual_queue.v1\n",
        )
        sys.exit(2)
    return data


def save_queue(path: Path, data: dict[str, Any]) -> None:
    tmp = path.with_suffix(".tmp")
    with tmp.open("w") as fh:
        json.dump(data, fh, indent=2, sort_keys=False)
        fh.write("\n")
    tmp.replace(path)


def row_sort_key(row: dict[str, Any]) -> tuple[int, int, int]:
    return (
        PRIORITY_ORDER.get(row.get("priority", "P3"), 9),
        EFFORT_ORDER.get(row.get("effort_estimate", "M"), 9),
        row.get("tier", 9),
    )


def filter_rows(
    rows: list[dict[str, Any]],
    tier: int | None,
    priority: str | None,
    status: str | None,
) -> list[dict[str, Any]]:
    out = []
    for r in rows:
        if status is None:
            if r.get("status") not in {"open", "progressed", "partially_resolved"}:
                continue
        else:
            if r.get("status") != status:
                continue
        if tier is not None and r.get("tier") != tier:
            continue
        if priority is not None and r.get("priority") != priority:
            continue
        out.append(r)
    return out


def select_next(
    rows: list[dict[str, Any]],
    n: int,
    diversify_by_tier: bool,
) -> list[dict[str, Any]]:
    rows_sorted = sorted(rows, key=row_sort_key)
    if not diversify_by_tier:
        return rows_sorted[:n]
    selected: list[dict[str, Any]] = []
    seen_tiers: set[int] = set()
    deferred: list[dict[str, Any]] = []
    for r in rows_sorted:
        t = r.get("tier")
        if t not in seen_tiers:
            selected.append(r)
            seen_tiers.add(t)
        else:
            deferred.append(r)
        if len(selected) >= n:
            break
    while len(selected) < n and deferred:
        selected.append(deferred.pop(0))
    return selected


def update_status(
    queue_path: Path,
    row_id: str,
    new_status: str,
) -> dict[str, Any]:
    if new_status not in VALID_STATUSES:
        sys.stderr.write(
            f"queue-next: invalid status {new_status!r}; "
            f"expected one of {sorted(VALID_STATUSES)}\n",
        )
        sys.exit(2)
    data = load_queue(queue_path)
    target = None
    for r in data.get("rows", []):
        if r.get("id") == row_id:
            target = r
            break
    if target is None:
        sys.stderr.write(f"queue-next: row id {row_id!r} not found\n")
        sys.exit(2)
    old = target.get("status")
    target["status"] = new_status
    target["last_updated"] = datetime.utcnow().strftime("%Y-%m-%d")
    save_queue(queue_path, data)
    return {
        "id": row_id,
        "previous_status": old,
        "new_status": new_status,
        "last_updated": target["last_updated"],
    }


def render_human(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "(no eligible rows)"
    lines = []
    header = f"{'TIER':<5}{'ID':<32}{'PRI':<5}{'EFFORT':<8}{'STATUS':<22}{'TITLE'}"
    lines.append(header)
    lines.append("-" * len(header))
    for r in rows:
        lines.append(
            f"{r.get('tier','?'):<5}{r.get('id',''):<32}"
            f"{r.get('priority',''):<5}{r.get('effort_estimate',''):<8}"
            f"{r.get('status',''):<22}{r.get('title','')[:80]}",
        )
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--queue", type=Path, default=DEFAULT_QUEUE_PATH,
                        help="Path to master_perpetual_queue.json")
    parser.add_argument("-n", "--limit", type=int, default=5,
                        help="Number of rows to surface (default 5)")
    parser.add_argument("--tier", type=int, choices=range(1, 8), default=None,
                        help="Filter to a specific tier 1..7")
    parser.add_argument("--priority", choices=["P0", "P1", "P2", "P3"], default=None,
                        help="Filter to a specific priority")
    parser.add_argument("--status", choices=sorted(VALID_STATUSES), default=None,
                        help="Filter to a specific status (default: open|progressed|partially_resolved)")
    parser.add_argument("--no-diversify", action="store_true",
                        help="Disable cross-tier diversification (default: on)")
    parser.add_argument("--json", action="store_true",
                        help="Emit JSON instead of a human table")
    parser.add_argument("--update", metavar="ROW_ID",
                        help="Update a row's status; use with --status")
    args = parser.parse_args(argv)

    if args.update is not None:
        if args.status is None:
            sys.stderr.write("queue-next: --update requires --status\n")
            return 2
        result = update_status(args.queue, args.update, args.status)
        print(json.dumps(result, indent=2))
        return 0

    data = load_queue(args.queue)
    rows = data.get("rows", [])
    eligible = filter_rows(rows, args.tier, args.priority, args.status)
    diversify = (
        args.tier is None
        and args.priority is None
        and not args.no_diversify
    )
    selected = select_next(eligible, args.limit, diversify_by_tier=diversify)

    if args.json:
        print(json.dumps({
            "schema": "auditooor.master_perpetual_queue.v1",
            "filters": {
                "tier": args.tier,
                "priority": args.priority,
                "status": args.status,
            },
            "diversified": diversify,
            "limit": args.limit,
            "eligible_total": len(eligible),
            "selected": selected,
        }, indent=2))
    else:
        print(render_human(selected))
        print(f"\n(eligible_total={len(eligible)}, returned={len(selected)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
