#!/usr/bin/env python3
"""llm-delegation-matrix-update — auto-update LLM_DELEGATION_MATRIX.md from calibration log.

Lane 12 (PR #658) deferred item #2. Cron-friendly: reads
tools/calibration/llm_calibration_log.jsonl, computes per-provider × task_type
TP-rate, rewrites the auto-table block in docs/LLM_DELEGATION_MATRIX.md
between sentinel markers (rest of doc untouched).

Sentinel markers:
    <!-- AUDITOOOR_AUTO:delegation-matrix-table -->
    ...auto-rendered table...
    <!-- /AUDITOOOR_AUTO:delegation-matrix-table -->

If markers don't exist in the doc, no changes (advisory). Idempotent.

Usage:
    tools/llm-delegation-matrix-update.py             # update doc
    tools/llm-delegation-matrix-update.py --dry-run   # show what would change
    tools/llm-delegation-matrix-update.py --check     # exit 1 if doc out of sync
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from datetime import datetime, timezone

REPO = pathlib.Path(__file__).resolve().parent.parent
LOG_PATH = REPO / "tools" / "calibration" / "llm_calibration_log.jsonl"
DOC_PATH = REPO / "docs" / "LLM_DELEGATION_MATRIX.md"
MARKER_START = "<!-- AUDITOOOR_AUTO:delegation-matrix-table -->"
MARKER_END = "<!-- /AUDITOOOR_AUTO:delegation-matrix-table -->"


def load_calibration_rows():
    if not LOG_PATH.is_file():
        return []
    rows = []
    for line in LOG_PATH.read_text(errors="replace").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def aggregate(rows):
    """Aggregate by (provider, task_type). Returns dict of stats."""
    stats = {}
    for r in rows:
        key = (r.get("provider", "?"), r.get("task_type", "?"))
        s = stats.setdefault(key, {"total": 0, "true": 0, "false": 0, "other": 0, "last_ts": ""})
        s["total"] += 1
        verdict = str(r.get("verdict", "")).upper()
        if verdict == "TRUE":
            s["true"] += 1
        elif verdict == "FALSE":
            s["false"] += 1
        else:
            s["other"] += 1
        ts = r.get("ts", "")
        if ts and ts > s["last_ts"]:
            s["last_ts"] = ts
    return stats


def render_table(stats):
    """Render markdown table sorted by provider, task_type."""
    if not stats:
        return "_(calibration log empty — no per-provider × task-type data yet)_\n"
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [
        f"_Auto-rendered by `tools/llm-delegation-matrix-update.py` at {now}._",
        f"_Source: `tools/calibration/llm_calibration_log.jsonl` ({len(stats)} provider × task_type cells)._",
        "",
        "| Provider | Task type | Total | TP (TRUE) | FP (FALSE) | Other | TP-rate | Recommended | Last seen |",
        "|---|---|---:|---:|---:|---:|---:|:---:|---|",
    ]
    for (provider, task_type), s in sorted(stats.items()):
        decided = s["true"] + s["false"]
        rate = round(s["true"] / decided, 2) if decided else None
        rate_str = f"{int(rate * 100)}%" if rate is not None else "—"
        recommended = "✓" if (decided >= 10 and rate is not None and rate >= 0.70) else " "
        last = s["last_ts"][:10] if s["last_ts"] else "—"
        lines.append(
            f"| `{provider}` | `{task_type}` | {s['total']} | {s['true']} | {s['false']} | {s['other']} | {rate_str} | {recommended} | {last} |"
        )
    lines.append("")
    lines.append("**Recommended** = TP-rate ≥ 70% with ≥10 decided rows. ✓ = ready for promotion-grade dispatch (`--routing-purpose=promotion`).")
    return "\n".join(lines) + "\n"


def update_doc(new_table, *, dry_run=False):
    """Replaces content between markers in DOC_PATH. Returns (changed: bool, reason: str)."""
    if not DOC_PATH.is_file():
        return False, f"doc not found: {DOC_PATH}"
    text = DOC_PATH.read_text(encoding="utf-8")
    if MARKER_START not in text or MARKER_END not in text:
        # Insert markers + table near the top (after the first ## heading)
        # Advisory: don't auto-insert; require operator to add markers first
        return False, "markers not present in doc; add manually first"
    pattern = re.compile(
        r"(" + re.escape(MARKER_START) + r")(.*?)(" + re.escape(MARKER_END) + r")",
        re.DOTALL,
    )
    new_block = MARKER_START + "\n\n" + new_table + "\n" + MARKER_END
    new_text = pattern.sub(new_block, text)
    if new_text == text:
        return False, "no changes"
    if dry_run:
        return True, "would update (dry-run)"
    DOC_PATH.write_text(new_text, encoding="utf-8")
    return True, "updated"


def check_in_sync():
    """Returns True if current doc matches what we'd render."""
    if not DOC_PATH.is_file():
        return True
    text = DOC_PATH.read_text(encoding="utf-8")
    if MARKER_START not in text:
        return True  # vacuously in sync
    rows = load_calibration_rows()
    stats = aggregate(rows)
    fresh_table = render_table(stats)
    pattern = re.compile(
        r"" + re.escape(MARKER_START) + r"(.*?)" + re.escape(MARKER_END),
        re.DOTALL,
    )
    m = pattern.search(text)
    if not m:
        return True
    # Compare bodies; ignore the auto-rendered timestamp on first line
    current = m.group(1).strip()
    fresh = fresh_table.strip()
    # Strip the timestamp line for comparison (changes every run)
    current_ts_stripped = re.sub(r"^_Auto-rendered.*$", "", current, count=1, flags=re.MULTILINE).strip()
    fresh_ts_stripped = re.sub(r"^_Auto-rendered.*$", "", fresh, count=1, flags=re.MULTILINE).strip()
    return current_ts_stripped == fresh_ts_stripped


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--check", action="store_true", help="exit 1 if doc out of sync")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    if args.check:
        in_sync = check_in_sync()
        if not args.quiet:
            print(f"[llm-delegation-matrix-update] in_sync: {in_sync}")
        return 0 if in_sync else 1

    rows = load_calibration_rows()
    stats = aggregate(rows)
    if not args.quiet:
        print(f"[llm-delegation-matrix-update] {len(rows)} calibration rows; {len(stats)} provider × task_type cells")

    table = render_table(stats)
    changed, reason = update_doc(table, dry_run=args.dry_run)
    if not args.quiet:
        print(f"[llm-delegation-matrix-update] {reason}")
    if args.dry_run and changed:
        print("\n--- proposed table ---")
        print(table)
    return 0


if __name__ == "__main__":
    sys.exit(main())
