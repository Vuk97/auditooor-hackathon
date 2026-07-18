#!/usr/bin/env python3
"""capv3-iter-ledger-emit.py — emit CAPV3 ITER docs as meta-tasks into universal_task_ledger.

Lane 6 T12 wiring (PR #658, Tier-B #4). Each CAPV3 ITER becomes one
`next_loop_priority` meta-task in the universal task ledger. Lane 6's T12
consumer reads from this ledger instead of a parallel mechanism.

Usage:
    python3 tools/capv3-iter-ledger-emit.py --workspace ~/auditooor-worktrees/dlt-workflow-gaps-main
    python3 tools/capv3-iter-ledger-emit.py --json                   # emit to stdout (dry-run)
    python3 tools/capv3-iter-ledger-emit.py --apply                  # write to ledger file
    python3 tools/capv3-iter-ledger-emit.py --filter-priority        # print highest open ITER number

Exit codes:
    0 = success
    1 = parse/schema error
    2 = no CAPV3 ITER docs found

Written by Claude for PR #658 Tier-B #4.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any

REPO = pathlib.Path(__file__).resolve().parent.parent
DOCS_DIR = REPO / "docs"

# Pattern: CAPV3_ITER<N>_T<M>_<slug>.md
ITER_FILE_RE = re.compile(r"CAPV3_ITER(\d+)_T(\d+)_(.*?)\.md$", re.IGNORECASE)

# Completion markers found in CAPV3 ITER docs (case-insensitive search)
DONE_MARKERS = [
    "status: shipped",
    "status: done",
    "status: complete",
    "**shipped**",
    "## status: shipped",
    "## status: done",
    "## status: complete",
    r"\*\*shipped\*\*",
]

DONE_RE = re.compile(
    r"(status:\s*(shipped|done|complete)|##\s*status:\s*(shipped|done|complete)|"
    r"\*\*shipped\*\*|\*\*complete\*\*|\*\*done\*\*)",
    re.IGNORECASE,
)

# ID prefix for CAPV3 meta-tasks
ID_PREFIX = "TNEXT_LOOP_PRIORITY"

# Default ledger path (mirrors universal-task-ledger-validate.py default)
DEFAULT_LEDGER = REPO.parent / "obsidian-vault" / "universal_task_ledger.jsonl"
# Workspace-local fallback
LOCAL_LEDGER = REPO / ".auditooor" / "universal_task_ledger.jsonl"


def _iter_date(iter_num: int, task_files: list[pathlib.Path]) -> str:
    """Infer creation date from file mtime or fallback to a fixed base date."""
    if task_files:
        mtimes = [f.stat().st_mtime for f in task_files if f.is_file()]
        if mtimes:
            ts = min(mtimes)  # earliest task file = iter start date
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    # fallback
    return "2026-04-24T08:00:00Z"


def _iter_last_touched(task_files: list[pathlib.Path]) -> str:
    """Latest mtime across the ITER's task files."""
    if task_files:
        mtimes = [f.stat().st_mtime for f in task_files if f.is_file()]
        if mtimes:
            ts = max(mtimes)
            dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _iter_done(task_files: list[pathlib.Path]) -> bool:
    """Return True if ALL tasks in the ITER show a completion marker."""
    if not task_files:
        return False
    for tf in task_files:
        try:
            text = tf.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
        if not DONE_RE.search(text):
            return False
    return True


def _task_list(iter_num: int, task_files: list[pathlib.Path]) -> list[str]:
    """Build human-readable task list from file names."""
    tasks = []
    for tf in sorted(task_files, key=lambda f: f.name):
        m = ITER_FILE_RE.match(tf.name)
        if m:
            tasks.append(f"T{m.group(2)}: {m.group(3).replace('_', ' ')}")
    return tasks


def _build_ledger_id(iter_num: int, created_at: str) -> str:
    """Build a schema-compliant ledger ID: T<TYPE>-<YYYYMMDD>-<slug>."""
    # Extract YYYYMMDD from ISO datetime
    date_part = created_at[:10].replace("-", "")
    slug = f"capv3-iter{iter_num:02d}"
    return f"{ID_PREFIX}-{date_part}-{slug}"


def scan_iters(docs_dir: pathlib.Path) -> dict[int, list[pathlib.Path]]:
    """Scan docs/ for CAPV3_ITER*.md files; group by ITER number."""
    iters: dict[int, list[pathlib.Path]] = {}
    if not docs_dir.is_dir():
        return iters
    for f in sorted(docs_dir.iterdir()):
        m = ITER_FILE_RE.match(f.name)
        if m:
            n = int(m.group(1))
            iters.setdefault(n, []).append(f)
    return iters


def build_row(iter_num: int, task_files: list[pathlib.Path]) -> dict[str, Any]:
    """Build a single universal_task_ledger.v1 row for a CAPV3 ITER."""
    created_at = _iter_date(iter_num, task_files)
    last_touched = _iter_last_touched(task_files)
    done = _iter_done(task_files)
    status = "shipped" if done else "in-progress"
    substate = "done" if done else "active"
    task_list = _task_list(iter_num, task_files)
    row_id = _build_ledger_id(iter_num, created_at)

    # Clamp title length to ≤120 chars
    task_summary = ", ".join(task_list[:3])
    if len(task_list) > 3:
        task_summary += f" (+{len(task_list) - 3} more)"
    title_raw = f"CAPV3 iter-{iter_num:03d}: {task_summary}"
    title = title_raw[:120]
    if len(title) < 8:
        title = f"CAPV3 iteration {iter_num:03d} meta-task"

    evidence = [
        f"docs/CAPV3_ITER{iter_num}_T{ITER_FILE_RE.match(f.name).group(2)}_{ITER_FILE_RE.match(f.name).group(3)}.md"
        for f in sorted(task_files, key=lambda x: x.name)
        if ITER_FILE_RE.match(f.name)
    ]

    return {
        "schema": "auditooor.universal_task_ledger.v1",
        "id": row_id,
        "type": "next_loop_priority",
        "title": title,
        "status": status,
        "status_substate": substate,
        "workspace": str(REPO),
        "engagement": None,
        "owner_agent": "claude",
        "priority": "P1",
        "created_at": created_at,
        "last_touched": last_touched,
        "source_refs": evidence,
        "evidence_paths": evidence,
        "transitions": [
            {
                "at": created_at,
                "from_status": "planned",
                "to_status": status,
                "agent": "claude",
                "evidence": f"CAPV3_ITER{iter_num} auto-emitted by capv3-iter-ledger-emit.py",
            }
        ],
    }


def emit_rows(docs_dir: pathlib.Path) -> list[dict[str, Any]]:
    """Scan and build all CAPV3 ITER rows."""
    iters = scan_iters(docs_dir)
    if not iters:
        return []
    rows = []
    for iter_num in sorted(iters):
        rows.append(build_row(iter_num, iters[iter_num]))
    return rows


def validate_rows(rows: list[dict[str, Any]], validator: pathlib.Path) -> bool:
    """Run rows through universal-task-ledger-validate.py. Returns True if valid."""
    import tempfile
    import os

    if not validator.is_file():
        print(f"[capv3-iter-ledger-emit] validator not found: {validator}", file=sys.stderr)
        return False
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".jsonl", delete=False, encoding="utf-8"
    ) as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
        tmppath = fh.name
    try:
        proc = subprocess.run(
            [sys.executable, str(validator), tmppath],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            print(proc.stderr, file=sys.stderr)
            return False
        return True
    finally:
        os.unlink(tmppath)


def find_ledger(workspace: pathlib.Path | None) -> pathlib.Path:
    """Resolve ledger path. Prefer obsidian-vault, fall back to local .auditooor/."""
    if workspace is not None:
        local = workspace / ".auditooor" / "universal_task_ledger.jsonl"
        obsidian = workspace.parent / "obsidian-vault" / "universal_task_ledger.jsonl"
    else:
        local = LOCAL_LEDGER
        obsidian = DEFAULT_LEDGER

    # If obsidian-vault exists and is writable, prefer it
    if obsidian.parent.is_dir():
        return obsidian
    return local


def apply_rows(rows: list[dict[str, Any]], ledger: pathlib.Path) -> None:
    """Merge rows into ledger JSONL. Existing rows with same ID are replaced."""
    ledger.parent.mkdir(parents=True, exist_ok=True)
    existing: dict[str, dict[str, Any]] = {}
    if ledger.is_file():
        with ledger.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    row = json.loads(line)
                    existing[row.get("id", "")] = row
                except json.JSONDecodeError:
                    pass

    # Merge: update or insert CAPV3 rows
    for r in rows:
        existing[r["id"]] = r

    with ledger.open("w", encoding="utf-8") as fh:
        for row in existing.values():
            fh.write(json.dumps(row, separators=(",", ":")) + "\n")

    print(f"[capv3-iter-ledger-emit] wrote {len(rows)} CAPV3 rows → {ledger}")


def filter_priority(rows: list[dict[str, Any]]) -> int | None:
    """Return highest-numbered open ITER for Lane 6 T12 next-loop-priority consumer."""
    open_iters = []
    for r in rows:
        if r.get("status") in {"planned", "in-progress", "blocked"}:
            # Extract iter number from id slug (e.g. capv3-iter03 → 3)
            m = re.search(r"capv3-iter(\d+)", r.get("id", ""))
            if m:
                open_iters.append(int(m.group(1)))
    return max(open_iters) if open_iters else None


def main():
    parser = argparse.ArgumentParser(
        description=__doc__.split("\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--workspace",
        default=None,
        help="Path to auditooor worktree (default: repo root containing this script)",
    )
    parser.add_argument(
        "--json",
        dest="emit_json",
        action="store_true",
        help="Emit rows to stdout as JSONL (dry-run; no file write)",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write/merge rows into the universal task ledger",
    )
    parser.add_argument(
        "--filter-priority",
        action="store_true",
        help="Print highest open ITER number for T12 next-loop-priority consumer and exit",
    )
    parser.add_argument(
        "--ledger",
        default=None,
        help="Explicit ledger path (overrides auto-resolve)",
    )
    parser.add_argument(
        "--no-validate",
        action="store_true",
        help="Skip schema validation (useful for offline use)",
    )
    args = parser.parse_args()

    workspace = pathlib.Path(args.workspace).resolve() if args.workspace else REPO
    docs_dir = workspace / "docs"
    validator = workspace / "tools" / "universal-task-ledger-validate.py"

    rows = emit_rows(docs_dir)
    if not rows:
        print(
            f"[capv3-iter-ledger-emit] no CAPV3_ITER*.md docs found in {docs_dir}",
            file=sys.stderr,
        )
        sys.exit(2)

    print(
        f"[capv3-iter-ledger-emit] found {len(rows)} ITER(s): "
        + ", ".join(str(re.search(r'capv3-iter(\d+)', r['id']).group(1)) for r in rows
                    if re.search(r'capv3-iter(\d+)', r['id'])),
        file=sys.stderr,
    )

    # Validate
    if not args.no_validate:
        ok = validate_rows(rows, validator)
        if not ok:
            print("[capv3-iter-ledger-emit] schema validation FAILED", file=sys.stderr)
            sys.exit(1)
        print("[capv3-iter-ledger-emit] schema validation PASS", file=sys.stderr)

    if args.filter_priority:
        n = filter_priority(rows)
        if n is None:
            print("none")
        else:
            print(n)
        sys.exit(0)

    if args.emit_json:
        for r in rows:
            print(json.dumps(r))
        sys.exit(0)

    if args.apply:
        ledger = pathlib.Path(args.ledger).resolve() if args.ledger else find_ledger(workspace)
        apply_rows(rows, ledger)
        sys.exit(0)

    # Default: print summary
    done_count = sum(1 for r in rows if r["status"] == "shipped")
    open_count = len(rows) - done_count
    print(f"[capv3-iter-ledger-emit] {len(rows)} ITERs: {done_count} done, {open_count} open")
    highest_open = filter_priority(rows)
    if highest_open is not None:
        print(f"[capv3-iter-ledger-emit] highest open ITER (T12 consumer): {highest_open}")
    print("[capv3-iter-ledger-emit] use --json for JSONL output, --apply to write ledger")


if __name__ == "__main__":
    main()
