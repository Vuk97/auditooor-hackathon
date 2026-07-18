#!/usr/bin/env python3
"""
r36-parallel-session-check.py
=============================

R36 (parallel-worktree-commit-pathspec-discipline) operator helper.

One-shot diagnostic that scans the running process table for sibling
Claude / Codex sessions touching the same auditooor worktree as the caller.
A "stomp" happens when two concurrent agent sessions write to the same
worktree without per-agent pathspec discipline; this tool surfaces the
sibling PIDs and recent-file fingerprints so the operator can decide
whether to pause one of them.

Detection signals:

1. PIDs whose argv mentions the target worktree path (Claude --mcp-config
   contains `--vault-dir <worktree>/...` or working_directory is in or
   under the worktree).
2. PIDs whose argv mentions a sibling Claude /Codex session
   (`claude --resume <uuid>` or `codex --resume`).
3. Recent file mtime fingerprints: files under the worktree modified in
   the last `--mtime-window` minutes (default 30) whose owner PID can be
   correlated via `lsof` (best-effort; macOS / Linux).

This tool is read-only - it does NOT kill or signal any process. The
operator decides whether the sibling session is intentional (operator-
orchestrated parallel dispatch with explicit per-lane pathspecs) or
accidental (background scheduled-task loop that escaped).

Empirical anchor: iter17 Lane QQQQQ 2026-05-23 - PID 83461 (8h+ Claude
session) reverted iter15 YYYY anchor sections on 7 agent_briefs/*.md
mid-lane while iter16 Lane DDDDD was running parallel. Tool would have
surfaced PID 83461's age + working-directory match before the lane
started, letting the operator pause it first.

Usage:
    python3 tools/r36-parallel-session-check.py \
        [--worktree <abs-path>] \
        [--mtime-window 30] \
        [--json]

Default worktree = current working directory.

Exit codes:
    0  - no concurrent sibling sessions detected
    1  - sibling(s) found (operator action: review and decide)
    2  - tool error (ps unreadable, permission denied, etc.)
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path


CLAUDE_RE_TOKENS = ("claude", "Claude.app", "claude.app")
CODEX_RE_TOKENS = ("codex", "Codex.app", "codex.app")


def _run_ps() -> list[dict]:
    """Return list of {pid, etime_seconds, command} for all user processes."""
    try:
        # ps -eo on macOS - get user, pid, etime, command
        out = subprocess.check_output(
            ["ps", "-Ao", "pid,etime,command"],
            text=True,
            stderr=subprocess.STDOUT,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        print(f"ERROR running ps: {exc}", file=sys.stderr)
        sys.exit(2)

    rows: list[dict] = []
    for line in out.splitlines()[1:]:
        parts = line.strip().split(None, 2)
        if len(parts) < 3:
            continue
        try:
            pid = int(parts[0])
        except ValueError:
            continue
        rows.append({"pid": pid, "etime": parts[1], "command": parts[2]})
    return rows


def _etime_to_seconds(etime: str) -> int:
    """Parse ps etime ([[DD-]HH:]MM:SS) to seconds."""
    days = 0
    if "-" in etime:
        d, rest = etime.split("-", 1)
        days = int(d)
        etime = rest
    parts = [int(p) for p in etime.split(":")]
    if len(parts) == 3:
        h, m, s = parts
    elif len(parts) == 2:
        h, m, s = 0, parts[0], parts[1]
    else:
        return 0
    return days * 86400 + h * 3600 + m * 60 + s


def _classify_process(cmd: str, worktree: str, self_pid: int, pid: int) -> dict | None:
    """Return classification dict if cmd matches a Claude/Codex session touching the worktree, else None."""
    if pid == self_pid:
        return None

    is_claude = any(tok in cmd for tok in CLAUDE_RE_TOKENS)
    is_codex = any(tok in cmd for tok in CODEX_RE_TOKENS)
    if not (is_claude or is_codex):
        return None

    # Skip the bash wrapper that invoked this very tool
    if "r36-parallel-session-check" in cmd:
        return None

    # Look for a worktree path mention in the argv
    worktree_abs = str(Path(worktree).resolve())
    touches_worktree = worktree_abs in cmd

    # Look for --resume <uuid> as a sibling-session indicator
    has_resume = " --resume " in cmd or "\t--resume\t" in cmd

    # Look for bypass-permissions / dangerous flags (stomp risk amplifier)
    has_bypass = "--allow-dangerously-skip-permissions" in cmd or "bypassPermissions" in cmd

    if not (touches_worktree or has_resume):
        return None

    kind = "claude" if is_claude else "codex"
    return {
        "agent": kind,
        "touches_worktree": touches_worktree,
        "has_resume_flag": has_resume,
        "has_bypass_permissions": has_bypass,
    }


def _recent_writers(worktree: str, window_minutes: int, limit: int = 20) -> list[dict]:
    """Return list of {path, mtime_iso, age_seconds} for files modified within the window."""
    now = time.time()
    cutoff = now - window_minutes * 60
    rows: list[dict] = []
    wt = Path(worktree)
    if not wt.is_dir():
        return rows

    # Exclude noisy dirs
    excludes = {".git", "node_modules", ".pytest_cache", "__pycache__", ".kimi",
                "external", "_archive", "defihacklabs", "obsidian-vault"}

    for root, dirs, files in os.walk(wt):
        # Prune excluded dirs in-place
        dirs[:] = [d for d in dirs if d not in excludes and not d.startswith(".")]
        for fn in files:
            full = os.path.join(root, fn)
            try:
                st = os.stat(full)
            except OSError:
                continue
            if st.st_mtime < cutoff:
                continue
            rows.append({
                "path": os.path.relpath(full, worktree),
                "mtime_epoch": int(st.st_mtime),
                "age_seconds": int(now - st.st_mtime),
            })
    rows.sort(key=lambda r: r["mtime_epoch"], reverse=True)
    return rows[:limit]


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--worktree", default=os.getcwd(),
                   help="Worktree path to check (default: cwd)")
    p.add_argument("--mtime-window", type=int, default=30,
                   help="Minutes of recent-file mtime window (default: 30)")
    p.add_argument("--json", action="store_true",
                   help="Emit JSON report instead of human text")
    args = p.parse_args()

    worktree = str(Path(args.worktree).resolve())
    self_pid = os.getpid()

    ps_rows = _run_ps()
    siblings: list[dict] = []
    for row in ps_rows:
        cls = _classify_process(row["command"], worktree, self_pid, row["pid"])
        if cls is None:
            continue
        siblings.append({
            "pid": row["pid"],
            "age": row["etime"],
            "age_seconds": _etime_to_seconds(row["etime"]),
            "command_excerpt": (row["command"][:220] + "...") if len(row["command"]) > 220 else row["command"],
            **cls,
        })

    siblings.sort(key=lambda s: s["age_seconds"], reverse=True)

    recent = _recent_writers(worktree, args.mtime_window)

    report = {
        "worktree": worktree,
        "self_pid": self_pid,
        "checked_at": int(time.time()),
        "mtime_window_minutes": args.mtime_window,
        "sibling_count": len(siblings),
        "siblings": siblings,
        "recent_file_writes": recent,
    }

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"R36 parallel-session check")
        print(f"  worktree:           {worktree}")
        print(f"  self pid:           {self_pid}")
        print(f"  mtime window:       last {args.mtime_window} min")
        print(f"  sibling sessions:   {len(siblings)}")
        if siblings:
            print()
            print("  Concurrent Claude/Codex sessions touching this worktree:")
            for s in siblings:
                tags = []
                if s["touches_worktree"]:
                    tags.append("WORKTREE-MATCH")
                if s["has_resume_flag"]:
                    tags.append("RESUMED")
                if s["has_bypass_permissions"]:
                    tags.append("BYPASS-PERMS")
                tagstr = " ".join(tags) if tags else "-"
                print(f"    PID {s['pid']:>6}  age {s['age']:>10}  [{s['agent']}] {tagstr}")
                print(f"        argv: {s['command_excerpt']}")
            print()
            print("  Operator action: review each sibling. If unintentional,")
            print("  pause / kill the older PID before re-running the current lane.")
            print("  Per R36, parallel sessions on a shared worktree require")
            print("  per-agent pathspec discipline (see ~/.claude/CLAUDE.md Rule 36).")
        if recent:
            print()
            print(f"  Recent writes (last {args.mtime_window} min, top {len(recent)}):")
            for r in recent:
                print(f"    {r['age_seconds']:>5}s ago  {r['path']}")

    return 1 if siblings else 0


if __name__ == "__main__":
    sys.exit(main())
