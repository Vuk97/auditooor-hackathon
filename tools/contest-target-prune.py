#!/usr/bin/env python3
"""
contest-target-prune.py — GC for /private/tmp/contest_targets/ directories.

Removes contest clone directories (and their git worktrees) that are older
than --max-age-days (default 30). Uses the mtime of .fetch_meta.json as the
freshness indicator; if .fetch_meta.json is absent, falls back to directory
mtime.

Usage:
  python3 tools/contest-target-prune.py [--max-age-days 30] [--dry-run]
                                         [--output-dir /private/tmp/contest_targets]

Exit codes: 0 = ok, 2 = usage error.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

_DEFAULT_OUTPUT_DIR = Path("/private/tmp/contest_targets")


def _dir_mtime_utc(path: Path) -> datetime:
    """Return mtime of path as a UTC datetime."""
    return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)


def _meta_mtime_utc(contest_dir: Path) -> datetime:
    meta = contest_dir / ".fetch_meta.json"
    if meta.exists():
        return _dir_mtime_utc(meta)
    return _dir_mtime_utc(contest_dir)


def _prune_worktrees_in_bare(bare_dir: Path, dry_run: bool) -> None:
    """git worktree prune inside a bare clone."""
    if not bare_dir.is_dir():
        return
    cmd = ["git", "--git-dir", str(bare_dir), "worktree", "prune"]
    if dry_run:
        print(f"  [DRY-RUN] {' '.join(cmd)}")
    else:
        subprocess.run(cmd, capture_output=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="GC old contest clone directories")
    parser.add_argument("--max-age-days", type=int, default=30,
                        help="Remove dirs older than this many days (default 30)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print actions without deleting")
    parser.add_argument("--output-dir", type=Path,
                        default=_DEFAULT_OUTPUT_DIR)

    args = parser.parse_args()

    if not args.output_dir.is_dir():
        print(f"[INFO] output dir does not exist: {args.output_dir} — nothing to prune")
        return 0

    cutoff = datetime.now(tz=timezone.utc) - timedelta(days=args.max_age_days)
    print(f"[INFO] pruning dirs older than {args.max_age_days}d "
          f"(cutoff {cutoff.strftime('%Y-%m-%dT%H:%M:%SZ')})"
          + (" [DRY-RUN]" if args.dry_run else ""))

    pruned = []
    kept = []

    for contest_dir in sorted(args.output_dir.iterdir()):
        if not contest_dir.is_dir():
            continue
        mtime = _meta_mtime_utc(contest_dir)
        age_days = (datetime.now(tz=timezone.utc) - mtime).days

        if mtime < cutoff:
            print(f"  PRUNE  {contest_dir.name} (age {age_days}d)")
            # First prune all git worktrees inside to keep git bookkeeping clean
            for repo_dir in contest_dir.iterdir():
                if repo_dir.is_dir():
                    bare_dir = repo_dir / ".git_bare"
                    _prune_worktrees_in_bare(bare_dir, dry_run=args.dry_run)
            if not args.dry_run:
                shutil.rmtree(contest_dir, ignore_errors=True)
            pruned.append(contest_dir.name)
        else:
            print(f"  keep   {contest_dir.name} (age {age_days}d)")
            kept.append(contest_dir.name)

    print(f"\n=== Prune Summary ===")
    print(f"  Pruned : {len(pruned)}")
    print(f"  Kept   : {len(kept)}")
    if pruned and args.dry_run:
        print("  (dry-run: nothing was actually deleted)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
