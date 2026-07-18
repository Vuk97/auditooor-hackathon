#!/usr/bin/env python3
# r36-rebuttal: LIFT-26 lane registered in .auditooor/agent_pathspec.json (lane-LIFT-26-R67)
"""R67 rotation-cursor verifier (LIFT-26).

Walks the corpus surfaces under ``audit/corpus_tags/derived/`` and
``audit/corpus_tags/tags/`` and verifies, for each file:

1. A sibling ``<path>.rotation_log.jsonl`` exists.
2. At least one entry is present within the last 24 hours (configurable).
3. The file's current byte count has NOT shrunk by more than 50% since the
   most-recent rotation_log entry's ``byte_count`` value.

Emits a structured report and exits non-zero on FAIL conditions.

Usage:
    tools/r67-rotation-cursor-verifier.py [--workspace <ws>] [--file <path>] [--json] [--strict]

Verdicts (per-file):
    pass-fresh-rotation-and-stable
    warn-no-rotation-log
    warn-stale-rotation-log
    warn-line-shrinkage-but-uid-stable  (dedup, not real loss)
    fail-shrinkage-over-50pct-no-log-entry  (line-count shrinkage, no UID data)
    fail-unique-id-shrinkage-over-5pct  (real record loss - unique IDs dropped)
    error

Overall exit code:
    0 if no FAILs (warnings allowed)
    1 if any FAIL verdict OR if --strict and any WARN verdict
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Path-fix.
_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from tools.lib.atomic_corpus_writer import (  # noqa: E402
    read_rotation_log,
    rotation_log_path,
)

SCHEMA = "auditooor.r67_rotation_cursor_verifier.v2"

DEFAULT_CORPUS_DIRS = (
    "audit/corpus_tags/derived",
    "audit/corpus_tags/tags",
)
DEFAULT_FRESHNESS_HOURS = 24
DEFAULT_SHRINKAGE_RATIO = 0.5  # 50%


def _parse_log_ts(ts_str: str) -> float | None:
    """Parse a rotation_log ts (`YYYYMMDDTHHMMSSZ` or ISO8601) into epoch."""
    if not ts_str:
        return None
    for fmt in ("%Y%m%dT%H%M%SZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            dt = datetime.strptime(ts_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            continue
    return None


def verify_file(path: Path, *, freshness_hours: int, shrinkage_ratio: float) -> dict:
    """Return a per-file verdict dict."""
    if not path.exists():
        return {
            "schema": SCHEMA,
            "path": str(path),
            "verdict": "error",
            "reason": "file-not-found",
            "byte_count_current": None,
            "byte_count_logged": None,
            "shrinkage_pct": None,
            "log_entries": 0,
            "last_log_age_hours": None,
        }

    current_bytes = path.stat().st_size
    log_path = rotation_log_path(path)

    if not log_path.exists():
        return {
            "schema": SCHEMA,
            "path": str(path),
            "verdict": "warn-no-rotation-log",
            "reason": "no rotation_log.jsonl sibling exists",
            "byte_count_current": current_bytes,
            "byte_count_logged": None,
            "shrinkage_pct": None,
            "log_entries": 0,
            "last_log_age_hours": None,
        }

    log = read_rotation_log(path)
    if not log:
        return {
            "schema": SCHEMA,
            "path": str(path),
            "verdict": "warn-no-rotation-log",
            "reason": "rotation_log.jsonl exists but has zero entries",
            "byte_count_current": current_bytes,
            "byte_count_logged": None,
            "shrinkage_pct": None,
            "log_entries": 0,
            "last_log_age_hours": None,
        }

    last_entry = log[-1]
    last_ts = _parse_log_ts(last_entry.get("ts", ""))
    last_bytes = last_entry.get("byte_count")
    last_age_hours: float | None = None
    if last_ts is not None:
        last_age_hours = (time.time() - last_ts) / 3600.0

    # Shrinkage check: catches LIFT-9-style 2.0M -> 216K events where a refresh
    # silently truncated the file without an atomic-write rotation log entry.
    shrinkage_pct: float | None = None
    fail_shrinkage = False
    if isinstance(last_bytes, int) and last_bytes > 0:
        shrinkage_pct = (last_bytes - current_bytes) / last_bytes * 100.0
        # Shrinkage > shrinkage_ratio (e.g. 50%) is the failure threshold.
        if shrinkage_pct > shrinkage_ratio * 100.0:
            fail_shrinkage = True

    # Freshness check.
    stale = (
        last_age_hours is not None and last_age_hours > freshness_hours
    )

    # Unique-ID shrinkage check (Task #229 forensic anchor).
    # If the rotation_log entry carries unique_record_id_count_before/after,
    # use those to distinguish real record loss from dedup-shrinkage.
    uid_before = last_entry.get("unique_record_id_count_before")
    uid_after = last_entry.get("unique_record_id_count_after")
    uid_field = last_entry.get("record_id_field")
    uid_shrinkage_pct: float | None = None
    fail_uid_shrinkage = False
    warn_line_shrink_uid_stable = False

    if isinstance(uid_before, int) and isinstance(uid_after, int) and uid_before > 0:
        uid_shrinkage_pct = (uid_before - uid_after) / uid_before * 100.0
        if uid_shrinkage_pct > 5.0:  # >5% real ID loss = FAIL
            fail_uid_shrinkage = True
        # Line-count shrank but UID count is stable (or grew) -> dedup
        if fail_shrinkage and not fail_uid_shrinkage:
            warn_line_shrink_uid_stable = True
            fail_shrinkage = False  # Downgrade from FAIL to WARN

    if fail_uid_shrinkage:
        return {
            "schema": SCHEMA,
            "path": str(path),
            "verdict": "fail-unique-id-shrinkage-over-5pct",
            "reason": (
                f"unique record IDs dropped from {uid_before} to {uid_after} "
                f"({uid_shrinkage_pct:.1f}% loss > 5% threshold); "
                f"field={uid_field!r}; this is REAL record loss, not dedup"
            ),
            "byte_count_current": current_bytes,
            "byte_count_logged": last_bytes,
            "shrinkage_pct": shrinkage_pct,
            "uid_count_before": uid_before,
            "uid_count_after": uid_after,
            "uid_shrinkage_pct": uid_shrinkage_pct,
            "record_id_field": uid_field,
            "log_entries": len(log),
            "last_log_age_hours": last_age_hours,
        }

    if warn_line_shrink_uid_stable:
        return {
            "schema": SCHEMA,
            "path": str(path),
            "verdict": "warn-line-shrinkage-but-uid-stable",
            "reason": (
                f"line-count shrinkage detected ({shrinkage_pct:.1f}%) but "
                f"unique record IDs stable ({uid_before} -> {uid_after}); "
                f"this is dedup/compaction, not real record loss; field={uid_field!r}"
            ),
            "byte_count_current": current_bytes,
            "byte_count_logged": last_bytes,
            "shrinkage_pct": shrinkage_pct,
            "uid_count_before": uid_before,
            "uid_count_after": uid_after,
            "uid_shrinkage_pct": uid_shrinkage_pct,
            "record_id_field": uid_field,
            "log_entries": len(log),
            "last_log_age_hours": last_age_hours,
        }

    if fail_shrinkage:
        return {
            "schema": SCHEMA,
            "path": str(path),
            "verdict": "fail-shrinkage-over-50pct-no-log-entry",
            "reason": (
                f"current bytes {current_bytes} shrunk "
                f"{shrinkage_pct:.1f}% from logged {last_bytes} "
                f"(threshold {shrinkage_ratio * 100:.0f}%); "
                f"no rotation_log entry recorded the shrinkage; "
                f"no UID data available to distinguish dedup from real loss"
            ),
            "byte_count_current": current_bytes,
            "byte_count_logged": last_bytes,
            "shrinkage_pct": shrinkage_pct,
            "uid_count_before": uid_before,
            "uid_count_after": uid_after,
            "record_id_field": uid_field,
            "log_entries": len(log),
            "last_log_age_hours": last_age_hours,
        }
    if stale:
        return {
            "schema": SCHEMA,
            "path": str(path),
            "verdict": "warn-stale-rotation-log",
            "reason": (
                f"last rotation_log entry is {last_age_hours:.1f}h old "
                f"(freshness threshold {freshness_hours}h)"
            ),
            "byte_count_current": current_bytes,
            "byte_count_logged": last_bytes,
            "shrinkage_pct": shrinkage_pct,
            "uid_count_before": last_entry.get("unique_record_id_count_before"),
            "uid_count_after": last_entry.get("unique_record_id_count_after"),
            "record_id_field": last_entry.get("record_id_field"),
            "log_entries": len(log),
            "last_log_age_hours": last_age_hours,
        }
    return {
        "schema": SCHEMA,
        "path": str(path),
        "verdict": "pass-fresh-rotation-and-stable",
        "reason": "rotation_log fresh and no shrinkage above threshold",
        "byte_count_current": current_bytes,
        "byte_count_logged": last_bytes,
        "shrinkage_pct": shrinkage_pct,
        "uid_count_before": uid_before,
        "uid_count_after": uid_after,
        "record_id_field": uid_field,
        "log_entries": len(log),
        "last_log_age_hours": last_age_hours,
    }


def walk_corpus(
    workspace: Path,
    *,
    corpus_dirs: tuple[str, ...] = DEFAULT_CORPUS_DIRS,
) -> list[Path]:
    """Return every corpus file under the configured corpus dirs."""
    out: list[Path] = []
    for rel in corpus_dirs:
        base = workspace / rel
        if not base.exists():
            continue
        for entry in base.rglob("*"):
            if entry.is_file():
                # Skip .rotation_log.jsonl files (they're the logs themselves)
                # and skip .bak.* backups.
                if entry.name.endswith(".rotation_log.jsonl"):
                    continue
                if ".bak." in entry.name:
                    continue
                if ".tmp." in entry.name:
                    continue
                # Only check known corpus extensions.
                if entry.suffix in (".jsonl", ".json", ".yaml", ".yml"):
                    out.append(entry)
    return sorted(out)


def main():
    parser = argparse.ArgumentParser(
        description="R67 rotation-cursor verifier (LIFT-26)"
    )
    parser.add_argument(
        "--workspace",
        default=os.environ.get("AUDITOOOR_WORKSPACE", str(_REPO)),
        help="Workspace root (default: repo root)",
    )
    parser.add_argument(
        "--file",
        action="append",
        default=None,
        help="Check a specific file (repeatable). If unset, walk corpus dirs.",
    )
    parser.add_argument(
        "--freshness-hours",
        type=int,
        default=DEFAULT_FRESHNESS_HOURS,
        help=f"Max age for last rotation_log entry (default: {DEFAULT_FRESHNESS_HOURS})",
    )
    parser.add_argument(
        "--shrinkage-ratio",
        type=float,
        default=DEFAULT_SHRINKAGE_RATIO,
        help=f"Fail if file shrunk by > this ratio (default: {DEFAULT_SHRINKAGE_RATIO})",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON.")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat warnings as failures.",
    )
    args = parser.parse_args()

    workspace = Path(args.workspace).resolve()
    if args.file:
        targets = [Path(f).resolve() for f in args.file]
    else:
        targets = walk_corpus(workspace)

    results = [
        verify_file(
            t,
            freshness_hours=args.freshness_hours,
            shrinkage_ratio=args.shrinkage_ratio,
        )
        for t in targets
    ]

    summary = {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "freshness_hours": args.freshness_hours,
        "shrinkage_ratio": args.shrinkage_ratio,
        "total": len(results),
        "pass": sum(1 for r in results if r["verdict"].startswith("pass")),
        "warn": sum(1 for r in results if r["verdict"].startswith("warn")),
        "fail": sum(1 for r in results if r["verdict"].startswith("fail")),
        "error": sum(1 for r in results if r["verdict"] == "error"),
        "results": results,
    }

    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True, default=str))
    else:
        for r in results:
            v = r["verdict"]
            mark = "[OK]" if v.startswith("pass") else (
                "[WARN]" if v.startswith("warn") else (
                    "[FAIL]" if v.startswith("fail") else "[ERROR]"
                )
            )
            print(f"{mark} {r['path']}: {v}")
            if r["reason"] and not v.startswith("pass"):
                print(f"    {r['reason']}")
        print()
        print(
            f"Summary: total={summary['total']} pass={summary['pass']} "
            f"warn={summary['warn']} fail={summary['fail']} error={summary['error']}"
        )

    rc = 0
    if summary["fail"] or summary["error"]:
        rc = 1
    elif args.strict and summary["warn"]:
        rc = 1
    sys.exit(rc)


if __name__ == "__main__":
    main()
