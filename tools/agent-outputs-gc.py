#!/usr/bin/env python3
"""Garbage-collect namespaced agent output artifacts.

The retained namespace is:

    agent_outputs/<owner>/<lane>/<YYYYMMDDTHHMMSSZ>_<phase>.json

The tool only considers files under that three-level namespace and never
touches legacy top-level artifacts.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


SCHEMA = "auditooor.agent_outputs_gc.v1"
STAMP_RE = re.compile(r"^(?P<stamp>\d{8}T\d{6}Z)_[^/]+\.json$")
OLDER_RE = re.compile(r"^(?P<num>\d+)(?P<unit>[dhm])$")


def parse_duration(raw: str) -> timedelta:
    match = OLDER_RE.fullmatch(raw.strip().lower())
    if not match:
        raise ValueError("OLDER must look like 30d, 12h, or 90m")
    num = int(match.group("num"))
    unit = match.group("unit")
    if unit == "d":
        return timedelta(days=num)
    if unit == "h":
        return timedelta(hours=num)
    return timedelta(minutes=num)


def artifact_timestamp(path: Path) -> datetime | None:
    match = STAMP_RE.fullmatch(path.name)
    if not match:
        return None
    return datetime.strptime(match.group("stamp"), "%Y%m%dT%H%M%SZ").replace(
        tzinfo=timezone.utc
    )


def iter_namespaced_outputs(root: Path) -> list[Path]:
    base = root / "agent_outputs"
    if not base.is_dir():
        return []
    rows: list[Path] = []
    for path in base.glob("*/*/*.json"):
        if path.is_file() and artifact_timestamp(path) is not None:
            rows.append(path)
    return sorted(rows)


def build_report(root: Path, older: str, dry_run: bool, now: datetime) -> dict:
    threshold = now - parse_duration(older)
    candidates = []
    for path in iter_namespaced_outputs(root):
        ts = artifact_timestamp(path)
        if ts is None or ts >= threshold:
            continue
        candidates.append(
            {
                "path": path.relative_to(root).as_posix(),
                "timestamp": ts.isoformat().replace("+00:00", "Z"),
            }
        )

    deleted = []
    if not dry_run:
        for row in candidates:
            path = root / row["path"]
            if path.exists():
                path.unlink()
                deleted.append(row["path"])

    return {
        "schema": SCHEMA,
        "root": str(root),
        "older": older,
        "threshold": threshold.isoformat().replace("+00:00", "Z"),
        "dry_run": dry_run,
        "candidate_count": len(candidates),
        "deleted_count": len(deleted),
        "candidates": candidates,
        "deleted": deleted,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".", help="repository root")
    parser.add_argument("--older", default="30d", help="retention age: 30d, 12h, 90m")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json", action="store_true", help="print JSON report")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    try:
        report = build_report(root, args.older, args.dry_run, datetime.now(timezone.utc))
    except ValueError as exc:
        print(f"[agent-outputs-gc] ERR {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        action = "would delete" if args.dry_run else "deleted"
        print(
            f"[agent-outputs-gc] {action} {report['deleted_count'] if not args.dry_run else report['candidate_count']} "
            f"file(s) older than {args.older}"
        )
        for row in report["candidates"]:
            print(f"  {row['path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
