#!/usr/bin/env python3
"""
contest-registry.py — Phase 1 of §J GitHub fix-commit mining.

Manages reference/contest_registry.jsonl: the canonical registry of audit
contests from which fix patches will be mined in Phase 2.

Schema (auditooor.contest_registry.v1):
  schema             str  — "auditooor.contest_registry.v1"
  contest_id         str  — unique slug, e.g. "cantina-morpho-2024q1"
  platform           str  — cantina | sherlock | c4 | spearbit | cyfrin |
                            immunefi | h1 | tob | oz
  protocol           str  — human-readable protocol name
  target_repos       list — [{url, commit_pin, notes}]
  audit_window       dict — {start, end}  ISO-8601 dates or null
  report_published   str  — ISO-8601 date or null
  report_url         str  — URL or null
  status             str  — active | completed | unknown
  fix_mine_status    str  — pending | running | done | skipped
  fix_mine_last_run  str  — ISO-8601 datetime or null
  findings_disclosed_count  int  — known finding count (-1 = unknown)
  fix_commits_mined  int  — how many fix commits Phase 2 found
  detectors_promoted int  — how many detectors were promoted from this

M14-trap note: commit_pin values set to "<TODO_OPERATOR>" are explicit
placeholders. Do NOT substitute plausible-looking SHAs — this file documents
them as TODO until an operator looks them up from the platform's commit history.

Usage:
  python3 tools/contest-registry.py add --json '{...}'
  python3 tools/contest-registry.py list [--platform <p>] [--status <s>]
                                          [--fix-mine-status <s>]
  python3 tools/contest-registry.py mark-fix-mined <contest_id>
                                          --commits-found N --detectors-promoted N
  python3 tools/contest-registry.py audit-windows --since <date>
  python3 tools/contest-registry.py validate

Exit codes: 0 = ok, 1 = validation error, 2 = usage error.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Repo root and registry path
# ---------------------------------------------------------------------------
_SCRIPT_DIR = Path(__file__).resolve().parent
_REPO_ROOT = _SCRIPT_DIR.parent
_REGISTRY_PATH = _REPO_ROOT / "reference" / "contest_registry.jsonl"

SCHEMA_VERSION = "auditooor.contest_registry.v1"

VALID_PLATFORMS = {"cantina", "sherlock", "c4", "spearbit", "cyfrin",
                   "immunefi", "h1", "tob", "oz"}
VALID_STATUS = {"active", "completed", "unknown"}
VALID_FIX_MINE_STATUS = {"pending", "running", "done", "skipped"}

# Fields required in every row
REQUIRED_FIELDS = [
    "schema", "contest_id", "platform", "protocol", "target_repos",
    "audit_window", "report_published", "report_url", "status",
    "fix_mine_status", "fix_mine_last_run", "findings_disclosed_count",
    "fix_commits_mined", "detectors_promoted",
]


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def _load_registry() -> list:
    if not _REGISTRY_PATH.exists():
        return []
    rows = []
    with _REGISTRY_PATH.open() as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                print(f"[ERROR] registry line {lineno} is not valid JSON: {exc}",
                      file=sys.stderr)
                sys.exit(1)
    return rows


def _save_registry(rows: list) -> None:
    _REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _REGISTRY_PATH.open("w") as fh:
        for row in rows:
            fh.write(json.dumps(row, separators=(",", ":")) + "\n")


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _validate_row(row: dict, idx: int) -> list:
    """Return list of error strings for a single row."""
    errs = []
    prefix = f"row[{idx}] contest_id={row.get('contest_id', '?')!r}"

    for f in REQUIRED_FIELDS:
        if f not in row:
            errs.append(f"{prefix}: missing field '{f}'")

    if row.get("schema") != SCHEMA_VERSION:
        errs.append(f"{prefix}: schema must be {SCHEMA_VERSION!r}, "
                    f"got {row.get('schema')!r}")

    if row.get("platform") not in VALID_PLATFORMS:
        errs.append(f"{prefix}: platform {row.get('platform')!r} not in "
                    f"{sorted(VALID_PLATFORMS)}")

    if row.get("status") not in VALID_STATUS:
        errs.append(f"{prefix}: status {row.get('status')!r} not in "
                    f"{sorted(VALID_STATUS)}")

    if row.get("fix_mine_status") not in VALID_FIX_MINE_STATUS:
        errs.append(f"{prefix}: fix_mine_status {row.get('fix_mine_status')!r} "
                    f"not in {sorted(VALID_FIX_MINE_STATUS)}")

    target_repos = row.get("target_repos", [])
    if not isinstance(target_repos, list):
        errs.append(f"{prefix}: target_repos must be a list")
    else:
        for i, repo in enumerate(target_repos):
            if not isinstance(repo, dict):
                errs.append(f"{prefix}: target_repos[{i}] must be an object")
                continue
            if "url" not in repo:
                errs.append(f"{prefix}: target_repos[{i}] missing 'url'")
            if "commit_pin" not in repo:
                errs.append(f"{prefix}: target_repos[{i}] missing 'commit_pin'")

    for int_field in ("findings_disclosed_count", "fix_commits_mined",
                      "detectors_promoted"):
        val = row.get(int_field)
        if val is not None and not isinstance(val, int):
            errs.append(f"{prefix}: {int_field} must be int, got {type(val).__name__}")

    return errs


# ---------------------------------------------------------------------------
# Subcommand: validate
# ---------------------------------------------------------------------------

def cmd_validate(args) -> int:
    rows = _load_registry()
    if not rows:
        print(f"[WARN] registry is empty: {_REGISTRY_PATH}", file=sys.stderr)
        return 0

    all_errs = []
    ids_seen = {}
    for idx, row in enumerate(rows):
        cid = row.get("contest_id", f"<row {idx}>")
        if cid in ids_seen:
            all_errs.append(f"row[{idx}]: duplicate contest_id {cid!r} "
                            f"(first seen at row[{ids_seen[cid]}])")
        ids_seen[cid] = idx
        all_errs.extend(_validate_row(row, idx))

    if all_errs:
        print(f"[FAIL] {len(all_errs)} validation error(s):", file=sys.stderr)
        for e in all_errs:
            print(f"  {e}", file=sys.stderr)
        return 1

    print(f"[OK] registry valid — {len(rows)} rows, "
          f"{len(set(r['platform'] for r in rows))} platforms")
    return 0


# ---------------------------------------------------------------------------
# Subcommand: add
# ---------------------------------------------------------------------------

def cmd_add(args) -> int:
    raw = args.json
    if not raw and not args.file:
        print("[ERROR] provide --json JSON or --file PATH", file=sys.stderr)
        return 2
    if args.file:
        with open(args.file) as fh:
            raw = fh.read()

    try:
        new_row = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"[ERROR] invalid JSON: {exc}", file=sys.stderr)
        return 2

    # Inject schema if missing
    new_row.setdefault("schema", SCHEMA_VERSION)

    errs = _validate_row(new_row, -1)
    if errs:
        print("[ERROR] row fails validation:", file=sys.stderr)
        for e in errs:
            print(f"  {e}", file=sys.stderr)
        return 1

    rows = _load_registry()
    existing_ids = {r["contest_id"] for r in rows}
    if new_row["contest_id"] in existing_ids:
        print(f"[ERROR] contest_id {new_row['contest_id']!r} already exists. "
              "Use mark-fix-mined to update.", file=sys.stderr)
        return 1

    rows.append(new_row)
    _save_registry(rows)
    print(f"[OK] added {new_row['contest_id']!r} — registry now has {len(rows)} rows")
    return 0


# ---------------------------------------------------------------------------
# Subcommand: list
# ---------------------------------------------------------------------------

def cmd_list(args) -> int:
    rows = _load_registry()
    filtered = rows

    if args.platform:
        filtered = [r for r in filtered if r.get("platform") == args.platform]
    if args.status:
        filtered = [r for r in filtered if r.get("status") == args.status]
    if args.fix_mine_status:
        filtered = [r for r in filtered
                    if r.get("fix_mine_status") == args.fix_mine_status]

    if args.json_out:
        print(json.dumps(filtered, indent=2))
        return 0

    if not filtered:
        print("(no rows match)")
        return 0

    # Tabular output
    col_widths = {"contest_id": 36, "platform": 10, "protocol": 22,
                  "status": 11, "fix_mine_status": 14,
                  "findings_disclosed_count": 8, "fix_commits_mined": 6,
                  "detectors_promoted": 6}
    header = (
        f"{'contest_id':<36}  {'platform':<10}  {'protocol':<22}  "
        f"{'status':<11}  {'fix_mine':<14}  {'findings':>8}  "
        f"{'commits':>7}  {'dets':>4}"
    )
    print(header)
    print("-" * len(header))
    for r in filtered:
        print(
            f"{r.get('contest_id',''):<36}  "
            f"{r.get('platform',''):<10}  "
            f"{r.get('protocol',''):<22}  "
            f"{r.get('status',''):<11}  "
            f"{r.get('fix_mine_status',''):<14}  "
            f"{r.get('findings_disclosed_count',-1):>8}  "
            f"{r.get('fix_commits_mined',0):>7}  "
            f"{r.get('detectors_promoted',0):>4}"
        )
    print(f"\n{len(filtered)} row(s) shown / {len(rows)} total")
    return 0


# ---------------------------------------------------------------------------
# Subcommand: mark-fix-mined
# ---------------------------------------------------------------------------

def cmd_mark_fix_mined(args) -> int:
    rows = _load_registry()
    found = False
    for row in rows:
        if row["contest_id"] == args.contest_id:
            row["fix_mine_status"] = "done"
            row["fix_mine_last_run"] = _now_iso()
            row["fix_commits_mined"] = args.commits_found
            row["detectors_promoted"] = args.detectors_promoted
            found = True
            break

    if not found:
        print(f"[ERROR] contest_id {args.contest_id!r} not found", file=sys.stderr)
        return 1

    _save_registry(rows)
    print(f"[OK] marked {args.contest_id!r}: commits={args.commits_found}, "
          f"detectors={args.detectors_promoted}")
    return 0


# ---------------------------------------------------------------------------
# Subcommand: audit-windows
# ---------------------------------------------------------------------------

def cmd_audit_windows(args) -> int:
    rows = _load_registry()
    since = args.since  # ISO date string

    results = []
    for r in rows:
        aw = r.get("audit_window") or {}
        end_str = aw.get("end")
        if end_str and end_str >= since:
            results.append(r)

    if not results:
        print(f"(no contests with audit_window.end >= {since})")
        return 0

    results.sort(key=lambda r: (r.get("audit_window") or {}).get("end", ""))
    for r in results:
        aw = r.get("audit_window") or {}
        print(f"{r['contest_id']:<40}  {aw.get('start','?'):>12} — "
              f"{aw.get('end','?'):>12}  [{r['platform']}]")
    return 0


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Manage reference/contest_registry.jsonl")
    sub = p.add_subparsers(dest="command", required=True)

    # validate
    sub.add_parser("validate", help="Check registry integrity")

    # add
    p_add = sub.add_parser("add", help="Add a new contest row")
    p_add.add_argument("--json", default="", help="Row as JSON string")
    p_add.add_argument("--file", help="Path to a JSON file for the row")

    # list
    p_list = sub.add_parser("list", help="List registry rows")
    p_list.add_argument("--platform")
    p_list.add_argument("--status")
    p_list.add_argument("--fix-mine-status", dest="fix_mine_status")
    p_list.add_argument("--json", dest="json_out", action="store_true",
                        help="Output JSON array")

    # mark-fix-mined
    p_mfm = sub.add_parser("mark-fix-mined",
                            help="Record Phase 2 fix-mining outcome")
    p_mfm.add_argument("contest_id")
    p_mfm.add_argument("--commits-found", type=int, required=True)
    p_mfm.add_argument("--detectors-promoted", type=int, required=True)

    # audit-windows
    p_aw = sub.add_parser("audit-windows",
                           help="List contests with audit_window.end >= --since")
    p_aw.add_argument("--since", required=True, help="ISO date e.g. 2024-01-01")

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    dispatch = {
        "validate": cmd_validate,
        "add": cmd_add,
        "list": cmd_list,
        "mark-fix-mined": cmd_mark_fix_mined,
        "audit-windows": cmd_audit_windows,
    }
    return dispatch[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
