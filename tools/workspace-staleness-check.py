#!/usr/bin/env python3
"""
workspace-staleness-check.py - CAP-MORPHO-D

Checks workspace freshness at session start.  Warns when key artifacts
(engage_report.md, docs/LIVE_TARGET_REPORT.md, SCOPE.md) are stale or when the
upstream bounty repo has new commits since the last workspace refresh.

Usage:
    python3 tools/workspace-staleness-check.py --workspace <ws>
            [--output <path>]       # default: <ws>/.auditooor/staleness_check.json
            [--json]                # print JSON to stdout
            [--quiet]               # suppress output (only write JSON)
            [--strict]              # exit 1 when any STALE or CRITICAL item found

Freshness thresholds (env-overridable):
    AUDITOOOR_STALENESS_WARN_DAYS    (default 7)
    AUDITOOOR_STALENESS_STALE_DAYS   (default 14)
    AUDITOOOR_STALENESS_CRITICAL_DAYS (default 30)

Exit codes:
    0  all artifacts fresh, or --strict not set
    1  at least one STALE/CRITICAL artifact AND --strict flag is set
    2  usage error or workspace does not exist
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Thresholds (overridable via env)
# ---------------------------------------------------------------------------

_WARN_DAYS = int(os.environ.get("AUDITOOOR_STALENESS_WARN_DAYS", "7"))
_STALE_DAYS = int(os.environ.get("AUDITOOOR_STALENESS_STALE_DAYS", "14"))
_CRITICAL_DAYS = int(os.environ.get("AUDITOOOR_STALENESS_CRITICAL_DAYS", "30"))

# Severity labels
SEV_FRESH = "FRESH"
SEV_WARN = "WARN"
SEV_STALE = "STALE"
SEV_CRITICAL = "CRITICAL"
SEV_MISSING = "MISSING"
SEV_INFO = "INFO"


def _age_severity(age_days: float) -> str:
    if age_days >= _CRITICAL_DAYS:
        return SEV_CRITICAL
    if age_days >= _STALE_DAYS:
        return SEV_STALE
    if age_days >= _WARN_DAYS:
        return SEV_WARN
    return SEV_FRESH


def _file_age_days(path: Path) -> float | None:
    try:
        mtime = path.stat().st_mtime
        return (time.time() - mtime) / 86400.0
    except FileNotFoundError:
        return None


def _git_log_count_since_date(repo_dir: Path, since_date: str) -> int | None:
    """Return number of commits in repo since ISO date string (YYYY-MM-DD)."""
    try:
        r = subprocess.run(
            ["git", "log", f"--since={since_date}", "--oneline"],
            cwd=str(repo_dir),
            capture_output=True,
            text=True,
            timeout=10,
        )
        if r.returncode != 0:
            return None
        return len([l for l in r.stdout.splitlines() if l.strip()])
    except Exception:
        return None


def _iso_from_mtime(path: Path) -> str | None:
    try:
        mtime = path.stat().st_mtime
        return datetime.fromtimestamp(mtime, tz=timezone.utc).strftime("%Y-%m-%d")
    except FileNotFoundError:
        return None


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def _check_file(
    ws: Path,
    rel_path: str,
    label: str,
    critical_ok: bool = True,
) -> dict[str, Any]:
    path = ws / rel_path
    age = _file_age_days(path)
    result: dict[str, Any] = {
        "artifact": rel_path,
        "label": label,
        "exists": path.exists(),
        "age_days": round(age, 1) if age is not None else None,
        "last_modified": _iso_from_mtime(path),
        "severity": SEV_MISSING,
        "note": "",
    }
    if age is None:
        result["severity"] = SEV_MISSING
        result["note"] = f"File not found: {path}"
        return result

    sev = _age_severity(age)
    result["severity"] = sev
    result["note"] = f"Age: {age:.1f}d (thresholds: warn={_WARN_DAYS}d, stale={_STALE_DAYS}d, critical={_CRITICAL_DAYS}d)"
    return result


def _check_file_any(
    ws: Path,
    rel_paths: list[str],
    label: str,
) -> dict[str, Any]:
    for rel_path in rel_paths:
        path = ws / rel_path
        if path.exists():
            result = _check_file(ws, rel_path, label)
            result["accepted_paths"] = rel_paths
            return result

    primary = rel_paths[0]
    result = _check_file(ws, primary, label)
    result["accepted_paths"] = rel_paths
    result["note"] = "File not found in accepted paths: " + ", ".join(
        str(ws / rel_path) for rel_path in rel_paths
    )
    return result


def _check_scope_vs_repo(ws: Path) -> dict[str, Any]:
    """Check if any upstream repo has commits newer than SCOPE.md."""
    scope = ws / "SCOPE.md"
    scope_mtime = _iso_from_mtime(scope)
    src_dir = ws / "src"

    result: dict[str, Any] = {
        "artifact": "SCOPE.md vs upstream repos",
        "label": "Upstream repo freshness",
        "scope_last_modified": scope_mtime,
        "repos_checked": [],
        "repos_with_new_commits": [],
        "severity": SEV_INFO,
        "note": "",
    }

    if not scope.exists():
        result["severity"] = SEV_MISSING
        result["note"] = "SCOPE.md not found"
        return result

    if not src_dir.exists():
        result["note"] = "src/ not found; skipping upstream repo check"
        return result

    repos_checked: list[str] = []
    repos_with_new: list[dict[str, Any]] = []

    for repo_dir in sorted(src_dir.iterdir()):
        if not (repo_dir / ".git").exists():
            continue
        repos_checked.append(repo_dir.name)
        if scope_mtime:
            count = _git_log_count_since_date(repo_dir, scope_mtime)
            if count and count > 0:
                repos_with_new.append({"repo": repo_dir.name, "new_commits": count})

    result["repos_checked"] = repos_checked
    result["repos_with_new_commits"] = repos_with_new

    if repos_with_new:
        result["severity"] = SEV_WARN
        names = [r["repo"] for r in repos_with_new]
        result["note"] = (
            f"{len(repos_with_new)} repo(s) have commits since SCOPE.md was last updated "
            f"({scope_mtime}): {', '.join(names)}"
        )
    else:
        result["note"] = (
            f"Checked {len(repos_checked)} repo(s). No new commits since SCOPE.md ({scope_mtime})."
        )

    return result


def _check_prior_audits(ws: Path) -> dict[str, Any]:
    pa_dir = ws / "prior_audits"
    result: dict[str, Any] = {
        "artifact": "prior_audits/",
        "label": "Prior audits corpus",
        "exists": pa_dir.exists(),
        "file_count": 0,
        "severity": SEV_INFO,
        "note": "",
    }
    if pa_dir.exists():
        files = list(pa_dir.iterdir())
        result["file_count"] = len(files)
        result["note"] = f"{len(files)} file(s) in prior_audits/"
    else:
        result["note"] = "prior_audits/ not found (may not have been populated yet)"
    return result


# ---------------------------------------------------------------------------
# Main check runner
# ---------------------------------------------------------------------------


def run_checks(ws: Path) -> dict[str, Any]:
    checks = []

    # Core artifacts with severity thresholds
    checks.append(_check_file(ws, "engage_report.md", "Engagement report"))
    checks.append(
        _check_file_any(
            ws,
            ["docs/LIVE_TARGET_REPORT.md", "LIVE_TARGET_REPORT.md"],
            "Live target report",
        )
    )
    checks.append(_check_file(ws, "SCOPE.md", "Scope definition"))

    # Upstream repo freshness (INFO/WARN - does not block)
    checks.append(_check_scope_vs_repo(ws))

    # Prior audits corpus (INFO only)
    checks.append(_check_prior_audits(ws))

    # Compute overall severity
    sev_order = {SEV_CRITICAL: 5, SEV_STALE: 4, SEV_WARN: 3, SEV_MISSING: 2, SEV_INFO: 1, SEV_FRESH: 0}
    worst = max(checks, key=lambda c: sev_order.get(c["severity"], 0))
    overall = worst["severity"]

    # Build summary
    critical_items = [c["label"] for c in checks if c["severity"] == SEV_CRITICAL]
    stale_items = [c["label"] for c in checks if c["severity"] == SEV_STALE]
    warn_items = [c["label"] for c in checks if c["severity"] == SEV_WARN]

    summary = {
        "workspace": str(ws),
        "checked_at": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "overall_severity": overall,
        "critical_count": len(critical_items),
        "stale_count": len(stale_items),
        "warn_count": len(warn_items),
        "critical_items": critical_items,
        "stale_items": stale_items,
        "warn_items": warn_items,
        "thresholds": {
            "warn_days": _WARN_DAYS,
            "stale_days": _STALE_DAYS,
            "critical_days": _CRITICAL_DAYS,
        },
        "checks": checks,
    }
    return summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check workspace staleness at session start",
    )
    parser.add_argument("--workspace", "-w", required=True, help="Audit workspace root")
    parser.add_argument(
        "--output",
        help="Output JSON path (default: <workspace>/.auditooor/staleness_check.json)",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON to stdout")
    parser.add_argument("--quiet", action="store_true", help="Suppress output lines")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 when any STALE or CRITICAL artifact found",
    )
    args = parser.parse_args(argv)

    ws = Path(args.workspace).expanduser().resolve()
    if not ws.is_dir():
        print(f"ERROR: workspace '{ws}' does not exist", file=sys.stderr)
        return 2

    output_path = (
        Path(args.output).expanduser().resolve()
        if args.output
        else ws / ".auditooor" / "staleness_check.json"
    )

    summary = run_checks(ws)

    # Write JSON sidecar
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w") as fh:
        json.dump(summary, fh, indent=2)
        fh.write("\n")

    overall = summary["overall_severity"]

    if not args.quiet:
        icon_map = {
            SEV_FRESH: "OK  ",
            SEV_WARN: "WARN",
            SEV_STALE: "STALE",
            SEV_CRITICAL: "!!!CRITICAL",
            SEV_MISSING: "MISSING",
            SEV_INFO: "INFO",
        }
        print(f"[workspace-staleness] Workspace: {ws}")
        print(f"[workspace-staleness] Overall: {overall}")
        for c in summary["checks"]:
            icon = icon_map.get(c["severity"], c["severity"])
            print(f"  [{icon:12}] {c['label']}: {c['note']}")
        if summary["critical_items"]:
            print(
                f"[workspace-staleness] ACTION REQUIRED: refresh {', '.join(summary['critical_items'])}"
            )
        elif summary["stale_items"]:
            print(
                f"[workspace-staleness] STALE: consider refreshing {', '.join(summary['stale_items'])}"
            )
        print(f"[workspace-staleness] Sidecar: {output_path}")

    if args.json:
        print(json.dumps(summary, indent=2))

    if args.strict and overall in (SEV_STALE, SEV_CRITICAL):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
