#!/usr/bin/env python3
"""lane-volume-guard.py  - Mechanical no-over-flag bar for structural lanes.

MOTIVATION
==========
Agents repeatedly missed lane floods (CRC 1231 on beanstalk, SADL 147, etc.).
The no-over-flag bar must be MECHANICAL, not agent-judgment. This tool reads
existing lane JSONL sidecars and enforces two invariants:

  1. VERDICT PURITY: every record in a lane sidecar must have verdict in
     {needs-fuzz, needs-llm, typed-skip}. Any record carrying
     confirmed/proven/auto-credit/a severity string -> FAIL.

  2. FLOOD GUARD: a lane emitting more than FLOOD_THRESHOLD records on a single
     workspace is flagged FLOOD. Default thresholds are per-lane (value-mover-
     gated lanes at 50, structural lanes at 200). Override with --max N.

This tool reads EXISTING sidecars only - it does NOT re-run any lane tool.
That means it is instant and safe to run at any time.

LANE REGISTRY
=============
Lane name            -> sidecar file in <ws>/.auditooor/
self-dealing-hypothesis-lane   -> self_dealing_hypotheses.jsonl
callback-reentrancy-composition -> callback_reentrancy_hypotheses.jsonl
share-inflation-lane           -> share_inflation_hypotheses.jsonl
oracle-reachability-lane       -> oracle_reachability_hypotheses.jsonl
rounding-drain-lane            -> rounding_drain_hypotheses.jsonl
mev-ordering-lane              -> mev_ordering_hypotheses.jsonl
access-control-coverage        -> access_control_hypotheses.jsonl
init-upgrade-lane              -> init_upgrade_hypotheses.jsonl
authority-blast-radius         -> authority_blast_radius_hypotheses.jsonl

VALID VERDICTS
==============
  needs-fuzz, needs-llm, typed-skip

Any other value (confirmed, proven, auto-credit, high, medium, low, critical,
empty string) causes a FAIL on the verdict-purity check.

CLI
===
  python3 tools/lane-volume-guard.py [--workspace W]... [--max N] [--json]

  --workspace W   workspace path to scan (repeatable; default: morpho-midnight
                  + beanstalk under /Users/wolf/audits)
  --max N         flood threshold override (applies to ALL lanes); default uses
                  per-lane defaults
  --json          emit JSON report to stdout instead of human-readable table

EXIT CODES
==========
  0  all checks passed (PASS)
  1  one or more FAIL conditions (flood or invalid verdict)
  2  usage / argument error
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Lane registry: lane_name -> (sidecar_filename, default_flood_threshold)
# Threshold rationale:
#   - value-mover-gated (SADL, CRC, rounding, share-inflation): 50
#     because these should fire on function-count, not every callsite combo
#   - structural / sweep lanes (ACL, oracle, MEV, init-upgrade): 200
#     wider scope but still bounded per workspace
# ---------------------------------------------------------------------------
LANE_REGISTRY: dict[str, tuple[str, int]] = {
    "self-dealing-hypothesis-lane":    ("self_dealing_hypotheses.jsonl",    50),
    "callback-reentrancy-composition": ("callback_reentrancy_hypotheses.jsonl", 200),
    "share-inflation-lane":            ("share_inflation_hypotheses.jsonl",  50),
    "oracle-reachability-lane":        ("oracle_reachability_hypotheses.jsonl", 200),
    "rounding-drain-lane":             ("rounding_drain_hypotheses.jsonl",   50),
    "mev-ordering-lane":               ("mev_ordering_hypotheses.jsonl",     200),
    "access-control-coverage":         ("access_control_hypotheses.jsonl",   200),
    "init-upgrade-lane":               ("init_upgrade_hypotheses.jsonl",     200),
    "authority-blast-radius":          ("authority_blast_radius_hypotheses.jsonl", 50),
}

# The exhaustive set of valid verdict tokens (case-sensitive).
VALID_VERDICTS: frozenset[str] = frozenset({"needs-fuzz", "needs-llm", "typed-skip"})

DEFAULT_WORKSPACES: list[str] = [
    "/Users/wolf/audits/morpho-midnight",
    "/Users/wolf/audits/beanstalk",
]


# ---------------------------------------------------------------------------
# Core check logic
# ---------------------------------------------------------------------------

def _load_jsonl(path: Path) -> tuple[list[dict[str, Any]], str | None]:
    """Load a JSONL file. Returns (records, error_str).

    error_str is None on success, or a short description on failure.
    Records list may be partial if there are parse errors mid-file (we
    collect all parseable lines and report the first error).
    """
    records: list[dict[str, Any]] = []
    first_err: str | None = None
    try:
        with path.open("r", encoding="utf-8") as fh:
            for lineno, raw in enumerate(fh, 1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    obj = json.loads(raw)
                    if isinstance(obj, dict):
                        records.append(obj)
                except json.JSONDecodeError as exc:
                    if first_err is None:
                        first_err = f"line {lineno}: {exc}"
    except OSError as exc:
        return [], f"cannot open: {exc}"
    return records, first_err


def check_lane_workspace(
    lane_name: str,
    sidecar_file: str,
    default_threshold: int,
    workspace: Path,
    flood_threshold_override: int | None,
) -> dict[str, Any]:
    """Run the two checks for one (lane, workspace) pair.

    Returns a result dict with keys:
      lane, workspace, sidecar_path, status (pass|fail|skip),
      count, flood, verdict_ok, bad_verdicts (list), skip_reason,
      flood_threshold_used, parse_error
    """
    threshold = flood_threshold_override if flood_threshold_override is not None else default_threshold
    sidecar_path = workspace / ".auditooor" / sidecar_file

    result: dict[str, Any] = {
        "lane": lane_name,
        "workspace": str(workspace),
        "sidecar_path": str(sidecar_path),
        "status": "pass",
        "count": 0,
        "flood": False,
        "verdict_ok": True,
        "bad_verdicts": [],
        "skip_reason": None,
        "flood_threshold_used": threshold,
        "parse_error": None,
    }

    # Workspace does not exist
    if not workspace.exists():
        result["status"] = "skip"
        result["skip_reason"] = f"workspace not found: {workspace}"
        return result

    # Sidecar does not exist yet (lane not yet run)
    if not sidecar_path.exists():
        result["status"] = "skip"
        result["skip_reason"] = f"sidecar not found: {sidecar_path.name}"
        return result

    records, parse_err = _load_jsonl(sidecar_path)
    result["parse_error"] = parse_err
    result["count"] = len(records)

    # Check 1: verdict purity
    bad: list[str] = []
    for rec in records:
        v = rec.get("verdict", "")
        if v not in VALID_VERDICTS:
            bad.append(v if v else "<empty>")

    if bad:
        result["verdict_ok"] = False
        result["bad_verdicts"] = bad
        result["status"] = "fail"

    # Check 2: flood guard
    if len(records) > threshold:
        result["flood"] = True
        if result["status"] != "fail":
            result["status"] = "fail"

    return result


def run_checks(
    workspaces: list[str],
    flood_threshold_override: int | None,
) -> tuple[list[dict[str, Any]], bool]:
    """Run all lane x workspace checks.

    Returns (results_list, overall_pass).
    overall_pass is True iff no result has status=="fail".
    """
    results: list[dict[str, Any]] = []
    for ws_str in workspaces:
        ws = Path(ws_str)
        for lane_name, (sidecar_file, default_threshold) in LANE_REGISTRY.items():
            r = check_lane_workspace(
                lane_name=lane_name,
                sidecar_file=sidecar_file,
                default_threshold=default_threshold,
                workspace=ws,
                flood_threshold_override=flood_threshold_override,
            )
            results.append(r)

    overall_pass = all(r["status"] != "fail" for r in results)
    return results, overall_pass


# ---------------------------------------------------------------------------
# Output formatters
# ---------------------------------------------------------------------------

def _short_ws(ws: str) -> str:
    """Shorten workspace path for display."""
    return Path(ws).name


def format_human(results: list[dict[str, Any]], overall_pass: bool) -> str:
    lines: list[str] = []
    lines.append("lane-volume-guard  diagnostic report")
    lines.append("=" * 70)

    col_lane = 36
    col_ws = 18
    col_count = 8
    col_thresh = 8
    col_status = 8

    header = (
        f"{'LANE':<{col_lane}} {'WORKSPACE':<{col_ws}} "
        f"{'COUNT':>{col_count}} {'THRESH':>{col_thresh}} {'STATUS':<{col_status}}"
    )
    lines.append(header)
    lines.append("-" * 70)

    for r in results:
        ws_short = _short_ws(r["workspace"])
        status = r["status"].upper()
        count_str = str(r["count"]) if r["status"] != "skip" else "-"
        thresh_str = str(r["flood_threshold_used"]) if r["status"] != "skip" else "-"

        row = (
            f"{r['lane']:<{col_lane}} {ws_short:<{col_ws}} "
            f"{count_str:>{col_count}} {thresh_str:>{col_thresh}} {status:<{col_status}}"
        )
        lines.append(row)

        if r["skip_reason"]:
            lines.append(f"  skip: {r['skip_reason']}")
        if r["flood"]:
            lines.append(f"  FLOOD: {r['count']} > threshold {r['flood_threshold_used']}")
        if r["bad_verdicts"]:
            unique_bad = sorted(set(r["bad_verdicts"]))
            lines.append(f"  BAD VERDICTS ({len(r['bad_verdicts'])} records): {unique_bad}")
        if r["parse_error"]:
            lines.append(f"  parse error: {r['parse_error']}")

    lines.append("-" * 70)
    verdict_str = "PASS" if overall_pass else "FAIL"
    lines.append(f"Overall verdict: {verdict_str}")
    return "\n".join(lines)


def format_json(results: list[dict[str, Any]], overall_pass: bool) -> str:
    report = {
        "overall": "PASS" if overall_pass else "FAIL",
        "results": results,
    }
    return json.dumps(report, indent=2)


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Lane volume guard: verdict-purity + flood checks on lane JSONL sidecars.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--workspace",
        metavar="W",
        action="append",
        dest="workspaces",
        default=None,
        help=(
            "Workspace path to scan (repeatable). "
            "Default: morpho-midnight + beanstalk under /Users/wolf/audits"
        ),
    )
    parser.add_argument(
        "--max",
        metavar="N",
        type=int,
        default=None,
        dest="flood_override",
        help="Override flood threshold for ALL lanes (default: per-lane sane defaults).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="emit_json",
        help="Emit JSON report instead of human-readable table.",
    )

    args = parser.parse_args(argv)

    workspaces = args.workspaces if args.workspaces else list(DEFAULT_WORKSPACES)

    results, overall_pass = run_checks(
        workspaces=workspaces,
        flood_threshold_override=args.flood_override,
    )

    if args.emit_json:
        print(format_json(results, overall_pass))
    else:
        print(format_human(results, overall_pass))

    return 0 if overall_pass else 1


if __name__ == "__main__":
    sys.exit(main())
