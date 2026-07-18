#!/usr/bin/env python3
"""
capability-readiness-dashboard.py -- Capability health dashboard for the auditooor harness.

Reads reference/capability_inventory.jsonl (built by capability-inventory-build.py).
For each capability: runs its verification_command, compares exit code and stdout
against expected_verification_output, and computes a verdict:

  GREEN    - verification passed (exit 0 + output matched)
  YELLOW   - degraded (exit non-zero but output matches, or vice versa)
  RED      - broken (command errored, output mismatch, or status KNOWN-BROKEN)
  UNTESTED - no verification_command or expected_verification_output

Outputs:
  - Terminal dashboard with color-coded summary by category
  - JSON dashboard written to .auditooor/capability_health.json
  - Summary stats: total / GREEN / YELLOW / RED / UNTESTED / regression_count_since_yesterday

Schema: auditooor.capability_health_dashboard.v1

CLI:
  python3 tools/capability-readiness-dashboard.py [--json] [--category <cat>] [--strict] [--diff-yesterday]
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
REFERENCE_DIR = REPO_ROOT / "reference"
INVENTORY_PATH = REFERENCE_DIR / "capability_inventory.jsonl"
AUDITOOOR_DIR = REPO_ROOT / ".auditooor"
HEALTH_JSON = AUDITOOOR_DIR / "capability_health.json"
HEALTH_HISTORY_DIR = AUDITOOOR_DIR / "capability_health_history"
SCHEMA = "auditooor.capability_health_dashboard.v1"

# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------
VERDICT_GREEN = "GREEN"
VERDICT_YELLOW = "YELLOW"
VERDICT_RED = "RED"
VERDICT_UNTESTED = "UNTESTED"

CATEGORIES_ORDER = [
    "make-target",
    "mcp-callable",
    "r-rule",
    "python-tool",
    "shell-tool",
]

# Color codes (disabled if not a tty)
_IS_TTY = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    if not _IS_TTY:
        return text
    return f"\033[{code}m{text}\033[0m"


GREEN_C = lambda t: _c("32", t)
YELLOW_C = lambda t: _c("33;1", t)
RED_C = lambda t: _c("31;1", t)
GRAY_C = lambda t: _c("90", t)
BOLD_C = lambda t: _c("1", t)
CYAN_C = lambda t: _c("36", t)

NOW_ISO = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
TODAY_DATE = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# Load inventory
# ---------------------------------------------------------------------------

def load_inventory(path: Path) -> list[dict[str, Any]]:
    """Load JSONL capability inventory. Returns list of capability records."""
    if not path.exists():
        return []
    caps = []
    with open(path) as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                caps.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"[WARN] inventory line {i} parse error: {e}", file=sys.stderr)
    return caps


# ---------------------------------------------------------------------------
# Verification logic
# ---------------------------------------------------------------------------

def _run_verification(cmd: str, timeout: int = 15) -> tuple[int, str]:
    """Run a verification command, return (returncode, combined output)."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        combined = (result.stdout + result.stderr).strip()
        return result.returncode, combined
    except subprocess.TimeoutExpired:
        return -2, "TIMEOUT"
    except Exception as e:
        return -1, f"ERROR: {e}"


def verify_capability(cap: dict[str, Any]) -> tuple[str, str]:
    """
    Returns (verdict, detail).
    verdict is one of GREEN / YELLOW / RED / UNTESTED.
    """
    cap_id = cap.get("id", "?")
    status = cap.get("status", "")
    cmd = (cap.get("verification_command") or "").strip()
    expected = (cap.get("expected_verification_output") or "").strip()

    # KNOWN-BROKEN always RED
    if status == "KNOWN-BROKEN":
        return VERDICT_RED, f"status=KNOWN-BROKEN (pre-declared)"

    # No verification command - UNTESTED
    if not cmd:
        return VERDICT_UNTESTED, "no verification_command"

    rc, output = _run_verification(cmd)

    # Timeout / subprocess error -> RED
    if rc in (-1, -2):
        return VERDICT_RED, f"command error: {output}"

    # Match expected output patterns (pipe-separated regex alternatives)
    matched_output = True
    if expected:
        patterns = [p.strip() for p in expected.split("|") if p.strip()]
        matched_output = any(re.search(p, output, re.IGNORECASE) for p in patterns)

    if rc == 0 and (not expected or matched_output):
        return VERDICT_GREEN, f"exit=0, output matched"
    elif rc == 0 and not matched_output:
        return VERDICT_YELLOW, f"exit=0 but output mismatch (expected '{expected}', got '{output[:100]}')"
    elif rc != 0 and matched_output:
        return VERDICT_YELLOW, f"exit={rc} but output matched pattern"
    else:
        return VERDICT_RED, f"exit={rc}, output mismatch (got '{output[:120]}')"


# ---------------------------------------------------------------------------
# Yesterday health load
# ---------------------------------------------------------------------------

def load_yesterday_health() -> dict[str, str]:
    """Load yesterday's capability_health.json if it exists. Returns id->verdict map."""
    if HEALTH_JSON.exists():
        try:
            with open(HEALTH_JSON) as f:
                data = json.load(f)
            return {r["id"]: r["verdict"] for r in data.get("results", [])}
        except Exception:
            pass
    # Try health history
    if HEALTH_HISTORY_DIR.exists():
        dates = sorted(HEALTH_HISTORY_DIR.glob("*.json"), reverse=True)
        for p in dates:
            if TODAY_DATE not in p.name:
                try:
                    with open(p) as f:
                        data = json.load(f)
                    return {r["id"]: r["verdict"] for r in data.get("results", [])}
                except Exception:
                    continue
    return {}


# ---------------------------------------------------------------------------
# Main dashboard logic
# ---------------------------------------------------------------------------

def build_dashboard(
    caps: list[dict[str, Any]],
    category_filter: str | None = None,
    run_verification: bool = True,
    yesterday_verdicts: dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    Build the dashboard result dict.
    """
    if category_filter:
        caps = [c for c in caps if c.get("category") == category_filter]

    results = []
    for cap in caps:
        if run_verification:
            verdict, detail = verify_capability(cap)
        else:
            # For testing: use pre-supplied verdict if present
            verdict = cap.get("_test_verdict", VERDICT_UNTESTED)
            detail = cap.get("_test_detail", "no verification run")

        prev_verdict = (yesterday_verdicts or {}).get(cap["id"])
        is_regression = (
            prev_verdict in (VERDICT_GREEN,)
            and verdict == VERDICT_RED
        )

        results.append({
            "id": cap["id"],
            "name": cap.get("name", cap["id"]),
            "category": cap.get("category", "unknown"),
            "status": cap.get("status", ""),
            "verdict": verdict,
            "detail": detail,
            "prev_verdict": prev_verdict,
            "is_regression": is_regression,
            "verification_command": cap.get("verification_command", ""),
        })

    # Stats
    by_verdict = {VERDICT_GREEN: 0, VERDICT_YELLOW: 0, VERDICT_RED: 0, VERDICT_UNTESTED: 0}
    regressions = 0
    for r in results:
        by_verdict[r["verdict"]] = by_verdict.get(r["verdict"], 0) + 1
        if r["is_regression"]:
            regressions += 1

    by_category: dict[str, dict[str, int]] = {}
    for r in results:
        cat = r["category"]
        if cat not in by_category:
            by_category[cat] = {VERDICT_GREEN: 0, VERDICT_YELLOW: 0, VERDICT_RED: 0, VERDICT_UNTESTED: 0}
        by_category[cat][r["verdict"]] = by_category[cat].get(r["verdict"], 0) + 1

    return {
        "schema": SCHEMA,
        "generated_at": NOW_ISO,
        "total": len(results),
        "by_verdict": by_verdict,
        "by_category": by_category,
        "regression_count": regressions,
        "results": results,
    }


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

VERDICT_COLORS = {
    VERDICT_GREEN: GREEN_C,
    VERDICT_YELLOW: YELLOW_C,
    VERDICT_RED: RED_C,
    VERDICT_UNTESTED: GRAY_C,
}

VERDICT_ICONS = {
    VERDICT_GREEN: "OK ",
    VERDICT_YELLOW: "DG ",  # degraded
    VERDICT_RED: "RD ",
    VERDICT_UNTESTED: "-- ",
}


def print_dashboard(data: dict[str, Any], verbose: bool = False) -> None:
    total = data["total"]
    bv = data["by_verdict"]
    regressions = data["regression_count"]

    print()
    print(BOLD_C("=== Capability Readiness Dashboard ==="))
    print(GRAY_C(f"Generated: {data['generated_at']}  Total: {total}"))
    print()

    # Summary bar
    g = bv.get(VERDICT_GREEN, 0)
    y = bv.get(VERDICT_YELLOW, 0)
    r = bv.get(VERDICT_RED, 0)
    u = bv.get(VERDICT_UNTESTED, 0)
    print(f"  {GREEN_C(f'GREEN {g:3d}')}  "
          f"{YELLOW_C(f'YELLOW {y:3d}')}  "
          f"{RED_C(f'RED {r:3d}')}  "
          f"{GRAY_C(f'UNTESTED {u:3d}')}  "
          f"{'REGRESSIONS ' + RED_C(str(regressions)) if regressions else GRAY_C('regressions: 0')}")
    print()

    # By category
    print(BOLD_C("--- By Category ---"))
    bcat = data["by_category"]
    for cat in CATEGORIES_ORDER + [c for c in bcat if c not in CATEGORIES_ORDER]:
        if cat not in bcat:
            continue
        cv = bcat[cat]
        cg = cv.get(VERDICT_GREEN, 0)
        cy = cv.get(VERDICT_YELLOW, 0)
        cr = cv.get(VERDICT_RED, 0)
        cu = cv.get(VERDICT_UNTESTED, 0)
        ctotal = cg + cy + cr + cu
        pct_green = int(100 * cg / ctotal) if ctotal else 0
        bar = GREEN_C("#" * (pct_green // 5)) + GRAY_C("." * (20 - pct_green // 5))
        print(f"  {cat:20s} [{bar}] {pct_green:3d}%  "
              f"G:{cg:3d} Y:{cy:2d} R:{cr:2d} U:{cu:3d}")

    # Regressions (always shown)
    regressions_list = [r for r in data["results"] if r["is_regression"]]
    if regressions_list:
        print()
        print(RED_C("--- REGRESSIONS (was GREEN, now RED) ---"))
        for r in regressions_list:
            print(f"  {RED_C('!!!')} {r['id']:50s}  {r['detail'][:80]}")

    # RED items
    red_items = [r for r in data["results"] if r["verdict"] == VERDICT_RED and not r.get("_test_verdict")]
    red_items = [r for r in data["results"] if r["verdict"] == VERDICT_RED]
    if red_items:
        print()
        print(RED_C("--- RED (broken) ---"))
        for r in red_items[:30]:
            icon = RED_C("RD")
            reg = RED_C(" [REGRESSION]") if r["is_regression"] else ""
            print(f"  {icon} {r['id']:50s}  {r['detail'][:80]}{reg}")
        if len(red_items) > 30:
            print(f"  ... and {len(red_items)-30} more RED items")

    # YELLOW items (verbose only)
    yellow_items = [r for r in data["results"] if r["verdict"] == VERDICT_YELLOW]
    if yellow_items and verbose:
        print()
        print(YELLOW_C("--- YELLOW (degraded) ---"))
        for r in yellow_items[:20]:
            print(f"  {YELLOW_C('DG')} {r['id']:50s}  {r['detail'][:80]}")

    print()
    # Health verdict line
    if regressions > 0:
        print(RED_C(f"OVERALL: {regressions} REGRESSION(S) DETECTED - action required"))
    elif red_items:
        print(YELLOW_C(f"OVERALL: {len(red_items)} RED capabilities ({len(yellow_items)} YELLOW) - review recommended"))
    elif yellow_items:
        print(YELLOW_C(f"OVERALL: YELLOW - {len(yellow_items)} degraded capabilities"))
    else:
        print(GREEN_C(f"OVERALL: GREEN - all {g} verified capabilities passing"))
    print()


# ---------------------------------------------------------------------------
# Persist health JSON
# ---------------------------------------------------------------------------

def save_health_json(data: dict[str, Any]) -> None:
    AUDITOOOR_DIR.mkdir(exist_ok=True)
    with open(HEALTH_JSON, "w") as f:
        json.dump(data, f, indent=2)
    # Also save to history
    HEALTH_HISTORY_DIR.mkdir(exist_ok=True)
    hist_path = HEALTH_HISTORY_DIR / f"{TODAY_DATE}.json"
    with open(hist_path, "w") as f:
        json.dump(data, f, indent=2)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Capability readiness dashboard for the auditooor harness."
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON summary to stdout instead of terminal dashboard")
    parser.add_argument("--category", metavar="CAT", help="Filter to specific category (make-target|mcp-callable|r-rule|python-tool|shell-tool)")
    parser.add_argument("--strict", action="store_true", help="Exit 1 if any RED capability or regression detected")
    parser.add_argument("--diff-yesterday", action="store_true", help="Highlight regressions vs yesterday's health snapshot")
    parser.add_argument("--verbose", action="store_true", help="Also show YELLOW items in terminal output")
    parser.add_argument("--inventory", metavar="PATH", default=str(INVENTORY_PATH), help="Path to capability_inventory.jsonl")
    parser.add_argument("--no-verify", action="store_true", help="Skip live verification (for testing/CI speed)")
    args = parser.parse_args()

    inventory_path = Path(args.inventory)
    caps = load_inventory(inventory_path)

    if not caps:
        msg = {"error": f"No capabilities loaded from {inventory_path}. Run: python3 tools/capability-inventory-build.py first."}
        if args.json:
            print(json.dumps(msg, indent=2))
        else:
            print(f"[ERROR] {msg['error']}", file=sys.stderr)
        return 1

    yesterday_verdicts = load_yesterday_health() if args.diff_yesterday else {}

    data = build_dashboard(
        caps,
        category_filter=args.category,
        run_verification=not args.no_verify,
        yesterday_verdicts=yesterday_verdicts,
    )

    if args.json:
        # Compact summary for JSON mode
        summary = {
            "schema": data["schema"],
            "generated_at": data["generated_at"],
            "total": data["total"],
            "by_verdict": data["by_verdict"],
            "by_category": data["by_category"],
            "regression_count": data["regression_count"],
            "regressions": [
                {"id": r["id"], "name": r["name"], "prev_verdict": r["prev_verdict"]}
                for r in data["results"] if r["is_regression"]
            ],
            "red_items": [
                {"id": r["id"], "name": r["name"], "detail": r["detail"]}
                for r in data["results"] if r["verdict"] == VERDICT_RED
            ],
        }
        print(json.dumps(summary, indent=2))
    else:
        print_dashboard(data, verbose=args.verbose)

    # Always save health JSON (unless no-verify)
    if not args.no_verify:
        try:
            save_health_json(data)
        except Exception as e:
            print(f"[WARN] Could not save health JSON: {e}", file=sys.stderr)

    # Strict mode: exit 1 on any RED or regression
    if args.strict:
        bv = data["by_verdict"]
        if bv.get(VERDICT_RED, 0) > 0 or data["regression_count"] > 0:
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
