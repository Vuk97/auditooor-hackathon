#!/usr/bin/env python3
# r36-rebuttal: lane-RULE-65-CALIBRATION declared in .auditooor/agent_pathspec.json
"""deepseek-task-router.py - R65 model-routing-calibration gate.

Reads reference/deepseek_task_routing.json. For a given task-id, returns
the recommended provider, the calibration freshness, and a verdict that
gates whether a budget-bearing dispatch is allowed to proceed.

R65 fires at BUDGET-COMMITMENT time. Composes with R37 (per-emit) and
R64 (per-dispatch claim verification). See
docs/RULE_65_MODEL_ROUTING_CALIBRATION_2026-05-26.md.

CLI
---
    python3 tools/deepseek-task-router.py --task-id <TOK-X>
        [--budget-usd <amount>]
        [--routing-json <path>]
        [--ttl-days <N>]
        [--require-fresh-calibration]
        [--json]

Output JSON shape (schema auditooor.deepseek_task_router.v1):

    {
      "schema": "auditooor.deepseek_task_router.v1",
      "task_id": "TOK-B-CL",
      "budget_usd": 11.0,
      "recommended_provider": "deepseek-pro",
      "confidence": 0.85,
      "calibration_date": "2026-05-26",
      "calibration_days_old": 0,
      "flash_score": 3.2,
      "pro_score": 4.7,
      "ratio_flash_over_pro": 0.68,
      "decision_rationale": "Pro 5/5 idiomatic Rust...",
      "stale": false,
      "verdict": "pass-calibration-fresh"
    }

Verdicts:
    pass-calibration-fresh        : routing entry exists, calibration_days_old <= ttl
    pass-calibration-not-required : budget below $1 threshold
    ok-rebuttal                   : env AUDITOOOR_R65_BYPASS=1
    fail-no-calibration           : no routing entry for task_id
    fail-calibration-stale        : routing entry exists but stale
    error                         : tool exception

Override marker (in caller's draft):
    <!-- r65-rebuttal: <reason up to 200 chars> -->

Audit log: .auditooor/r65_routing_decisions.jsonl (append-only).
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys
from pathlib import Path
from typing import Any

SCHEMA = "auditooor.deepseek_task_router.v1"

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_ROUTING_JSON = _REPO_ROOT / "reference" / "deepseek_task_routing.json"
_DEFAULT_TTL_DAYS = int(os.environ.get("AUDITOOOR_R65_CALIBRATION_TTL_DAYS", "90"))
_BUDGET_THRESHOLD_USD = float(os.environ.get("AUDITOOOR_R65_BUDGET_THRESHOLD_USD", "1.0"))
_AUDIT_LOG_PATH = _REPO_ROOT / ".auditooor" / "r65_routing_decisions.jsonl"
_BYPASS_LOG_PATH = _REPO_ROOT / ".auditooor" / "r65_bypass_log.jsonl"


def load_routing(routing_path: Path) -> dict[str, Any]:
    """Load routing.json. Empty / missing -> empty dict."""
    if not routing_path.exists():
        return {}
    try:
        return json.loads(routing_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"_error": f"failed-to-load-routing-json: {exc!r}"}


def _parse_iso_date(date_str: str) -> _dt.date | None:
    """Parse YYYY-MM-DD or ISO datetime, return date or None."""
    if not date_str:
        return None
    try:
        # Try date format first
        return _dt.date.fromisoformat(date_str[:10])
    except (ValueError, TypeError):
        return None


def _days_since(date_str: str) -> int | None:
    """Days between today (UTC) and the iso date string."""
    d = _parse_iso_date(date_str)
    if d is None:
        return None
    today = _dt.date.today()
    return (today - d).days


def lookup_routing_entry(routing: dict[str, Any], task_id: str) -> dict[str, Any] | None:
    """Find the entry whose task_id (case-insensitive) matches."""
    entries = routing.get("entries", [])
    if not isinstance(entries, list):
        return None
    needle = task_id.strip().upper()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("task_id", "")).strip().upper() == needle:
            return entry
    return None


def _audit_log(path: Path, payload: dict[str, Any]) -> None:
    """Append a JSONL line to the audit log; best-effort."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(payload, separators=(",", ":")) + "\n")
    except OSError:
        pass


def route_task(
    task_id: str,
    budget_usd: float,
    routing: dict[str, Any],
    ttl_days: int = _DEFAULT_TTL_DAYS,
    bypass: bool = False,
) -> dict[str, Any]:
    """Decide routing verdict for (task_id, budget_usd).

    Returns the full result dict (caller serialises to JSON if needed).
    """
    now_iso = _dt.datetime.now(tz=_dt.timezone.utc).isoformat()

    # Short-circuit: budget below threshold => calibration not required.
    if budget_usd is not None and budget_usd <= _BUDGET_THRESHOLD_USD:
        result = {
            "schema": SCHEMA,
            "task_id": task_id,
            "budget_usd": budget_usd,
            "recommended_provider": None,
            "confidence": None,
            "calibration_date": None,
            "calibration_days_old": None,
            "flash_score": None,
            "pro_score": None,
            "ratio_flash_over_pro": None,
            "decision_rationale": (
                f"budget ${budget_usd:.2f} <= ${_BUDGET_THRESHOLD_USD:.2f} R65 threshold; "
                "calibration not required"
            ),
            "stale": False,
            "verdict": "pass-calibration-not-required",
            "ts": now_iso,
        }
        _audit_log(_AUDIT_LOG_PATH, {
            "ts": now_iso, "task_id": task_id, "budget_usd": budget_usd,
            "verdict": "pass-calibration-not-required",
            "routing_entry": None,
            "decision_reason": result["decision_rationale"],
            "bypass_marker": "",
        })
        return result

    # Env bypass => ok-rebuttal.
    if bypass:
        bypass_reason = os.environ.get("AUDITOOOR_R65_BYPASS_REASON",
                                       "AUDITOOOR_R65_BYPASS=1")[:200]
        result = {
            "schema": SCHEMA,
            "task_id": task_id,
            "budget_usd": budget_usd,
            "recommended_provider": None,
            "confidence": None,
            "calibration_date": None,
            "calibration_days_old": None,
            "flash_score": None,
            "pro_score": None,
            "ratio_flash_over_pro": None,
            "decision_rationale": f"AUDITOOOR_R65_BYPASS env override: {bypass_reason}",
            "stale": False,
            "verdict": "ok-rebuttal",
            "ts": now_iso,
        }
        _audit_log(_BYPASS_LOG_PATH, {
            "ts": now_iso, "task_id": task_id, "budget_usd": budget_usd,
            "reason": bypass_reason,
        })
        _audit_log(_AUDIT_LOG_PATH, {
            "ts": now_iso, "task_id": task_id, "budget_usd": budget_usd,
            "verdict": "ok-rebuttal",
            "routing_entry": None,
            "decision_reason": result["decision_rationale"],
            "bypass_marker": bypass_reason,
        })
        return result

    # Routing-load failure -> error.
    if "_error" in routing:
        return {
            "schema": SCHEMA,
            "task_id": task_id,
            "budget_usd": budget_usd,
            "recommended_provider": None,
            "confidence": None,
            "calibration_date": None,
            "calibration_days_old": None,
            "flash_score": None,
            "pro_score": None,
            "ratio_flash_over_pro": None,
            "decision_rationale": routing["_error"],
            "stale": None,
            "verdict": "error",
            "ts": now_iso,
        }

    entry = lookup_routing_entry(routing, task_id)
    if entry is None:
        result = {
            "schema": SCHEMA,
            "task_id": task_id,
            "budget_usd": budget_usd,
            "recommended_provider": None,
            "confidence": None,
            "calibration_date": None,
            "calibration_days_old": None,
            "flash_score": None,
            "pro_score": None,
            "ratio_flash_over_pro": None,
            "decision_rationale": (
                f"no routing.json entry for task_id={task_id}; "
                f"run `make deepseek-calibrate TASK={task_id}` first"
            ),
            "stale": None,
            "verdict": "fail-no-calibration",
            "ts": now_iso,
        }
        _audit_log(_AUDIT_LOG_PATH, {
            "ts": now_iso, "task_id": task_id, "budget_usd": budget_usd,
            "verdict": "fail-no-calibration",
            "routing_entry": None,
            "decision_reason": result["decision_rationale"],
            "bypass_marker": "",
        })
        return result

    # Found entry. Compute calibration_days_old.
    cal_date = str(entry.get("calibration_date", ""))
    days_old = _days_since(cal_date)
    if days_old is None:
        return {
            "schema": SCHEMA,
            "task_id": task_id,
            "budget_usd": budget_usd,
            "recommended_provider": entry.get("winner"),
            "confidence": entry.get("confidence"),
            "calibration_date": cal_date,
            "calibration_days_old": None,
            "flash_score": entry.get("flash_score"),
            "pro_score": entry.get("pro_score"),
            "ratio_flash_over_pro": entry.get("ratio_flash_over_pro"),
            "decision_rationale": (
                f"routing entry has malformed calibration_date={cal_date!r}; "
                "re-run calibration to refresh"
            ),
            "stale": None,
            "verdict": "error",
            "ts": now_iso,
        }

    stale = days_old > ttl_days
    if stale:
        result = {
            "schema": SCHEMA,
            "task_id": task_id,
            "budget_usd": budget_usd,
            "recommended_provider": entry.get("winner"),
            "confidence": entry.get("confidence"),
            "calibration_date": cal_date,
            "calibration_days_old": days_old,
            "flash_score": entry.get("flash_score"),
            "pro_score": entry.get("pro_score"),
            "ratio_flash_over_pro": entry.get("ratio_flash_over_pro"),
            "decision_rationale": (
                f"calibration is {days_old} days old (TTL {ttl_days}); "
                f"re-run `make deepseek-calibrate TASK={task_id}` to refresh"
            ),
            "stale": True,
            "verdict": "fail-calibration-stale",
            "ts": now_iso,
        }
        _audit_log(_AUDIT_LOG_PATH, {
            "ts": now_iso, "task_id": task_id, "budget_usd": budget_usd,
            "verdict": "fail-calibration-stale",
            "routing_entry": entry.get("task_id"),
            "decision_reason": result["decision_rationale"],
            "bypass_marker": "",
        })
        return result

    # Fresh entry.
    rationale = entry.get("decision_rationale",
                          f"winner={entry.get('winner')} per calibration "
                          f"{cal_date} ({days_old} days old)")
    result = {
        "schema": SCHEMA,
        "task_id": task_id,
        "budget_usd": budget_usd,
        "recommended_provider": entry.get("winner"),
        "confidence": entry.get("confidence"),
        "calibration_date": cal_date,
        "calibration_days_old": days_old,
        "flash_score": entry.get("flash_score"),
        "pro_score": entry.get("pro_score"),
        "ratio_flash_over_pro": entry.get("ratio_flash_over_pro"),
        "decision_rationale": rationale,
        "stale": False,
        "verdict": "pass-calibration-fresh",
        "ts": now_iso,
    }
    _audit_log(_AUDIT_LOG_PATH, {
        "ts": now_iso, "task_id": task_id, "budget_usd": budget_usd,
        "verdict": "pass-calibration-fresh",
        "routing_entry": entry.get("task_id"),
        "decision_reason": rationale,
        "bypass_marker": "",
    })
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="R65 model-routing-calibration gate. Decide whether a "
                    "budget-bearing dispatch is allowed.",
    )
    parser.add_argument("--task-id", required=True,
                        help="Task identifier, e.g. TOK-B-CL.")
    parser.add_argument("--budget-usd", type=float, default=None,
                        help="Declared budget cap in USD. If <= "
                             "$AUDITOOOR_R65_BUDGET_THRESHOLD_USD (default 1.0), "
                             "calibration is not required.")
    parser.add_argument("--routing-json", type=Path, default=_DEFAULT_ROUTING_JSON,
                        help="Path to routing.json (default: "
                             "reference/deepseek_task_routing.json).")
    parser.add_argument("--ttl-days", type=int, default=_DEFAULT_TTL_DAYS,
                        help="Calibration TTL in days (default 90).")
    parser.add_argument("--require-fresh-calibration", action="store_true",
                        help="Exit non-zero if verdict is not "
                             "pass-calibration-fresh or pass-calibration-not-required "
                             "or ok-rebuttal.")
    parser.add_argument("--json", action="store_true",
                        help="Emit JSON output instead of human-readable.")
    args = parser.parse_args(argv)

    # Bypass env var honored only when set to "1".
    bypass = os.environ.get("AUDITOOOR_R65_BYPASS", "").strip() == "1"

    routing = load_routing(args.routing_json)
    # Effective budget for routing: if not given, treat as unspecified
    # (above threshold, so calibration required).
    effective_budget = args.budget_usd if args.budget_usd is not None else 999.0

    try:
        result = route_task(
            task_id=args.task_id,
            budget_usd=effective_budget,
            routing=routing,
            ttl_days=args.ttl_days,
            bypass=bypass,
        )
    except Exception as exc:  # pragma: no cover
        result = {
            "schema": SCHEMA,
            "task_id": args.task_id,
            "budget_usd": args.budget_usd,
            "verdict": "error",
            "decision_rationale": f"router exception: {exc!r}",
        }

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        verdict = result.get("verdict", "?")
        provider = result.get("recommended_provider", "<none>")
        rationale = result.get("decision_rationale", "")
        print(f"[R65 router] task={args.task_id} budget=${args.budget_usd if args.budget_usd is not None else '?'}")
        print(f"  verdict:    {verdict}")
        print(f"  provider:   {provider}")
        print(f"  rationale:  {rationale}")
        if result.get("calibration_days_old") is not None:
            print(f"  cal days:   {result['calibration_days_old']} (TTL {args.ttl_days})")
        if result.get("flash_score") is not None and result.get("pro_score") is not None:
            print(f"  scores:     flash={result['flash_score']} pro={result['pro_score']} "
                  f"ratio={result.get('ratio_flash_over_pro')}")

    # Exit code logic.
    pass_verdicts = {
        "pass-calibration-fresh",
        "pass-calibration-not-required",
        "ok-rebuttal",
    }
    if args.require_fresh_calibration:
        if result.get("verdict") == "pass-calibration-fresh" or \
           result.get("verdict") == "ok-rebuttal":
            return 0
        # Budget-not-required is acceptable if budget IS below threshold,
        # but if the operator passed --require-fresh-calibration the
        # intent is to enforce a measured spend; only allow when the
        # routing is fresh OR bypass.
        # (We accept pass-calibration-not-required when explicit small
        # budget was passed, since the gate is then vacuous.)
        if result.get("verdict") == "pass-calibration-not-required":
            return 0
        return 1

    if result.get("verdict") in pass_verdicts:
        return 0
    if result.get("verdict") == "error":
        return 2
    # In non-strict mode, return 0 for visibility but the verdict tells
    # the caller what happened.
    return 0


if __name__ == "__main__":
    sys.exit(main())
