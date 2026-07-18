#!/usr/bin/env python3
"""agent-recall-suggester.py — T1-PRIORITY-3 v0 scanner-improvement recall pipeline.

Reads an emitted ``reports/outcome_scoreboard*.json`` snapshot (schema
``auditooor.outcome_scoreboard.v1``) plus the live ``reference/outcomes.jsonl``
ledger, then surfaces actionable scanner-improvement suggestions for the next
loop. The output is a single JSON file enumerating:

* (a) per-detector lanes whose precision regressed by >= ``--regression-pp``
  percentage points vs. the rolling/prior window (default 10pp);
* (b) the top FP root-cause hint for each lane, inferred from the outcomes
  ledger's optional ``fp_reason`` field — gracefully degrades to
  ``rejection_reason`` and finally to ``unknown`` when neither field is
  present (current ledger has neither populated, so the v0 emitter records
  ``hint_source: "absent"`` honestly);
* (c) a suggested next-loop action per lane: ``lower-confidence-threshold``,
  ``add-allow-list``, ``split-detector``, or ``pause``.

Determinism / discipline (Codex M14-trap rules)
-----------------------------------------------
* stdlib-only, offline-safe.
* The script never invents outcomes — it consumes the scoreboard verbatim and
  derives suggestions; rows under the preliminary threshold (``sample_size <
  5``) are skipped so we never promote n<5 cohorts. This keeps the v0 emitter
  honest when most ledger rows still lack a ``lane`` (currently 0/67 rows
  carry one).
* Suggestions are advisory only — they emit a ``confidence`` band derived
  from sample size, never a hard pause directive. Operator integrates.
* Empty input emits an empty-but-valid suggestions document with
  ``empty_input=true`` so the next-loop closeout step never silently passes
  when the scoreboard is missing.
* No mutation of inputs. No side effects beyond writing the output file.

Usage
-----
    python3 tools/agent-recall-suggester.py
    python3 tools/agent-recall-suggester.py --scoreboard reports/outcome_scoreboard.json
    python3 tools/agent-recall-suggester.py --regression-pp 5 --top-n 20

Schema
------
    {
      "schema": "auditooor.agent_recall_suggester.v1",
      "generated_at": "<ISO-8601 UTC>",
      "scoreboard_path": "<relative path>",
      "scoreboard_generated_at": "<ISO-8601 UTC>|null",
      "ledger_path": "<relative path>",
      "ledger_row_count": <int>,
      "preliminary_threshold": <int>,
      "regression_threshold_pp": <float>,
      "empty_input": <bool>,
      "suggestions": [
        {
          "lane": <str>,
          "tp": <int>, "fp": <int>, "fn": <int>,
          "current_precision": <float|null>,
          "previous_precision": <float|null>,
          "delta_pp": <float|null>,
          "sample_size": <int>,
          "preliminary": <bool>,
          "hint_source": "fp_reason"|"rejection_reason"|"absent",
          "top_fp_reason": <str|null>,
          "top_fp_reason_count": <int>,
          "suggested_action": "lower-confidence-threshold"|"add-allow-list"|"split-detector"|"pause"|"observe",
          "confidence": "low"|"medium"|"high",
          "rationale": <str>
        }
      ],
      "summary": {
        "total_lanes": <int>,
        "regressing_lanes": <int>,
        "preliminary_lanes_skipped": <int>,
        "by_action": {<action>: <count>, ...}
      }
    }
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCOREBOARD = REPO_ROOT / "reports" / "outcome_scoreboard.json"
DEFAULT_LEDGER = REPO_ROOT / "reference" / "outcomes.jsonl"
DEFAULT_OUT_DIR = REPO_ROOT / "reports"

SCHEMA = "auditooor.agent_recall_suggester.v1"
PRELIMINARY_THRESHOLD = 5  # mirrors outcome-scoreboard.py
DEFAULT_REGRESSION_PP = 10.0
DEFAULT_TOP_N = 25

# Suggested-action thresholds. Operator can override via flags later; v0 keeps
# them constant and well-documented.
LOW_PRECISION_PAUSE = 0.20  # under 20% precision = pause / split
LOW_PRECISION_SPLIT = 0.40  # under 40% precision = split-detector
MID_PRECISION_ALLOWLIST = 0.65  # 40-65% = add-allow-list
# 65-100% precision but regressing -> lower-confidence-threshold


# ---------------------------------------------------------------------------
# IO helpers
# ---------------------------------------------------------------------------
def _load_scoreboard(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if data.get("schema") != "auditooor.outcome_scoreboard.v1":
        return None
    return data


def _load_ledger(path: Path) -> list[dict]:
    if not path.exists():
        return []
    rows: list[dict] = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                rows.append({"_parse_error": True, "_raw": line[:200]})
    return rows


# ---------------------------------------------------------------------------
# FP root-cause hint extraction
# ---------------------------------------------------------------------------
# FP-shaped outcome vocabulary. Mirrors ``tools/outcomes-backfill.py``
# ``FP_OUTCOMES`` so the two tools agree on what counts as FP-shaped for the
# purposes of fp_reason aggregation. Kept narrower than the scoreboard's
# ``_is_fp`` because the scoreboard's TP/FP precision math (rejected + oos
# only) intentionally excludes withdrawn/duplicate; here we want every
# operator-derived FP signal so the recall suggester can surface root-cause
# hints from the full ledger vocabulary.
_FP_SHAPED_OUTCOMES = {
    "rejected",
    "rejected_oos",
    "duplicate",
    "duplicate_of_rejected",
    "withdrawn",
}


def _fp_reasons_by_lane(rows: list[dict]) -> tuple[dict[str, Counter], str]:
    """Return ({lane: Counter[hint]}, hint_source).

    Prefers ``fp_reason`` when any row carries it. Falls back to
    ``rejection_reason`` (which is populated for some rejected rows in the
    current ledger). Returns ``("absent")`` when neither is observed.
    """
    by_lane_fp: dict[str, Counter] = defaultdict(Counter)
    saw_fp_reason = False
    saw_rejection_reason = False
    for row in rows:
        if row.get("_parse_error"):
            continue
        lane = str(row.get("lane") or "unassigned")
        outcome = str(row.get("outcome") or "").lower()
        # Only consider FP-shaped rows (rejected / withdrawn / duplicate /
        # OOS-flavoured rejection).
        if outcome not in _FP_SHAPED_OUTCOMES:
            # Also include rejection_reason hints for OOS-flagged rejections.
            rr_lower = str(row.get("rejection_reason") or "").lower()
            if not (rr_lower and ("oos" in rr_lower or "out of scope" in rr_lower or "out_of_scope" in rr_lower)):
                continue
        fp_reason = row.get("fp_reason")
        if fp_reason:
            saw_fp_reason = True
            by_lane_fp[lane][str(fp_reason).strip()[:160]] += 1
            continue
        rejection_reason = row.get("rejection_reason")
        if rejection_reason:
            saw_rejection_reason = True
            by_lane_fp[lane][str(rejection_reason).strip()[:160]] += 1
    if saw_fp_reason:
        hint_source = "fp_reason"
    elif saw_rejection_reason:
        hint_source = "rejection_reason"
    else:
        hint_source = "absent"
    return by_lane_fp, hint_source


# ---------------------------------------------------------------------------
# Suggestion derivation
# ---------------------------------------------------------------------------
def _classify_action(
    *,
    current_precision: float | None,
    delta_pp: float | None,
    regression_threshold_pp: float,
    sample_size: int,
) -> tuple[str, str]:
    """Return (action, rationale). Pure function, no IO."""
    if current_precision is None:
        return ("observe", "no terminal TP/FP yet; cannot score precision.")
    # Severe-precision rules dominate any delta classification.
    if current_precision < LOW_PRECISION_PAUSE:
        return (
            "pause",
            f"precision {current_precision:.2%} below pause floor {LOW_PRECISION_PAUSE:.0%}; "
            "lane should be paused until detector authoring revisits it.",
        )
    if current_precision < LOW_PRECISION_SPLIT:
        return (
            "split-detector",
            f"precision {current_precision:.2%} below split floor {LOW_PRECISION_SPLIT:.0%}; "
            "consider splitting the detector by sub-pattern to lift signal.",
        )
    if current_precision < MID_PRECISION_ALLOWLIST:
        return (
            "add-allow-list",
            f"precision {current_precision:.2%} in mid band; an allow-list "
            "for the dominant FP class typically recovers >5pp.",
        )
    # High precision but regressing -> lower confidence threshold first.
    if delta_pp is not None and delta_pp <= -regression_threshold_pp:
        return (
            "lower-confidence-threshold",
            f"precision {current_precision:.2%} still acceptable but regressed "
            f"{abs(delta_pp):.1f}pp; tighten confidence floor before authoring changes.",
        )
    return (
        "observe",
        f"precision {current_precision:.2%} stable; no action recommended this loop.",
    )


def _confidence_band(sample_size: int) -> str:
    if sample_size >= 30:
        return "high"
    if sample_size >= 10:
        return "medium"
    return "low"


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------
def build_suggestions(
    scoreboard: dict | None,
    ledger_rows: list[dict],
    *,
    scoreboard_path: Path,
    ledger_path: Path,
    regression_threshold_pp: float,
    top_n: int,
    preliminary_threshold: int = PRELIMINARY_THRESHOLD,
) -> dict:
    """Build the agent-recall suggestions document.

    Pure function, no side effects. ``scoreboard`` may be ``None`` (missing
    file) in which case we emit an honest empty document.
    """
    now_iso = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if scoreboard is None:
        return {
            "schema": SCHEMA,
            "generated_at": now_iso,
            "scoreboard_path": _rel(scoreboard_path),
            "scoreboard_generated_at": None,
            "ledger_path": _rel(ledger_path),
            "ledger_row_count": len(ledger_rows),
            "preliminary_threshold": preliminary_threshold,
            "regression_threshold_pp": regression_threshold_pp,
            "empty_input": True,
            "suggestions": [],
            "summary": {
                "total_lanes": 0,
                "regressing_lanes": 0,
                "preliminary_lanes_skipped": 0,
                "by_action": {},
            },
        }

    detectors = scoreboard.get("detectors") or []
    fp_hints, hint_source = _fp_reasons_by_lane(ledger_rows)

    suggestions: list[dict] = []
    skipped_preliminary = 0
    by_action: Counter = Counter()
    regressing_lanes = 0

    for det in detectors:
        lane = det.get("lane", "unassigned")
        sample_size = int(det.get("sample_size") or 0)
        preliminary = bool(det.get("preliminary")) or sample_size < preliminary_threshold
        if preliminary:
            skipped_preliminary += 1
            # Still emit a passive observe row so operator sees the lane.
            suggestions.append({
                "lane": lane,
                "tp": int(det.get("tp") or 0),
                "fp": int(det.get("fp") or 0),
                "fn": int(det.get("fn") or 0),
                "current_precision": det.get("precision"),
                "previous_precision": None,
                "delta_pp": None,
                "sample_size": sample_size,
                "preliminary": True,
                "hint_source": hint_source,
                "top_fp_reason": None,
                "top_fp_reason_count": 0,
                "suggested_action": "observe",
                "confidence": "low",
                "rationale": (
                    f"sample_size={sample_size} below preliminary threshold "
                    f"{preliminary_threshold}; M14-trap discipline requires no "
                    "promotion."
                ),
            })
            by_action["observe"] += 1
            continue

        cur = det.get("precision")
        rolling = det.get("rolling") or {}
        prev = rolling.get("precision") if rolling else None
        # If the rolling slice is identical to current (because rolling-days
        # captured the entire ledger), prev and cur match — treat as no delta.
        delta_pp: float | None
        if cur is None or prev is None:
            delta_pp = None
        else:
            delta_pp = (cur - prev) * 100.0

        action, rationale = _classify_action(
            current_precision=cur,
            delta_pp=delta_pp,
            regression_threshold_pp=regression_threshold_pp,
            sample_size=sample_size,
        )

        if delta_pp is not None and delta_pp <= -regression_threshold_pp:
            regressing_lanes += 1

        top_hint: str | None = None
        top_hint_count = 0
        lane_hints = fp_hints.get(lane) or Counter()
        if lane_hints:
            top_hint, top_hint_count = lane_hints.most_common(1)[0]

        suggestions.append({
            "lane": lane,
            "tp": int(det.get("tp") or 0),
            "fp": int(det.get("fp") or 0),
            "fn": int(det.get("fn") or 0),
            "current_precision": cur,
            "previous_precision": prev,
            "delta_pp": delta_pp,
            "sample_size": sample_size,
            "preliminary": False,
            "hint_source": hint_source,
            "top_fp_reason": top_hint,
            "top_fp_reason_count": top_hint_count,
            "suggested_action": action,
            "confidence": _confidence_band(sample_size),
            "rationale": rationale,
        })
        by_action[action] += 1

    # Sort: regressing first (most negative delta), then by lowest precision,
    # then by lane name. Stable.
    def _sort_key(s: dict) -> tuple:
        delta = s["delta_pp"] if s["delta_pp"] is not None else 0.0
        prec = s["current_precision"] if s["current_precision"] is not None else 1.0
        return (delta, prec, s["lane"])

    suggestions.sort(key=_sort_key)
    if top_n > 0:
        suggestions = suggestions[:top_n]

    return {
        "schema": SCHEMA,
        "generated_at": now_iso,
        "scoreboard_path": _rel(scoreboard_path),
        "scoreboard_generated_at": scoreboard.get("generated_at"),
        "ledger_path": _rel(ledger_path),
        "ledger_row_count": len(ledger_rows),
        "preliminary_threshold": preliminary_threshold,
        "regression_threshold_pp": regression_threshold_pp,
        "empty_input": len(detectors) == 0,
        "suggestions": suggestions,
        "summary": {
            "total_lanes": len(detectors),
            "regressing_lanes": regressing_lanes,
            "preliminary_lanes_skipped": skipped_preliminary,
            "by_action": dict(sorted(by_action.items())),
        },
    }


def _rel(p: Path) -> str:
    try:
        if p.is_absolute() and REPO_ROOT in p.parents:
            return str(p.relative_to(REPO_ROOT))
    except ValueError:
        pass
    return str(p)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--scoreboard",
        type=Path,
        default=DEFAULT_SCOREBOARD,
        help="Path to outcome_scoreboard.json (default: reports/outcome_scoreboard.json)",
    )
    parser.add_argument(
        "--ledger",
        type=Path,
        default=DEFAULT_LEDGER,
        help="Path to outcomes ledger (.jsonl). Default: reference/outcomes.jsonl",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=None,
        help="Output JSON path. Default: reports/agent_recall_suggestions_<DATE>.json",
    )
    parser.add_argument(
        "--regression-pp",
        type=float,
        default=DEFAULT_REGRESSION_PP,
        help=f"Precision drop (in percentage points) to flag as regression (default: {DEFAULT_REGRESSION_PP}).",
    )
    parser.add_argument(
        "--top-n",
        type=int,
        default=DEFAULT_TOP_N,
        help=f"Cap suggestions to top-N rows (default: {DEFAULT_TOP_N}); 0 = unlimited.",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Also print the JSON suggestions to stdout.",
    )
    parser.add_argument(
        "--no-write",
        action="store_true",
        help="Do not write the output file (useful for tests).",
    )
    args = parser.parse_args(argv)

    scoreboard = _load_scoreboard(args.scoreboard)
    ledger_rows = _load_ledger(args.ledger)
    payload = build_suggestions(
        scoreboard,
        ledger_rows,
        scoreboard_path=args.scoreboard,
        ledger_path=args.ledger,
        regression_threshold_pp=args.regression_pp,
        top_n=args.top_n,
    )

    out_path = args.out
    if out_path is None:
        date_tag = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
        out_path = DEFAULT_OUT_DIR / f"agent_recall_suggestions_{date_tag}.json"

    serialized = json.dumps(payload, indent=2, sort_keys=False) + "\n"
    if not args.no_write:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(serialized, encoding="utf-8")
    if args.stdout:
        sys.stdout.write(serialized)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
