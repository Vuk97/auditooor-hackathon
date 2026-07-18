#!/usr/bin/env python3
"""outcome-scoreboard.py — T1-P0-4 v0 outcome-learning scoreboard.

Reads ``reference/outcomes.jsonl`` (the live outcome ledger) and emits a
compact JSON scoreboard to ``reports/outcome_scoreboard.json`` summarising:

* per-engagement / per-workspace counts of accepted / rejected / dupe / OOS /
  pending outcomes,
* per-detector-lane precision (TP / FP / FN, plus a rolling-window slice when
  ``--rolling-days`` is provided),
* per-dispatcher (``model_route``) routing accuracy: how often the route led
  to a TP outcome vs. a non-TP terminal outcome,
* top regressions: lanes whose precision flipped from PASS-shaped to
  FAIL-shaped between this run and the previous emitted scoreboard, capped at
  ``--top-regressions`` rows.

Determinism / discipline
------------------------
* stdlib-only, offline-safe.
* The script never invents outcomes — rows are read verbatim from the
  outcomes ledger; rows missing ``outcome`` are bucketed as ``unknown`` and
  excluded from precision math (M14-trap discipline: no n<5 promotions are
  ever emitted; ``preliminary=true`` flag is set for any cohort with
  ``sample_size < 5``).
* No mutation of the input ledger. No mutation of detector tier registry.
* Exit non-zero only on argument / IO errors. A missing ledger emits an
  empty-but-valid scoreboard with ``empty_input=true`` so closeout never
  silently passes when the ledger is absent.

Usage
-----
    python3 tools/outcome-scoreboard.py
    python3 tools/outcome-scoreboard.py --outcomes <path> --out <path>
    python3 tools/outcome-scoreboard.py --rolling-days 30 --top-regressions 5

Schema
------
    {
      "schema": "auditooor.outcome_scoreboard.v1",
      "generated_at": "<ISO-8601 UTC>",
      "ledger_path": "<relative path>",
      "ledger_row_count": <int>,
      "empty_input": <bool>,
      "summary": {
        "by_outcome": {<bucket>: <count>, ...},
        "by_severity": {...},
        "by_workspace": {...}
      },
      "engagements": [
        {"engagement": <str>, "workspace": <str>,
         "counts": {"accepted":..., "rejected":..., "duplicate":...,
                    "oos":..., "pending":..., "withdrawn":..., "other":...},
         "sample_size": <int>, "preliminary": <bool>}
      ],
      "detectors": [
        {"lane": <str>, "tp": <int>, "fp": <int>, "fn": <int>,
         "pending_or_other": <int>, "total_rows": <int>,
         "precision": <float|null>, "sample_size": <int>,
         "preliminary": <bool>,
         "rolling": {"window_days": <int>, "tp": ..., "fp": ..., "fn": ...,
                     "precision": ...} | null}
      ],
      "dispatchers": [
        {"model_route": <str>, "tp": <int>, "non_tp_terminal": <int>,
         "routing_accuracy": <float|null>, "sample_size": <int>,
         "preliminary": <bool>}
      ],
      "top_regressions": [
        {"lane": <str>, "previous_precision": <float|null>,
         "current_precision": <float|null>, "delta": <float|null>}
      ]
    }
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LEDGER = REPO_ROOT / "reference" / "outcomes.jsonl"
DEFAULT_OUT = REPO_ROOT / "reports" / "outcome_scoreboard.json"

SCHEMA = "auditooor.outcome_scoreboard.v1"

# Outcome bucketing -- M14-trap: keep verbatim ledger semantics; only re-shape
# at the scoreboard layer. "OOS" is not a first-class outcome value in the
# current ledger; we map ``rejection_reason`` substrings to OOS as a v0
# heuristic. Any row whose ``outcome`` is unknown is bucketed as ``unknown``.
ACCEPTED = {"accepted", "paid", "rewarded"}
REJECTED = {"rejected", "rejected_oos", "duplicate_of_rejected"}
DUPLICATE = {"duplicate", "duplicate_of_accepted"}
OOS = {"oos", "out_of_scope"}
WITHDRAWN = {"withdrawn"}
PENDING = {"pending", "in_review", "submitted"}

PRELIMINARY_THRESHOLD = 5  # M14-trap discipline


def _bucket(outcome: str | None, rejection_reason: str | None) -> str:
    o = (outcome or "").strip().lower()
    if o in ACCEPTED:
        return "accepted"
    if o in DUPLICATE:
        return "duplicate"
    if o in OOS:
        return "oos"
    if o in REJECTED:
        # Treat OOS-flavoured rejections as oos when reason hints at scope.
        rr = (rejection_reason or "").lower()
        if "out of scope" in rr or "out_of_scope" in rr or "oos" in rr:
            return "oos"
        return "rejected"
    if o in WITHDRAWN:
        return "withdrawn"
    if o in PENDING:
        return "pending"
    return "other"


def _is_terminal(bucket: str) -> bool:
    return bucket in {"accepted", "rejected", "duplicate", "oos", "withdrawn"}


def _is_tp(bucket: str) -> bool:
    return bucket == "accepted"


def _is_fp(bucket: str) -> bool:
    # Widened in L14 (closes Worker-JJJ L13 deferred) to mirror the
    # ``_FP_SHAPED_OUTCOMES`` vocabulary used by ``tools/agent-recall-suggester.py``
    # so the scoreboard's TP/FP precision math sees the same FP-shaped lane
    # signal the suggester aggregates.
    #
    # Bucket ↔ raw outcome mapping (see ``_bucket``):
    #   rejected   ← {rejected, rejected_oos (no-OOS-reason), duplicate_of_rejected}
    #   oos        ← {oos, out_of_scope, rejected_oos with OOS rejection_reason}
    #   duplicate  ← {duplicate, duplicate_of_accepted}
    #   withdrawn  ← {withdrawn}
    #
    # IMPORTANT discipline: duplicate-of-accepted IS counted as FP-shaped at
    # the scoreboard layer because the operator did not retain it as a unique
    # acceptance — even though the underlying bug was real, the lane fired
    # late / redundant work, which is the signal the recall suggester needs
    # to surface (and the same signal ``_FP_SHAPED_OUTCOMES`` captures).
    # ``_is_tp`` continues to require ``accepted`` only, so dupes are never
    # double-counted as TPs. M14-trap: precision is bounded in [0, 1].
    return bucket in {"rejected", "oos", "duplicate", "withdrawn"}


def _parse_date(value: str | None) -> dt.date | None:
    if not value:
        return None
    for fmt in ("%Y-%m-%d", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            return dt.datetime.strptime(value[: len(fmt) + 5], fmt).date()
        except ValueError:
            continue
    try:
        return dt.date.fromisoformat(value[:10])
    except ValueError:
        return None


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
                # M14-trap: never silently drop; record a sentinel.
                rows.append({"_parse_error": True, "_raw": line[:200]})
    return rows


def _load_previous(out_path: Path) -> dict | None:
    if not out_path.exists():
        return None
    try:
        return json.loads(out_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _engagements(rows: list[dict]) -> list[dict]:
    by_key: dict[tuple[str, str], Counter] = defaultdict(Counter)
    for row in rows:
        if row.get("_parse_error"):
            continue
        eng = str(row.get("engagement") or row.get("workspace") or "unknown")
        ws = str(row.get("workspace") or "unknown")
        bucket = _bucket(row.get("outcome"), row.get("rejection_reason"))
        by_key[(eng, ws)][bucket] += 1
    out: list[dict] = []
    for (eng, ws), counts in sorted(by_key.items()):
        sample = sum(counts.values())
        out.append(
            {
                "engagement": eng,
                "workspace": ws,
                "counts": {
                    k: counts.get(k, 0)
                    for k in (
                        "accepted",
                        "rejected",
                        "duplicate",
                        "oos",
                        "pending",
                        "withdrawn",
                        "other",
                    )
                },
                "sample_size": sample,
                "preliminary": sample < PRELIMINARY_THRESHOLD,
            }
        )
    return out


def _detectors(
    rows: list[dict],
    *,
    rolling_days: int | None,
    today: dt.date | None = None,
) -> list[dict]:
    """Return per-lane detector precision rows.

    Lane-bucketing widening (L15, closes Worker-JJJ L13 + Worker-NNN L14
    cumulative deferred):

    Pre-widening, ``by_lane`` was only populated when a row's bucket hit
    ``_is_tp`` or ``_is_fp``. That meant lanes whose rows were *all* pending
    / in_review / unknown ("other"-bucketed) silently disappeared from the
    scoreboard, even though the operator clearly owns those lanes (e.g.
    ``unknown`` 22 rows + ``centrifuge-historical-stub`` 2 rows in the live
    ledger). The recall suggester therefore never saw them and could not
    even emit an "observe" row to make them visible.

    Post-widening, ``by_lane`` is seeded with every lane that appears on any
    non-parse-error row. TP/FP/FN counters still only increment from
    terminal-shaped buckets (``_is_tp`` / ``_is_fp``); pending / other rows
    contribute to ``sample_size`` via a separate ``pending`` counter so
    operators can see the lane's footprint without inflating precision math.

    M14-trap discipline preserved:
      * precision is still ``tp / (tp + fp)``; lanes with no terminal rows
        still surface ``precision=None`` (the suggester maps that to an
        ``observe`` row).
      * ``preliminary`` is still ``sample_size < PRELIMINARY_THRESHOLD`` —
        no n<5 promotion ever happens.
      * Worker-NNN's L14 ``_is_fp`` widening (rejected/oos/duplicate/
        withdrawn) is unchanged; precision math invariants from
        ``test_withdrawn_and_duplicate_count_as_fp_in_detector_precision``
        still hold.
    """
    today = today or dt.datetime.now(dt.timezone.utc).date()
    by_lane: dict[str, Counter] = defaultdict(Counter)
    rolling_by_lane: dict[str, Counter] = defaultdict(Counter)
    for row in rows:
        if row.get("_parse_error"):
            continue
        lane = str(row.get("lane") or "unassigned")
        bucket = _bucket(row.get("outcome"), row.get("rejection_reason"))
        # L15 lane-diversity widening: touch the counter so the lane shows
        # up even when no row is terminal-shaped. Counters default to 0,
        # so this preserves all downstream tp/fp/fn math.
        by_lane[lane]
        if _is_tp(bucket):
            by_lane[lane]["tp"] += 1
        elif _is_fp(bucket):
            by_lane[lane]["fp"] += 1
        else:
            # Non-terminal (pending / other) — track footprint without
            # inflating precision math. ``pending_or_other`` flows into
            # ``sample_size`` only, never into tp/fp/fn.
            by_lane[lane]["pending_or_other"] += 1
        # FN proxy: the row had a real outcome but no detector lane recorded,
        # i.e. operator triaged something the dispatcher never routed.
        if lane == "unassigned" and _is_tp(bucket):
            by_lane[lane]["fn"] += 1
        if rolling_days is not None:
            rdate = _parse_date(row.get("resolved_at") or row.get("date"))
            if rdate is not None and (today - rdate).days <= rolling_days:
                if _is_tp(bucket):
                    rolling_by_lane[lane]["tp"] += 1
                elif _is_fp(bucket):
                    rolling_by_lane[lane]["fp"] += 1
    out: list[dict] = []
    for lane, counts in sorted(by_lane.items()):
        tp = counts.get("tp", 0)
        fp = counts.get("fp", 0)
        fn = counts.get("fn", 0)
        pending_or_other = counts.get("pending_or_other", 0)
        denom = tp + fp
        precision = (tp / denom) if denom else None
        # ``sample_size`` REMAINS the precision-relevant cohort (tp+fp+fn)
        # so existing precision-math invariants (and ``preliminary`` flag
        # semantics) carry over verbatim — Worker-NNN L14's tests still
        # pass. ``total_rows`` is the lane footprint including pending /
        # other-bucket rows, surfaced so operators can see lane diversity
        # without polluting precision math.
        sample = tp + fp + fn
        total_rows = sample + pending_or_other
        rolling_block: dict | None = None
        if rolling_days is not None:
            rc = rolling_by_lane.get(lane, Counter())
            r_tp = rc.get("tp", 0)
            r_fp = rc.get("fp", 0)
            r_denom = r_tp + r_fp
            rolling_block = {
                "window_days": rolling_days,
                "tp": r_tp,
                "fp": r_fp,
                "fn": 0,
                "precision": (r_tp / r_denom) if r_denom else None,
            }
        out.append(
            {
                "lane": lane,
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "pending_or_other": pending_or_other,
                "total_rows": total_rows,
                "precision": precision,
                "sample_size": sample,
                "preliminary": sample < PRELIMINARY_THRESHOLD,
                "rolling": rolling_block,
            }
        )
    return out


def _dispatchers(rows: list[dict]) -> list[dict]:
    by_route: dict[str, Counter] = defaultdict(Counter)
    for row in rows:
        if row.get("_parse_error"):
            continue
        route = str(row.get("model_route") or "unrouted")
        bucket = _bucket(row.get("outcome"), row.get("rejection_reason"))
        if not _is_terminal(bucket):
            continue
        if _is_tp(bucket):
            by_route[route]["tp"] += 1
        else:
            by_route[route]["non_tp_terminal"] += 1
    out: list[dict] = []
    for route, counts in sorted(by_route.items()):
        tp = counts.get("tp", 0)
        non_tp = counts.get("non_tp_terminal", 0)
        denom = tp + non_tp
        accuracy = (tp / denom) if denom else None
        out.append(
            {
                "model_route": route,
                "tp": tp,
                "non_tp_terminal": non_tp,
                "routing_accuracy": accuracy,
                "sample_size": denom,
                "preliminary": denom < PRELIMINARY_THRESHOLD,
            }
        )
    return out


def _top_regressions(
    current: list[dict], previous: dict | None, limit: int
) -> list[dict]:
    if not previous:
        return []
    prev_index = {d["lane"]: d.get("precision") for d in previous.get("detectors", [])}
    deltas: list[dict] = []
    for det in current:
        lane = det["lane"]
        if lane not in prev_index:
            continue
        prev_p = prev_index[lane]
        cur_p = det["precision"]
        if prev_p is None or cur_p is None:
            continue
        # Regression == precision dropped. Only flag drops, not gains.
        delta = cur_p - prev_p
        if delta < 0:
            deltas.append(
                {
                    "lane": lane,
                    "previous_precision": prev_p,
                    "current_precision": cur_p,
                    "delta": delta,
                }
            )
    deltas.sort(key=lambda d: d["delta"])  # most negative first
    return deltas[:limit]


def build_scoreboard(
    rows: list[dict],
    *,
    ledger_path: Path,
    rolling_days: int | None,
    top_regressions: int,
    previous: dict | None,
    today: dt.date | None = None,
) -> dict:
    real_rows = [r for r in rows if not r.get("_parse_error")]
    by_outcome: Counter = Counter()
    by_severity: Counter = Counter()
    by_workspace: Counter = Counter()
    for row in real_rows:
        bucket = _bucket(row.get("outcome"), row.get("rejection_reason"))
        by_outcome[bucket] += 1
        by_severity[str(row.get("severity") or "unknown")] += 1
        by_workspace[str(row.get("workspace") or "unknown")] += 1
    detectors = _detectors(real_rows, rolling_days=rolling_days, today=today)
    return {
        "schema": SCHEMA,
        "generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ledger_path": str(ledger_path.relative_to(REPO_ROOT))
        if ledger_path.is_absolute() and REPO_ROOT in ledger_path.parents
        else str(ledger_path),
        "ledger_row_count": len(rows),
        "ledger_parse_errors": sum(1 for r in rows if r.get("_parse_error")),
        "empty_input": len(real_rows) == 0,
        "summary": {
            "by_outcome": dict(sorted(by_outcome.items())),
            "by_severity": dict(sorted(by_severity.items())),
            "by_workspace": dict(sorted(by_workspace.items())),
        },
        "engagements": _engagements(real_rows),
        "detectors": detectors,
        "dispatchers": _dispatchers(real_rows),
        "top_regressions": _top_regressions(
            detectors, previous, top_regressions
        ),
        "preliminary_threshold": PRELIMINARY_THRESHOLD,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument(
        "--outcomes",
        type=Path,
        default=DEFAULT_LEDGER,
        help="Path to outcomes ledger (.jsonl). Default: reference/outcomes.jsonl",
    )
    p.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        help="Output JSON path. Default: reports/outcome_scoreboard.json",
    )
    p.add_argument(
        "--rolling-days",
        type=int,
        default=None,
        help="If set, include a rolling per-detector slice over the last N days.",
    )
    p.add_argument(
        "--top-regressions",
        type=int,
        default=5,
        help="How many top precision regressions to surface (default: 5).",
    )
    p.add_argument(
        "--stdout",
        action="store_true",
        help="Also print the JSON scoreboard to stdout.",
    )
    p.add_argument(
        "--no-write",
        action="store_true",
        help="Do not write the output file (useful for tests).",
    )
    args = p.parse_args(argv)

    rows = _load_ledger(args.outcomes)
    previous = _load_previous(args.out)
    scoreboard = build_scoreboard(
        rows,
        ledger_path=args.outcomes,
        rolling_days=args.rolling_days,
        top_regressions=args.top_regressions,
        previous=previous,
    )
    payload = json.dumps(scoreboard, indent=2, sort_keys=False) + "\n"
    if not args.no_write:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(payload, encoding="utf-8")
    if args.stdout:
        sys.stdout.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
