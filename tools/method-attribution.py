#!/usr/bin/env python3
"""method-attribution.py - Lane K K9 method attribution + budget allocator.

K9 is the structural answer to "spend budget on methods that pay".

Every candidate/artifact record produced during an engagement should record:

* ``discovery_method``    - how the candidate was found (e.g. detector_scan,
  commit_mining, manual_review, provider_fanout, cross_engagement_pattern,
  upstream_fork_divergence, harness_fuzz).
* ``source_surface``      - what was read/run (e.g. go_source, rust_source,
  audit_pdf, provider_output, git_history).
* ``agent`` / ``provider`` - who produced it.
* ``time_spent_minutes``  - discovery time.
* ``proof_time_minutes``  - PoC build/verify time.
* ``killed_reason``       - if dropped, why (dupe, OOS, no_impact, ...).
* ``filed_outcome``       - one of: filed, accepted, rejected, escalated,
  paste_ready, dropped, killed, in_progress.
* ``moved_success_metric`` - bool: did this candidate move the engagement's
  success metric (a filed/accepted/escalated finding)?

This tool ingests those records (a JSON list, a JSONL ledger, or an object with
a ``candidates`` / ``records`` / ``artifacts`` list) and emits:

* a per-``discovery_method`` attribution summary (yield, proof-time cost,
  kill rate, filed/accepted counts, a ``method_score``);
* a reweighted dispatch budget that shifts share toward methods with
  proved/filed/survived outcomes and away from dead scanners / stale lanes /
  low-yield provider paths.

The next engagement's dispatch plan is expected to cite the emitted summary
(K9 acceptance).  The tool is offline-only and deterministic.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any, Iterable, Sequence


SCHEMA = "auditooor.method_attribution.v1"

# Outcomes that count as "this method paid": the candidate moved the success
# metric or is on track to.
POSITIVE_OUTCOMES = {"filed", "accepted", "escalated", "paste_ready"}
# Outcomes that count as wasted dispatch.
NEGATIVE_OUTCOMES = {"dropped", "killed", "rejected", "oos", "duplicate"}

# Floor / ceiling on any single method's reweighted budget share so a single
# good engagement cannot starve exploration entirely.
MIN_METHOD_SHARE = 0.05
MAX_METHOD_SHARE = 0.55
# A method with zero records this engagement keeps a small exploration share.
COLD_METHOD_SHARE = 0.05


def _utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _load_records(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    stripped = text.strip()
    records: list[dict[str, Any]] = []
    if not stripped:
        return records
    # Try whole-file JSON first (list or object), then fall back to JSONL.
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, list):
        return [r for r in payload if isinstance(r, dict)]
    if isinstance(payload, dict):
        for key in ("candidates", "records", "artifacts", "rows"):
            val = payload.get(key)
            if isinstance(val, list):
                return [r for r in val if isinstance(r, dict)]
        # A single record object.
        return [payload]
    # JSONL fallback.
    for raw in stripped.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            row = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            records.append(row)
    return records


def _str(record: dict[str, Any], *keys: str, default: str = "") -> str:
    for key in keys:
        value = str(record.get(key) or "").strip()
        if value:
            return value
    return default


def _num(record: dict[str, Any], *keys: str) -> float:
    for key in keys:
        value = record.get(key)
        if isinstance(value, (int, float)):
            return float(value)
    return 0.0


def _outcome(record: dict[str, Any]) -> str:
    raw = _str(record, "filed_outcome", "outcome", "status", "verdict").lower()
    if raw in POSITIVE_OUTCOMES or raw in NEGATIVE_OUTCOMES:
        return raw
    if raw in {"in_progress", "open", "pending"}:
        return "in_progress"
    # An explicit kill reason with no outcome means killed.
    if _str(record, "killed_reason", "kill_reason"):
        return "killed"
    return raw or "unknown"


def _moved_metric(record: dict[str, Any]) -> bool:
    val = record.get("moved_success_metric")
    if isinstance(val, bool):
        return val
    return _outcome(record) in POSITIVE_OUTCOMES


def _method(record: dict[str, Any]) -> str:
    return _str(
        record,
        "discovery_method",
        "method",
        "discovery_surface",
        default="unattributed",
    )


def _method_score(stats: dict[str, Any]) -> float:
    """A bounded 0..1 score: paid outcomes per record, discounted by proof cost.

    A method that files/accepts findings cheaply scores high; a method that
    only produces killed/dropped candidates scores near 0.
    """
    total = stats["record_count"]
    if total <= 0:
        return 0.0
    positive = stats["positive_count"]
    negative = stats["negative_count"]
    # Base yield: net positive fraction, clamped to 0..1.
    yield_frac = max(0.0, (positive - 0.5 * negative) / total)
    # Proof-cost penalty: methods that burn lots of proof time per positive
    # finding are less budget-efficient.  Normalize against a 4h reference.
    proof_per_positive = (
        stats["proof_time_minutes"] / positive if positive else stats["proof_time_minutes"]
    )
    cost_factor = 1.0 / (1.0 + proof_per_positive / 240.0)
    return round(min(1.0, yield_frac) * cost_factor, 4)


def attribute(records: list[dict[str, Any]]) -> dict[str, Any]:
    by_method: dict[str, dict[str, Any]] = {}
    for record in records:
        method = _method(record)
        stats = by_method.setdefault(
            method,
            {
                "method": method,
                "record_count": 0,
                "positive_count": 0,
                "negative_count": 0,
                "in_progress_count": 0,
                "moved_metric_count": 0,
                "time_spent_minutes": 0.0,
                "proof_time_minutes": 0.0,
                "killed_reasons": {},
                "source_surfaces": {},
                "outcomes": {},
            },
        )
        stats["record_count"] += 1
        outcome = _outcome(record)
        stats["outcomes"][outcome] = stats["outcomes"].get(outcome, 0) + 1
        if outcome in POSITIVE_OUTCOMES:
            stats["positive_count"] += 1
        elif outcome in NEGATIVE_OUTCOMES:
            stats["negative_count"] += 1
        elif outcome == "in_progress":
            stats["in_progress_count"] += 1
        if _moved_metric(record):
            stats["moved_metric_count"] += 1
        stats["time_spent_minutes"] += _num(record, "time_spent_minutes", "time_spent")
        stats["proof_time_minutes"] += _num(record, "proof_time_minutes", "proof_time")
        killed = _str(record, "killed_reason", "kill_reason")
        if killed:
            stats["killed_reasons"][killed] = stats["killed_reasons"].get(killed, 0) + 1
        surface = _str(record, "source_surface", "surface")
        if surface:
            stats["source_surfaces"][surface] = stats["source_surfaces"].get(surface, 0) + 1

    for stats in by_method.values():
        stats["method_score"] = _method_score(stats)
        stats["kill_rate"] = round(
            stats["negative_count"] / stats["record_count"], 4
        ) if stats["record_count"] else 0.0
        stats["proof_time_minutes"] = round(stats["proof_time_minutes"], 2)
        stats["time_spent_minutes"] = round(stats["time_spent_minutes"], 2)
        stats["killed_reasons"] = dict(sorted(stats["killed_reasons"].items()))
        stats["source_surfaces"] = dict(sorted(stats["source_surfaces"].items()))
        stats["outcomes"] = dict(sorted(stats["outcomes"].items()))

    return by_method


def reweight_budget(by_method: dict[str, dict[str, Any]]) -> dict[str, float]:
    """K9 - reweight dispatch budget toward methods that proved/filed/survived.

    Share is proportional to ``method_score`` (clamped per-method), with a small
    exploration floor so a zero-score method is throttled, not eliminated.
    """
    if not by_method:
        return {}
    raw: dict[str, float] = {}
    for method, stats in by_method.items():
        # Score-weighted, but every method keeps an exploration floor.
        raw[method] = max(COLD_METHOD_SHARE, stats["method_score"])
    total = sum(raw.values())
    if total <= 0:
        even = round(1.0 / len(raw), 4)
        return {method: even for method in raw}
    shares = {method: value / total for method, value in raw.items()}
    # Clamp toward the [MIN, MAX] band, then renormalize.  The exploration
    # floor (MIN_METHOD_SHARE) is the hard guarantee - a dead method is
    # throttled, never eliminated.  With very few methods the post-renorm
    # share of a dominant method can still exceed MAX; the clamp is a
    # best-effort smoothing, the floor is the invariant.
    clamped = {
        method: min(MAX_METHOD_SHARE, max(MIN_METHOD_SHARE, share))
        for method, share in shares.items()
    }
    norm = sum(clamped.values())
    return {method: round(share / norm, 4) for method, share in clamped.items()}


def build_summary(
    records: list[dict[str, Any]],
    *,
    engagement: str,
    prior_budget_path: Path | None = None,
) -> dict[str, Any]:
    by_method = attribute(records)
    new_budget = reweight_budget(by_method)

    prior_budget: dict[str, float] = {}
    if prior_budget_path and prior_budget_path.is_file():
        try:
            prior = json.loads(prior_budget_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            prior = None
        if isinstance(prior, dict):
            candidate = prior.get("next_dispatch_budget") or prior.get("dispatch_budget") or prior
            if isinstance(candidate, dict):
                prior_budget = {
                    str(k): float(v)
                    for k, v in candidate.items()
                    if isinstance(v, (int, float))
                }

    budget_shift = {
        method: round(new_budget.get(method, 0.0) - prior_budget.get(method, 0.0), 4)
        for method in sorted(set(new_budget) | set(prior_budget))
    }

    methods_sorted = sorted(
        by_method.values(), key=lambda s: s["method_score"], reverse=True
    )
    top_methods = [s["method"] for s in methods_sorted if s["method_score"] > 0][:3]
    dead_methods = [
        s["method"]
        for s in methods_sorted
        if s["method_score"] == 0.0 and s["record_count"] > 0
    ]

    total_records = len(records)
    total_positive = sum(s["positive_count"] for s in by_method.values())
    total_negative = sum(s["negative_count"] for s in by_method.values())

    return {
        "schema": SCHEMA,
        "generated_at_utc": _utc_now(),
        "engagement": engagement,
        "record_count": total_records,
        "method_count": len(by_method),
        "positive_outcome_count": total_positive,
        "negative_outcome_count": total_negative,
        "per_method": [methods_sorted[i] for i in range(len(methods_sorted))],
        "next_dispatch_budget": new_budget,
        "prior_dispatch_budget": prior_budget,
        "budget_shift": budget_shift,
        "top_methods": top_methods,
        "dead_methods": dead_methods,
        "dispatch_guidance": (
            f"Reweight next-engagement dispatch toward {', '.join(top_methods) or 'no proven method yet'}"
            + (f"; throttle {', '.join(dead_methods)}" if dead_methods else "")
            + ". Cite this summary in the next dispatch plan (K9 acceptance)."
        ),
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--records",
        required=True,
        type=Path,
        help="JSON list / JSONL ledger / object with a candidates/records/artifacts list.",
    )
    parser.add_argument("--engagement", default="", help="Engagement label for the summary.")
    parser.add_argument(
        "--prior-budget",
        type=Path,
        help="Prior method-attribution summary JSON to diff the budget against.",
    )
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    records_path = args.records.expanduser().resolve()
    if not records_path.is_file():
        print(f"method-attribution: ERR records file not found: {records_path}")
        return 2
    records = _load_records(records_path)
    engagement = args.engagement or records_path.parent.name
    summary = build_summary(
        records,
        engagement=engagement,
        prior_budget_path=args.prior_budget.expanduser().resolve() if args.prior_budget else None,
    )
    if args.out_json:
        out = args.out_json.expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.print_json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    elif not args.out_json:
        print(
            f"method-attribution: engagement={summary['engagement']} "
            f"records={summary['record_count']} methods={summary['method_count']} "
            f"top={','.join(summary['top_methods']) or 'none'} "
            f"dead={','.join(summary['dead_methods']) or 'none'}"
        )
        for method, share in sorted(summary["next_dispatch_budget"].items(), key=lambda kv: -kv[1]):
            print(f"  budget {method}: {share}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
