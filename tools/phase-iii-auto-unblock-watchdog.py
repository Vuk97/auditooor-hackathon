#!/usr/bin/env python3
"""Watchdog for PHASE-III.4 / PHASE-III.5 auto-unblock from Phase E evidence."""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[1]
SCHEMA = "auditooor.phase_iii_auto_unblock_watchdog.v1"
DEFAULT_MEASUREMENT_SUMMARY = (
    REPO / "reports/v3_iter_2026-05-24/lane_PHASE_III_4_PHASE_E_AB_TEST_STATUS/measurement_summary.json"
)
DEFAULT_PRQS_COMPARATOR = (
    REPO / "reports/v3_iter_2026-05-23/lane_HB_PRQS_COMPARATOR_MATCHED_COHORT/summary.json"
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        payload = json.load(fh)
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object: {path}")
    return payload


def _load_phase_e_measurement_module() -> Any:
    path = REPO / "tools" / "phase-b-e-measurement-report.py"
    spec = importlib.util.spec_from_file_location("phase_b_e_measurement_report", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _as_int(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    return 0


def _as_float_or_none(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _phase_e_from_summary(summary_path: Path) -> dict[str, Any]:
    payload = _read_json(summary_path)
    phase_e = payload.get("phase_e_ab_dogfood")
    if not isinstance(phase_e, dict):
        raise ValueError(f"missing phase_e_ab_dogfood in {summary_path}")
    return phase_e


def _phase_e_from_rows(
    *,
    rows_path: Path,
    prqs_path: Path,
    required_future_engagements: int,
) -> dict[str, Any]:
    mod = _load_phase_e_measurement_module()
    return mod.phase_e_measurement(
        rows_path=rows_path,
        prqs_path=prqs_path,
        required_engagements=required_future_engagements,
    )


def _status_payload(
    *,
    observed: dict[str, Any],
    blockers: list[str],
    required_future_engagements: int,
    required_valid_future_matched_pairs: int,
) -> dict[str, Any]:
    valid_pair_count = _as_int(observed.get("valid_matched_pair_count"))
    valid_ab_row_count = _as_int(observed.get("valid_matched_ab_row_count"))
    engagement_count = _as_int(observed.get("observed_engagement_count"))
    invalid_row_count = len(observed.get("invalid_rows") or [])
    unmatched_pair_count = len(observed.get("unmatched_pairs") or [])
    mismatched_engagement_pair_count = len(observed.get("mismatched_engagement_pairs") or [])
    avg_delta = _as_float_or_none(observed.get("average_composite_delta_a_minus_b"))

    pair_threshold_pass = valid_pair_count >= required_valid_future_matched_pairs
    engagement_threshold_pass = engagement_count >= required_future_engagements
    row_shape_clean = (
        invalid_row_count == 0
        and unmatched_pair_count == 0
        and mismatched_engagement_pair_count == 0
    )
    phase_e_ready = pair_threshold_pass and engagement_threshold_pass and row_shape_clean
    composite_uplift_computable = phase_e_ready and avg_delta is not None

    watchdog_blockers: list[str] = []
    if not pair_threshold_pass:
        watchdog_blockers.append("insufficient_valid_future_matched_pairs")
    if not engagement_threshold_pass:
        watchdog_blockers.append("insufficient_valid_future_matched_engagements")
    if invalid_row_count > 0:
        watchdog_blockers.append("invalid_phase_e_rows_present")
    if unmatched_pair_count > 0:
        watchdog_blockers.append("unmatched_phase_e_pairs_present")
    if mismatched_engagement_pair_count > 0:
        watchdog_blockers.append("mismatched_phase_e_engagement_pairs_present")

    phase_e_blockers = [str(item) for item in blockers]
    merged_blockers = sorted(set([*phase_e_blockers, *watchdog_blockers]))

    iii4_auto_unblock = phase_e_ready
    iii5_auto_unblock = composite_uplift_computable
    iii4_reason = (
        "phase_e_has_required_future_matched_pairs_and_engagements"
        if iii4_auto_unblock
        else "waiting_for_phase_e_future_matched_pairs_engagements_or_row_shape_fixes"
    )
    iii5_reason = (
        "phase_e_composite_uplift_now_computable"
        if iii5_auto_unblock
        else "phase_e_composite_uplift_not_yet_computable"
    )

    return {
        "thresholds": {
            "required_valid_future_matched_pairs": required_valid_future_matched_pairs,
            "required_future_matched_engagements": required_future_engagements,
        },
        "observed": {
            "valid_matched_pair_count": valid_pair_count,
            "valid_matched_ab_row_count": valid_ab_row_count,
            "observed_engagement_count": engagement_count,
            "invalid_row_count": invalid_row_count,
            "unmatched_pair_count": unmatched_pair_count,
            "mismatched_engagement_pair_count": mismatched_engagement_pair_count,
            "average_composite_delta_a_minus_b": avg_delta,
        },
        "phase_e_readiness": {
            "phase_e_measurement_ready": phase_e_ready,
            "composite_uplift_computable": composite_uplift_computable,
            "blockers": merged_blockers,
        },
        "phase_iii": {
            "III.4": {
                "status": "auto_unblocked" if iii4_auto_unblock else "blocked",
                "auto_unblock": iii4_auto_unblock,
                "reason": iii4_reason,
                "blockers": [] if iii4_auto_unblock else merged_blockers,
            },
            "III.5": {
                "status": "auto_unblocked" if iii5_auto_unblock else "blocked",
                "auto_unblock": iii5_auto_unblock,
                "reason": iii5_reason,
                "blockers": [] if iii5_auto_unblock else merged_blockers,
            },
        },
        "auto_unblock_summary": {
            "all_phase_iii_unblocked": iii4_auto_unblock and iii5_auto_unblock,
            "blocked_gate_ids": [
                gate
                for gate, payload in (
                    ("III.4", {"auto_unblock": iii4_auto_unblock}),
                    ("III.5", {"auto_unblock": iii5_auto_unblock}),
                )
                if not payload["auto_unblock"]
            ],
        },
    }


def _rel(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        return str(path.resolve().relative_to(REPO))
    except ValueError:
        return str(path.resolve())


def evaluate(args: argparse.Namespace) -> dict[str, Any]:
    required_future_engagements = int(args.required_future_engagements)
    required_pairs = (
        int(args.required_valid_future_matched_pairs)
        if args.required_valid_future_matched_pairs is not None
        else required_future_engagements
    )
    if required_future_engagements <= 0 or required_pairs <= 0:
        raise ValueError("required thresholds must be positive integers")

    phase_e_rows = Path(args.phase_e_rows).expanduser().resolve() if args.phase_e_rows else None
    measurement_summary = (
        Path(args.measurement_summary).expanduser().resolve()
        if args.measurement_summary
        else DEFAULT_MEASUREMENT_SUMMARY.resolve()
    )
    prqs_path = (
        Path(args.prqs_comparator).expanduser().resolve()
        if args.prqs_comparator
        else DEFAULT_PRQS_COMPARATOR.resolve()
    )

    phase_e: dict[str, Any]
    source_mode: str
    if phase_e_rows is not None:
        phase_e = _phase_e_from_rows(
            rows_path=phase_e_rows,
            prqs_path=prqs_path,
            required_future_engagements=required_future_engagements,
        )
        source_mode = "phase_e_rows"
    else:
        phase_e = _phase_e_from_summary(measurement_summary)
        source_mode = "measurement_summary"

    observed = phase_e.get("observed") if isinstance(phase_e.get("observed"), dict) else {}
    blockers = phase_e.get("blockers") if isinstance(phase_e.get("blockers"), list) else []

    status = _status_payload(
        observed=observed,
        blockers=[str(item) for item in blockers],
        required_future_engagements=required_future_engagements,
        required_valid_future_matched_pairs=required_pairs,
    )
    return {
        "schema": SCHEMA,
        "generated_at_utc": _utc_now(),
        "source_mode": source_mode,
        "inputs": {
            "measurement_summary": _rel(measurement_summary) if source_mode == "measurement_summary" else None,
            "phase_e_rows": _rel(phase_e_rows),
            "prqs_comparator": _rel(prqs_path),
        },
        **status,
    }


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Watch PHASE-III.4 / PHASE-III.5 auto-unblock readiness from Phase E measurement thresholds."
    )
    p.add_argument(
        "--measurement-summary",
        default=str(DEFAULT_MEASUREMENT_SUMMARY),
        help="Path to measurement_summary.json containing phase_e_ab_dogfood.",
    )
    p.add_argument(
        "--phase-e-rows",
        default=None,
        help="If set, compute Phase E readiness directly from these outcome rows (takes precedence over --measurement-summary).",
    )
    p.add_argument(
        "--prqs-comparator",
        default=str(DEFAULT_PRQS_COMPARATOR),
        help="PRQS comparator JSON used only when --phase-e-rows is provided.",
    )
    p.add_argument(
        "--required-future-engagements",
        type=int,
        default=4,
        help="Minimum distinct future engagements required.",
    )
    p.add_argument(
        "--required-valid-future-matched-pairs",
        type=int,
        default=None,
        help="Minimum valid future matched A/B pairs required (defaults to required-future-engagements).",
    )
    p.add_argument("--out", default=None, help="Optional JSON output file path.")
    p.add_argument("--json", action="store_true", help="Print full JSON payload.")
    p.add_argument("--advisory", action="store_true", help="Always exit 0, even when still blocked.")
    return p


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    payload = evaluate(args)
    if args.out:
        out = Path(args.out).expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        summary = {
            "all_phase_iii_unblocked": payload["auto_unblock_summary"]["all_phase_iii_unblocked"],
            "iii4_status": payload["phase_iii"]["III.4"]["status"],
            "iii5_status": payload["phase_iii"]["III.5"]["status"],
            "valid_matched_pair_count": payload["observed"]["valid_matched_pair_count"],
            "observed_engagement_count": payload["observed"]["observed_engagement_count"],
            "required_valid_future_matched_pairs": payload["thresholds"]["required_valid_future_matched_pairs"],
            "required_future_matched_engagements": payload["thresholds"]["required_future_matched_engagements"],
        }
        print(json.dumps(summary, sort_keys=True))
    if args.advisory:
        return 0
    return 0 if payload["auto_unblock_summary"]["all_phase_iii_unblocked"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
