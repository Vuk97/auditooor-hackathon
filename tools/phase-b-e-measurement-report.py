#!/usr/bin/env python3
"""Report-only Phase B Gate and Phase E A/B measurement summary.

This tool reads existing artifacts and computes the current measurement
state. It does not run detectors, edit submissions, or promote any
capability output.
"""
from __future__ import annotations

import argparse
import json
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[1]
SCHEMA = "auditooor.phase_b_e_measurement_report.v1"

DEFAULT_P1_CURRENT = (
    REPO
    / "reports/v3_iter_2026-05-24/lane_P1_DOGFOOD_AUDITED_PRIMARY/p1_candidate_triage_dogfood.json"
)
DEFAULT_P1_FINAL_ACCEPTED = (
    REPO
    / "reports/v3_iter_2026-05-23/p1_candidate_triage_final_after_gate_patch/p1_candidate_triage_dogfood.json"
)
DEFAULT_P3 = Path("/Users/wolf/audits/hyperbridge/.auditooor/p3_tp_poc_pass_measure.json")
DEFAULT_P3_FALLBACK = REPO / "reports/v3_iter_2026-05-23/p3_tp_poc_pass_hyperbridge_final_after_gate_patch.json"
DEFAULT_PRQS = REPO / "reports/v3_iter_2026-05-23/lane_HB_PRQS_COMPARATOR_MATCHED_COHORT/summary.json"
DEFAULT_OUTPUT_DIR = REPO / "reports/v3_iter_2026-05-24/lane_PHASE_B_GATE_PHASE_E_MEASUREMENT"

P1_TARGET_PCT = 30.0
P3_TARGET_PCT = 10.0
PRQS_MAX_REGRESSION_DROP = 5.0
PHASE_E_REQUIRED_ENGAGEMENTS = 4
PHASE_E_WEIGHTS = {
    "ppe": 0.30,
    "frph": 0.20,
    "prqs": 0.20,
    "supporting": 0.30,
}
PHASE_E_ROW_SCHEMA = "auditooor.phase_e_ab_outcome_row.v1"
PHASE_E_ROW_SCHEMA_PATH = REPO / "docs/schemas/phase_e_ab_outcome_row.v1.json"
PHASE_E_REQUIRED_METRICS = tuple(PHASE_E_WEIGHTS.keys())
PHASE_E_MIN_OUTCOME_OBSERVED_AT_UTC = datetime(2026, 5, 24, tzinfo=timezone.utc)


def _read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    if not path.is_file():
        return rows
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def _rel(path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        return str(path.resolve().relative_to(REPO))
    except ValueError:
        return str(path)


def _pct(numer: int, denom: int) -> float | None:
    if denom <= 0:
        return None
    return round((numer / denom) * 100.0, 3)


def _pass_fail(value: bool | None) -> str:
    if value is True:
        return "pass"
    if value is False:
        return "fail"
    return "unknown"


def _display(value: Any) -> Any:
    return "null" if value is None else value


def default_p1_path() -> Path:
    if DEFAULT_P1_CURRENT.is_file():
        return DEFAULT_P1_CURRENT
    return DEFAULT_P1_FINAL_ACCEPTED


def default_p3_path() -> Path:
    if DEFAULT_P3.is_file():
        return DEFAULT_P3
    return DEFAULT_P3_FALLBACK


def phase_b_metrics(
    *,
    p1_path: Path,
    p3_path: Path,
    prqs_path: Path,
    p1_target_pct: float = P1_TARGET_PCT,
    p3_target_pct: float = P3_TARGET_PCT,
    prqs_max_regression_drop: float = PRQS_MAX_REGRESSION_DROP,
) -> dict[str, Any]:
    p1 = _read_json(p1_path)
    p3 = _read_json(p3_path)
    prqs = _read_json(prqs_path)

    p1_rows = p1.get("candidate_rows") or []
    p1_summary = p1.get("summary") or {}
    p1_states = p1_summary.get("states") or {}
    eligible_states = {"accepted", "cited", "suggested", "no-match"}
    if p1_rows:
        eligible_rows = [row for row in p1_rows if row.get("state") in eligible_states]
        accepted_count = sum(1 for row in eligible_rows if row.get("state") == "accepted")
        cited_count = sum(1 for row in eligible_rows if row.get("state") == "cited")
        suggested_count = sum(1 for row in eligible_rows if row.get("state") == "suggested")
        no_match_count = sum(1 for row in eligible_rows if row.get("state") == "no-match")
        blocked_count = sum(1 for row in p1_rows if row.get("state") == "blocked")
        candidate_count = len(p1_rows)
    else:
        accepted_count = int(p1_states.get("accepted") or 0)
        cited_count = int(p1_states.get("cited") or 0)
        suggested_count = int(p1_states.get("suggested") or 0)
        no_match_count = int(p1_states.get("no-match") or 0)
        blocked_count = int(p1_states.get("blocked") or 0)
        candidate_count = int(p1_summary.get("candidate_count") or sum(int(v or 0) for v in p1_states.values()))
    eligible_count = accepted_count + cited_count + suggested_count + no_match_count
    p1_strict_citation_rate = _pct(cited_count, eligible_count)
    p1_grounding_rate = _pct(cited_count + accepted_count, eligible_count)
    p1_suggested_rate = _pct(suggested_count, eligible_count)
    p1_pass = (
        p1_grounding_rate >= p1_target_pct
        if isinstance(p1_grounding_rate, (int, float))
        else None
    )

    p3_summary = p3.get("summary") or {}
    p3_rate = p3_summary.get("tp_poc_pass_rate")
    p3_rate_pct = None
    if isinstance(p3_rate, (int, float)):
        p3_rate_pct = round(float(p3_rate) * 100.0, 3) if 0 <= float(p3_rate) <= 1 else round(float(p3_rate), 3)
    p3_pass = p3_rate_pct >= p3_target_pct if isinstance(p3_rate_pct, (int, float)) else None

    comparator = prqs.get("comparator") or {}
    prqs_drop = comparator.get("max_pair_regression_drop_points")
    prqs_drop_ok = (
        float(prqs_drop) <= prqs_max_regression_drop
        if isinstance(prqs_drop, (int, float))
        else None
    )
    prqs_exceeding = comparator.get("pairs_exceeding_regression_limit") or []
    prqs_decisive = prqs.get("gate1_prqs_state") == "decisive"
    prqs_pass = bool(prqs_decisive and prqs_drop_ok and not prqs_exceeding)

    blockers: list[str] = []
    if p1_pass is not True:
        blockers.append("p1_current_grounding_below_gate_target")
    if p3_pass is not True:
        blockers.append("p3_tp_poc_pass_below_gate_target_or_unknown")
    if prqs_pass is not True:
        blockers.append("prqs_regression_not_decisive_or_above_limit")

    gate_pass = p1_pass is True and p3_pass is True and prqs_pass is True
    return {
        "schema": "auditooor.phase_b_gate_metrics.v1",
        "targets": {
            "p1_citation_or_accepted_grounding_rate_pct": p1_target_pct,
            "p3_tp_poc_pass_rate_pct": p3_target_pct,
            "prqs_max_regression_drop_points": prqs_max_regression_drop,
        },
        "inputs": {
            "p1_candidate_triage": _rel(p1_path),
            "p3_tp_poc_pass_measurement": _rel(p3_path),
            "prqs_comparator": _rel(prqs_path),
        },
        "p1_citation_rate": {
            "verdict": _pass_fail(p1_pass),
            "candidate_count": candidate_count,
            "eligible_candidate_count": eligible_count,
            "accepted_candidate_count": accepted_count,
            "cited_candidate_count": cited_count,
            "suggested_candidate_count": suggested_count,
            "no_match_candidate_count": no_match_count,
            "blocked_candidate_count": blocked_count,
            "strict_draft_citation_rate_pct": p1_strict_citation_rate,
            "accepted_or_cited_grounding_rate_pct": p1_grounding_rate,
            "suggested_only_rate_pct": p1_suggested_rate,
            "indexed_invariant_count": p1_summary.get("indexed_invariant_count"),
            "invariant_quality_source": p1_summary.get("invariant_quality_source"),
            "include_extracted_broad": p1_summary.get("include_extracted_broad"),
            "no_draft_or_submission_edits": p1_summary.get("no_draft_or_submission_edits"),
        },
        "p3_tp_poc_pass": {
            "verdict": _pass_fail(p3_pass),
            "candidate_count": p3_summary.get("candidate_count"),
            "tp_evidence_count": p3_summary.get("tp_evidence_count"),
            "poc_pass_count": p3_summary.get("poc_pass_count"),
            "semantic_pattern_attributed_candidate_count": p3_summary.get(
                "semantic_pattern_attributed_candidate_count"
            ),
            "tp_poc_pass_rate": p3_rate,
            "tp_poc_pass_rate_pct": p3_rate_pct,
            "tp_poc_pass_rate_state": p3_summary.get("tp_poc_pass_rate_state"),
            "unattributed_poc_pass_count": p3_summary.get("unattributed_poc_pass_count"),
            "unknown_unattributed_tp_evidence_count": p3_summary.get(
                "unknown_unattributed_tp_evidence_count"
            ),
        },
        "prqs_regression": {
            "verdict": _pass_fail(prqs_pass),
            "decisive": prqs_decisive,
            "matched_pair_count": comparator.get("matched_pair_count"),
            "cohort_a_average_score": (comparator.get("cohort_a") or {}).get("average_score"),
            "cohort_b_average_score": (comparator.get("cohort_b") or {}).get("average_score"),
            "average_delta_a_minus_b": comparator.get("average_delta_a_minus_b"),
            "max_pair_regression_drop_points": prqs_drop,
            "pairs_exceeding_regression_limit": prqs_exceeding,
            "source_verdict": prqs.get("verdict"),
        },
        "gate_status": "passed_all_metrics" if gate_pass else "blocked_or_failed_metric",
        "advance_allowed": gate_pass,
        "blockers": blockers,
    }


def _normal_metric(value: Any) -> float | None:
    if not isinstance(value, (int, float)):
        return None
    value = float(value)
    if not math.isfinite(value):
        return None
    if value > 1.0:
        value = value / 100.0
    if value < 0.0 or value > 1.0:
        return None
    return value


def _composite(metrics: dict[str, Any]) -> float | None:
    total = 0.0
    for key, weight in PHASE_E_WEIGHTS.items():
        value = _normal_metric(metrics.get(key))
        if value is None:
            return None
        total += value * weight
    return round(total, 6)


def _nonempty_str(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _evidence_path_exists(value: str) -> bool:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = REPO / path
    return path.exists()


def _parse_utc_datetime(value: str) -> datetime | None:
    try:
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _phase_e_row_validation_errors(row: Any) -> list[str]:
    if not isinstance(row, dict):
        return ["row_not_object"]

    errors: list[str] = []
    if row.get("schema") != PHASE_E_ROW_SCHEMA:
        errors.append("missing_or_invalid_schema")
    if row.get("template_only") is True or row.get("replace_before_use") is True:
        errors.append("template_row_not_measurement")

    for key in ("measurement_window_id", "engagement_id", "pair_id"):
        if not _nonempty_str(row.get(key)):
            errors.append(f"missing_{key}")

    observed_at = row.get("outcome_observed_at_utc")
    if not _nonempty_str(observed_at):
        errors.append("missing_outcome_observed_at_utc")
    else:
        parsed_observed_at = _parse_utc_datetime(observed_at)
        if parsed_observed_at is None:
            errors.append("invalid_outcome_observed_at_utc")
        elif parsed_observed_at < PHASE_E_MIN_OUTCOME_OBSERVED_AT_UTC:
            errors.append("historical_outcome_not_phase_e")

    if row.get("cohort") not in {"A", "B"}:
        errors.append("invalid_cohort")

    metrics = row.get("metrics")
    if not isinstance(metrics, dict):
        errors.append("missing_metrics")
    else:
        for key in PHASE_E_REQUIRED_METRICS:
            if key not in metrics:
                errors.append(f"missing_metric_{key}")
            elif _normal_metric(metrics.get(key)) is None:
                errors.append(f"invalid_metric_{key}")

    evidence_paths = row.get("evidence_paths")
    if not isinstance(evidence_paths, list) or not any(
        _nonempty_str(item) for item in evidence_paths
    ):
        errors.append("missing_evidence_paths")
    elif any(not _nonempty_str(item) for item in evidence_paths):
        errors.append("invalid_evidence_path")
    else:
        missing_evidence = [
            item
            for item in evidence_paths
            if _nonempty_str(item) and not _evidence_path_exists(item)
        ]
        if missing_evidence:
            errors.append("missing_evidence_path")

    return errors


def phase_e_measurement(
    *,
    rows_path: Path | None,
    prqs_path: Path,
    required_engagements: int = PHASE_E_REQUIRED_ENGAGEMENTS,
) -> dict[str, Any]:
    rows = _read_jsonl(rows_path) if rows_path is not None else []
    by_pair: dict[str, dict[str, dict[str, Any]]] = {}
    invalid_rows: list[dict[str, Any]] = []
    for idx, row in enumerate(rows, start=1):
        errors = _phase_e_row_validation_errors(row)
        line_info: dict[str, Any] = {"line": idx}
        if isinstance(row, dict):
            if row.get("pair_id"):
                line_info["pair_id"] = row.get("pair_id")
            if row.get("cohort"):
                line_info["cohort"] = row.get("cohort")
        if errors:
            invalid_rows.append({**line_info, "errors": errors})
            continue
        assert isinstance(row, dict)
        pair_id = str(row["pair_id"])
        cohort = str(row["cohort"])
        metrics = row["metrics"]
        composite = _composite(metrics)
        if composite is None:
            invalid_rows.append({**line_info, "errors": ["missing_or_invalid_metric"]})
            continue
        cohort_map = by_pair.setdefault(pair_id, {})
        if cohort in cohort_map:
            invalid_rows.append({**line_info, "errors": ["duplicate_pair_cohort"]})
            continue
        enriched = dict(row)
        enriched["composite_score"] = composite
        cohort_map[cohort] = enriched

    matched_pairs: list[dict[str, Any]] = []
    matched_engagement_ids: set[str] = set()
    unmatched_pairs: list[dict[str, Any]] = []
    mismatched_engagement_pairs: list[dict[str, Any]] = []
    for pair_id in sorted(by_pair):
        cohort_map = by_pair[pair_id]
        if "A" not in cohort_map or "B" not in cohort_map:
            unmatched_pairs.append({
                "pair_id": pair_id,
                "cohorts_present": sorted(cohort_map),
                "reason": "missing_required_a_b_pair",
            })
            continue
        engagement_a = str(cohort_map["A"]["engagement_id"])
        engagement_b = str(cohort_map["B"]["engagement_id"])
        if engagement_a != engagement_b:
            mismatched_engagement_pairs.append({
                "pair_id": pair_id,
                "cohort_a_engagement_id": engagement_a,
                "cohort_b_engagement_id": engagement_b,
            })
            continue
        score_a = cohort_map["A"]["composite_score"]
        score_b = cohort_map["B"]["composite_score"]
        matched_pairs.append({
            "pair_id": pair_id,
            "engagement_id": engagement_a,
            "cohort_a_composite": score_a,
            "cohort_b_composite": score_b,
            "delta_a_minus_b": round(score_a - score_b, 6),
        })
        matched_engagement_ids.add(engagement_a)

    comparator = (_read_json(prqs_path).get("comparator") or {}) if prqs_path.is_file() else {}
    deltas = [row["delta_a_minus_b"] for row in matched_pairs]
    avg_delta = round(sum(deltas) / len(deltas), 6) if deltas else None
    observed_engagement_count = len(matched_engagement_ids)
    required_matched_ab_row_count = required_engagements * 2
    valid_matched_ab_row_count = len(matched_pairs) * 2
    blockers: list[str] = []
    if len(matched_pairs) < required_engagements or observed_engagement_count < required_engagements:
        blockers.append("phase_e_requires_4_future_matched_engagements")
    if not rows:
        blockers.append("no_phase_e_ab_outcome_rows_present")
    if invalid_rows:
        blockers.append("invalid_phase_e_rows_present")
    if unmatched_pairs:
        blockers.append("unmatched_phase_e_pairs_present")
    if mismatched_engagement_pairs:
        blockers.append("mismatched_phase_e_engagement_pairs_present")

    measurement_ready = (
        len(matched_pairs) >= required_engagements
        and observed_engagement_count >= required_engagements
        and not invalid_rows
        and not unmatched_pairs
        and not mismatched_engagement_pairs
    )
    production_readiness_status = (
        "eligible_for_production_readiness_review"
        if measurement_ready
        else "blocked_missing_future_matched_ab_engagement_rows"
    )

    return {
        "schema": "auditooor.phase_e_ab_dogfood_measurement.v1",
        "policy": {
            "measurement_only": True,
            "required_future_engagements": required_engagements,
            "cohort_a": "full hacker-brain (P1-P5 + existing stack)",
            "cohort_b": "existing stack only",
            "composite_weights": PHASE_E_WEIGHTS,
            "row_schema": PHASE_E_ROW_SCHEMA,
            "row_schema_path": _rel(PHASE_E_ROW_SCHEMA_PATH),
            "minimum_outcome_observed_at_utc": PHASE_E_MIN_OUTCOME_OBSERVED_AT_UTC.strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
            "template_rows_rejected": True,
            "evidence_paths_must_exist": True,
            "required_matched_ab_row_count": required_matched_ab_row_count,
        },
        "inputs": {
            "phase_e_rows": _rel(rows_path) if rows_path else None,
            "prqs_proxy_comparator": _rel(prqs_path),
        },
        "observed": {
            "row_count": len(rows),
            "valid_matched_pair_count": len(matched_pairs),
            "valid_matched_ab_row_count": valid_matched_ab_row_count,
            "observed_engagement_count": observed_engagement_count,
            "average_composite_delta_a_minus_b": avg_delta,
            "matched_pairs": matched_pairs,
            "invalid_rows": invalid_rows,
            "unmatched_pairs": unmatched_pairs,
            "mismatched_engagement_pairs": mismatched_engagement_pairs,
        },
        "prqs_dogfood_proxy": {
            "matched_pair_count": comparator.get("matched_pair_count"),
            "cohort_a_average_score": (comparator.get("cohort_a") or {}).get("average_score"),
            "cohort_b_average_score": (comparator.get("cohort_b") or {}).get("average_score"),
            "average_delta_a_minus_b": comparator.get("average_delta_a_minus_b"),
            "max_pair_regression_drop_points": comparator.get("max_pair_regression_drop_points"),
            "scope": "PRQS-only Phase B dogfood proxy; not a Phase E composite decision.",
        },
        "verdict": "phase_e_measurement_ready" if measurement_ready else "insufficient_phase_e_data_prqs_proxy_only",
        "production_readiness_status": production_readiness_status,
        "blockers": blockers,
    }


def render_markdown(summary: dict[str, Any]) -> str:
    phase_b = summary["phase_b_gate"]
    phase_e = summary["phase_e_ab_dogfood"]
    p1 = phase_b["p1_citation_rate"]
    p3 = phase_b["p3_tp_poc_pass"]
    prqs = phase_b["prqs_regression"]
    proxy = phase_e["prqs_dogfood_proxy"]
    lines = [
        "# Phase B Gate + Phase E Measurement",
        "",
        f"- schema: `{summary['schema']}`",
        f"- generated_at_utc: `{summary['generated_at_utc']}`",
        f"- scope: `{summary['scope']}`",
        "",
        "## Phase B Gate #1",
        "",
        f"- gate_status: `{phase_b['gate_status']}`",
        f"- advance_allowed: `{str(phase_b['advance_allowed']).lower()}`",
        f"- P1 strict draft citation rate: `{p1['strict_draft_citation_rate_pct']}%` ({p1['cited_candidate_count']}/{p1['eligible_candidate_count']})",
        f"- P1 accepted-or-cited grounding rate: `{p1['accepted_or_cited_grounding_rate_pct']}%` ({p1['accepted_candidate_count'] + p1['cited_candidate_count']}/{p1['eligible_candidate_count']})",
        f"- P1 suggested-only rate: `{p1['suggested_only_rate_pct']}%` ({p1['suggested_candidate_count']}/{p1['eligible_candidate_count']})",
        f"- P3 TP-PoC-PASS conversion: `{p3['tp_poc_pass_rate_pct']}%` ({p3['poc_pass_count']}/{p3['tp_evidence_count']})",
        f"- PRQS regression: max drop `{prqs['max_pair_regression_drop_points']}` over `{prqs['matched_pair_count']}` pairs; A avg `{prqs['cohort_a_average_score']}`, B avg `{prqs['cohort_b_average_score']}`",
        "",
        "## Phase E A/B Dogfood",
        "",
        f"- verdict: `{phase_e['verdict']}`",
        f"- production readiness: `{phase_e['production_readiness_status']}`",
        f"- observed matched pairs: `{phase_e['observed']['valid_matched_pair_count']}`",
        f"- observed matched A/B rows: `{phase_e['observed']['valid_matched_ab_row_count']}` / `{phase_e['policy']['required_matched_ab_row_count']}`",
        f"- observed engagements: `{phase_e['observed']['observed_engagement_count']}` / `{phase_e['policy']['required_future_engagements']}`",
        f"- invalid rows: `{len(phase_e['observed']['invalid_rows'])}`",
        f"- unmatched pairs: `{len(phase_e['observed']['unmatched_pairs'])}`",
        f"- composite average delta A-B: `{_display(phase_e['observed']['average_composite_delta_a_minus_b'])}`",
        f"- row schema: `{phase_e['policy']['row_schema']}`",
        f"- PRQS dogfood proxy: `{proxy['matched_pair_count']}` pairs, avg delta `{proxy['average_delta_a_minus_b']}`, max regression drop `{proxy['max_pair_regression_drop_points']}`",
        "",
        "## Blockers",
        "",
    ]
    blockers = [f"Phase B: {item}" for item in phase_b["blockers"]]
    blockers.extend(f"Phase E: {item}" for item in phase_e["blockers"])
    if blockers:
        lines.extend(f"- `{item}`" for item in blockers)
    else:
        lines.append("- none")
    lines.extend([
        "",
        "## Inputs",
        "",
        f"- P1: `{phase_b['inputs']['p1_candidate_triage']}`",
        f"- P3: `{phase_b['inputs']['p3_tp_poc_pass_measurement']}`",
        f"- PRQS: `{phase_b['inputs']['prqs_comparator']}`",
        f"- Phase E rows: `{phase_e['inputs']['phase_e_rows'] or 'none'}`",
    ])
    return "\n".join(lines).rstrip() + "\n"


def build_summary(args: argparse.Namespace) -> dict[str, Any]:
    p1_path = Path(args.p1_triage).expanduser().resolve()
    p3_path = Path(args.p3_measurement).expanduser().resolve()
    prqs_path = Path(args.prqs_comparator).expanduser().resolve()
    phase_e_rows = Path(args.phase_e_rows).expanduser().resolve() if args.phase_e_rows else None
    phase_b = phase_b_metrics(p1_path=p1_path, p3_path=p3_path, prqs_path=prqs_path)
    phase_e = phase_e_measurement(rows_path=phase_e_rows, prqs_path=prqs_path)
    return {
        "schema": SCHEMA,
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope": "measurement-only; reads existing artifacts; no detector/capability execution",
        "phase_b_gate": phase_b,
        "phase_e_ab_dogfood": phase_e,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Report Phase B Gate and Phase E A/B measurement state.")
    parser.add_argument("--p1-triage", default=str(default_p1_path()), help="P1 candidate triage dogfood JSON.")
    parser.add_argument("--p3-measurement", default=str(default_p3_path()), help="P3 TP-PoC-PASS measurement JSON.")
    parser.add_argument("--prqs-comparator", default=str(DEFAULT_PRQS), help="PRQS comparator summary JSON.")
    parser.add_argument("--phase-e-rows", default=None, help="Optional Phase E A/B dogfood JSONL rows.")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Directory for measurement_summary.json/md.")
    parser.add_argument("--json", action="store_true", help="Print the full JSON summary.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    out_dir = Path(args.output_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    summary = build_summary(args)
    (out_dir / "measurement_summary.json").write_text(
        json.dumps(summary, allow_nan=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (out_dir / "measurement_summary.md").write_text(render_markdown(summary), encoding="utf-8")
    if args.json:
        print(json.dumps(summary, allow_nan=False, indent=2, sort_keys=True))
    else:
        print(json.dumps({
            "phase_b_gate_status": summary["phase_b_gate"]["gate_status"],
            "phase_e_production_readiness_status": summary["phase_e_ab_dogfood"][
                "production_readiness_status"
            ],
            "phase_e_verdict": summary["phase_e_ab_dogfood"]["verdict"],
            "summary": _rel(out_dir / "measurement_summary.json"),
        }, allow_nan=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
