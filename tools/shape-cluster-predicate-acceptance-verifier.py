#!/usr/bin/env python3
"""Verify Phase II.17 shape-cluster predicate distillation acceptance evidence.

Hermetic checker: reads an existing batch-shape summary, predicate candidate
JSONL, and one or more live-target report JSON files. It does not run source
mining, providers, network calls, or live-target generation.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.phase_ii17.shape_cluster_acceptance_verifier.v1"
DEFAULT_SUMMARY_JSON = (
    Path(__file__).resolve().parents[1]
    / "reports"
    / "v3_iter_2026-05-25"
    / "lane_II17_PARENT_BATCH_SHAPE_CLUSTER"
    / "summary.json"
)
DEFAULT_PREDICATES_JSONL = DEFAULT_SUMMARY_JSON.with_name("predicate_candidates.jsonl")
DEFAULT_TARGET_THRESHOLDS = {
    "hyperbridge": 3,
    "morpho": 5,
    "centrifuge": 5,
    "centrifuge-v3": 5,
}


def _read_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected JSON object")
    return data


def _iter_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line_no, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSONL: {exc}") from exc
            if isinstance(data, dict):
                rows.append(data)
    return rows


def _is_rejected_candidate(row: dict[str, Any]) -> bool:
    status = str(
        row.get("candidate_status")
        or row.get("validation_status")
        or row.get("status")
        or ""
    ).lower()
    return any(token in status for token in ("reject", "fail", "invalid"))


def _summary_value(payload: dict[str, Any], *path: str, default: Any = None) -> Any:
    current: Any = payload
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current


def _semantic_count(report: dict[str, Any]) -> int:
    count = _summary_value(
        report,
        "summary_card",
        "composability",
        "p1_match_tier_counts",
        "SEMANTIC-MATCH",
    )
    if isinstance(count, int):
        return count
    rows = report.get("entry_points")
    if not isinstance(rows, list):
        rows = report.get("prioritized_hunt_list")
    if not isinstance(rows, list):
        return 0
    return sum(
        1
        for row in rows
        if isinstance(row, dict)
        and str(row.get("p1_match_tier") or "").upper() == "SEMANTIC-MATCH"
    )


def _shape_match_count(report: dict[str, Any]) -> int:
    count = _summary_value(
        report,
        "summary_card",
        "composability",
        "shape_cluster_predicate_semantic_matches",
    )
    if isinstance(count, int):
        return count
    rows = report.get("entry_points")
    if not isinstance(rows, list):
        return 0
    total = 0
    for row in rows:
        if isinstance(row, dict) and isinstance(row.get("shape_cluster_predicate_matches"), list):
            total += len(row["shape_cluster_predicate_matches"])
    return total


def _entry_point_count(report: dict[str, Any]) -> int:
    rows = report.get("entry_points")
    if isinstance(rows, list):
        return len(rows)
    rows = report.get("prioritized_hunt_list")
    return len(rows) if isinstance(rows, list) else 0


def _parse_target(raw: str) -> tuple[str, int, Path]:
    parts = raw.split(":", 2)
    if len(parts) != 3:
        raise argparse.ArgumentTypeError(
            "--target must be formatted as name:semantic_threshold:/path/report.json"
        )
    name, threshold_raw, path_raw = parts
    name = name.strip()
    if not name:
        raise argparse.ArgumentTypeError("--target name cannot be empty")
    try:
        threshold = int(threshold_raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("--target semantic_threshold must be an integer") from exc
    if threshold < 0:
        raise argparse.ArgumentTypeError("--target semantic_threshold must be non-negative")
    return name, threshold, Path(path_raw)


def _distillation_checks(summary: dict[str, Any], predicate_rows: list[dict[str, Any]]) -> dict[str, Any]:
    clusters = summary.get("clusters") if isinstance(summary.get("clusters"), dict) else {}
    constraints = summary.get("constraints") if isinstance(summary.get("constraints"), dict) else {}
    annotation = summary.get("annotation") if isinstance(summary.get("annotation"), dict) else {}
    emitted = clusters.get("emitted_candidate_rows", clusters.get("selected_predicate_count"))
    non_rejected = [row for row in predicate_rows if not _is_rejected_candidate(row)]
    checks = {
        "summary_schema_ok": str(summary.get("schema") or "").endswith(".summary"),
        "uses_existing_index_only": (
            annotation.get("annotation_method")
            == "batch-join-existing-jsonl-index-no-record-mining"
        ),
        "no_network_or_provider": (
            constraints.get("network") is False
            and constraints.get("provider_calls") is False
            and constraints.get("per_record_mining") is False
        ),
        "cluster_key_excludes_attack_class": constraints.get("cluster_key_excludes_attack_class") is True,
        "target_coverage_reached": clusters.get("target_coverage_reached") is True,
        "predicate_jsonl_count_matches_summary": emitted == len(predicate_rows),
        "has_live_target_eligible_candidates": bool(non_rejected),
    }
    return {
        "checks": checks,
        "passed": all(checks.values()),
        "annotation_rows": annotation.get("annotation_rows", 0),
        "cluster_count": clusters.get("cluster_count", 0),
        "selected_annotation_coverage": clusters.get("selected_annotation_coverage", 0.0),
        "selected_predicate_count": clusters.get("selected_predicate_count", 0),
        "emitted_candidate_rows": clusters.get("emitted_candidate_rows", len(predicate_rows)),
        "candidate_jsonl_rows": len(predicate_rows),
        "live_target_eligible_candidate_rows": len(non_rejected),
        "full_validation_pass_count": clusters.get("full_validation_pass_count", 0),
        "out_of_cluster_zero_fp_pass_count": clusters.get("out_of_cluster_zero_fp_pass_count", 0),
    }


def build_payload(
    *,
    summary_json: Path,
    predicates_jsonl: Path,
    targets: list[tuple[str, int, Path]],
) -> dict[str, Any]:
    summary = _read_json(summary_json)
    predicate_rows = _iter_jsonl(predicates_jsonl)
    distillation = _distillation_checks(summary, predicate_rows)
    target_results: dict[str, Any] = {}
    for name, threshold, path in targets:
        if not path.is_file():
            target_results[name] = {
                "path": str(path),
                "status": "missing-report",
                "semantic_required": threshold,
                "semantic_observed": 0,
                "semantic_missing": threshold,
                "shape_cluster_predicate_semantic_matches": 0,
                "shape_evidence_gap": "report-missing",
                "passed": False,
            }
            continue
        report = _read_json(path)
        semantic = _semantic_count(report)
        shape_matches = _shape_match_count(report)
        target_results[name] = {
            "path": str(path),
            "status": "ok",
            "entry_point_rows": _entry_point_count(report),
            "semantic_required": threshold,
            "semantic_observed": semantic,
            "semantic_missing": max(0, threshold - semantic),
            "shape_cluster_predicate_semantic_matches": shape_matches,
            "shape_evidence_gap": (
                "none" if shape_matches > 0 else "no-shape-cluster-predicate-semantic-match"
            ),
            "passed": semantic >= threshold,
        }
    return {
        "schema": SCHEMA,
        "summary_json": str(summary_json),
        "predicates_jsonl": str(predicates_jsonl),
        "distillation": distillation,
        "targets": target_results,
        "passed": distillation["passed"] and all(
            target.get("passed") for target in target_results.values()
        ),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary-json", default=str(DEFAULT_SUMMARY_JSON))
    parser.add_argument("--predicates-jsonl", default=str(DEFAULT_PREDICATES_JSONL))
    parser.add_argument(
        "--target",
        action="append",
        type=_parse_target,
        default=[],
        help="Repeatable: name:semantic_threshold:/path/live-target-report.json",
    )
    parser.add_argument("--output-json", help="Optional path for verifier JSON.")
    return parser.parse_args(argv)


def _print_human(payload: dict[str, Any]) -> None:
    dist = payload["distillation"]
    print("distillation:", "PASS" if dist["passed"] else "FAIL")
    print(
        "  candidates:",
        dist["candidate_jsonl_rows"],
        "eligible:",
        dist["live_target_eligible_candidate_rows"],
        "coverage:",
        f"{float(dist['selected_annotation_coverage']):.4f}",
    )
    for name, target in payload["targets"].items():
        print(
            f"{name}:",
            "PASS" if target["passed"] else "FAIL",
            f"semantic={target['semantic_observed']}/{target['semantic_required']}",
            f"missing={target['semantic_missing']}",
            f"shape_matches={target['shape_cluster_predicate_semantic_matches']}",
            f"shape_gap={target['shape_evidence_gap']}",
        )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    targets = args.target
    payload = build_payload(
        summary_json=Path(args.summary_json),
        predicates_jsonl=Path(args.predicates_jsonl),
        targets=targets,
    )
    text = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output_json:
        out = Path(args.output_json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
    else:
        _print_human(payload)
    return 0 if payload["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
