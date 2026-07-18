#!/usr/bin/env python3
"""Build an outcome-calibration scorecard and concrete follow-up queue.

This is the bridge between "provider routing is advisory-only" and "what
should we verify next?". It reads existing outcome telemetry, triager feedback
patterns, provider/local verification artifacts, the LLM calibration seed, and
known-limitation rows, then emits a bounded queue of local/operator actions.

It never invents acceptance or rejection outcomes. Resolved outcome rows are
only copied from telemetry; provider/local rows become calibration candidates
that still require a terminal local adjudication before they can be logged into
``tools/calibration/llm_calibration_log.jsonl``.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Sequence

from outcome_semantics import (
    LEARNING_SCOPE_PLATFORM_BASE_RATE_ONLY,
    derive_outcome_semantics,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SEED = ROOT / "reference" / "llm_calibration_seed.json"
DEFAULT_PROVIDER_VERIFICATION = ROOT / ".audit_logs" / "pr560_worker_av" / "provider_result_local_verification.json"
DEFAULT_PROVIDER_QUEUE = ROOT / ".audit_logs" / "pr560_worker_at" / "local_provider_verification_queue.json"
DEFAULT_TRIAGER_PATTERNS = ROOT / "reference" / "triager_patterns.json"
DEFAULT_KNOWN_LIMITATIONS = ROOT / "docs" / "KNOWN_LIMITATIONS_BURNDOWN_MAP.json"
DEFAULT_TERMINAL_ROWS = ROOT / ".audit_logs" / "outcome_calibration" / "outcome_calibration_terminal_rows.jsonl"
DEFAULT_RESOLVED_LINKAGE_VALIDATION = ROOT / ".audit_logs" / "outcome_calibration" / "outcome_calibration_resolved_linkage_validation.json"
DEFAULT_OUT_JSON = ROOT / ".audit_logs" / "outcome_calibration" / "outcome_calibration_scorecard.json"
DEFAULT_OUT_MD = ROOT / ".audit_logs" / "outcome_calibration" / "outcome_calibration_scorecard.md"

RESOLVED_OUTCOMES = {"accepted", "duplicate", "rejected"}
LINKAGE_FIELDS = (
    "lane",
    "model_route",
    "proof_artifact",
    "production_path_status",
    "production_path_blockers_cleared",
    "final_triager_outcome",
)
PROVIDER_TASK_MAP = {
    "kimi": "source-extraction",
    "minimax": "adversarial-kill",
}


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _read_json_if_exists(path: Path) -> Any:
    if not path.is_file():
        return None
    return _read_json(path)


def _safe_str(value: Any) -> str:
    return str(value).strip() if value is not None else ""


def _portable(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT.resolve()))
    except ValueError:
        return str(path)


def _records_from_outcome_payload(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        return []
    records = payload.get("records")
    return [row for row in records if isinstance(row, dict)] if isinstance(records, list) else []


def _record_learning_scope(row: dict[str, Any]) -> str:
    semantics = derive_outcome_semantics(row)
    if semantics.learning_scope == LEARNING_SCOPE_PLATFORM_BASE_RATE_ONLY:
        return semantics.learning_scope
    scope = _safe_str(row.get("learning_scope"))
    if scope:
        return scope
    return semantics.learning_scope


def _eligible_for_calibration_learning(row: dict[str, Any]) -> bool:
    return _record_learning_scope(row) != LEARNING_SCOPE_PLATFORM_BASE_RATE_ONLY


def _load_outcome_records(paths: Sequence[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in paths:
        payload = _read_json_if_exists(path)
        rows.extend(_records_from_outcome_payload(payload))
    return rows


def _read_jsonl_if_exists(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def _terminal_key(row: dict[str, Any]) -> tuple[str, str, str]:
    return (
        _safe_str(row.get("workspace")).lower(),
        _safe_str(row.get("finding_id")).lower(),
        _safe_str(row.get("title")).lower(),
    )


def _terminal_row_records(paths: Sequence[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in paths:
        for row in _read_jsonl_if_exists(path):
            if row.get("schema") == "auditooor.outcome_calibration_terminal_row.v1":
                rows.append(row)
    return rows


def _terminal_rows_by_key(rows: Sequence[dict[str, Any]]) -> dict[tuple[str, str, str], dict[str, Any]]:
    keyed: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        keys = [_terminal_key(row)]
        report_id = _safe_str(row.get("report_id"))
        workspace = _safe_str(row.get("workspace")).lower()
        finding_id = _safe_str(row.get("finding_id")).lower()
        if report_id:
            keys.append((workspace, report_id.lower(), ""))
        if finding_id and finding_id != "unknown":
            keys.append((workspace, finding_id, ""))
        if finding_id == "unknown" and not _safe_str(row.get("title")):
            keys.append((workspace, "", ""))
        for key in keys:
            if any(key):
                keyed[key] = row
    return keyed


def _terminal_row_for_record(record: dict[str, Any], keyed: dict[tuple[str, str, str], dict[str, Any]]) -> dict[str, Any] | None:
    workspace = _safe_str(record.get("workspace")).lower()
    finding_id = _safe_str(record.get("finding_id")).lower()
    title = _safe_str(record.get("title")).lower()
    for key in (
        (workspace, finding_id, title),
        (workspace, finding_id, ""),
        (workspace, f"poly-{finding_id}", ""),
        (workspace, f"poly-cantina-{finding_id}", ""),
        (workspace, "", title),
        (workspace, "", ""),
    ):
        if key in keyed:
            return keyed[key]
    return None


def _provider_name_from_output(path_text: str) -> str:
    lowered = path_text.lower()
    for provider in PROVIDER_TASK_MAP:
        if f".{provider}." in lowered or f"/{provider}/" in lowered:
            return provider
    return ""


def _providers_from_verification_row(row: dict[str, Any]) -> list[str]:
    outputs = row.get("provider_outputs")
    providers: list[str] = []
    if isinstance(outputs, dict):
        for provider, path_text in outputs.items():
            if provider in PROVIDER_TASK_MAP and _safe_str(path_text):
                providers.append(provider)
    if providers:
        return sorted(set(providers))
    for path_text in row.get("provider_outputs", {}).values() if isinstance(row.get("provider_outputs"), dict) else []:
        provider = _provider_name_from_output(_safe_str(path_text))
        if provider:
            providers.append(provider)
    return sorted(set(providers))


def _seed_rows(seed_path: Path) -> list[dict[str, Any]]:
    payload = _read_json_if_exists(seed_path)
    if not isinstance(payload, dict):
        return []
    rows = payload.get("rows")
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def _route_status(row: dict[str, Any], *, min_samples: int, min_precision_pct: float) -> str:
    samples = int(row.get("sample_count") or 0)
    precision = row.get("precision_pct")
    if samples < min_samples or precision in (None, "", "insufficient-data"):
        return "needs_samples"
    try:
        precision_value = float(precision)
    except (TypeError, ValueError):
        return "needs_samples"
    if precision_value < min_precision_pct:
        return "below_precision_floor"
    return "primary_ready"


def _outcome_linkage_items(
    records: Sequence[dict[str, Any]],
    limit: int,
    *,
    terminal_rows: dict[tuple[str, str, str], dict[str, Any]],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for record in records:
        outcome = _safe_str(record.get("outcome"))
        if outcome not in RESOLVED_OUTCOMES:
            continue
        if not _eligible_for_calibration_learning(record):
            continue
        missing = [
            field for field in LINKAGE_FIELDS
            if not _safe_str(record.get(field))
        ]
        if not missing and record.get("outcome_row_present") is True:
            continue
        terminal_row = _terminal_row_for_record(record, terminal_rows)
        if terminal_row:
            item_id = f"OCQ-OUT-{len(items) + 1:03d}"
            finding_id = _safe_str(record.get("finding_id")) or _safe_str(terminal_row.get("finding_id")) or "unknown"
            items.append({
                "item_id": item_id,
                "queue_type": "outcome_linkage_terminalized_missing_linkage",
                "priority": 9,
                "workspace": _safe_str(record.get("workspace")) or _safe_str(terminal_row.get("workspace")),
                "finding_id": finding_id,
                "report_id": _safe_str(terminal_row.get("report_id")),
                "title": _safe_str(record.get("title")),
                "known_outcome": outcome,
                "missing_fields": missing,
                "terminal_row_status": _safe_str(terminal_row.get("terminal_row_status")),
                "terminal_row_artifact": ".audit_logs/outcome_calibration/outcome_calibration_terminal_rows.jsonl",
                "invented_outcome": False,
                "next_command": "do not fabricate linkage; record a new platform/proof linkage row only if real evidence appears",
                "stop_condition": "missing linkage is terminalized with durable evidence and cannot be counted as linked calibration",
            })
            if len(items) >= limit:
                break
            continue
        item_id = f"OCQ-OUT-{len(items) + 1:03d}"
        finding_id = _safe_str(record.get("finding_id")) or "unknown"
        items.append({
            "item_id": item_id,
            "queue_type": "outcome_linkage_backfill",
            "priority": 10 + len(missing),
            "workspace": _safe_str(record.get("workspace")),
            "finding_id": finding_id,
            "title": _safe_str(record.get("title")),
            "known_outcome": outcome,
            "missing_fields": missing,
            "invented_outcome": False,
            "next_command": (
                "verify the platform/triager row, then run "
                f"make record-outcome WS=<workspace> ID={finding_id} STATE={outcome} "
                "with lane/model_route/proof_artifact linkage in reference/outcomes.jsonl"
            ),
            "stop_condition": "resolved row has final_triager_outcome plus lane/model_route/proof_artifact linkage",
        })
        if len(items) >= limit:
            break
    return items


def _provider_terminal_items(provider_verification: dict[str, Any] | None, limit: int) -> list[dict[str, Any]]:
    if not isinstance(provider_verification, dict):
        return []
    rows = [row for row in provider_verification.get("rows", []) if isinstance(row, dict)]
    status_rank = {
        "source_symbol_confirmed": 8,
        "repo_grep_confirmed": 7,
        "source_file_confirmed": 6,
        "no_local_evidence": 5,
        "off_repo_source": 4,
    }
    rows = sorted(rows, key=lambda row: status_rank.get(_safe_str(row.get("local_status")), 0), reverse=True)
    items: list[dict[str, Any]] = []
    for row in rows:
        providers = _providers_from_verification_row(row) or ["provider"]
        for provider in providers:
            task_type = PROVIDER_TASK_MAP.get(provider, "source-extraction")
            item_id = f"OCQ-PROV-{len(items) + 1:03d}"
            local_status = _safe_str(row.get("local_status"))
            classifications = [str(v) for v in row.get("classifications", []) if v]
            items.append({
                "item_id": item_id,
                "queue_type": "provider_local_terminal_adjudication",
                "priority": 8 if local_status in {"source_symbol_confirmed", "repo_grep_confirmed"} else 5,
                "provider": provider,
                "task_type": task_type,
                "task_id": _safe_str(row.get("task_id")),
                "local_status": local_status,
                "classifications": classifications,
                "local_check_count": int(row.get("local_check_count") or 0),
                "calibration_log_ready": False,
                "invented_outcome": False,
                "next_command": (
                    "complete local adjudication; only after TRUE/FALSE/PARTIAL is proven, "
                    f"append with python3 tools/llm-calibration-log.py log {provider} {task_type} "
                    f"{_safe_str(row.get('task_id')) or '<task-ref>'} <VERDICT> --evidence '<local artifact>'"
                ),
                "stop_condition": "provider claim has a terminal local verdict and linked evidence artifact",
            })
            if len(items) >= limit:
                return items
    return items


def _route_seed_items(seed_rows: Sequence[dict[str, Any]], *, min_samples: int, min_precision_pct: float) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for row in seed_rows:
        status = _route_status(row, min_samples=min_samples, min_precision_pct=min_precision_pct)
        if status == "primary_ready":
            continue
        provider = _safe_str(row.get("provider"))
        task_type = _safe_str(row.get("task_type"))
        samples = int(row.get("sample_count") or 0)
        items.append({
            "item_id": f"OCQ-ROUTE-{len(items) + 1:03d}",
            "queue_type": "routing_sample_gap",
            "priority": 6,
            "provider": provider,
            "task_type": task_type,
            "route_status": status,
            "sample_count": samples,
            "precision_pct": row.get("precision_pct"),
            "samples_needed": max(0, min_samples - samples),
            "invented_outcome": False,
            "next_command": (
                "use the provider/local adjudication queue to add verified TRUE/FALSE rows; "
                f"then refresh reference/llm_calibration_seed.json for {provider}/{task_type}"
            ),
            "stop_condition": f">= {min_samples} verified samples and precision >= {min_precision_pct:.0f}%",
        })
    return items


def _triager_feedback_items(records: Sequence[dict[str, Any]], patterns_path: Path) -> list[dict[str, Any]]:
    patterns = _read_json_if_exists(patterns_path)
    rejection_count = len(patterns.get("rejections", [])) if isinstance(patterns, dict) else 0
    acceptance_count = len(patterns.get("acceptances", [])) if isinstance(patterns, dict) else 0
    by_outcome = Counter(
        _safe_str(row.get("outcome"))
        for row in records
        if _eligible_for_calibration_learning(row)
    )
    items: list[dict[str, Any]] = []
    for outcome, pattern_bucket, count in (
        ("rejected", "rejections", rejection_count),
        ("accepted", "acceptances", acceptance_count),
        ("duplicate", "rejections", rejection_count),
    ):
        if by_outcome[outcome] <= 0:
            continue
        items.append({
            "item_id": f"OCQ-TRIAGE-{len(items) + 1:03d}",
            "queue_type": "triager_feedback_sync",
            "priority": 4,
            "outcome": outcome,
            "resolved_rows": by_outcome[outcome],
            "current_pattern_bucket": pattern_bucket,
            "current_pattern_count": count,
            "invented_outcome": False,
            "next_command": (
                "extract only real triager language from resolved reports, update "
                "reference/triager_patterns.md, then run python3 tools/triage-feedback-collector.py --sync-from-md"
            ),
            "stop_condition": "resolved triager rationale is represented as a reusable guard or acceptance lesson",
        })
    return items


def _known_limitation_items(path: Path) -> list[dict[str, Any]]:
    payload = _read_json_if_exists(path)
    if not isinstance(payload, dict):
        return []
    rows = [row for row in payload.get("rows", []) if isinstance(row, dict)]
    items: list[dict[str, Any]] = []
    for row in rows:
        blob = json.dumps(row, sort_keys=True).lower()
        if "outcome" not in blob and "calibration" not in blob and "triager" not in blob:
            continue
        if row.get("stop_condition_met") is True:
            continue
        items.append({
            "item_id": f"OCQ-LIMIT-{len(items) + 1:03d}",
            "queue_type": "known_limitation_route_adjustment",
            "priority": 3,
            "limitation_id": _safe_str(row.get("limitation_id")),
            "title": _safe_str(row.get("title")),
            "terminal_state": _safe_str(row.get("terminal_state")),
            "invented_outcome": False,
            "next_command": _safe_str(row.get("next_command")) or "run the limitation's owner command and attach outcome evidence",
            "stop_condition": _safe_str(row.get("stop_condition")),
        })
    return items


def _scorecard(
    seed_rows: Sequence[dict[str, Any]],
    provider_verification: dict[str, Any] | None,
    outcome_records: Sequence[dict[str, Any]],
    terminal_rows: dict[tuple[str, str, str], dict[str, Any]],
    resolved_linkage_validation: dict[str, Any] | None,
    *,
    min_samples: int,
    min_precision_pct: float,
) -> dict[str, Any]:
    provider_rows = provider_verification.get("rows", []) if isinstance(provider_verification, dict) else []
    provider_candidates: dict[tuple[str, str], int] = defaultdict(int)
    terminal_candidates: dict[tuple[str, str], int] = defaultdict(int)
    for row in provider_rows:
        for provider in _providers_from_verification_row(row) or []:
            key = (provider, PROVIDER_TASK_MAP.get(provider, "source-extraction"))
            provider_candidates[key] += 1
            if _safe_str(row.get("local_status")) in {"source_symbol_confirmed", "source_file_confirmed", "repo_grep_confirmed", "no_local_evidence", "off_repo_source"}:
                terminal_candidates[key] += 1
    route_rows = []
    for row in seed_rows:
        key = (_safe_str(row.get("provider")), _safe_str(row.get("task_type")))
        route_rows.append({
            "provider": key[0],
            "task_type": key[1],
            "sample_count": int(row.get("sample_count") or 0),
            "precision_pct": row.get("precision_pct"),
            "route_status": _route_status(row, min_samples=min_samples, min_precision_pct=min_precision_pct),
            "provider_local_candidates": provider_candidates.get(key, 0),
            "terminal_candidate_rows": terminal_candidates.get(key, 0),
        })
    resolved = [row for row in outcome_records if _safe_str(row.get("outcome")) in RESOLVED_OUTCOMES]
    calibration_eligible_resolved = [
        row for row in resolved if _eligible_for_calibration_learning(row)
    ]
    linked = [
        row for row in calibration_eligible_resolved
        if row.get("outcome_row_present") is True
        and all(_safe_str(row.get(field)) for field in LINKAGE_FIELDS)
    ]
    terminalized_missing = [
        row for row in calibration_eligible_resolved
        if row not in linked and _terminal_row_for_record(row, terminal_rows)
    ]
    validation_summary = (
        resolved_linkage_validation.get("summary", {})
        if isinstance(resolved_linkage_validation, dict)
        and resolved_linkage_validation.get("schema") == "auditooor.outcome_calibration_resolved_linkage_validator.v1"
        else {}
    )
    if validation_summary:
        eligible_count = len(calibration_eligible_resolved)
        linked_count = min(int(validation_summary.get("valid_linked_rows") or 0), eligible_count)
        terminalized_count = min(
            int(validation_summary.get("terminalized_missing_linkage_rows") or 0),
            max(eligible_count - linked_count, 0),
        )
        missing_count = min(
            int(validation_summary.get("missing_linkage_rows") or 0),
            max(eligible_count - linked_count - terminalized_count, 0),
        )
        linkage_validator_status = _safe_str(validation_summary.get("calibration_closure_status"))
    else:
        linked_count = len(linked)
        terminalized_count = len(terminalized_missing)
        missing_count = len(calibration_eligible_resolved) - linked_count - terminalized_count
        linkage_validator_status = "not_run"
    return {
        "routing_rows": route_rows,
        "outcome_rows": {
            "resolved": len(resolved),
            "calibration_eligible_resolved": len(calibration_eligible_resolved),
            "base_rate_only_resolved": len(resolved) - len(calibration_eligible_resolved),
            "linked_for_calibration": linked_count,
            "terminalized_missing_linkage": terminalized_count,
            "missing_linkage": missing_count,
            "by_outcome": dict(sorted(Counter(_safe_str(row.get("outcome")) for row in calibration_eligible_resolved).items())),
            "resolved_linkage_validator_status": linkage_validator_status,
            "resolved_linkage_validator_artifact": (
                _safe_str(resolved_linkage_validation.get("inputs", {}).get("linkage_jsonl"))
                if isinstance(resolved_linkage_validation, dict)
                else ""
            ),
        },
        "provider_local_verification": {
            "candidate_harvest_count": int(provider_verification.get("candidate_harvest_count") or 0) if isinstance(provider_verification, dict) else 0,
            "verified_row_count": int(provider_verification.get("verified_row_count") or 0) if isinstance(provider_verification, dict) else 0,
            "local_status_counts": provider_verification.get("local_status_counts", {}) if isinstance(provider_verification, dict) else {},
            "classification_counts": provider_verification.get("classification_counts", {}) if isinstance(provider_verification, dict) else {},
        },
    }


def build_scorecard(
    *,
    outcome_json: Sequence[Path],
    provider_verification_json: Path,
    provider_queue_json: Path,
    seed_json: Path,
    triager_patterns_json: Path,
    known_limitations_json: Path,
    terminal_rows_jsonl: Sequence[Path],
    resolved_linkage_validation_json: Path,
    limit: int,
    min_samples: int,
    min_precision_pct: float,
) -> dict[str, Any]:
    outcome_records = _load_outcome_records(outcome_json)
    terminal_row_records = _terminal_row_records(terminal_rows_jsonl)
    terminal_rows = _terminal_rows_by_key(terminal_row_records)
    resolved_linkage_validation = _read_json_if_exists(resolved_linkage_validation_json)
    provider_verification = _read_json_if_exists(provider_verification_json)
    provider_queue = _read_json_if_exists(provider_queue_json)
    seed_rows = _seed_rows(seed_json)

    items: list[dict[str, Any]] = []
    builders: list[Iterable[dict[str, Any]]] = [
        _outcome_linkage_items(outcome_records, limit, terminal_rows=terminal_rows),
        _provider_terminal_items(provider_verification, limit),
        _route_seed_items(seed_rows, min_samples=min_samples, min_precision_pct=min_precision_pct),
        _triager_feedback_items(outcome_records, triager_patterns_json),
        _known_limitation_items(known_limitations_json),
    ]
    for batch in builders:
        items.extend(batch)
    items = sorted(items, key=lambda item: (-int(item.get("priority") or 0), _safe_str(item.get("item_id"))))[:limit]
    for index, item in enumerate(items, start=1):
        item["rank"] = index

    summary = {
        "total_queue_items": len(items),
        "target_queue_items": limit,
        "invented_outcomes": 0,
        "inputs": {
            "outcome_json": [_portable(path) for path in outcome_json],
            "provider_verification_json": _portable(provider_verification_json),
            "provider_queue_json": _portable(provider_queue_json),
            "seed_json": _portable(seed_json),
            "triager_patterns_json": _portable(triager_patterns_json),
            "known_limitations_json": _portable(known_limitations_json),
            "terminal_rows_jsonl": [_portable(path) for path in terminal_rows_jsonl],
            "resolved_linkage_validation_json": _portable(resolved_linkage_validation_json),
        },
        "provider_queue_items": (
            int(provider_queue.get("summary", {}).get("total_queue_items") or 0)
            if isinstance(provider_queue, dict) else 0
        ),
        "terminal_rows_available": len(terminal_row_records),
        "queue_type_counts": dict(sorted(Counter(_safe_str(item.get("queue_type")) for item in items).items())),
    }
    scorecard = _scorecard(
        seed_rows,
        provider_verification,
        outcome_records,
        terminal_rows,
        resolved_linkage_validation if isinstance(resolved_linkage_validation, dict) else None,
        min_samples=min_samples,
        min_precision_pct=min_precision_pct,
    )
    outcome_rows = scorecard["outcome_rows"]
    outcome_rows["strict_linkage_fields"] = list(LINKAGE_FIELDS)
    outcome_rows["terminal_rows_available"] = len(terminal_row_records)
    outcome_rows["resolved_linkage_validation_available"] = isinstance(resolved_linkage_validation, dict)
    outcome_rows["all_resolved_rows_accounted_for"] = (
        int(outcome_rows["missing_linkage"]) == 0
        and int(outcome_rows["calibration_eligible_resolved"]) == int(outcome_rows["linked_for_calibration"]) + int(outcome_rows["terminalized_missing_linkage"])
    )
    outcome_rows["calibration_closure_status"] = (
        "closed_for_current_terminal_rows"
        if outcome_rows["all_resolved_rows_accounted_for"] and int(outcome_rows["linked_for_calibration"]) > 0
        else "terminalized_missing_linkage_not_calibration"
        if outcome_rows["all_resolved_rows_accounted_for"]
        else "open_missing_linkage"
    )
    return {
        "schema": "auditooor.outcome_calibration_scorecard.v1",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "advisory_only": True,
        "promotion_authority": False,
        "no_invented_acceptance_or_rejection": True,
        "summary": summary,
        "scorecard": scorecard,
        "queue": items,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    outcome_rows = payload["scorecard"]["outcome_rows"]
    lines = [
        "# Outcome Calibration Scorecard",
        "",
        "Concrete queue for turning real outcomes and local provider verification into calibrated routing evidence.",
        "",
        "No row invents an acceptance or rejection outcome. Provider/local rows stay advisory until terminal local evidence is recorded.",
        "",
        f"- queue items: `{summary['total_queue_items']}` / target `{summary['target_queue_items']}`",
        f"- invented outcomes: `{summary['invented_outcomes']}`",
        f"- advisory only: `{str(payload['advisory_only']).lower()}`",
        "",
        "## Routing Scorecard",
        "",
        "| Provider | Task Type | Samples | Precision | Status | Local Candidates |",
        "|---|---|---:|---|---|---:|",
    ]
    for row in payload["scorecard"]["routing_rows"]:
        lines.append(
            f"| `{row['provider']}` | `{row['task_type']}` | {row['sample_count']} | "
            f"{row['precision_pct']} | `{row['route_status']}` | {row['provider_local_candidates']} |"
        )
    lines.extend([
        "",
        "## Outcome Linkage",
        "",
        f"- resolved rows: `{outcome_rows.get('resolved', 0)}`",
        f"- calibration-eligible resolved rows: `{outcome_rows.get('calibration_eligible_resolved', outcome_rows.get('resolved', 0))}`",
        f"- base-rate-only resolved rows: `{outcome_rows.get('base_rate_only_resolved', 0)}`",
        f"- linked for calibration: `{outcome_rows.get('linked_for_calibration', 0)}`",
        f"- terminalized missing linkage: `{outcome_rows.get('terminalized_missing_linkage', 0)}`",
        f"- missing linkage: `{outcome_rows.get('missing_linkage', 0)}`",
        f"- terminal rows available: `{outcome_rows.get('terminal_rows_available', 0)}`",
        f"- resolved-linkage validator: `{outcome_rows.get('resolved_linkage_validator_status', 'not_run')}`",
        f"- calibration closure status: `{outcome_rows.get('calibration_closure_status', 'unknown')}`",
        "",
        "## Queue",
        "",
        "| Rank | Item | Type | Priority | Next Command |",
        "|---:|---|---|---:|---|",
    ])
    for item in payload["queue"]:
        command = _safe_str(item.get("next_command")).replace("|", "\\|")
        lines.append(
            f"| {item['rank']} | `{item['item_id']}` | `{item['queue_type']}` | "
            f"{item['priority']} | {command} |"
        )
    return "\n".join(lines) + "\n"


def write_outputs(payload: dict[str, Any], out_json: Path, out_md: Path | None) -> None:
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if out_md is not None:
        out_md.parent.mkdir(parents=True, exist_ok=True)
        out_md.write_text(render_markdown(payload), encoding="utf-8")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outcome-json", action="append", type=Path, default=[], help="Outcome telemetry JSON produced by tools/outcome-telemetry.py --json/--out; repeatable.")
    parser.add_argument("--provider-verification-json", type=Path, default=DEFAULT_PROVIDER_VERIFICATION)
    parser.add_argument("--provider-queue-json", type=Path, default=DEFAULT_PROVIDER_QUEUE)
    parser.add_argument("--seed-json", type=Path, default=DEFAULT_SEED)
    parser.add_argument("--triager-patterns-json", type=Path, default=DEFAULT_TRIAGER_PATTERNS)
    parser.add_argument("--known-limitations-json", type=Path, default=DEFAULT_KNOWN_LIMITATIONS)
    parser.add_argument("--terminal-rows-jsonl", action="append", type=Path, default=[DEFAULT_TERMINAL_ROWS], help="Terminal outcome-linkage rows proving missing linkage should not be fabricated; repeatable.")
    parser.add_argument("--resolved-linkage-validation-json", type=Path, default=DEFAULT_RESOLVED_LINKAGE_VALIDATION)
    parser.add_argument("--out-json", type=Path, default=DEFAULT_OUT_JSON)
    parser.add_argument("--out-md", type=Path, default=DEFAULT_OUT_MD)
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--min-samples", type=int, default=20)
    parser.add_argument("--min-precision-pct", type=float, default=70.0)
    parser.add_argument("--print-json", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    payload = build_scorecard(
        outcome_json=args.outcome_json,
        provider_verification_json=args.provider_verification_json,
        provider_queue_json=args.provider_queue_json,
        seed_json=args.seed_json,
        triager_patterns_json=args.triager_patterns_json,
        known_limitations_json=args.known_limitations_json,
        terminal_rows_jsonl=args.terminal_rows_jsonl,
        resolved_linkage_validation_json=args.resolved_linkage_validation_json,
        limit=args.limit,
        min_samples=args.min_samples,
        min_precision_pct=args.min_precision_pct,
    )
    write_outputs(payload, args.out_json, args.out_md)
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
