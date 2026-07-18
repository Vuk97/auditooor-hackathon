#!/usr/bin/env python3
"""Build an advisory recall-to-detector/source-proof queue.

This bridges agent-found behavior recall, locally verified provider rows,
semantic scanner inventory rows, and known-limitation recall blockers into one
bounded scanner-owner queue. It never promotes a finding: rows stay advisory
until a source proof, fixture pair, and local detector smoke/replay evidence are
recorded elsewhere.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "auditooor.pr560.agent_recall_detector_queue.v1"
TASK_SCHEMA = "auditooor.pr560.agent_recall_detector_tasks.v1"
FULL_CORPUS_SCHEMA = "auditooor.pr560.agent_recall_full_corpus_proof.v1"
TERMINAL_STATES = (
    "detector_queue_ready",
    "source_proof_queue_ready",
    "local_proof_required",
    "detectorized_terminal",
    "killed_duplicate_or_oos",
    "non_detectorizable_terminal",
    "blocked_missing_impact_contract",
    "blocked_missing_local_smoke",
    "blocked_known_limitation",
    "local_proof_recorded_terminal",
    "source_proof_terminal_blocked",
)
ADVISORY_LIMITATIONS = (
    "queue rows are recall/planning items only",
    "no row assigns severity or selected impact",
    "detector routes require vulnerable fixture, clean fixture, and smoke output before coverage can be claimed",
    "source-proof routes require line-cited local source proof before detector or harness work",
    "provider and semantic rows are advisory until local proof/smoke exists",
)
SOURCE_REF_RE = re.compile(
    r"(?P<path>(?:\.?/)?[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\."
    r"(?:sol|rs|go|cairo|move|vy|py|ts|tsx|js|jsx|md|json|yaml|yml))"
    r":(?P<line>[0-9]+)(?:-[0-9]+)?"
)
SOURCE_PATH_RE = re.compile(
    r"(?:^|[`\s])(?P<path>(?:\.?/)?[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\."
    r"(?:sol|rs|go|cairo|move|vy|py|ts|tsx|js|jsx|md|json|yaml|yml))(?:$|[`\s,;])"
)
CONCEPTUAL_SOURCE_RE = re.compile(r"\b(?:n/a|na|none|conceptual|pattern|typical|illustrative|hypothetical|generic|sample)\b", re.I)
COVERAGE_TERMINAL_STATES = {
    "detectorized_terminal",
    "local_proof_recorded_terminal",
}
SOURCE_REF_KEYS = (
    "source_ref",
    "source_refs",
    "source_reference",
    "source_references",
    "source_citation",
    "source_citations",
    "required_citations",
    "citations",
    "file_line",
    "file_lines",
    "line_ref",
    "line_refs",
)
SKIP_REASON_KEYS = (
    "skip_reason",
    "skipped_reason",
    "reason",
    "blocker",
    "error",
    "message",
)
TASK_TYPE_BY_LANE = {
    "detector_fixture": "detector_task",
    "semantic_worklist": "detector_task",
    "source_proof": "source_proof_task",
    "source_review_or_kill": "source_proof_task",
    "local_verification": "local_proof_task",
    "harness_or_replay": "local_proof_task",
    "impact_contract": "terminal_blocker",
    "kill_record": "terminal_blocker",
    "roadmap_recall_blocker": "terminal_blocker",
}
TERMINAL_DECISIONS = {
    "detector_task": (
        "detectorized_with_vulnerable_and_clean_fixtures",
        "blocked_missing_local_smoke",
        "killed_duplicate_or_oos",
        "non_detectorizable_terminal",
    ),
    "source_proof_task": (
        "proved_source_only_after_exact_impact_and_oos",
        "blocked_missing_impact_contract",
        "blocked_missing_citations",
        "killed_duplicate_or_oos",
        "non_detectorizable_terminal",
    ),
    "local_proof_task": (
        "local_proof_recorded",
        "blocked_missing_impact_contract",
        "blocked_missing_local_smoke",
        "killed_duplicate_or_oos",
    ),
    "terminal_blocker": (
        "blocker_resolved_with_evidence",
        "blocker_kept_terminal",
    ),
}


def _read_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _slug(value: object, fallback: str = "row") -> str:
    text = str(value or "")
    out = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return out[:90] or fallback


def _safe_rel(path: Path, root: Path = ROOT) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except (OSError, ValueError):
        return str(path)


def _records(payload: dict[str, Any], *keys: str) -> list[dict[str, Any]]:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, list):
            return [row for row in value if isinstance(row, dict)]
    return []


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def _clean_text(value: Any) -> str:
    return str(value or "").strip().strip("`'\".,;")


def _looks_like_source_path(value: str) -> bool:
    return bool(SOURCE_PATH_RE.search(f" {value} "))


def _resolve_path(workspace: Path, value: Any) -> Path | None:
    text = _clean_text(value)
    if not text:
        return None
    match = SOURCE_REF_RE.search(text)
    if match:
        text = match.group("path")
    path = Path(text).expanduser()
    candidates = [path] if path.is_absolute() else [workspace / path, ROOT / path]
    for candidate in candidates:
        try:
            if candidate.is_file():
                return candidate
        except OSError:
            continue
    return None


def _line_count(path: Path) -> int:
    try:
        return len(path.read_text(encoding="utf-8", errors="replace").splitlines())
    except OSError:
        return 0


def _skip_entry(
    *,
    source_field: str,
    reason: str,
    value: Any = "",
    file: str = "",
    function: str = "",
) -> dict[str, str | bool]:
    return {
        "source_field": source_field,
        "value": _clean_text(value),
        "file": file,
        "function": function,
        "reason": reason,
        "counts_as_scanned_coverage": False,
    }


def _validate_source_ref(workspace: Path, value: Any, source_field: str) -> list[dict[str, Any]]:
    text = _clean_text(value)
    if not text:
        return []
    if CONCEPTUAL_SOURCE_RE.search(text) and ("line" in source_field or "source" in source_field or "citation" in source_field):
        return [_skip_entry(source_field=source_field, value=text, reason="conceptual_or_missing_source_ref")]
    match = SOURCE_REF_RE.search(text)
    if not match:
        if source_field in SOURCE_REF_KEYS or _looks_like_source_path(text):
            reason = "malformed_source_ref_missing_line" if _looks_like_source_path(text) else "malformed_source_ref"
            return [_skip_entry(source_field=source_field, value=text, reason=reason)]
        return []
    source_path = match.group("path")
    resolved = _resolve_path(workspace, source_path)
    if not resolved:
        return [_skip_entry(source_field=source_field, value=text, file=source_path, reason="source_ref_file_not_found")]
    line_no = int(match.group("line"))
    count = _line_count(resolved)
    if line_no < 1 or line_no > count:
        return [
            _skip_entry(
                source_field=source_field,
                value=text,
                file=_safe_rel(resolved),
                reason=f"source_ref_line_out_of_range:{line_no}>{count}",
            )
        ]
    return []


def _source_ref_skip_entries(workspace: Path, row: dict[str, Any], *, include_claims: bool = True) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for key in SOURCE_REF_KEYS:
        for value in _as_list(row.get(key)):
            entries.extend(_validate_source_ref(workspace, value, key))
    if include_claims:
        for value in _as_list(row.get("claims_detected")):
            entries.extend(_validate_source_ref(workspace, value, "claims_detected"))
    return entries


def _skip_metadata_entries(row: dict[str, Any]) -> list[dict[str, Any]]:
    status_text = " ".join(
        _clean_text(row.get(key))
        for key in ("status", "local_status", "scanner_inventory_status", "task_type", "verdict")
    ).lower()
    skipped = bool(row.get("skipped")) or "skip" in status_text
    if not skipped:
        return []
    reason = next((_clean_text(row.get(key)) for key in SKIP_REASON_KEYS if _clean_text(row.get(key))), "")
    reason_code = "reasoned_skip:" + reason[:160] if reason else "unreasoned_skip"
    return [
        _skip_entry(
            source_field="skip_metadata",
            value=status_text,
            file=_clean_text(row.get("path") or row.get("source_path") or row.get("file")),
            function=_clean_text(row.get("function") or row.get("symbol")),
            reason=reason_code,
        )
    ]


def _source_hit_skip_entries(workspace: Path, row: dict[str, Any]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for source_path in _as_list(row.get("source_paths")):
        text = _clean_text(source_path)
        if text and not _resolve_path(workspace, text):
            entries.append(_skip_entry(source_field="source_paths", value=text, file=text, reason="source_path_file_not_found"))
    for hit in _as_list(row.get("source_hits")):
        if not isinstance(hit, dict):
            continue
        hit_path = _clean_text(hit.get("path"))
        resolved = _resolve_path(workspace, hit_path)
        if hit_path and not resolved:
            entries.append(_skip_entry(source_field="source_hits.path", value=hit_path, file=hit_path, reason="source_hit_file_not_found"))
            continue
        symbols: list[Any] = []
        for key in ("matched_symbols", "symbols", "functions", "matched_functions"):
            symbols.extend(_as_list(hit.get(key)))
        if resolved and symbols:
            try:
                text = resolved.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            for symbol in symbols:
                symbol_text = _clean_text(symbol)
                if symbol_text and symbol_text not in text:
                    entries.append(
                        _skip_entry(
                            source_field="source_hits.matched_symbols",
                            value=symbol_text,
                            file=_safe_rel(resolved),
                            function=symbol_text,
                            reason="symbol_not_found_in_file",
                        )
                    )
    return entries


def _sidecar_freshness_entries(
    workspace: Path,
    *,
    sidecar: Path,
    referenced_paths: Iterable[Any],
    label: str,
) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    try:
        sidecar_mtime = sidecar.stat().st_mtime
    except OSError:
        return [_skip_entry(source_field=label, value=str(sidecar), file=str(sidecar), reason="sidecar_file_not_found")]
    for raw_path in referenced_paths:
        text = _clean_text(raw_path)
        if not text:
            continue
        resolved = _resolve_path(workspace, text)
        if not resolved:
            entries.append(_skip_entry(source_field=label, value=text, file=text, reason="referenced_file_not_found"))
            continue
        try:
            if resolved.stat().st_mtime > sidecar_mtime:
                entries.append(
                    _skip_entry(
                        source_field=label,
                        value=text,
                        file=_safe_rel(resolved),
                        reason="stale_sidecar_older_than_referenced_file",
                    )
                )
        except OSError:
            entries.append(_skip_entry(source_field=label, value=text, file=text, reason="referenced_file_not_readable"))
    return entries


def _dedupe_skip_entries(entries: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str, str, str]] = set()
    for entry in entries:
        key = (
            str(entry.get("source_field") or ""),
            str(entry.get("value") or ""),
            str(entry.get("file") or ""),
            str(entry.get("function") or ""),
            str(entry.get("reason") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(entry)
    return out


def _attach_skipped_coverage(row: dict[str, Any], entries: Iterable[dict[str, Any]]) -> dict[str, Any]:
    clean_entries = _dedupe_skip_entries(entries)
    row["skipped_coverage"] = clean_entries
    row["skipped_coverage_count"] = len(clean_entries)
    row["coverage_counted"] = not clean_entries
    if clean_entries:
        row["coverage_skip_reasons"] = sorted({str(entry.get("reason") or "") for entry in clean_entries})
    else:
        row["coverage_skip_reasons"] = []
    return row


def _fail_open_if_terminal_coverage_skipped(row: dict[str, Any]) -> dict[str, Any]:
    if not row.get("skipped_coverage") or str(row.get("terminal_state") or "") not in COVERAGE_TERMINAL_STATES:
        return row
    original_state = str(row.get("terminal_state") or "")
    reasons = ", ".join(str(reason) for reason in row.get("coverage_skip_reasons", [])[:3])
    row["terminal_state"] = "source_proof_queue_ready"
    row["action_lane"] = "source_review_or_kill"
    row["reason"] = (
        f"terminal coverage skipped ({reasons}); original {original_state} cannot count as scanned coverage"
    )
    row["local_proof_status"] = "skipped_coverage_requires_source_recheck"
    row["original_terminal_state_before_skip"] = original_state
    return row


def _artifact_paths_from_source_hits(row: dict[str, Any]) -> list[str]:
    paths: list[str] = []
    paths.extend(_clean_text(path) for path in _as_list(row.get("source_paths")) if _clean_text(path))
    for hit in _as_list(row.get("source_hits")):
        if isinstance(hit, dict) and _clean_text(hit.get("path")):
            paths.append(_clean_text(hit.get("path")))
    return paths


def _slug_to_argument(slug: str) -> str:
    return slug.replace("_", "-")


def _all_provider_hits_are_internal_tool_paths(row: dict[str, Any]) -> bool:
    """Provider rows about Auditooor's own tools are not Solidity detector tasks."""
    paths: list[str] = []
    source_paths = row.get("source_paths")
    if isinstance(source_paths, list):
        paths.extend(str(path) for path in source_paths if str(path))
    source_hits = row.get("source_hits")
    if isinstance(source_hits, list):
        for hit in source_hits:
            if isinstance(hit, dict) and str(hit.get("path") or ""):
                paths.append(str(hit["path"]))
    term_hits = row.get("term_hits")
    if isinstance(term_hits, dict):
        for values in term_hits.values():
            if isinstance(values, list):
                paths.extend(str(path) for path in values if str(path))
    concrete_paths = [
        path for path in paths
        if not path.startswith(".auditooor/")
    ]
    if not concrete_paths:
        return False
    allowed_prefixes = ("tools/", "docs/", "reference/", "Makefile")
    return all(path.startswith(allowed_prefixes) for path in concrete_paths)


def _passed_smoke_by_argument(workspace: Path) -> dict[str, dict[str, Any]]:
    payload = _read_json(workspace / ".auditooor" / "semantic_detector_smoke_executor.json")
    passed: dict[str, dict[str, Any]] = {}
    for row in _records(payload, "rows"):
        if row.get("status") != "passed_vulnerable_clean_smoke":
            continue
        argument = str(row.get("argument") or "")
        if argument:
            passed[argument] = row
            passed[argument.strip("-")] = row
    return passed


def _provider_verification_paths(workspace: Path, explicit: Sequence[Path]) -> list[Path]:
    paths = [path for path in explicit if path.is_file()]
    if not paths:
        paths.extend(sorted((ROOT / ".audit_logs").glob("**/provider_result_local_verification.json")))
        paths.extend(sorted((workspace / ".auditooor").glob("**/provider_result_local_verification.json")))
    seen: set[Path] = set()
    unique: list[Path] = []
    for path in paths:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        unique.append(path)
    return unique


def _known_limitation_rows(workspace: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in (workspace / ".auditooor" / "known_limitations_burndown.json", ROOT / "docs" / "KNOWN_LIMITATIONS_BURNDOWN_MAP.json"):
        payload = _read_json(path)
        for row in _records(payload, "rows", "open_rows"):
            blob = json.dumps(row, sort_keys=True).lower()
            if "open_agent_recall_terminal_routes" in blob or "agent-found behavior recall" in blob:
                rows.append({**row, "_source_path": str(path)})
    return rows


def _agent_row_state(status: str) -> tuple[str, str, str]:
    if status == "detectorized":
        return ("detectorized_terminal", "archive_as_detectorized_recall", "matching detector/scanner output already exists")
    if status == "source_proof_required":
        return ("source_proof_queue_ready", "source_proof", "needs line-cited source/invariant proof before detector work")
    if status == "harness_task_required":
        return ("local_proof_required", "harness_or_replay", "needs local harness/PoC execution before proof")
    if status == "killed_duplicate_or_oos":
        return ("killed_duplicate_or_oos", "kill_record", "row already records duplicate/OOS/kill disposition")
    if status == "blocked_missing_impact_contract":
        return ("blocked_missing_impact_contract", "impact_contract", "reportable/direct claim lacks exact impact contract")
    return ("source_proof_queue_ready", "source_proof", "unclassified recall row needs source proof")


def _queue_row(
    *,
    idx: int,
    source: str,
    source_id: str,
    terminal_state: str,
    action_lane: str,
    reason: str,
    next_command: str,
    artifact: str = "",
    claims: Sequence[Any] | None = None,
    proof_status: str = "missing_local_proof",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    row = {
        "queue_id": f"ARDQ-{idx:03d}",
        "source": source,
        "source_id": source_id,
        "source_artifact": artifact,
        "terminal_state": terminal_state,
        "action_lane": action_lane,
        "reason": reason,
        "claims_detected": [str(item) for item in claims or []],
        "next_command": next_command,
        "required_before_promotion": [
            "line-cited source proof" if action_lane == "source_proof" else "bounded local proof artifact",
            "vulnerable fixture and clean fixture" if "detector" in action_lane else "exact impact contract if report/harness work follows",
            "local detector smoke output" if "detector" in action_lane else "local replay/harness output when applicable",
            "OOS/duplicate clearance",
        ],
        "local_proof_status": proof_status,
        "advisory_only": True,
        "promotion_allowed": False,
        "severity": "none",
        "selected_impact": "",
        "submission_posture": "NOT_SUBMIT_READY",
    }
    if extra:
        row.update(extra)
    return row


def _task_type(row: dict[str, Any]) -> str:
    lane = str(row.get("action_lane") or "")
    state = str(row.get("terminal_state") or "")
    if state in {
        "detectorized_terminal",
        "killed_duplicate_or_oos",
        "non_detectorizable_terminal",
        "blocked_known_limitation",
        "local_proof_recorded_terminal",
        "source_proof_terminal_blocked",
    }:
        return "terminal_blocker"
    if state == "detector_queue_ready":
        return "detector_task"
    if state == "source_proof_queue_ready":
        return "source_proof_task"
    if state == "local_proof_required":
        return "local_proof_task"
    return TASK_TYPE_BY_LANE.get(lane, "terminal_blocker")


def _recall_closure_rows(workspace: Path) -> dict[str, dict[str, Any]]:
    path = workspace / ".auditooor" / "agent_recall_source_local_proof_closure.json"
    payload = _read_json(path)
    by_key: dict[str, dict[str, Any]] = {}
    for row in _records(payload, "rows"):
        row = {**row, "_closure_sidecar_path": str(path)}
        queue_id = str(row.get("queue_id") or "")
        source_id = str(row.get("source_id") or "")
        if queue_id:
            by_key[f"queue:{queue_id}"] = row
        if source_id:
            by_key[f"source:{source_id}"] = row
    return by_key


def _closure_skip_entries(workspace: Path, row: dict[str, Any], closure: dict[str, Any]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    sidecar = Path(str(closure.get("_closure_sidecar_path") or ""))
    source_artifact = str(row.get("source_artifact") or "")
    if source_artifact and _resolve_path(workspace, source_artifact):
        entries.extend(
            _sidecar_freshness_entries(
                workspace,
                sidecar=sidecar,
                referenced_paths=[source_artifact],
                label="recall_closure_sidecar",
            )
        )
    closure_artifact = str(closure.get("closure_artifact") or closure.get("proof_artifact") or "")
    if not closure_artifact and _resolve_path(workspace, closure.get("next_command")):
        closure_artifact = str(closure.get("next_command") or "")
    target_terminal = str(closure.get("terminal_state") or "")
    if target_terminal in COVERAGE_TERMINAL_STATES:
        if closure_artifact:
            entries.extend(
                _sidecar_freshness_entries(
                    workspace,
                    sidecar=sidecar,
                    referenced_paths=[closure_artifact],
                    label="recall_closure_artifact",
                )
            )
        else:
            entries.append(
                _skip_entry(
                    source_field="recall_closure_artifact",
                    reason="coverage_closure_missing_artifact",
                    value=target_terminal,
                )
            )
    entries.extend(_source_ref_skip_entries(workspace, closure, include_claims=False))
    entries.extend(_skip_metadata_entries(closure))
    return _dedupe_skip_entries(entries)


def _apply_recall_closure(
    row: dict[str, Any],
    closure_rows: dict[str, dict[str, Any]],
    workspace: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    closure = (
        closure_rows.get(f"queue:{row.get('queue_id') or ''}")
        or closure_rows.get(f"source:{row.get('source_id') or ''}")
        or {}
    )
    if not closure:
        return row, {}
    closure_skips = _closure_skip_entries(workspace, row, closure)
    if closure_skips:
        skipped = dict(row)
        existing = skipped.get("skipped_coverage") if isinstance(skipped.get("skipped_coverage"), list) else []
        _attach_skipped_coverage(skipped, [*existing, *closure_skips])
        skipped["recall_closure_skipped"] = True
        skipped["recall_closure_skip_reasons"] = skipped["coverage_skip_reasons"]
        skipped["recall_closure_decision"] = str(closure.get("decision") or "")
        skipped["recall_closure_artifact"] = str(closure.get("closure_artifact") or "")
        skipped = _fail_open_if_terminal_coverage_skipped(skipped)
        return skipped, {}
    closed = dict(row)
    closed["terminal_state"] = str(closure.get("terminal_state") or row.get("terminal_state") or "")
    closed["action_lane"] = str(closure.get("action_lane") or row.get("action_lane") or "")
    closed["reason"] = str(closure.get("reason") or row.get("reason") or "")
    closed["next_command"] = str(closure.get("next_command") or row.get("next_command") or "")
    closed["local_proof_status"] = str(closure.get("proof_status") or row.get("local_proof_status") or "")
    closed["recall_closure_artifact"] = str(closure.get("closure_artifact") or "")
    closed["recall_closure_decision"] = str(closure.get("decision") or "")
    existing = closed.get("skipped_coverage") if isinstance(closed.get("skipped_coverage"), list) else []
    _attach_skipped_coverage(closed, existing)
    return closed, closure


def _terminal_blockers(row: dict[str, Any], task_type: str) -> list[str]:
    blockers = [
        "advisory_provider_or_recall_row_not_proof",
        "severity_unassigned",
        "selected_impact_missing",
    ]
    lane = str(row.get("action_lane") or "")
    state = str(row.get("terminal_state") or "")
    if task_type == "detector_task" or lane == "detector_fixture":
        blockers.extend([
            "missing_vulnerable_fixture",
            "missing_clean_fixture",
            "missing_local_detector_smoke_output",
        ])
    if task_type == "source_proof_task":
        blockers.extend([
            "missing_line_cited_source_proof",
            "missing_exact_impact_contract",
            "missing_oos_duplicate_clearance",
        ])
    if task_type == "local_proof_task":
        blockers.extend([
            "missing_bounded_local_replay_or_harness_output",
            "missing_exact_impact_contract_if_report_work_follows",
        ])
    if state == "blocked_missing_impact_contract":
        blockers.append("impact_contract_required_before_harness_or_report_work")
    if state == "blocked_missing_local_smoke":
        blockers.append("local_smoke_or_review_record_required")
    if state == "blocked_known_limitation":
        blockers.append("known_limitation_stop_condition_open")
    if state in {"killed_duplicate_or_oos", "non_detectorizable_terminal", "detectorized_terminal"}:
        blockers.append("terminal_disposition_requires_no_reopen_without_new_evidence")
    if row.get("skipped_coverage"):
        blockers.append("skipped_files_or_functions_do_not_count_as_scanned_coverage")
    if row.get("recall_closure_skipped"):
        blockers.append("recall_closure_sidecar_rejected")
    return sorted(set(blockers))


def build_task_manifest(queue_payload: dict[str, Any]) -> dict[str, Any]:
    tasks: list[dict[str, Any]] = []
    workspace = Path(str(queue_payload.get("workspace") or ""))
    closure_rows = _recall_closure_rows(workspace) if str(workspace) else {}
    for idx, row in enumerate(queue_payload.get("rows", []), start=1):
        if not isinstance(row, dict):
            continue
        row, closure = _apply_recall_closure(row, closure_rows, workspace)
        task_type = _task_type(row)
        task = {
            "task_id": f"ARDT-{idx:03d}",
            "queue_id": str(row.get("queue_id") or ""),
            "task_type": task_type,
            "source": str(row.get("source") or ""),
            "source_id": str(row.get("source_id") or ""),
            "source_artifact": str(row.get("source_artifact") or ""),
            "action_lane": str(row.get("action_lane") or ""),
            "terminal_state": str(row.get("terminal_state") or ""),
            "claims_detected": [str(item) for item in row.get("claims_detected", []) if str(item)],
            "reason": str(row.get("reason") or ""),
            "next_command": str(row.get("next_command") or ""),
            "terminal_blockers": _terminal_blockers(row, task_type),
            "allowed_terminal_decisions": list(TERMINAL_DECISIONS[task_type]),
            "required_before_promotion": list(row.get("required_before_promotion", [])),
            "local_proof_status": str(row.get("local_proof_status") or ""),
            "advisory_only": True,
            "promotion_allowed": False,
            "severity": "none",
            "selected_impact": "",
            "submission_posture": "NOT_SUBMIT_READY",
            "coverage_counted": bool(row.get("coverage_counted", True)),
            "skipped_coverage": row.get("skipped_coverage", []),
            "skipped_coverage_count": int(row.get("skipped_coverage_count") or 0),
            "coverage_skip_reasons": row.get("coverage_skip_reasons", []),
        }
        if row.get("recall_closure_skipped"):
            task["recall_closure_skipped"] = True
            task["recall_closure_skip_reasons"] = row.get("recall_closure_skip_reasons", [])
        if closure:
            task["recall_closure_artifact"] = row.get("recall_closure_artifact", "")
            task["recall_closure_decision"] = row.get("recall_closure_decision", "")
            task["recall_closure_terminal_blockers"] = closure.get("terminal_blockers", [])
        if row.get("provider_classifications"):
            task["provider_classifications"] = row.get("provider_classifications")
        if row.get("verification_queue"):
            task["verification_queue"] = row.get("verification_queue")
        if row.get("suggested_detector_slug"):
            task["suggested_detector_slug"] = row.get("suggested_detector_slug")
        tasks.append(task)
    task_counts = Counter(str(task["task_type"]) for task in tasks)
    for task_type in TERMINAL_DECISIONS:
        task_counts.setdefault(task_type, 0)
    return {
        "schema": TASK_SCHEMA,
        "generated_at_utc": queue_payload.get("generated_at_utc") or dt.datetime.now(dt.timezone.utc).isoformat(),
        "workspace": queue_payload.get("workspace", ""),
        "queue_source": str(Path(str(queue_payload.get("workspace", ""))) / ".auditooor" / "agent_recall_detector_queue.json") if queue_payload.get("workspace") else "",
        "queue_count": int(queue_payload.get("queue_count") or 0),
        "task_count": len(tasks),
        "task_type_counts": dict(sorted(task_counts.items())),
        "terminal_state_counts": queue_payload.get("terminal_state_counts", {}),
        "advisory_only": True,
        "promotion_allowed": False,
        "severity_assigned": False,
        "selected_impact": "",
        "submission_posture": "NOT_SUBMIT_READY",
        "limitations": list(ADVISORY_LIMITATIONS),
        "tasks": tasks,
    }


def build_full_corpus_proof(queue_payload: dict[str, Any], tasks_payload: dict[str, Any]) -> dict[str, Any]:
    """Summarize whether the recall corpus was fully classified.

    This is intentionally separate from the default 50-row queue so a bounded
    operator queue cannot be mistaken for full recall closure.
    """
    tasks = [task for task in tasks_payload.get("tasks", []) if isinstance(task, dict)]
    open_tasks = [
        task for task in tasks
        if str(task.get("task_type") or "") in {"detector_task", "source_proof_task", "local_proof_task"}
    ]
    terminal_tasks = [
        task for task in tasks
        if str(task.get("task_type") or "") == "terminal_blocker"
    ]
    skipped_coverage_tasks = [
        task for task in tasks
        if int(task.get("skipped_coverage_count") or 0) > 0
    ]
    coverage_counted_tasks = [
        task for task in tasks
        if bool(task.get("coverage_counted", True)) and int(task.get("skipped_coverage_count") or 0) == 0
    ]
    open_by_type = Counter(str(task.get("task_type") or "unknown") for task in open_tasks)
    terminal_by_state = Counter(str(task.get("terminal_state") or "unknown") for task in terminal_tasks)
    task_state_counts = Counter(str(task.get("terminal_state") or "unknown") for task in tasks)
    for state in TERMINAL_STATES:
        task_state_counts.setdefault(state, 0)
    full_recall_closed = not queue_payload.get("truncated") and not open_tasks and not skipped_coverage_tasks
    return {
        "schema": FULL_CORPUS_SCHEMA,
        "generated_at_utc": queue_payload.get("generated_at_utc") or dt.datetime.now(dt.timezone.utc).isoformat(),
        "workspace": queue_payload.get("workspace", ""),
        "queue_artifact": str(Path(str(queue_payload.get("workspace", ""))) / ".auditooor" / "agent_recall_detector_queue.json") if queue_payload.get("workspace") else "",
        "task_artifact": str(Path(str(queue_payload.get("workspace", ""))) / ".auditooor" / "agent_recall_detector_tasks.json") if queue_payload.get("workspace") else "",
        "full_corpus_evaluated": bool(not queue_payload.get("truncated")),
        "total_candidate_rows": int(queue_payload.get("total_candidate_rows") or 0),
        "queue_count": int(queue_payload.get("queue_count") or 0),
        "terminalized_or_bounded_rows": len(terminal_tasks),
        "coverage_counted_rows": len(coverage_counted_tasks),
        "skipped_coverage_rows": len(skipped_coverage_tasks),
        "open_actionable_rows": len(open_tasks),
        "open_actionable_counts": dict(sorted(open_by_type.items())),
        "terminal_state_counts": dict(sorted(task_state_counts.items())),
        "queue_terminal_state_counts": queue_payload.get("terminal_state_counts", {}),
        "source_counts": queue_payload.get("source_counts", {}),
        "task_type_counts": tasks_payload.get("task_type_counts", {}),
        "detector_recall_closure_status": (
            "closed_for_current_local_evidence"
            if not queue_payload.get("truncated") and int(tasks_payload.get("task_type_counts", {}).get("detector_task", 0)) == 0
            else "open"
        ),
        "full_recall_closure_status": (
            "closed_for_current_local_evidence"
            if full_recall_closed
            else "reduced_not_closed"
        ),
        "skipped_coverage": [
            {
                "task_id": str(task.get("task_id") or ""),
                "queue_id": str(task.get("queue_id") or ""),
                "source": str(task.get("source") or ""),
                "source_id": str(task.get("source_id") or ""),
                "terminal_state": str(task.get("terminal_state") or ""),
                "entries": task.get("skipped_coverage", []),
            }
            for task in skipped_coverage_tasks
        ],
        "remaining_open_tasks": [
            {
                "task_id": str(task.get("task_id") or ""),
                "queue_id": str(task.get("queue_id") or ""),
                "task_type": str(task.get("task_type") or ""),
                "source": str(task.get("source") or ""),
                "source_id": str(task.get("source_id") or ""),
                "terminal_state": str(task.get("terminal_state") or ""),
                "next_command": str(task.get("next_command") or ""),
                "terminal_blockers": task.get("terminal_blockers", []),
            }
            for task in open_tasks
        ],
        "promotion_allowed": False,
        "severity_assigned": False,
        "selected_impact": "",
        "submission_posture": "NOT_SUBMIT_READY",
        "limitations": [
            "full-corpus proof is still advisory until open source/local proof tasks are closed",
            "detector recall closure only means no detector tasks remain in this corpus snapshot",
            "terminal rows are not exploit proof and cannot assign severity or selected impact",
        ],
    }


def _agent_rows(workspace: Path, start_idx: int) -> list[dict[str, Any]]:
    payload = _read_json(workspace / ".auditooor" / "agent_found_not_detector_found.json")
    rows: list[dict[str, Any]] = []
    for row in _records(payload, "rows"):
        status = str(row.get("status") or "")
        terminal_state, lane, reason = _agent_row_state(status)
        artifact = str(row.get("agent_output") or "")
        if not str(row.get("impact_contract_id") or "") and (
            artifact.endswith("/README.md") or artifact.endswith(".tombstone.md")
        ):
            terminal_state = "non_detectorizable_terminal"
            lane = "kill_record"
            reason = "placeholder/tombstone agent artifact has no impact contract or source proof to execute"
        proof_status = "detectorized_advisory" if terminal_state == "detectorized_terminal" else "missing_local_proof"
        if terminal_state == "killed_duplicate_or_oos":
            proof_status = "terminal_kill_recorded"
        if terminal_state == "non_detectorizable_terminal":
            proof_status = "terminal_placeholder_or_tombstone"
        queue_row = _queue_row(
            idx=start_idx + len(rows),
            source="agent_recall",
            source_id=_slug(row.get("candidate_id") or row.get("agent_output") or len(rows), "agent-recall"),
            terminal_state=terminal_state,
            action_lane=lane,
            reason=str(row.get("reason") or reason),
            next_command=str(row.get("next_command") or "make source-proof-task-queue WS=<workspace>"),
            artifact=artifact,
            claims=row.get("claims_detected") if isinstance(row.get("claims_detected"), list) else [],
            proof_status=proof_status,
            extra={
                "impact_contract_id": str(row.get("impact_contract_id") or ""),
                "mechanically_covered": bool(row.get("mechanically_covered")),
            },
        )
        _attach_skipped_coverage(queue_row, [
            *_source_ref_skip_entries(workspace, row),
            *_skip_metadata_entries(row),
        ])
        rows.append(_fail_open_if_terminal_coverage_skipped(queue_row))
    return rows


def _provider_state(row: dict[str, Any]) -> tuple[str, str, str, str]:
    classes = set(str(item) for item in row.get("classifications", []) if item)
    local_status = str(row.get("local_status") or "")
    if _all_provider_hits_are_internal_tool_paths(row) and str(row.get("evidence_class") or "") == "generated_hypothesis":
        return (
            "non_detectorizable_terminal",
            "source_review_or_kill",
            "provider row targets Auditooor internal tool code, not a smart-contract detector fixture",
            local_status or "internal_tool_hypothesis",
        )
    if "non_detectorizable" in classes:
        return ("non_detectorizable_terminal", "source_review_or_kill", "provider row is marked non-detectorizable", local_status or "advisory_classified")
    if "needs_fixture" in classes:
        return ("detector_queue_ready", "detector_fixture", "provider row needs fixture-backed detectorization", "missing_detector_smoke")
    if local_status in {"source_symbol_confirmed", "source_file_confirmed", "repo_grep_confirmed"}:
        return ("source_proof_queue_ready", "source_proof", "provider row has local grep/source signal but no proof record", local_status)
    if local_status == "off_repo_source":
        return ("blocked_missing_local_smoke", "source_review_or_kill", "provider source is off-repo; local proof impossible here", local_status)
    return ("local_proof_required", "local_verification", "provider row still needs local verification", local_status or "no_local_evidence")


def _provider_rows(workspace: Path, start_idx: int, provider_paths: Sequence[Path]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in _provider_verification_paths(workspace, provider_paths):
        payload = _read_json(path)
        for row in _records(payload, "rows"):
            terminal_state, lane, reason, proof_status = _provider_state(row)
            skip_entries = [
                *_source_ref_skip_entries(workspace, row, include_claims=False),
                *_source_hit_skip_entries(workspace, row),
                *_skip_metadata_entries(row),
                *_sidecar_freshness_entries(
                    workspace,
                    sidecar=path,
                    referenced_paths=_artifact_paths_from_source_hits(row),
                    label="provider_verification_sidecar",
                ),
            ]
            if skip_entries and terminal_state == "detector_queue_ready":
                terminal_state = "source_proof_queue_ready"
                lane = "source_review_or_kill"
                reason = "provider detector route has skipped source coverage; source review required before fixture work"
                proof_status = "skipped_coverage_requires_source_recheck"
            next_commands = row.get("verification_queue", {}).get("next_commands") if isinstance(row.get("verification_queue"), dict) else []
            queue_row = _queue_row(
                idx=start_idx + len(rows),
                source="provider_local_verification",
                source_id=_slug(row.get("task_id") or len(rows), "provider-row"),
                terminal_state=terminal_state,
                action_lane=lane,
                reason=reason,
                next_command=str(next_commands[0]) if next_commands else "make live-provider-local-verification-queue",
                artifact=_safe_rel(path),
                claims=row.get("symbols") if isinstance(row.get("symbols"), list) else [],
                proof_status=proof_status,
                extra={
                    "provider_local_status": str(row.get("local_status") or ""),
                    "provider_classifications": row.get("classifications", []),
                    "verification_queue": row.get("verification_queue", {}),
                },
            )
            _attach_skipped_coverage(queue_row, skip_entries)
            rows.append(_fail_open_if_terminal_coverage_skipped(queue_row))
    return rows


def _semantic_state(row: dict[str, Any]) -> tuple[str, str, str]:
    task_type = str(row.get("task_type") or "")
    status = str(row.get("scanner_inventory_status") or "")
    if task_type in {"detector_rewrite_with_fixture_pair", "fixture_pair_before_detector_rewrite"}:
        return ("detector_queue_ready", "detector_fixture", "semantic inventory row needs detector rewrite plus fixture pair")
    if task_type == "source_review_or_kill_note" or status in {"source_review_or_kill", "query_zero_match", "query_not_executed"}:
        return ("source_proof_queue_ready", "source_review_or_kill", "semantic inventory row needs source review or kill note")
    if task_type == "coverage_to_detector_worklist":
        return ("blocked_missing_local_smoke", "semantic_worklist", "semantic coverage row must become detector worklist before smoke")
    return ("blocked_missing_local_smoke", "semantic_inventory", "semantic inventory row is coverage-only until routed and smoked")


def _semantic_smoke_skip_entries(
    workspace: Path,
    inventory_path: Path,
    smoke_path: Path,
    smoke_row: dict[str, Any],
) -> list[dict[str, Any]]:
    referenced = [
        smoke_row.get("positive_fixture"),
        smoke_row.get("clean_fixture"),
        inventory_path,
    ]
    entries = _sidecar_freshness_entries(
        workspace,
        sidecar=smoke_path,
        referenced_paths=referenced,
        label="semantic_smoke_sidecar",
    )
    for field in ("positive_fixture", "clean_fixture"):
        if not _clean_text(smoke_row.get(field)):
            entries.append(_skip_entry(source_field=f"semantic_smoke.{field}", reason="smoke_fixture_path_missing"))
    entries.extend(_source_ref_skip_entries(workspace, smoke_row, include_claims=False))
    entries.extend(_skip_metadata_entries(smoke_row))
    return _dedupe_skip_entries(entries)


def _semantic_rows(workspace: Path, start_idx: int) -> list[dict[str, Any]]:
    path = workspace / ".auditooor" / "semantic_scanner_inventory.json"
    smoke_path = workspace / ".auditooor" / "semantic_detector_smoke_executor.json"
    payload = _read_json(path)
    passed_smoke = _passed_smoke_by_argument(workspace)
    rows: list[dict[str, Any]] = []
    for row in _records(payload, "detector_fixture_task_queue"):
        suggested_slug = str(row.get("suggested_detector_slug") or "")
        smoke_argument = _slug_to_argument(suggested_slug)
        smoke_row = passed_smoke.get(smoke_argument)
        smoke_skip_entries = _semantic_smoke_skip_entries(workspace, path, smoke_path, smoke_row) if smoke_row else []
        if smoke_row and not smoke_skip_entries:
            terminal_state = "detectorized_terminal"
            lane = "detector_fixture"
            reason = "semantic inventory row has vulnerable/clean detector smoke proof"
            proof_status = "passed_vulnerable_clean_smoke"
        else:
            terminal_state, lane, reason = _semantic_state(row)
            proof_status = "missing_detector_smoke"
            if smoke_row and smoke_skip_entries:
                reason = "semantic smoke proof skipped; source/fixture freshness must be repaired before coverage counts"
                proof_status = "skipped_coverage_requires_source_recheck"
        queue_row = _queue_row(
            idx=start_idx + len(rows),
            source="semantic_scanner_inventory",
            source_id=_slug(row.get("queue_id") or row.get("inventory_id") or len(rows), "semantic-row"),
            terminal_state=terminal_state,
            action_lane=lane,
            reason=reason,
            next_command=str(row.get("next_command") or "make semantic-scanner-inventory WS=<workspace>"),
            artifact=str(path),
            claims=[row.get("source_component", ""), row.get("query_shape", "")],
            proof_status=proof_status,
            extra={
                "semantic_inventory_id": str(row.get("inventory_id") or ""),
                "suggested_detector_slug": suggested_slug,
                "smoke_evidence_artifact": str(workspace / ".auditooor" / "semantic_detector_smoke_executor.json") if smoke_row else "",
                "smoke_evidence_status": str(smoke_row.get("status") or "") if smoke_row else "",
                "positive_fixture": str(smoke_row.get("positive_fixture") or "") if smoke_row else "",
                "clean_fixture": str(smoke_row.get("clean_fixture") or "") if smoke_row else "",
                "fixture_task": row.get("fixture_task", {}),
            },
        )
        _attach_skipped_coverage(queue_row, [
            *_source_ref_skip_entries(workspace, row, include_claims=False),
            *_skip_metadata_entries(row),
            *smoke_skip_entries,
        ])
        rows.append(_fail_open_if_terminal_coverage_skipped(queue_row))
    return rows


def _known_rows(workspace: Path, start_idx: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in _known_limitation_rows(workspace):
        queue_row = _queue_row(
            idx=start_idx + len(rows),
            source="known_limitations",
            source_id=_slug(row.get("limitation_id") or row.get("blocker_id") or len(rows), "known-limitation"),
            terminal_state="blocked_known_limitation",
            action_lane="roadmap_recall_blocker",
            reason=str(row.get("blocker") or row.get("title") or "open agent recall terminal-route limitation"),
            next_command=str(row.get("next_command") or "make agent-recall-detector-queue WS=<workspace>"),
            artifact=str(row.get("_source_path") or ""),
            claims=[row.get("target_status_after", ""), row.get("remaining_after_560", "")],
            proof_status="roadmap_blocker_open",
            extra={
                "stop_condition_met": bool(row.get("stop_condition_met")),
                "limitation_terminal_state": str(row.get("terminal_state") or ""),
            },
        )
        _attach_skipped_coverage(queue_row, _skip_metadata_entries(row))
        rows.append(queue_row)
    return rows


def build_queue(workspace: Path, *, limit: int, provider_paths: Sequence[Path]) -> dict[str, Any]:
    groups = [
        _agent_rows(workspace, 1),
        _provider_rows(workspace, 1, provider_paths),
        _semantic_rows(workspace, 1),
        _known_rows(workspace, 1),
    ]
    all_rows = [row for group in groups for row in group]
    rows: list[dict[str, Any]] = []
    max_group_len = max((len(group) for group in groups), default=0)
    for offset in range(max_group_len):
        for group in groups:
            if offset >= len(group) or len(rows) >= limit:
                continue
            row = dict(group[offset])
            row["queue_id"] = f"ARDQ-{len(rows) + 1:03d}"
            rows.append(row)
        if len(rows) >= limit:
            break
    terminal_counts = Counter(str(row.get("terminal_state") or "unknown") for row in rows)
    source_counts = Counter(str(row.get("source") or "unknown") for row in rows)
    skipped_coverage = [
        {
            "queue_id": str(row.get("queue_id") or ""),
            "source": str(row.get("source") or ""),
            "source_id": str(row.get("source_id") or ""),
            "terminal_state": str(row.get("terminal_state") or ""),
            "entries": row.get("skipped_coverage", []),
        }
        for row in rows
        if int(row.get("skipped_coverage_count") or 0) > 0
    ]
    for state in TERMINAL_STATES:
        terminal_counts.setdefault(state, 0)
    return {
        "schema": SCHEMA,
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "workspace": str(workspace),
        "limit": limit,
        "total_candidate_rows": len(all_rows),
        "queue_count": len(rows),
        "truncated": len(all_rows) > limit,
        "allowed_terminal_states": list(TERMINAL_STATES),
        "terminal_state_counts": dict(sorted(terminal_counts.items())),
        "source_counts": dict(sorted(source_counts.items())),
        "skipped_coverage_count": sum(int(row.get("skipped_coverage_count") or 0) for row in rows),
        "skipped_coverage_rows": len(skipped_coverage),
        "skipped_coverage": skipped_coverage,
        "advisory_only": True,
        "promotion_allowed": False,
        "severity_assigned": False,
        "selected_impact": "",
        "submission_posture": "NOT_SUBMIT_READY",
        "limitations": list(ADVISORY_LIMITATIONS),
        "source_artifacts": {
            "agent_recall": str(workspace / ".auditooor" / "agent_found_not_detector_found.json"),
            "semantic_scanner_inventory": str(workspace / ".auditooor" / "semantic_scanner_inventory.json"),
            "known_limitations_burndown": str(workspace / ".auditooor" / "known_limitations_burndown.json"),
            "provider_verification_glob": ".audit_logs/**/provider_result_local_verification.json",
        },
        "rows": rows,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Agent Recall Detector Queue",
        "",
        "Advisory queue that routes agent-found/provider/semantic recall rows into detector, source-proof, local-proof, or terminal kill lanes.",
        "",
        f"- queue rows: `{payload['queue_count']}`",
        f"- total candidates before limit: `{payload['total_candidate_rows']}`",
        f"- limit: `{payload['limit']}`",
        f"- truncated: `{str(payload['truncated']).lower()}`",
        f"- skipped coverage entries: `{payload.get('skipped_coverage_count', 0)}`",
        f"- submission posture: `{payload['submission_posture']}`",
        "",
        "## Terminal States",
        "",
    ]
    for state, count in payload["terminal_state_counts"].items():
        lines.append(f"- `{state}`: {count}")
    lines.extend([
        "",
        "## Rows",
        "",
        "| Queue | Source | State | Lane | Skipped coverage | Artifact | Next command |",
        "|---|---|---|---|---|---|---|",
    ])
    if not payload["rows"]:
        lines.append("| _none_ | _none_ | `empty` | _none_ | _none_ | _none_ | _none_ |")
    for row in payload["rows"]:
        skipped = ", ".join(str(reason) for reason in row.get("coverage_skip_reasons", [])[:2]) or "_none_"
        lines.append("| `{}` | `{}` | `{}` | `{}` | {} | `{}` | `{}` |".format(
            row["queue_id"],
            row["source"],
            row["terminal_state"],
            row["action_lane"],
            skipped,
            row["source_artifact"],
            row["next_command"],
        ))
    if payload.get("skipped_coverage"):
        lines.extend(["", "## Skipped Coverage", ""])
        for item in payload["skipped_coverage"]:
            for entry in item.get("entries", []):
                target = str(entry.get("file") or entry.get("function") or entry.get("value") or "_unknown_")
                lines.append(
                    f"- `{item.get('queue_id')}` skipped `{target}`: {entry.get('reason')}"
                )
    return "\n".join(lines) + "\n"


def render_tasks_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Agent Recall Detector Tasks",
        "",
        "Materialized detector/source-proof/local-proof tasks from the advisory recall queue.",
        "",
        f"- task rows: `{payload['task_count']}`",
        f"- queue rows: `{payload['queue_count']}`",
        f"- submission posture: `{payload['submission_posture']}`",
        f"- promotion allowed: `{str(payload['promotion_allowed']).lower()}`",
        "",
        "## Task Types",
        "",
    ]
    for task_type, count in payload["task_type_counts"].items():
        lines.append(f"- `{task_type}`: {count}")
    lines.extend([
        "",
        "## Tasks",
        "",
        "| Task | Queue | Type | State | Skipped coverage | Blockers | Next command |",
        "|---|---|---|---|---|---|---|",
    ])
    if not payload["tasks"]:
        lines.append("| _none_ | _none_ | `empty` | _none_ | _none_ | _none_ | _none_ |")
    for task in payload["tasks"]:
        blockers = ", ".join(task["terminal_blockers"][:4])
        if len(task["terminal_blockers"]) > 4:
            blockers += ", ..."
        skipped = ", ".join(str(reason) for reason in task.get("coverage_skip_reasons", [])[:2]) or "_none_"
        lines.append("| `{}` | `{}` | `{}` | `{}` | {} | `{}` | `{}` |".format(
            task["task_id"],
            task["queue_id"],
            task["task_type"],
            task["terminal_state"],
            skipped,
            blockers,
            task["next_command"],
        ))
    return "\n".join(lines) + "\n"


def render_full_corpus_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Agent Recall Full-Corpus Proof",
        "",
        "Full-corpus classification proof for agent/provider/semantic recall rows. This deliberately separates full-corpus status from the default bounded 50-row operator queue.",
        "",
        f"- full corpus evaluated: `{str(payload['full_corpus_evaluated']).lower()}`",
        f"- total candidate rows: `{payload['total_candidate_rows']}`",
        f"- queue rows emitted: `{payload['queue_count']}`",
        f"- terminalized or bounded rows: `{payload['terminalized_or_bounded_rows']}`",
        f"- coverage counted rows: `{payload.get('coverage_counted_rows', 0)}`",
        f"- skipped coverage rows: `{payload.get('skipped_coverage_rows', 0)}`",
        f"- open actionable rows: `{payload['open_actionable_rows']}`",
        f"- detector recall closure status: `{payload['detector_recall_closure_status']}`",
        f"- full recall closure status: `{payload['full_recall_closure_status']}`",
        "",
        "## Open Actionable Counts",
        "",
    ]
    if payload["open_actionable_counts"]:
        for task_type, count in payload["open_actionable_counts"].items():
            lines.append(f"- `{task_type}`: {count}")
    else:
        lines.append("- _none_")
    lines.extend([
        "",
        "## Remaining Open Tasks",
        "",
        "| Task | Type | Source | State | Next command |",
        "|---|---|---|---|---|",
    ])
    if not payload["remaining_open_tasks"]:
        lines.append("| _none_ | _none_ | _none_ | _none_ | _none_ |")
    for task in payload["remaining_open_tasks"]:
        lines.append("| `{}` | `{}` | `{}` | `{}` | `{}` |".format(
            task["task_id"],
            task["task_type"],
            task["source"],
            task["terminal_state"],
            task["next_command"],
        ))
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True, type=Path)
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--full-corpus", action="store_true", help="Evaluate every candidate row instead of the bounded operator queue.")
    parser.add_argument("--provider-verification", action="append", type=Path, default=[])
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--out-tasks-json", type=Path)
    parser.add_argument("--out-tasks-md", type=Path)
    parser.add_argument("--out-full-corpus-json", type=Path)
    parser.add_argument("--out-full-corpus-md", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    limit = 1_000_000_000 if args.full_corpus else args.limit
    payload = build_queue(workspace, limit=limit, provider_paths=args.provider_verification)
    out_json = args.out_json or workspace / ".auditooor" / "agent_recall_detector_queue.json"
    out_md = args.out_md or workspace / ".auditooor" / "agent_recall_detector_queue.md"
    tasks_payload = build_task_manifest(payload)
    out_tasks_json = args.out_tasks_json or workspace / ".auditooor" / "agent_recall_detector_tasks.json"
    out_tasks_md = args.out_tasks_md or workspace / ".auditooor" / "agent_recall_detector_tasks.md"
    full_corpus_payload = build_full_corpus_proof(payload, tasks_payload)
    out_full_corpus_json = args.out_full_corpus_json or workspace / ".auditooor" / "agent_recall_full_corpus_proof.json"
    out_full_corpus_md = args.out_full_corpus_md or workspace / ".auditooor" / "agent_recall_full_corpus_proof.md"
    _write_json(out_json, payload)
    _write_text(out_md, render_markdown(payload))
    _write_json(out_tasks_json, tasks_payload)
    _write_text(out_tasks_md, render_tasks_markdown(tasks_payload))
    if args.full_corpus or args.out_full_corpus_json or args.out_full_corpus_md:
        _write_json(out_full_corpus_json, full_corpus_payload)
        _write_text(out_full_corpus_md, render_full_corpus_markdown(full_corpus_payload))
    if args.print_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"wrote {out_json}")
        print(f"wrote {out_md}")
        print(f"wrote {out_tasks_json}")
        print(f"wrote {out_tasks_md}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
