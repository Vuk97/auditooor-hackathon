#!/usr/bin/env python3
"""Build an offline model-takeover readiness packet.

The packet is deliberately fail-closed: takeover is blocked unless the core
handoff artifacts are present and parseable enough to bound the state given to
Claude/Kimi/Minimax. Commit-mining next jobs are optional because not every
handoff round has fresh history-mining work queued, but current commit scan
tasks are required when deciding takeover readiness.
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NamedTuple


PROVIDERS = {
    "claude": {"display_name": "Claude", "target_packet_tokens": 60_000},
    "kimi": {"display_name": "Kimi", "target_packet_tokens": 48_000},
    "minimax": {"display_name": "Minimax", "target_packet_tokens": 48_000},
}

OBSIDIAN_ENTRYPOINT_REPORTS = (
    "reports/obsidian_memory_entrypoints_*.json",
    "reports/obsidian_memory_entrypoints.json",
)
OBSIDIAN_ENTRYPOINT_NOTE = (
    "obsidian memory entrypoint report is not present; artifact discovery is "
    "limited to repo-local paths until reports/obsidian_memory_entrypoints_2026-05-05.json "
    "is generated"
)

READY = "READY"
WARN = "WARN"
BLOCKED = "BLOCKED"


class ArtifactSpec(NamedTuple):
    key: str
    category: str
    label: str
    required: bool
    candidates: tuple[str, ...]


ARTIFACT_SPECS: tuple[ArtifactSpec, ...] = (
    ArtifactSpec(
        key="shared_memory_index",
        category="context",
        label="shared-memory index",
        required=True,
        candidates=(
            "reports/shared_memory_index_*.json",
            "reports/shared_memory_index.json",
            "reports/shared-memory-index.json",
            "docs/SHARED_MEMORY_INDEX_*.md",
            "docs/SHARED_MEMORY_INDEX.md",
            "docs/shared-memory-index.md",
            "agent_outputs/shared_memory_index.json",
            "agent_outputs/shared-memory-index.json",
            "agent_outputs/*shared*memory*index*.json",
            "agent_outputs/*shared*memory*index*.md",
            "agent_outputs/*prior_index*.json",
        ),
    ),
    ArtifactSpec(
        key="memory_brief",
        category="context",
        label="memory brief",
        required=True,
        candidates=(
            "reports/memory_brief_*.json",
            "reports/memory_brief.json",
            "reports/memory-brief.json",
            "docs/MEMORY_BRIEF_*.md",
            "docs/MEMORY_BRIEF.md",
            "docs/memory-brief.md",
            "agent_outputs/memory_brief.json",
            "agent_outputs/memory-brief.md",
            "agent_outputs/*memory*brief*.json",
            "agent_outputs/*memory*brief*.md",
        ),
    ),
    ArtifactSpec(
        key="known_limitations_dispatch",
        category="limits",
        label="known limitations dispatch",
        required=True,
        candidates=(
            "reports/known_limitations_dispatch_*.json",
            "reports/known_limitations_dispatch.json",
            "reports/known-limitations-dispatch.json",
            "docs/KNOWN_LIMITATIONS_DISPATCH_*.md",
            "docs/KNOWN_LIMITATIONS_DISPATCH.md",
            "docs/KNOWN_LIMITATIONS.md",
            "agent_outputs/known_limitations_dispatch.json",
            "agent_outputs/*known*limitations*dispatch*.json",
            "agent_outputs/*known*limitations*dispatch*.md",
        ),
    ),
    ArtifactSpec(
        key="scanner_wiring_burndown",
        category="known_limitation_burndown",
        label="scanner wiring burndown",
        required=True,
        candidates=(
            "reports/known_limitations_harness_memory_status_2026-05-05.json",
            "reports/known_limitations_harness_memory_status_*.json",
            "reports/scanner_wiring_burndown_queue_*.json",
            "reports/scanner_wiring_burndown_*.json",
            "reports/scanner_wiring_burndown_queue.json",
            "reports/scanner-wiring-burndown.json",
            "docs/SCANNER_WIRING_BURNDOWN_QUEUE_*.md",
            "docs/SCANNER_WIRING_BURNDOWN_*.md",
            "agent_outputs/*scanner*wiring*burndown*.json",
            "agent_outputs/*scanner*wiring*burndown*.md",
        ),
    ),
    ArtifactSpec(
        key="harness_execution_queue",
        category="harness",
        label="harness execution queue",
        required=True,
        candidates=(
            "reports/harness_execution_queue_*.json",
            "reports/harness_execution_queue.json",
            "reports/harness-execution-queue.json",
            "docs/HARNESS_EXECUTION_QUEUE_*.md",
            "docs/HARNESS_EXECUTION_QUEUE.md",
            "agent_outputs/harness_execution_queue.json",
            "agent_outputs/*harness*execution*queue*.json",
            "agent_outputs/*harness*queue*.json",
            "agent_outputs/*harness*execution*queue*.md",
            "agent_outputs/*harness*queue*.md",
        ),
    ),
    ArtifactSpec(
        key="source_mirror_verify",
        category="source",
        label="source mirror verify",
        required=True,
        candidates=(
            "reports/source_mirror_verify_*.json",
            "reports/source_mirror_verify.json",
            "reports/source-mirror-verify.json",
            "docs/SOURCE_MIRROR_VERIFY_*.md",
            "docs/SOURCE_MIRROR_VERIFY.md",
            "agent_outputs/source_mirror_verify.json",
            "agent_outputs/*source*mirror*verify*.json",
            "agent_outputs/*source*mirror*verified*.json",
            "agent_outputs/*source*mirror*verify*.md",
        ),
    ),
    ArtifactSpec(
        key="source_mirror_queue",
        category="source",
        label="source mirror queue",
        required=False,
        candidates=(
            "reports/source_mirror_queue_*.json",
            "reports/source_mirror_queue.json",
            "reports/source-mirror-queue.json",
            "docs/SOURCE_MIRROR_QUEUE_*.md",
            "docs/SOURCE_MIRROR_QUEUE.md",
            "agent_outputs/source_mirror_queue.json",
            "agent_outputs/*source*mirror*queue*.json",
            "agent_outputs/*source*mirror*queue*.md",
        ),
    ),
    ArtifactSpec(
        key="commit_mining_next_jobs",
        category="commit_mining",
        label="commit-mining next jobs",
        required=False,
        candidates=(
            "reports/commit_mining_next_jobs_*.json",
            "reports/commit_mining_next_jobs.json",
            "reports/commit-mining-next-jobs.json",
            "docs/COMMIT_MINING_NEXT_JOBS_*.md",
            "docs/COMMIT_MINING_NEXT_JOBS.md",
            "docs/archive/MINING_BACKLOG.md",
            "docs/archive/MINING_PRIORITIES.md",
            "agent_outputs/commit_mining_next_jobs.json",
            "agent_outputs/*commit*mining*next*.json",
            "agent_outputs/*commit*mining*jobs*.json",
            "agent_outputs/*commit*mining*next*.md",
        ),
    ),
    ArtifactSpec(
        key="commit_mining_scan_tasks",
        category="commit_mining",
        label="commit-mining scan tasks",
        required=True,
        candidates=(
            "reports/commit_mining_scan_tasks_*.json",
            "reports/commit_mining_scan_tasks.json",
            "reports/commit-mining-scan-tasks.json",
            "docs/COMMIT_MINING_SCAN_TASKS_*.md",
            "docs/COMMIT_MINING_SCAN_TASKS.md",
            "agent_outputs/commit_mining_scan_tasks.json",
            "agent_outputs/*commit*mining*scan*tasks*.json",
            "agent_outputs/*commit*scan*tasks*.json",
            "agent_outputs/*commit*mining*scan*tasks*.md",
        ),
    ),
)


def utc_now() -> str:
    return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _append_unique(paths: list[Path], path: Path) -> None:
    try:
        resolved = path.expanduser().resolve()
    except OSError:
        resolved = path.expanduser()
    if resolved not in paths and resolved.exists():
        paths.append(resolved)


def _entrypoint_reports(root: Path) -> list[Path]:
    reports = []
    for pattern in OBSIDIAN_ENTRYPOINT_REPORTS:
        reports.extend(sorted(root.glob(pattern)))
    return reports


def discovery_dependency_notes(root: Path) -> list[dict[str, str]]:
    reports = _entrypoint_reports(root)
    if not reports:
        return [
            {
                "key": "obsidian_memory_entrypoints",
                "severity": "note",
                "message": OBSIDIAN_ENTRYPOINT_NOTE,
            }
        ]

    invalid_reports = []
    for report in reports:
        try:
            json.loads(read_text(report))
        except json.JSONDecodeError as exc:
            invalid_reports.append(f"{report}: {exc}")
    if invalid_reports:
        return [
            {
                "key": "obsidian_memory_entrypoints",
                "severity": "note",
                "message": (
                    "obsidian memory entrypoint report was present but one or more "
                    f"files could not be parsed and were ignored: {'; '.join(invalid_reports)}"
                ),
            }
        ]
    return []


def artifact_search_roots(root: Path) -> list[Path]:
    roots: list[Path] = []
    _append_unique(roots, root)
    for report in _entrypoint_reports(root):
        try:
            payload = json.loads(read_text(report))
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            for key in ("memory_root", "repo_root"):
                value = payload.get(key)
                if isinstance(value, str) and value.strip():
                    _append_unique(roots, Path(value))
            for row in payload.get("candidate_memory_roots", []):
                if isinstance(row, dict):
                    value = row.get("path")
                    if isinstance(value, str) and value.strip():
                        _append_unique(roots, Path(value))
    return roots


def discover_artifact(root: Path, spec: ArtifactSpec) -> Path | None:
    search_roots = artifact_search_roots(root)
    for pattern in spec.candidates:
        for search_root in search_roots:
            if any(ch in pattern for ch in "*?["):
                matches = sorted(path for path in search_root.glob(pattern) if path.is_file())
                if matches:
                    return matches[0]
                continue
            path = search_root / pattern
            if path.is_file():
                return path
    return None


def _first_list(payload: Any) -> list[Any] | None:
    if isinstance(payload, list):
        return payload
    if not isinstance(payload, dict):
        return None
    for key in (
        "items",
        "jobs",
        "queue",
        "tasks",
        "entries",
        "limitations",
        "briefs",
        "artifacts",
        "checks",
        "results",
        "next_jobs",
        "attack_angles",
        "angles",
        "rows",
        "queue_rows",
        "work_items",
        "next_worker_slots",
        "actions",
        "top_ready_now",
        "blocked_backlog",
        "maintenance_backlog",
        "command_rows",
        "ready_commands",
        "blocked_commands",
        "scan_tasks",
        "skipped_jobs",
        "preserved_blockers",
    ):
        value = payload.get(key)
        if isinstance(value, list):
            return value
    return None


def _status_from_value(value: Any) -> str | None:
    if isinstance(value, dict):
        for key in ("status", "state", "result", "verdict", "gate"):
            raw = value.get(key)
            if raw is not None:
                return str(raw).strip().lower()
    if isinstance(value, str):
        return value.strip().lower()
    return None


def _json_items(payload: Any) -> list[dict[str, Any]]:
    rows = _first_list(payload)
    if rows is None:
        if isinstance(payload, dict):
            return [payload]
        return []
    out: list[dict[str, Any]] = []
    for idx, row in enumerate(rows):
        if isinstance(row, dict):
            out.append(row)
        else:
            out.append({"value": row, "index": idx})
    return out


def _is_harness_memory_status_payload(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return False
    schema = str(payload.get("schema") or "")
    return (
        "known_limitations_harness_memory_status" in schema
        or "scanner_burndown_snapshot" in payload
    )


def _scanner_burndown_snapshot(payload: Any) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    snapshot = payload.get("scanner_burndown_snapshot")
    if isinstance(snapshot, dict):
        return snapshot
    return None


def _scanner_json_items(payload: Any) -> tuple[list[dict[str, Any]], str | None]:
    if _is_harness_memory_status_payload(payload):
        scanner_snapshot = _scanner_burndown_snapshot(payload)
        if scanner_snapshot is None:
            return [], "missing scanner_burndown_snapshot object"
        slots = scanner_snapshot.get("next_worker_slots")
        if not isinstance(slots, list):
            return [], "missing scanner_burndown_snapshot.next_worker_slots list"
        items: list[dict[str, Any]] = []
        for idx, slot in enumerate(slots):
            if isinstance(slot, dict):
                items.append(slot)
            else:
                items.append({"value": slot, "index": idx})
        return items, None
    return _json_items(payload), None


def _merge_status_counts(
    status_counts: dict[str, int], raw: Any, *, overwrite_existing: bool = False
) -> None:
    if not isinstance(raw, dict):
        return
    for key, value in raw.items():
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)) and value > 0:
            status = str(key).strip().lower()
            if status in status_counts and not overwrite_existing:
                continue
            status_counts[status] = int(value)


def _status_counts_from_payload(payload: Any, items: list[dict[str, Any]]) -> dict[str, int]:
    status_counts: dict[str, int] = {}
    for item in items:
        status = _status_from_value(item)
        if status:
            status_counts[status] = status_counts.get(status, 0) + 1
    if isinstance(payload, dict):
        _merge_status_counts(status_counts, payload.get("status_counts"))
        _merge_status_counts(status_counts, payload.get("counts_by_status"))
        _merge_status_counts(status_counts, payload.get("counts"))
        summary = payload.get("summary")
        if isinstance(summary, dict):
            _merge_status_counts(status_counts, summary.get("status_counts"))
    return status_counts


def _bounded_count_map(raw: Any, max_items: int = 20) -> dict[str, int]:
    if not isinstance(raw, dict):
        return {}
    out: dict[str, int] = {}
    for key, value in raw.items():
        if len(out) >= max_items:
            break
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            out[str(key)] = int(value)
    return out


def _collect_relevant_counts(value: Any, prefix: str = "") -> dict[str, int]:
    counts: dict[str, int] = {}
    if not isinstance(value, dict):
        return counts
    for key, child in value.items():
        full_key = f"{prefix}.{key}" if prefix else str(key)
        lowered = full_key.lower()
        is_relevant = (
            "skip" in lowered
            or "already" in lowered
            or "committed" in lowered
            or ("closed" in lowered and "fail_closed" not in lowered)
        )
        if isinstance(child, bool):
            continue
        if isinstance(child, (int, float)) and is_relevant:
            counts[full_key] = int(child)
        elif isinstance(child, list) and is_relevant:
            counts[full_key] = len(child)
        elif isinstance(child, dict):
            counts.update(_collect_relevant_counts(child, full_key))
        if len(counts) >= 20:
            break
    return dict(list(counts.items())[:20])


def _scanner_status_counts_from_payload(
    payload: Any, items: list[dict[str, Any]]
) -> dict[str, int]:
    status_counts = _status_counts_from_payload(payload, items)
    scanner_snapshot = _scanner_burndown_snapshot(payload)
    if scanner_snapshot is not None:
        _merge_status_counts(status_counts, scanner_snapshot.get("status_counts"))
        snapshot_status = scanner_snapshot.get("status")
        if isinstance(snapshot_status, str) and snapshot_status.strip():
            status_counts.setdefault(snapshot_status.strip().lower(), 1)
    return status_counts


def _scanner_snapshot_summary(payload: Any) -> dict[str, Any]:
    scanner_snapshot = _scanner_burndown_snapshot(payload)
    if scanner_snapshot is None:
        return {}
    summary: dict[str, Any] = {}
    for key in (
        "path",
        "present",
        "schema",
        "status",
        "actionable_row_count",
        "top_action_count",
        "worker_slot_cap",
        "skipped_worker_slot_count",
        "strict_caveat",
    ):
        value = scanner_snapshot.get(key)
        if isinstance(value, (str, int, float, bool)):
            summary[key] = value
    slots = scanner_snapshot.get("next_worker_slots")
    if isinstance(slots, list):
        summary["worker_slot_count"] = len(slots)
    for key in (
        "top_action_lane_counts",
        "lane_counts",
        "status_counts",
        "blocker_counts",
        "worker_slot_coordination_counts",
        "scanner_worker_next_rows",
    ):
        counts = _bounded_count_map(scanner_snapshot.get(key))
        if counts:
            summary[key] = counts
    selector_counts: dict[str, int] = {}
    for source_key in (
        "selector_summary",
        "selection_summary",
        "selection_rationale",
        "scanner_selector_summary",
    ):
        selector_counts.update(_collect_relevant_counts(scanner_snapshot.get(source_key)))
    selector_counts.update(_collect_relevant_counts(scanner_snapshot))
    if selector_counts:
        summary["selector_skipped_or_already_counts"] = selector_counts
    guidance = scanner_snapshot.get("scanner_coordination_guidance")
    if isinstance(guidance, dict):
        summary["scanner_coordination_guidance"] = {
            "do_not_redispatch_statuses": [
                str(item)[:80]
                for item in (
                    guidance.get("do_not_redispatch_statuses")
                    if isinstance(guidance.get("do_not_redispatch_statuses"), list)
                    else []
                )[:6]
            ],
            "do_not_redispatch_sample_row_ids": [
                str(item)[:120]
                for item in (
                    guidance.get("do_not_redispatch_sample_row_ids")
                    if isinstance(guidance.get("do_not_redispatch_sample_row_ids"), list)
                    else []
                )[:10]
            ],
            "refresh_inventory_before_more_detector_assignments": bool(
                guidance.get("refresh_inventory_before_more_detector_assignments")
            ),
            "refresh_recommended_statuses": [
                str(item)[:80]
                for item in (
                    guidance.get("refresh_recommended_statuses")
                    if isinstance(guidance.get("refresh_recommended_statuses"), list)
                    else []
                )[:6]
            ],
            "reason": str(guidance.get("reason") or "")[:260],
        }
    skipped_slots = scanner_snapshot.get("skipped_worker_slots")
    if isinstance(skipped_slots, list):
        summary["skipped_worker_slot_samples"] = [
            _bounded_scanner_worker_slot(slot)
            | {
                "skip_reason": str(slot.get("skip_reason") or "")[:120],
                "committed_after_queue_paths": [
                    str(path)
                    for path in (
                        slot.get("committed_after_queue_paths")
                        if isinstance(slot.get("committed_after_queue_paths"), list)
                        else []
                    )[:6]
                ],
            }
            for slot in skipped_slots[:10]
            if isinstance(slot, dict)
        ]
    return summary


def _markdown_items(text: str) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith(("- ", "* ", "+ ")):
            items.append({"summary": stripped[2:].strip()})
        elif re.match(r"^#{1,4}\s+\S", stripped):
            items.append({"summary": re.sub(r"^#{1,4}\s+", "", stripped)})
    if not items and text.strip():
        first = " ".join(text.strip().split()[:18])
        items.append({"summary": first})
    return items


def _estimate_tokens_from_words(word_count: int) -> int:
    return int(math.ceil(word_count * 1.33))


def _word_count_from_payload(payload: Any, fallback_text: str) -> int:
    if fallback_text:
        return len(fallback_text.split())
    return len(json.dumps(payload, sort_keys=True).split())


def _summarize_item(item: dict[str, Any]) -> str:
    for key in (
        "summary",
        "title",
        "name",
        "id",
        "row_id",
        "task_id",
        "source_row_id",
        "path",
        "file",
        "job",
        "task",
    ):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return " ".join(value.strip().split())[:180]
    status = _status_from_value(item)
    if status:
        return f"status={status}"
    return json.dumps(item, sort_keys=True)[:180]


def _bounded_scanner_worker_slot(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "slot_id": str(item.get("slot_id") or ""),
        "row_id": str(item.get("row_id") or ""),
        "lane": str(item.get("lane") or ""),
        "model_hint": str(item.get("model_hint") or ""),
        "task_kind": str(item.get("task_kind") or ""),
        "local_coordination_status": str(item.get("local_coordination_status") or ""),
        "coordination_note": str(item.get("coordination_note") or "")[:240],
        "matching_dirty_paths": [
            str(path)
            for path in (
                item.get("matching_dirty_paths")
                if isinstance(item.get("matching_dirty_paths"), list)
                else []
            )[:6]
        ],
        "local_evidence_paths": [
            str(path)
            for path in (
                item.get("local_evidence_paths")
                if isinstance(item.get("local_evidence_paths"), list)
                else []
            )[:6]
        ],
        "owned_paths": [
            str(path)
            for path in (item.get("owned_paths") if isinstance(item.get("owned_paths"), list) else [])[:6]
        ],
        "acceptance_criteria": [
            str(criterion)
            for criterion in (
                item.get("acceptance_criteria") if isinstance(item.get("acceptance_criteria"), list) else []
            )[:4]
        ],
    }


def _bounded_item_row(spec: ArtifactSpec, item: dict[str, Any], idx: int) -> dict[str, Any]:
    row: dict[str, Any] = {
        "index": idx,
        "summary": _summarize_item(item),
        "status": _status_from_value(item),
    }
    if spec.key == "scanner_wiring_burndown":
        row["worker_slot"] = _bounded_scanner_worker_slot(item)
    return row


def load_artifact(root: Path, spec: ArtifactSpec, max_items: int) -> dict[str, Any]:
    path = discover_artifact(root, spec)
    if path is None:
        return {
            "key": spec.key,
            "category": spec.category,
            "label": spec.label,
            "required": spec.required,
            "present": False,
            "path": None,
            "format": None,
            "item_count": 0,
            "bounded_item_count": 0,
            "status_counts": {},
            "parse_error": None,
            "est_raw_tokens": 0,
            "est_bounded_tokens": 0,
            "bounded_items": [],
        }

    rel = path.relative_to(root) if path.is_relative_to(root) else path
    source_root = next(
        (candidate for candidate in artifact_search_roots(root) if path.is_relative_to(candidate)),
        path.parent,
    )
    source_root_display = (
        str(source_root.relative_to(root)) if source_root.is_relative_to(root) else str(source_root)
    )
    text = read_text(path)
    suffix = path.suffix.lower()
    parse_error: str | None = None
    payload: Any = None
    items: list[dict[str, Any]]
    fmt = "text"
    if suffix == ".json":
        fmt = "json"
        try:
            payload = json.loads(text)
            if spec.key == "scanner_wiring_burndown":
                items, extraction_error = _scanner_json_items(payload)
                parse_error = extraction_error
            else:
                items = _json_items(payload)
        except json.JSONDecodeError as exc:
            parse_error = f"invalid JSON: {exc}"
            items = []
    else:
        fmt = "markdown" if suffix in {".md", ".markdown"} else "text"
        items = _markdown_items(text)

    if spec.key == "scanner_wiring_burndown":
        status_counts = _scanner_status_counts_from_payload(payload, items)
    else:
        status_counts = _status_counts_from_payload(payload, items)

    word_count = _word_count_from_payload(payload, text)
    all_summary_words = sum(len(_summarize_item(item).split()) + 8 for item in items)
    raw_tokens = max(
        _estimate_tokens_from_words(word_count),
        _estimate_tokens_from_words(all_summary_words + 24),
    )
    bounded = items[:max_items]
    bounded_summaries = [_bounded_item_row(spec, item, idx) for idx, item in enumerate(bounded)]
    bounded_words = sum(len(row["summary"].split()) + 8 for row in bounded_summaries)
    bounded_tokens = _estimate_tokens_from_words(bounded_words + 24)
    extra: dict[str, Any] = {}
    if spec.key == "scanner_wiring_burndown":
        snapshot_summary = _scanner_snapshot_summary(payload)
        if snapshot_summary:
            extra["snapshot_summary"] = snapshot_summary

    return {
        "key": spec.key,
        "category": spec.category,
        "label": spec.label,
        "required": spec.required,
        "present": True,
        "path": str(rel),
        "source_root": source_root_display,
        "format": fmt,
        "item_count": len(items),
        "bounded_item_count": len(bounded),
        "status_counts": status_counts,
        "parse_error": parse_error,
        "est_raw_tokens": raw_tokens,
        "est_bounded_tokens": bounded_tokens,
        "bounded_items": bounded_summaries,
        **extra,
    }


def _has_bad_status(status_counts: dict[str, int]) -> bool:
    bad_tokens = ("fail", "failed", "error", "blocked", "missing", "invalid")
    return any(any(tok in status for tok in bad_tokens) for status in status_counts)


def _source_verify_has_positive_status(artifact: dict[str, Any]) -> bool:
    if not artifact["present"] or artifact.get("parse_error"):
        return False
    status_counts = artifact.get("status_counts", {})
    if not status_counts:
        return True
    good_tokens = ("pass", "passed", "ok", "ready", "verified", "clean")
    return any(any(tok in status for tok in good_tokens) for status in status_counts)


def _harness_queue_has_runnable_signal(artifact: dict[str, Any]) -> bool:
    if not artifact["present"] or artifact.get("parse_error"):
        return False
    status_counts = artifact.get("status_counts", {})
    runnable_tokens = ("ready", "queued", "runnable", "execute")
    if any(
        count > 0 and any(token in status for token in runnable_tokens)
        for status, count in status_counts.items()
    ):
        return True
    return False


def evaluate_categories(artifacts: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    by_key = {a["key"]: a for a in artifacts}
    categories = {
        "context": {
            "label": "Context transfer",
            "requires": ["shared_memory_index", "memory_brief"],
            "optional": [],
            "blockers": [],
            "warnings": [],
        },
        "limits": {
            "label": "Known limitations",
            "requires": ["known_limitations_dispatch"],
            "optional": [],
            "blockers": [],
            "warnings": [],
        },
        "known_limitation_burndown": {
            "label": "Known limitation burndown",
            "requires": ["scanner_wiring_burndown"],
            "optional": [],
            "blockers": [],
            "warnings": [],
        },
        "harness": {
            "label": "Harness execution",
            "requires": ["harness_execution_queue"],
            "optional": [],
            "blockers": [],
            "warnings": [],
        },
        "source": {
            "label": "Source mirror",
            "requires": ["source_mirror_verify"],
            "optional": ["source_mirror_queue"],
            "blockers": [],
            "warnings": [],
        },
        "commit_mining": {
            "label": "Commit-mining scan tasks",
            "requires": ["commit_mining_scan_tasks"],
            "optional": ["commit_mining_next_jobs"],
            "blockers": [],
            "warnings": [],
        },
    }

    for category in categories.values():
        for key in category["requires"]:
            artifact = by_key[key]
            if not artifact["present"]:
                category["blockers"].append(f"missing required {artifact['label']}")
            elif artifact.get("parse_error"):
                category["blockers"].append(
                    f"{artifact['label']} parse failed: {artifact['parse_error']}"
                )
            elif artifact["item_count"] == 0:
                category["warnings"].append(f"{artifact['label']} is present but empty")
            elif _has_bad_status(artifact.get("status_counts", {})):
                category["warnings"].append(
                    f"{artifact['label']} contains failing/blocked status rows"
                )
        for key in category["optional"]:
            artifact = by_key[key]
            if artifact["present"] and artifact.get("parse_error"):
                category["warnings"].append(
                    f"optional {artifact['label']} parse failed: {artifact['parse_error']}"
                )

    scanner_burndown = by_key["scanner_wiring_burndown"]
    if scanner_burndown["present"] and not scanner_burndown.get("parse_error"):
        status_counts = scanner_burndown.get("status_counts", {})
        if not any(
            key in status_counts
            for key in (
                "open_actions_present",
                "generated_no_fixture",
                "dsl_only_or_unverified",
                "unclaimed_from_local_checkout",
            )
        ):
            categories["known_limitation_burndown"]["warnings"].append(
                "scanner wiring burndown has no open scanner-action signal in bounded status counts"
            )
        if scanner_burndown.get("item_count", 0) == 0:
            categories["known_limitation_burndown"]["warnings"].append(
                "scanner wiring burndown is present but exposes no actions or worker slots"
            )

    harness_queue = by_key["harness_execution_queue"]
    if (
        harness_queue["present"]
        and not harness_queue.get("parse_error")
        and harness_queue.get("item_count", 0) > 0
        and not _harness_queue_has_runnable_signal(harness_queue)
    ):
        categories["harness"]["warnings"].append(
            "harness execution queue has no ready/queued runnable command rows"
        )

    source_verify = by_key["source_mirror_verify"]
    if source_verify["present"] and not _source_verify_has_positive_status(source_verify):
        categories["source"]["blockers"].append(
            "source mirror verify has no positive pass/ok/verified status"
        )

    for category in categories.values():
        if category["blockers"]:
            category["status"] = BLOCKED
        elif category["warnings"]:
            category["status"] = WARN
        else:
            category["status"] = READY
    return categories


def provider_gates(categories: dict[str, dict[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    category_statuses = {key: value["status"] for key, value in categories.items()}
    blocker_count = sum(len(value["blockers"]) for value in categories.values())
    warning_count = sum(len(value["warnings"]) for value in categories.values())
    for provider, meta in PROVIDERS.items():
        status = BLOCKED if blocker_count else (WARN if warning_count else READY)
        readiness = max(0, min(100, 100 - blocker_count * 22 - warning_count * 4))
        out[provider] = {
            "display_name": meta["display_name"],
            "status": status,
            "readiness_estimate_percent": readiness,
            "target_packet_tokens": meta["target_packet_tokens"],
            "category_statuses": category_statuses,
        }
    return out


def readiness_counts(gates: dict[str, Any]) -> dict[str, int]:
    counts = {READY: 0, WARN: 0, BLOCKED: 0}
    for gate in gates.values():
        counts[gate["status"]] = counts.get(gate["status"], 0) + 1
    return counts


def build_packet(root: Path, max_items: int = 12) -> dict[str, Any]:
    root = root.expanduser().resolve()
    search_roots = artifact_search_roots(root)
    artifacts = [load_artifact(root, spec, max_items) for spec in ARTIFACT_SPECS]
    categories = evaluate_categories(artifacts)
    gates = provider_gates(categories)
    raw_tokens = sum(int(a["est_raw_tokens"]) for a in artifacts)
    bounded_tokens = sum(int(a["est_bounded_tokens"]) for a in artifacts)
    token_savings = max(0, raw_tokens - bounded_tokens)
    blockers = [
        {"category": key, "message": blocker}
        for key, category in categories.items()
        for blocker in category["blockers"]
    ]
    warnings = [
        {"category": key, "message": warning}
        for key, category in categories.items()
        for warning in category["warnings"]
    ]
    return {
        "schema": "auditooor.model_takeover_readiness.v1",
        "generated_at": utc_now(),
        "root": str(root),
        "bounds": {
            "max_items_per_artifact": max_items,
            "providers": list(PROVIDERS),
            "categories": list(categories),
            "artifact_search_roots": [str(path) for path in search_roots],
            "obsidian_entrypoint_reports": [str(path) for path in _entrypoint_reports(root)],
        },
        "artifacts": artifacts,
        "categories": categories,
        "provider_gates": gates,
        "readiness_counts": readiness_counts(gates),
        "token_estimates": {
            "est_raw_tokens": raw_tokens,
            "est_bounded_packet_tokens": bounded_tokens,
            "est_token_savings": token_savings,
            "est_token_savings_percent": (
                round((token_savings / raw_tokens) * 100.0, 2) if raw_tokens else 0.0
            ),
        },
        "fail_closed_blockers": blockers,
        "warnings": warnings,
        "dependency_notes": discovery_dependency_notes(root),
    }


def render_markdown(packet: dict[str, Any]) -> str:
    lines = [
        "# Model Takeover Readiness Packet",
        "",
        f"Generated: {packet['generated_at']}",
        f"Root: `{packet['root']}`",
        "",
    ]
    if packet.get("dependency_notes"):
        lines.extend(["## Dependency notes", ""])
        for note in packet["dependency_notes"]:
            lines.append(f"- {note['message']}")
        lines.append("")

    lines.extend(
        [
            "## Provider gates",
            "",
            "| Provider | Status | Readiness estimate | Target packet tokens |",
            "|---|---:|---:|---:|",
        ]
    )
    for gate in packet["provider_gates"].values():
        lines.append(
            f"| {gate['display_name']} | {gate['status']} | "
            f"{gate['readiness_estimate_percent']}% | {gate['target_packet_tokens']} |"
        )
    lines.extend(["", "## Category gates", ""])
    lines.append("| Category | Status | Blockers | Warnings |")
    lines.append("|---|---:|---|---|")
    for key, category in packet["categories"].items():
        blockers = "<br>".join(category["blockers"]) or "-"
        warnings = "<br>".join(category["warnings"]) or "-"
        lines.append(f"| {category['label']} | {category['status']} | {blockers} | {warnings} |")
    lines.extend(["", "## Token estimates", ""])
    te = packet["token_estimates"]
    lines.append(f"- Raw artifact estimate: {te['est_raw_tokens']} tokens")
    lines.append(f"- Bounded packet estimate: {te['est_bounded_packet_tokens']} tokens")
    lines.append(
        f"- Estimated savings: {te['est_token_savings']} tokens "
        f"({te['est_token_savings_percent']}%)"
    )
    lines.extend(["", "## Consumed artifacts", ""])
    lines.append("| Artifact | Present | Source root | Path | Items | Bounded items | Parse |")
    lines.append("|---|---:|---|---|---:|---:|---|")
    for artifact in packet["artifacts"]:
        parse = artifact["parse_error"] or "ok"
        path = f"`{artifact['path']}`" if artifact["path"] else "-"
        source_root = f"`{artifact.get('source_root', '-')}`" if artifact["path"] else "-"
        lines.append(
            f"| {artifact['label']} | {str(artifact['present']).lower()} | {source_root} | {path} | "
            f"{artifact['item_count']} | {artifact['bounded_item_count']} | {parse} |"
        )
    if packet["fail_closed_blockers"]:
        lines.extend(["", "## Fail-Closed Blockers", ""])
        for blocker in packet["fail_closed_blockers"]:
            lines.append(f"- **{blocker['category']}**: {blocker['message']}")
    return "\n".join(lines) + "\n"


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Offline fail-closed readiness packet for model takeover.",
    )
    parser.add_argument("--root", default=".", help="auditooor repo root (default: cwd)")
    parser.add_argument(
        "--out",
        default="reports/model_takeover_readiness_2026-05-05.json",
        help="JSON report path",
    )
    parser.add_argument(
        "--doc",
        default="docs/MODEL_TAKEOVER_READINESS_2026-05-05.md",
        help="Markdown packet path",
    )
    parser.add_argument("--json", action="store_true", help="print JSON to stdout")
    parser.add_argument(
        "--max-items-per-artifact",
        type=int,
        default=12,
        help="bound copied rows per source artifact",
    )
    parser.add_argument(
        "--fail-on-blockers",
        action="store_true",
        help="exit 2 when fail-closed blockers are present",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    root = Path(args.root).expanduser()
    packet = build_packet(root, max(1, args.max_items_per_artifact))

    out = Path(args.out)
    doc = Path(args.doc)
    if not out.is_absolute():
        out = root / out
    if not doc.is_absolute():
        doc = root / doc
    write_json(out, packet)
    write_text(doc, render_markdown(packet))

    if args.json:
        print(json.dumps(packet, indent=2, sort_keys=True))
    else:
        counts = packet["readiness_counts"]
        print(
            "model-takeover readiness: "
            f"{READY}={counts.get(READY, 0)} "
            f"{WARN}={counts.get(WARN, 0)} "
            f"{BLOCKED}={counts.get(BLOCKED, 0)}"
        )
        if packet["fail_closed_blockers"]:
            print(f"fail-closed blockers: {len(packet['fail_closed_blockers'])}")
        print(f"json: {out}")
        print(f"doc: {doc}")

    if args.fail_on_blockers and packet["fail_closed_blockers"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
