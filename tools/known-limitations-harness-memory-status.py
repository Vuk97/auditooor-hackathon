#!/usr/bin/env python3
"""Emit a fail-closed harness/memory status packet from known-limitations reports."""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable


SCHEMA = "auditooor.known_limitations_harness_memory_status.v1"
DEFAULT_DATE = "2026-05-05"
FOCUS_LANES = ("harness_execution", "memory_handoff")
SCANNER_WORKER_SLOT_CAP = 11
SCANNER_WORKER_SLOT_SCAN_LIMIT = 50
ASSIGNABLE_SCANNER_COORDINATION_STATUSES = {"unclaimed_from_local_checkout"}
SCANNER_DO_NOT_REDISPATCH_STATUSES = {
    "already_committed",
    "claimed_active_registry",
    "claimed_dirty_worktree",
    "local_evidence_present_refresh_needed",
}
SCANNER_REFRESH_RECOMMENDED_STATUSES = {
    "already_committed",
    "local_evidence_present_refresh_needed",
}
KLBQ_002_FINDING_IDS = ("38333", "36418", "33463")
EXECUTION_PRIORITY_POLICY = {
    "priority_order": ["MEMORY", "HARNESS", "KNOWN LIMITATION BURNDOWN"],
    "deferred_lanes": ["github_admin", "front_facing_docs", "readme_refresh"],
    "agent_usage": (
        "Prefer end-to-end implementation workers for owned rows; coordinator reviews, "
        "integrates, refreshes shared memory at batch boundaries, and avoids review-only "
        "agent slots while executable closure work remains."
    ),
    "batch_boundary_rule": (
        "Refresh shared reports/memory/docs after a clean worker batch settles; avoid "
        "GitHub/admin/readme churn during the active memory/harness/KLB burndown lane."
    ),
}


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def default_burndown_path(root: Path) -> Path:
    return root / "reports" / f"known_limitations_burndown_queue_{DEFAULT_DATE}.json"


def default_dispatch_path(root: Path) -> Path:
    return root / "reports" / f"known_limitations_dispatch_{DEFAULT_DATE}.json"


def default_scanner_burndown_queue_path(root: Path) -> Path:
    fallback = f"reports/scanner_wiring_burndown_queue_{DEFAULT_DATE}.json"
    return root / _latest_valid_report_rel_path(
        root,
        "scanner_wiring_burndown_queue",
        fallback,
        _scanner_queue_report_compatible,
    )


def default_scanner_worker_active_claims_path(root: Path) -> Path:
    fallback = f"reports/scanner_worker_active_claims_{DEFAULT_DATE}.json"
    return root / _latest_report_rel_path(root, "scanner_worker_active_claims", fallback)


def default_commit_mining_source_disposition_path(root: Path) -> Path:
    fallback = f"reports/commit_mining_source_disposition_{DEFAULT_DATE}.json"
    return root / _latest_report_rel_path(root, "commit_mining_source_disposition", fallback)


def default_output_path(root: Path) -> Path:
    return root / "reports" / f"known_limitations_harness_memory_status_{DEFAULT_DATE}.json"


def default_docs_path(root: Path) -> Path:
    return root / "docs" / f"KNOWN_LIMITATIONS_HARNESS_MEMORY_STATUS_{DEFAULT_DATE}.md"


def _report_sort_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _queue_loop_marker(path: Path) -> int:
    markers = re.findall(r"(?:^|[_-])l(\d+)(?:[_-]|$)", path.stem.lower())
    return max((_report_sort_int(marker) for marker in markers), default=0)


def _report_sort_key(path: Path, payload: dict[str, Any]) -> tuple[str, int, int, int, str]:
    dates = re.findall(r"\d{4}-\d{2}-\d{2}", path.name)
    return (
        dates[-1] if dates else "",
        _queue_loop_marker(path),
        _report_sort_int(payload.get("actionable_row_count")),
        _report_sort_int(payload.get("top_action_count")),
        path.name,
    )


def _latest_valid_report_rel_path(
    root: Path,
    stem: str,
    fallback_rel: str,
    validator: Callable[[dict[str, Any]], bool],
) -> str:
    reports_dir = root / "reports"
    if not reports_dir.is_dir():
        return fallback_rel
    candidates: list[tuple[Path, dict[str, Any]]] = []
    for path in reports_dir.glob(f"{stem}_*.json"):
        payload = _load_local_json(root, str(path.relative_to(root)))
        if validator(payload):
            candidates.append((path, payload))
    if candidates:
        path = max(candidates, key=lambda item: _report_sort_key(item[0], item[1]))[0]
        return str(path.relative_to(root))
    return fallback_rel


def _latest_report_rel_path(root: Path, stem: str, fallback_rel: str) -> str:
    return _latest_valid_report_rel_path(root, stem, fallback_rel, lambda packet: bool(packet))


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _safe_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    return []


def _safe_dict(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _scanner_queue_report_compatible(payload: dict[str, Any]) -> bool:
    if _safe_text(payload.get("schema")) != "auditooor.scanner_wiring_burndown_queue.v1":
        return False
    if isinstance(payload.get("actions"), list) and payload["actions"]:
        return True
    lane_top_actions = payload.get("lane_top_actions")
    if not isinstance(lane_top_actions, dict):
        return False
    return any(isinstance(rows, list) and rows for rows in lane_top_actions.values())


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _load_json_object(path: Path) -> tuple[dict[str, Any], list[str]]:
    issues: list[str] = []
    if not path.is_file():
        issues.append(f"missing input report: {path}")
        return {}, issues
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        issues.append(f"unable to load {path}: {exc}")
        return {}, issues
    if not isinstance(payload, dict):
        issues.append(f"expected object payload in {path}")
        return {}, issues
    return payload, issues


def _rel_or_abs(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _owner_lane_mentions_harness_memory(row: dict[str, Any]) -> bool:
    owner_lane = _safe_text(row.get("owner_lane")).lower()
    return "harness" in owner_lane or "memory" in owner_lane


def _existing_paths(root: Path, candidates: list[Any]) -> tuple[list[str], list[str]]:
    existing: list[str] = []
    missing: list[str] = []
    seen_existing: set[str] = set()
    seen_missing: set[str] = set()
    for candidate in candidates:
        text = _safe_text(candidate)
        if not text:
            continue
        candidate_path = Path(text)
        resolved = candidate_path if candidate_path.is_absolute() else root / candidate_path
        if resolved.exists():
            if text not in seen_existing:
                existing.append(text)
                seen_existing.add(text)
            continue
        if text not in seen_missing:
            missing.append(text)
            seen_missing.add(text)
    return existing, missing


def _row_blockers(row: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    for field in ("remaining_blockers", "blocked_until"):
        for item in _safe_list(row.get(field)):
            text = _safe_text(item)
            if text and text not in blockers:
                blockers.append(text)
    return blockers


def _normalized_blocker_key(text: str) -> str:
    lowered = text.strip().lower()
    if lowered.startswith("awaiting: "):
        lowered = lowered[len("awaiting: ") :]
    return lowered


def _dispatch_status_open(item: dict[str, Any]) -> bool:
    current_status = _safe_text(item.get("current_status"))
    if not current_status.startswith("implemented_verified"):
        return True
    if bool(item.get("dispatch_ready")):
        return True
    return int(item.get("expected_loop_cost") or 0) > 0


def _build_focus_row(
    root: Path,
    row_id: str,
    burndown_row: dict[str, Any],
    dispatch_item: dict[str, Any] | None,
    *,
    source: str,
) -> dict[str, Any]:
    evidence_candidates = _safe_list(burndown_row.get("local_evidence")) + _safe_list(burndown_row.get("source_refs"))
    burndown_evidence, burndown_missing = _existing_paths(root, evidence_candidates)
    if dispatch_item is None:
        return {
            "id": row_id,
            "source": source,
            "dispatch_lane": "missing_dispatch_item",
            "current_status": _safe_text(burndown_row.get("implementation_status")) or "unknown",
            "dispatch_ready": False,
            "expected_loop_cost": None,
            "owner_lane": _safe_text(burndown_row.get("owner_lane")),
            "next_action": _safe_text(burndown_row.get("concrete_next_patch")),
            "blockers": _row_blockers(burndown_row),
            "verification_commands": [
                _safe_text(command)
                for command in _safe_list(burndown_row.get("verification_commands"))
                if _safe_text(command)
            ],
            "evidence_paths": burndown_evidence,
            "missing_evidence_paths": burndown_missing,
            "status_notes": _safe_text(burndown_row.get("status_notes")),
            "not_submission_evidence": bool(burndown_row.get("not_submission_evidence", True)),
            "open": True,
        }

    blockers = list(_row_blockers(burndown_row))
    primary_blocker = _safe_text(dispatch_item.get("blocker"))
    blocker_keys = {_normalized_blocker_key(item) for item in blockers}
    if primary_blocker and _normalized_blocker_key(primary_blocker) not in blocker_keys:
        blockers.insert(0, primary_blocker)
    evidence_paths = [
        _safe_text(path)
        for path in _safe_list(dispatch_item.get("evidence_paths"))
        if _safe_text(path)
    ] or burndown_evidence
    missing_evidence_paths = [
        _safe_text(path)
        for path in _safe_list(dispatch_item.get("missing_evidence_paths"))
        if _safe_text(path)
    ] or burndown_missing
    return {
        "id": row_id,
        "source": source,
        "dispatch_lane": _safe_text(dispatch_item.get("dispatch_lane")),
        "current_status": _safe_text(dispatch_item.get("current_status")) or _safe_text(burndown_row.get("implementation_status")),
        "dispatch_ready": bool(dispatch_item.get("dispatch_ready")),
        "expected_loop_cost": dispatch_item.get("expected_loop_cost"),
        "scheduled_loop": dispatch_item.get("scheduled_loop"),
        "owner_lane": _safe_text(dispatch_item.get("owner_lane")) or _safe_text(burndown_row.get("owner_lane")),
        "next_action": _safe_text(dispatch_item.get("next_action")) or _safe_text(burndown_row.get("concrete_next_patch")),
        "blockers": blockers,
        "verification_commands": [
            _safe_text(command)
            for command in _safe_list(dispatch_item.get("verification_commands"))
            if _safe_text(command)
        ] or [
            _safe_text(command)
            for command in _safe_list(burndown_row.get("verification_commands"))
            if _safe_text(command)
        ],
        "evidence_paths": evidence_paths,
        "missing_evidence_paths": missing_evidence_paths,
        "status_notes": _safe_text(dispatch_item.get("status_notes")) or _safe_text(burndown_row.get("status_notes")),
        "not_submission_evidence": bool(burndown_row.get("not_submission_evidence", True)),
        "open": _dispatch_status_open(dispatch_item),
    }


def _file_contains(root: Path, rel_path: str, needles: tuple[str, ...]) -> bool:
    path = root / rel_path
    if not path.is_file():
        return False
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False
    return all(needle in text for needle in needles)


def _append_note(base: str, addition: str) -> str:
    if not addition:
        return base
    if not base:
        return addition
    if addition in base:
        return base
    return f"{base} {addition}"


def _load_local_json(root: Path, rel_path: str) -> dict[str, Any]:
    path = root / rel_path
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _smoke_passed(smoke: dict[str, Any]) -> bool:
    return (
        _safe_text(smoke.get("result")) == "pass"
        and _safe_int(smoke.get("positive_hits")) == 1
        and _safe_int(smoke.get("negative_hits")) == 0
    )


def _dedupe_text(items: list[Any]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for item in items:
        text = _safe_text(item)
        key = _normalized_blocker_key(text)
        if text and key not in seen:
            deduped.append(text)
            seen.add(key)
    return deduped


def _placeholder_tokens(command: str) -> list[str]:
    return _dedupe_text(re.findall(r"<[^>]+>", command))


def _build_action_plan(
    *,
    open_row: bool,
    actionable_now_commands: list[Any],
    blocked_command_templates: list[dict[str, Any]],
) -> dict[str, Any]:
    actionable = _dedupe_text(actionable_now_commands)
    blocked: list[dict[str, Any]] = []
    seen_blocked: set[tuple[str, tuple[str, ...], tuple[str, ...], tuple[str, ...]]] = set()
    for item in blocked_command_templates:
        if not isinstance(item, dict):
            continue
        command = _safe_text(item.get("command"))
        if not command:
            continue
        missing_inputs = _dedupe_text(_safe_list(item.get("missing_inputs")))
        expected_artifacts = _dedupe_text(_safe_list(item.get("expected_artifacts")))
        unblock_criteria = _dedupe_text(_safe_list(item.get("unblock_criteria")))
        key = (
            command,
            tuple(missing_inputs),
            tuple(expected_artifacts),
            tuple(unblock_criteria),
        )
        if key in seen_blocked:
            continue
        seen_blocked.add(key)
        blocked.append(
            {
                "command": command,
                "missing_inputs": missing_inputs,
                "expected_artifacts": expected_artifacts,
                "unblock_criteria": unblock_criteria,
            }
        )

    if not open_row:
        status = "completed_local_evidence"
    elif actionable and blocked:
        status = "actionable_now_with_blocked_followups"
    elif actionable:
        status = "ready_to_execute"
    elif blocked:
        status = "blocked_missing_runtime_inputs"
    else:
        status = "blocked_no_exact_command"

    return {
        "next_action_status": status,
        "actionable_now_commands": actionable,
        "blocked_command_templates": blocked,
    }


def _impact_contract_packet_closes_klbq_010(packet: dict[str, Any]) -> bool:
    return (
        _safe_text(packet.get("schema")) == "auditooor.impact_contract_preflight_status.v1"
        and _safe_text(packet.get("limitation_id")) == "KLBQ-010"
        and _safe_text(packet.get("implementation_status")).startswith("implemented_verified")
        and not bool(packet.get("open"))
        and not bool(packet.get("dispatch_ready"))
        and _safe_int(packet.get("expected_loop_cost")) == 0
        and bool(packet.get("not_submission_evidence", True))
    )


def _klbq_010_from_status_packet(packet: dict[str, Any], row: dict[str, Any]) -> dict[str, Any]:
    packet_path = "reports/impact_contract_preflight_status_2026-05-05.json"
    docs_path = "docs/IMPACT_CONTRACT_PREFLIGHT_STATUS_2026-05-05.md"
    closed_benefit = _safe_text(packet.get("closed_benefit"))
    refreshed = {
        "current_status": _safe_text(packet.get("implementation_status")),
        "dispatch_ready": False,
        "expected_loop_cost": 0,
        "scheduled_loop": None,
        "blockers": [],
        "verification_commands": _dedupe_text(_safe_list(packet.get("verification_commands"))),
        "evidence_paths": _dedupe_text(_safe_list(packet.get("evidence_paths")) + [packet_path, docs_path]),
        "status_notes": _append_note(
            _safe_text(row.get("status_notes")),
            (
                f"{closed_benefit} Local accounting only; this is not exploit proof, source proof, or submission proof."
            ).strip(),
        ),
        "not_submission_evidence": True,
        "local_status_packet": packet_path,
        "open": False,
    }
    refreshed.update(
        _build_action_plan(
            open_row=False,
            actionable_now_commands=refreshed.get("verification_commands", []),
            blocked_command_templates=[],
        )
    )
    return refreshed


def _klbq_006_terminal_boundary_ok(packet: dict[str, Any]) -> bool:
    boundary = _safe_dict(packet.get("rust_detector_boundary"))
    taxonomy = _safe_dict(packet.get("taxonomy_reconciliation"))
    return (
        _safe_text(packet.get("schema")) == "auditooor.klbq_006_terminal_boundary.v1"
        and _safe_text(packet.get("limitation_id")) == "KLBQ-006"
        and _safe_text(boundary.get("state")) == "terminal_inapplicable"
        and _safe_text(boundary.get("reason")) == "source_language_mismatch_solidity_root_without_rust_files"
        and boundary.get("can_interpret_detector_absence_as_clean_result") is False
        and packet.get("promotion_ready") is False
        and packet.get("verification_claim_allowed") is False
        and _safe_text(taxonomy.get("canonical_leaf_family"))
        == "safe-fallback-handler-setter-missing-address-guard"
        and _safe_text(taxonomy.get("parent_class")) == "input-validation"
        and _safe_text(taxonomy.get("input_validation_usage")) == "parent_or_alias_only"
        and bool(_safe_list(packet.get("exact_next_commands")))
    )


def _klbq_006_blockers(
    calibration_packet: dict[str, Any],
    precision_packet: dict[str, Any],
    anchors_packet: dict[str, Any],
    terminal_packet: dict[str, Any],
    replay_packet: dict[str, Any],
) -> list[str]:
    blockers: list[str] = []
    terminal_boundary_ok = _klbq_006_terminal_boundary_ok(terminal_packet)
    replay_status_ok = _klbq_006_solidity_replay_status_ok(replay_packet)
    promotion_blockers = _dedupe_text(_safe_list(calibration_packet.get("promotion_blockers")))
    if promotion_blockers:
        first = promotion_blockers[0]
        if terminal_boundary_ok and "taxonomy/coverage metadata" in first.lower():
            blockers.append(
                "Canonical KLBQ-006 taxonomy is reconciled locally, but repo-wide broad input-validation metadata remains outside this scoped patch."
            )
        else:
            blockers.append(first)

    anchor_classification = _safe_dict(anchors_packet.get("classification"))
    source_root_absent = _safe_text(anchor_classification.get("exact_renft_source_root")) == "absent"
    real_anchor_absent = _safe_text(anchor_classification.get("real_source_anchors")) == "absent"
    exact_blob_absent = _safe_text(anchor_classification.get("exact_finding_github_blob_anchors")) == "absent"
    if source_root_absent or real_anchor_absent:
        blockers.append(
            "Exact reNFT source root and real-source file/line anchors for Solodit #30522 are still absent locally."
        )
    elif exact_blob_absent:
        blockers.append(
            "Exact Solodit #30522 GitHub blob/file-line anchor is still absent; the local reNFT mirror is only a sibling/base source clue."
        )

    precision_missing_inputs = _dedupe_text(_safe_list(precision_packet.get("missing_or_insufficient_inputs")))
    real_target_limits = [
        item
        for item in precision_missing_inputs
        if "ground-truthed real-target clean corpus" in item.lower()
        or "real-source file/line anchors" in item.lower()
        or "source checkout" in item.lower()
    ]
    if real_target_limits:
        blockers.append(
            "Synthetic calibration evidence is clean, but no ground-truthed real-target replay/clean-corpus precision evidence exists yet."
        )

    if terminal_boundary_ok:
        blockers.append(
            "Rust detector replay is terminally inapplicable to the Solidity-only reNFT mirror; this is not a pass, negative replay, precision result, or exploit proof."
        )
    elif not source_root_absent and not real_anchor_absent:
        blockers.append(
            "Machine-readable KLBQ-006 terminal Rust-inapplicability boundary is absent or invalid for the Solidity mirror."
        )

    if replay_status_ok:
        blockers.append(
            "Machine-readable Solidity replay status consumes the terminal-boundary commands and still records exact #30522 citation absence plus no exact executable Foundry proof, so KLBQ-006 remains fail-closed."
        )
    dependency_unblock = _safe_dict(replay_packet.get("foundry_dependency_unblock"))
    dependency_state = _safe_text(dependency_unblock.get("state"))
    dependency_unblock_command = _safe_text(dependency_unblock.get("network_unblock_command"))
    if dependency_state == "blocked_uninitialized_or_empty_submodules":
        count = dependency_unblock.get("uninitialized_or_empty_submodule_count")
        blockers.append(
            "Foundry dependencies remain uninitialized or empty"
            + (f" for {count} declared submodules" if isinstance(count, int) and count > 0 else "")
            + (
                f"; run `{dependency_unblock_command}` or the recorded exact-commit offline fallback before re-running forge."
                if dependency_unblock_command
                else "; initialize exact dependency commits before re-running forge."
            )
        )

    return _dedupe_text(blockers or promotion_blockers)


def _klbq_006_next_action(
    precision_packet: dict[str, Any],
    anchors_packet: dict[str, Any],
    terminal_packet: dict[str, Any],
    replay_packet: dict[str, Any],
) -> str:
    anchor_classification = _safe_dict(anchors_packet.get("classification"))
    source_root_present = _safe_text(anchor_classification.get("exact_renft_source_root")) == "present"
    real_anchor_present = _safe_text(anchor_classification.get("real_source_anchors")) == "present"
    exact_blob_absent = _safe_text(anchor_classification.get("exact_finding_github_blob_anchors")) == "absent"
    replay_next_command = _safe_text(replay_packet.get("exact_next_command"))
    citation_acquisition = _safe_dict(replay_packet.get("source_citation_acquisition"))
    citation_acquisition_state = _safe_text(citation_acquisition.get("state"))
    citation_acquisition_commands = _safe_list(citation_acquisition.get("exact_next_commands"))
    citation_acquisition_command = _safe_text(
        citation_acquisition_commands[0] if citation_acquisition_commands else ""
    )
    dependency_unblock = _safe_dict(replay_packet.get("foundry_dependency_unblock"))
    dependency_unblock_command = _safe_text(dependency_unblock.get("network_unblock_command"))
    dependency_blocked = _safe_text(dependency_unblock.get("state")) == "blocked_uninitialized_or_empty_submodules"
    rerun_after_dependencies = _safe_text(
        dependency_unblock.get("rerun_exact_proof_command_after_dependencies")
    ) or replay_next_command
    if (
        source_root_present
        and real_anchor_present
        and exact_blob_absent
        and _klbq_006_terminal_boundary_ok(terminal_packet)
        and _klbq_006_solidity_replay_status_ok(replay_packet)
        and replay_next_command
    ):
        if citation_acquisition_state == "blocked_pending_exact_30522_source_citation":
            command = citation_acquisition_command or replay_next_command
            return (
                "Run the machine-recorded source-citation acquisition command "
                f"`{command}` first. KLBQ-006 has a pinned local reNFT mirror and local source anchors, but exact "
                "#30522 source metadata/blob citation is still absent; do not initialize dependencies, rerun forge, "
                "or promote until the acquisition packet records exact_finding_github_blob_anchors=present. "
                "The recorded Foundry dependency unblock remains queued after citation acquisition."
            )
        if dependency_blocked and dependency_unblock_command:
            return (
                "Run the machine-recorded dependency unblock command "
                f"`{dependency_unblock_command}` against the pinned local reNFT mirror first; if network remains unavailable, "
                "use the recorded exact-commit offline fallback commands. Only after the 7 declared Foundry submodules are "
                "initialized, rerun "
                f"`{rerun_after_dependencies}`; keep Rust detector absence classified as inapplicable, and do not promote "
                "until both exact #30522 citation and exact executable Foundry proof exist."
            )
        return (
            "Run the machine-recorded exact next command "
            f"`{replay_next_command}` against the pinned local reNFT mirror, keep Rust detector absence "
            "classified as inapplicable, and do not promote until both exact #30522 citation and exact executable "
            "Foundry proof exist."
        )
    if source_root_present and real_anchor_present and exact_blob_absent and _klbq_006_terminal_boundary_ok(terminal_packet):
        return (
            "Use the pinned local reNFT mirror and the terminal boundary packet exact commands to implement "
            "a Solidity/source-aware replay; keep Rust detector absence classified as inapplicable, then update "
            "repo-wide taxonomy/accounting metadata before promotion."
        )
    if source_root_present and real_anchor_present and exact_blob_absent:
        return (
            "Use the pinned local reNFT mirror to build a Solidity/source-aware replay or record a terminal "
            "Rust-detector-inapplicability boundary, then reconcile taxonomy/accounting metadata before promotion."
        )

    next_commands = _dedupe_text(_safe_list(precision_packet.get("next_commands")))
    if next_commands:
        return (
            "Provide the exact local reNFT source root or verified mirror root for Solodit #30522, "
            "then run the anchor grep and both rust-detect --only reruns before reconciling taxonomy/accounting metadata."
        )
    return (
        "Provide the exact local reNFT source root for Solodit #30522 so source-anchor grep and bounded real-target reruns can execute."
    )


def _klbq_006_blocked_templates(
    row: dict[str, Any],
    precision_packet: dict[str, Any],
    replay_packet: dict[str, Any],
) -> list[dict[str, Any]]:
    expected_artifacts = _dedupe_text(
        _safe_list(row.get("evidence_paths"))
        + [
            "reports/klbq_006_precision_evidence_2026-05-05.json",
            "reports/klbq_006_real_source_anchors_2026-05-05.json",
            "reports/klbq_006_solidity_replay_status_2026-05-05.json",
        ]
    )
    unblock_criteria = _dedupe_text(
        _safe_list(row.get("blockers"))
        + _safe_list(precision_packet.get("missing_or_insufficient_inputs"))
    )
    templates: list[dict[str, Any]] = []
    for command in _safe_list(precision_packet.get("next_commands")):
        text = _safe_text(command)
        if not text:
            continue
        placeholders = _placeholder_tokens(text)
        if placeholders:
            templates.append(
                {
                    "command": text,
                    "missing_inputs": placeholders,
                    "expected_artifacts": expected_artifacts,
                    "unblock_criteria": unblock_criteria,
                }
            )

    dependency_unblock = _safe_dict(replay_packet.get("foundry_dependency_unblock"))
    dependency_command = _safe_text(dependency_unblock.get("network_unblock_command"))
    rerun_command = _safe_text(dependency_unblock.get("rerun_exact_proof_command_after_dependencies"))
    if dependency_command:
        templates.append(
            {
                "command": dependency_command,
                "missing_inputs": ["initialized Foundry submodules"],
                "expected_artifacts": expected_artifacts,
                "unblock_criteria": _dedupe_text(
                    unblock_criteria
                    + [
                        "all declared reNFT Foundry submodules are initialized and non-empty",
                        "exact executable Foundry proof command can run after dependency initialization",
                    ]
                ),
            }
        )
    citation_acquisition = _safe_dict(replay_packet.get("source_citation_acquisition"))
    citation_commands = _safe_list(citation_acquisition.get("exact_next_commands"))
    citation_missing = _safe_list(citation_acquisition.get("missing_inputs"))
    for command in citation_commands:
        text = _safe_text(command)
        if not text:
            continue
        templates.append(
            {
                "command": text,
                "missing_inputs": citation_missing
                or ["exact Solodit #30522 source citation"],
                "expected_artifacts": expected_artifacts,
                "unblock_criteria": _dedupe_text(
                    unblock_criteria
                    + [
                        "exact_finding_github_blob_anchors is present for Solodit #30522",
                        "exact #30522 citation resolves to the pinned local reNFT source root before forge replay",
                    ]
                ),
            }
        )
    if rerun_command:
        templates.append(
            {
                "command": rerun_command,
                "missing_inputs": ["initialized Foundry submodules", "exact executable Foundry proof output"],
                "expected_artifacts": expected_artifacts,
                "unblock_criteria": _dedupe_text(
                    unblock_criteria
                    + [
                        "forge replay command executes against the pinned local reNFT mirror",
                        "exact #30522 source citation and executable proof are captured before promotion",
                    ]
                ),
            }
        )
    return templates


def _klbq_006_status_note(
    anchor_classification: dict[str, Any],
    terminal_packet: dict[str, Any],
    replay_packet: dict[str, Any],
) -> str:
    source_root_present = _safe_text(anchor_classification.get("exact_renft_source_root")) == "present"
    real_anchor_present = _safe_text(anchor_classification.get("real_source_anchors")) == "present"
    exact_blob_absent = _safe_text(anchor_classification.get("exact_finding_github_blob_anchors")) == "absent"
    replay_next_command = _safe_text(replay_packet.get("exact_next_command"))
    citation_acquisition = _safe_dict(replay_packet.get("source_citation_acquisition"))
    citation_acquisition_state = _safe_text(citation_acquisition.get("state"))
    dependency_unblock = _safe_dict(replay_packet.get("foundry_dependency_unblock"))
    dependency_blocked = _safe_text(dependency_unblock.get("state")) == "blocked_uninitialized_or_empty_submodules"
    dependency_unblock_command = _safe_text(dependency_unblock.get("network_unblock_command"))
    if (
        source_root_present
        and real_anchor_present
        and exact_blob_absent
        and _klbq_006_terminal_boundary_ok(terminal_packet)
        and _klbq_006_solidity_replay_status_ok(replay_packet)
        and replay_next_command
    ):
        return (
            "Synthetic precision evidence now extends beyond dedicated fixture smoke to a bounded 4-file Rust corpus "
            "with clean 1/0 results for both detectors, and a pinned local reNFT mirror now provides real source "
            "anchors. A machine-readable terminal boundary records that the current Rust detector path is "
            "inapplicable to the Solidity-only mirror and cannot be counted as pass, precision, negative replay, "
            "or exploit proof. A companion Solidity replay-status packet consumes the exact boundary commands, "
            "executes the git-based local source checks, records a source-citation acquisition packet, and advances the next exact command to "
            f"`{replay_next_command}` while keeping KLBQ-006 fail-closed because exact #30522 citation and exact "
            "executable Foundry proof are still absent."
            + (
                " The same packet deliberately keeps source-citation acquisition ahead of dependency initialization "
                "because replay is not proof-grade while exact_finding_github_blob_anchors is absent."
                if citation_acquisition_state == "blocked_pending_exact_30522_source_citation"
                else ""
            )
            + (
                " The same packet records uninitialized or empty Foundry submodules and makes "
                f"`{dependency_unblock_command}` the first replay-safe next action before any forge rerun."
                if (
                    dependency_blocked
                    and dependency_unblock_command
                    and citation_acquisition_state != "blocked_pending_exact_30522_source_citation"
                )
                else ""
            )
        )
    if source_root_present and real_anchor_present and exact_blob_absent and _klbq_006_terminal_boundary_ok(terminal_packet):
        return (
            "Synthetic precision evidence now extends beyond dedicated fixture smoke to a bounded 4-file Rust corpus "
            "with clean 1/0 results for both detectors, and a pinned local reNFT mirror now provides real source "
            "anchors. A machine-readable terminal boundary records that the current Rust detector path is "
            "inapplicable to the Solidity-only mirror and cannot be counted as pass, precision, negative replay, "
            "or exploit proof. KLBQ-006 remains open pending exact #30522 source citation, executable "
            "Solidity/source-aware replay, and repo-wide taxonomy metadata updates."
        )
    if source_root_present and real_anchor_present and exact_blob_absent:
        return (
            "Synthetic precision evidence now extends beyond dedicated fixture smoke to a bounded 4-file Rust corpus "
            "with clean 1/0 results for both detectors, and a pinned local reNFT mirror now provides real source "
            "anchors. The exact Solodit #30522 blob/file-line anchor is still absent and the current Rust detector "
            "path cannot replay on the Solidity mirror, so KLBQ-006 remains open pending source-aware replay or a "
            "terminal inapplicability boundary plus taxonomy reconciliation."
        )
    return (
        "Synthetic precision evidence now extends beyond dedicated fixture smoke to a bounded 4-file Rust corpus with "
        "clean 1/0 results for both detectors, but the real-source-anchor scan still found no exact reNFT root or "
        "real-source file/line anchors for Solodit #30522, so KLBQ-006 remains open pending exact source-root input "
        "and taxonomy reconciliation."
    )


def _klbq_006_solidity_replay_status_ok(packet: dict[str, Any]) -> bool:
    command_consumption = _safe_dict(packet.get("command_consumption"))
    replay_gate = _safe_dict(packet.get("replay_gate"))
    return (
        _safe_text(packet.get("schema")) == "auditooor.klbq_006_solidity_replay_status.v1"
        and _safe_text(packet.get("limitation_id")) == "KLBQ-006"
        and _safe_text(packet.get("finding_id")) == "30522"
        and _safe_text(packet.get("status")) == "source_aware_replay_commands_consumed_fail_closed"
        and packet.get("verification_claim_allowed") is False
        and packet.get("promotion_ready") is False
        and bool(command_consumption.get("consumed_command_count"))
        and bool(replay_gate.get("fail_closed"))
    )


def _rows_by_finding_id(rows: list[Any]) -> dict[str, dict[str, Any]]:
    return {
        _safe_text(row.get("finding_id")): row
        for row in rows
        if isinstance(row, dict) and _safe_text(row.get("finding_id"))
    }


def _klbq_002_source_root_actionability(root: Path) -> dict[str, Any]:
    locator_rel = _latest_report_rel_path(
        root,
        "g1_source_root_locator",
        "reports/g1_source_root_locator_2026-05-05.json",
    )
    readiness_rel = _latest_report_rel_path(
        root,
        "solodit_source_replay_readiness",
        "reports/solodit_source_replay_readiness_2026-05-05.json",
    )
    locator = _load_local_json(root, locator_rel)
    readiness = _load_local_json(root, readiness_rel)
    locator_by_id = _rows_by_finding_id(_safe_list(locator.get("findings")))
    readiness_by_id = _rows_by_finding_id(_safe_list(readiness.get("rows")))

    source_root_rows: list[dict[str, Any]] = []
    missing_ids: list[str] = []
    ready_ids: list[str] = []
    for finding_id in KLBQ_002_FINDING_IDS:
        locator_row = locator_by_id.get(finding_id, {})
        readiness_row = readiness_by_id.get(finding_id, {})
        local_source_root = _safe_text(locator_row.get("local_source_root"))
        source_root_status = _safe_text(locator_row.get("source_root_status")) or _safe_text(
            readiness_row.get("readiness_status")
        ) or "unknown"
        exact_root_ready = (
            bool(locator_row.get("local_source_checkout_found"))
            and bool(local_source_root)
            and source_root_status == "exact_local_root_found"
        )
        if exact_root_ready:
            ready_ids.append(finding_id)
        else:
            missing_ids.append(finding_id)

        source_root_rows.append(
            {
                "finding_id": finding_id,
                "title": _safe_text(locator_row.get("title")) or _safe_text(readiness_row.get("title")),
                "source_root_status": source_root_status,
                "confirmation_level": _safe_text(locator_row.get("confirmation_level")),
                "local_source_checkout_found": bool(locator_row.get("local_source_checkout_found")),
                "local_source_root": local_source_root or None,
                "candidate_repo": _safe_text(locator_row.get("candidate_repo")) or None,
                "candidate_commit": _safe_text(locator_row.get("candidate_commit")) or None,
                "candidate_source_root": _safe_text(locator_row.get("candidate_source_root")) or None,
                "confidence": _safe_text(locator_row.get("confidence")),
                "first_blockers": _dedupe_text(
                    _safe_list(locator_row.get("blockers"))[:2]
                    + _safe_list(readiness_row.get("source_replay_blockers"))[:2]
                ),
                "unblock_condition": _safe_text(readiness_row.get("unblock_condition")),
            }
        )

    if not locator_by_id:
        decision = "blocked_missing_source_root_locator_report"
        why = "The KLBQ-002 source-root locator report is absent or unreadable; source replay is not safe to dispatch."
    elif missing_ids:
        decision = "blocked_exact_source_roots_missing"
        why = (
            f"{len(missing_ids)}/{len(KLBQ_002_FINDING_IDS)} KLBQ-002 findings still lack exact local "
            "source roots; candidate repo/commit/root hints are not replay-safe until exact-row confirmation."
        )
    else:
        decision = "ready_for_source_replay_rerun"
        why = "All KLBQ-002 findings have exact local source roots in the locator report."

    return {
        "limitation_id": "KLBQ-002",
        "decision": decision,
        "can_dispatch_local_replay": not missing_ids and bool(locator_by_id),
        "can_dispatch_detector_design": False,
        "can_dispatch_source_acquisition": bool(missing_ids),
        "why": why,
        "required_input": (
            "Exact local checkout plus .auditooor/project_source_roots.json declaration for "
            f"{', '.join('#' + item for item in missing_ids or KLBQ_002_FINDING_IDS)}."
        ),
        "missing_finding_ids": missing_ids,
        "ready_finding_ids": ready_ids,
        "source_root_rows": source_root_rows,
        "read_first": [
            locator_rel,
            readiness_rel,
            "docs/PROJECT_SOURCE_ROOTS.md",
        ],
        "safe_next_commands": [
            "python3 -m unittest tools.tests.test_source_root_blocker_emitter -v",
            f"python3 -m json.tool {locator_rel}",
            f"python3 -m json.tool {readiness_rel}",
        ],
    }


def _klbq_002_source_root_actionability_report_ok(packet: dict[str, Any]) -> bool:
    return (
        _safe_text(packet.get("schema")) == "auditooor.source_root_acquisition_plan.v0"
        and _safe_int(packet.get("row_count")) is not None
        and _safe_text(packet.get("proof_boundary"))
        and packet.get("promotion_claim_allowed") is False
    )


def _local_row_refresh(root: Path, row: dict[str, Any]) -> dict[str, Any]:
    row_id = _safe_text(row.get("id"))

    if row_id == "KLBQ-004":
        if _file_contains(
            root,
            "tools/harness-scaffold-emitter.py",
            (
                "BINDING_MANIFEST_FILENAME",
                "write_attempt_and_binding_manifest",
                "write_binding_manifest",
                "binding_manifest_path",
                "binding_status",
            ),
        ) and _file_contains(
            root,
            "tools/tests/test_harness_scaffold_emitter.py",
            (
                "TestBindingManifestEmission",
                "test_ready_scaffold_writes_ready_binding_manifest",
                "test_blocked_attempt_writes_blocked_binding_manifest",
                "test_idempotent_rerun_backfills_missing_binding_manifest",
            ),
        ) and _file_contains(
            root,
            "tools/harness-binding-manifest.py",
            (
                "status_refresh",
                "ready_executable_binding",
            ),
        ) and _file_contains(
            root,
            "tools/tests/test_harness_binding_manifest.py",
            (
                "test_klbq_004_status_refresh_row_can_be_exact_without_harness_inputs",
                "status_refresh",
            ),
        ):
            refreshed = {
                "current_status": "implemented_verified_local_evidence",
                "dispatch_ready": False,
                "expected_loop_cost": 0,
                "scheduled_loop": None,
                "next_action": "Preserve harness-scaffold binding manifest emission and keep KLBQ status-refresh rows on exact local commands.",
                "blockers": [],
                "verification_commands": [
                    "python3 -m unittest tools.tests.test_harness_scaffold_emitter tools.tests.test_harness_binding_manifest -v",
                    "python3 tools/harness-binding-manifest.py --input reports/known_limitations_burndown_queue_2026-05-05.json --workspace . --print-json",
                    "python3 -m unittest tools.tests.test_known_limitations_harness_memory_status -v",
                ],
                "evidence_paths": [
                    "tools/harness-scaffold-emitter.py",
                    "tools/harness-binding-manifest.py",
                    "tools/known-limitations-harness-memory-status.py",
                    "tools/tests/test_harness_scaffold_emitter.py",
                    "tools/tests/test_harness_binding_manifest.py",
                    "tools/tests/test_known_limitations_harness_memory_status.py",
                    "reports/harness_binding_manifest_status_2026-05-05.json",
                ],
                "status_notes": _append_note(
                    _safe_text(row.get("status_notes")),
                    "Local evidence shows harness-scaffold now emits a schema-valid harness_binding_manifest.json beside attempt_manifest.json for ready, blocked, and idempotent backfill paths; the KLBQ-004 queue row now uses an exact local status-refresh command instead of prose gating.",
                ),
                "open": False,
            }
            refreshed.update(
                _build_action_plan(
                    open_row=False,
                    actionable_now_commands=refreshed.get("verification_commands", []),
                    blocked_command_templates=[],
                )
            )
            return refreshed

    if row_id == "KLBQ-002":
        actionability = _klbq_002_source_root_actionability(root)
        has_source_root_acquisition_plan = _file_contains(
            root,
            "tools/source-root-blocker-emitter.py",
            (
                "ACTIONABILITY_SCHEMA",
                "source_root_acquisition_plan",
                "blocked_pending_exact_source_acquisition",
                "local_verification_commands",
            ),
        ) and _file_contains(
            root,
            "tools/tests/test_source_root_blocker_emitter.py",
            (
                "candidate_confirmation_required",
                "exact_reviewed_source_report_or_metadata_for_this_solodit_row",
                "make project-source-root-readiness WS=<workspace> JSON=1",
            ),
        )
        if has_source_root_acquisition_plan:
            missing_ids = _safe_list(actionability.get("missing_finding_ids"))
            locator_report_rel = (
                _safe_list(actionability.get("read_first"))[0]
                if _safe_list(actionability.get("read_first"))
                else "reports/g1_source_root_locator_2026-05-05.json"
            )
            actionability_report_rel = _latest_valid_report_rel_path(
                root,
                "klbq_002_source_root_actionability",
                "reports/klbq_002_source_root_actionability_2026-05-05.json",
                _klbq_002_source_root_actionability_report_ok,
            )
            actionability_report = _load_local_json(root, actionability_report_rel)
            return {
                "current_status": "partially_implemented_v0_actionability_closed_source_absent",
                "next_action": (
                    "Use each emitted source_root_acquisition_plan to supply the exact reviewed source metadata, "
                    "declare the local source root, run project-source-root-readiness, and capture file/line anchors "
                    "before any replay or promotion claim."
                ),
                "blockers": _dedupe_text(
                    [
                        "Exact local source roots for Solodit #38333, #36418, and #33463 are still absent.",
                        "Source replay remains fail-closed until each source_root_acquisition_plan confirmation criterion is satisfied.",
                    ]
                    + _safe_list(row.get("blockers"))
                ),
                "verification_commands": _dedupe_text(
                    _safe_list(row.get("verification_commands"))
                    + _safe_list(actionability.get("safe_next_commands"))
                    + [
                        "make knowledge-gap-validate",
                        "python3 -m unittest tools.tests.test_source_root_blocker_emitter -v",
                        f"python3 -m json.tool {actionability_report_rel}",
                        f"make source-root-blocker-emitter INPUT={locator_report_rel} OUT=/tmp/klbq002_source_root_blockers.json",
                    ]
                ),
                "evidence_paths": _dedupe_text(
                    _safe_list(row.get("evidence_paths"))
                    + _safe_list(actionability.get("read_first"))
                    + [
                        "docs/G1_SOURCE_ROOT_LOCATOR_2026-05-05.md",
                        "tools/source-root-blocker-emitter.py",
                        "tools/tests/test_source_root_blocker_emitter.py",
                        actionability_report_rel,
                    ]
                ),
                "status_notes": _append_note(
                    _safe_text(row.get("status_notes")),
                    "KLBQ-002 source-root blockers now carry per-finding acquisition plans with missing inputs, confirmation criteria, and local verification commands; this closes the actionability gap without claiming source replay readiness.",
                ),
                "agent_actionability": actionability,
                "source_root_acquisition_report": {
                    "path": actionability_report_rel,
                    "row_count": actionability_report.get("row_count"),
                    "proof_boundary": _safe_text(actionability_report.get("proof_boundary")),
                    "promotion_claim_allowed": bool(actionability_report.get("promotion_claim_allowed")),
                },
                "open": True,
            }
        if actionability.get("decision") == "blocked_exact_source_roots_missing":
            missing_ids = _safe_list(actionability.get("missing_finding_ids"))
            return {
                "current_status": "partially_implemented_v0_source_roots_actionable_blocked",
                "next_action": (
                    "Do not dispatch source replay or detector design yet; acquire and declare exact local source roots for "
                    f"{', '.join('#' + _safe_text(item) for item in missing_ids)}, then rerun the blocker emitter and knowledge-gap validation."
                ),
                "blockers": _dedupe_text(
                    [
                        f"Exact local source roots are still absent for {', '.join('#' + _safe_text(item) for item in missing_ids)}.",
                        "Cluster-inferred candidate repo/commit/root hints are advisory only until confirmed against the exact Solodit rows.",
                    ]
                    + _safe_list(row.get("blockers"))
                ),
                "verification_commands": _dedupe_text(
                    _safe_list(row.get("verification_commands"))
                    + _safe_list(actionability.get("safe_next_commands"))
                    + ["make knowledge-gap-validate"]
                ),
                "evidence_paths": _dedupe_text(
                    _safe_list(row.get("evidence_paths"))
                    + _safe_list(actionability.get("read_first"))
                    + ["docs/G1_SOURCE_ROOT_LOCATOR_2026-05-05.md"]
                ),
                "status_notes": _append_note(
                    _safe_text(row.get("status_notes")),
                    "Structured KLBQ-002 actionability records each blocked Solodit ID, source-root status, candidate hints, and the replay-safe dispatch decision in this status packet.",
                ),
                "agent_actionability": actionability,
                "open": True,
            }
        if actionability.get("decision"):
            return {"agent_actionability": actionability}

    if row_id == "KLBQ-006":
        packet = _load_local_json(root, "reports/fallback_handler_address_guard_calibration_2026-05-05.json")
        precision_packet = _load_local_json(root, "reports/klbq_006_precision_evidence_2026-05-05.json")
        anchors_packet = _load_local_json(root, "reports/klbq_006_real_source_anchors_2026-05-05.json")
        terminal_packet = _load_local_json(root, "reports/klbq_006_terminal_boundary_2026-05-05.json")
        replay_packet = _load_local_json(root, "reports/klbq_006_solidity_replay_status_2026-05-05.json")
        registry = _safe_dict(packet.get("registry_backed_detector"))
        sibling = _safe_dict(packet.get("adjacent_sibling_detector"))
        promotion_blockers = _dedupe_text(_safe_list(packet.get("promotion_blockers")))
        if (
            _safe_text(packet.get("packet_name")) == "fallback_handler_address_guard_calibration"
            and _safe_text(packet.get("status")) == "calibration_only"
            and packet.get("promotion_ready") is False
            and registry.get("verified") is True
            and _smoke_passed(_safe_dict(registry.get("smoke")))
            and _smoke_passed(_safe_dict(sibling.get("smoke")))
            and _safe_text(packet.get("promotion_posture")) == "calibration_only_hold"
            and promotion_blockers
        ):
            precision_summary = _safe_dict(precision_packet.get("summary"))
            anchor_classification = _safe_dict(anchors_packet.get("classification"))
            has_precision_packet = (
                _safe_text(precision_packet.get("limitation_id")) == "KLBQ-006"
                and _safe_text(precision_packet.get("status")) == "moved_forward_not_verified"
                and bool(precision_summary.get("added_synthetic_precision_corpus"))
                and bool(precision_summary.get("bounded_synthetic_precision_passes"))
                and not bool(precision_summary.get("real_target_source_replay_passes"))
                and not bool(precision_summary.get("taxonomy_reconciled"))
            )
            source_root_state = _safe_text(anchor_classification.get("exact_renft_source_root"))
            real_anchor_state = _safe_text(anchor_classification.get("real_source_anchors"))
            exact_blob_state = _safe_text(anchor_classification.get("exact_finding_github_blob_anchors"))
            has_anchor_boundary_report = (
                _safe_text(anchors_packet.get("finding_id")) == "30522"
                and (
                    (source_root_state == "absent" and real_anchor_state == "absent")
                    or (
                        source_root_state == "present"
                        and real_anchor_state == "present"
                        and exact_blob_state == "absent"
                    )
                )
            )
            if has_precision_packet and has_anchor_boundary_report:
                refreshed = {
                    "current_status": "partially_implemented_v0_partial_pass",
                    "next_action": _klbq_006_next_action(
                        precision_packet,
                        anchors_packet,
                        terminal_packet,
                        replay_packet,
                    ),
                    "blockers": _klbq_006_blockers(
                        packet,
                        precision_packet,
                        anchors_packet,
                        terminal_packet,
                        replay_packet,
                    ),
                    "verification_commands": _dedupe_text(
                        _safe_list(row.get("verification_commands"))
                        + [
                            "python3 -m json.tool reports/klbq_006_precision_evidence_2026-05-05.json",
                            "python3 -m json.tool reports/klbq_006_real_source_anchors_2026-05-05.json",
                            "python3 -m json.tool reports/klbq_006_terminal_boundary_2026-05-05.json",
                            "python3 -m json.tool reports/klbq_006_solidity_replay_status_2026-05-05.json",
                            "python3 -m unittest tools.tests.test_klbq006_terminal_boundary tools.tests.test_klbq006_solidity_replay_status -v",
                        ]
                    ),
                    "evidence_paths": _dedupe_text(
                        _safe_list(row.get("evidence_paths"))
                        + [
                            "docs/KLBQ_006_PRECISION_EVIDENCE_2026-05-05.md",
                            "reports/klbq_006_precision_evidence_2026-05-05.json",
                            "docs/KLBQ_006_REAL_SOURCE_ANCHORS_2026-05-05.md",
                            "reports/klbq_006_real_source_anchors_2026-05-05.json",
                            "docs/KLBQ_006_TERMINAL_BOUNDARY_2026-05-05.md",
                            "reports/klbq_006_terminal_boundary_2026-05-05.json",
                            "docs/KLBQ_006_SOLIDITY_REPLAY_STATUS_2026-05-05.md",
                            "reports/klbq_006_solidity_replay_status_2026-05-05.json",
                            "tools/klbq006-terminal-boundary.py",
                            "tools/klbq006-solidity-replay-status.py",
                            "tools/tests/test_klbq006_terminal_boundary.py",
                            "tools/tests/test_klbq006_solidity_replay_status.py",
                        ]
                    ),
                    "status_notes": _append_note(
                        _safe_text(row.get("status_notes")),
                        _klbq_006_status_note(anchor_classification, terminal_packet, replay_packet),
                    ),
                    "open": True,
                }
                actionable_commands = _dedupe_text(
                    _safe_list(refreshed.get("verification_commands"))
                    + [
                        command
                        for command in _safe_list(precision_packet.get("next_commands"))
                        if _safe_text(command) and not _placeholder_tokens(_safe_text(command))
                    ]
                )
                refreshed.update(
                    _build_action_plan(
                        open_row=True,
                        actionable_now_commands=actionable_commands,
                        blocked_command_templates=_klbq_006_blocked_templates(
                            refreshed,
                            precision_packet,
                            replay_packet,
                        ),
                    )
                )
                return refreshed
            return {
                "current_status": "partially_implemented_v0_partial_pass",
                "blockers": promotion_blockers,
                "status_notes": _append_note(
                    _safe_text(row.get("status_notes")),
                    "Local calibration packet verifies bounded 1/0 fixture smoke for the registry-backed and sibling detectors, but promotion remains calibration_only_hold pending taxonomy reconciliation and broader precision evidence.",
                ),
                "open": True,
            }

    if row_id == "KLBQ-007":
        if _file_contains(
            root,
            "docs/HARNESS_FAILURE_MEMORY.md",
            (
                "KLBQ-007 adds a minimal per-occurrence event contract",
                "docs/schemas/harness_failure_event.v1.json",
                "docs/schemas/harness_failure_event_summary.v1.json",
                "When `--from-events` is supplied with `--events-report`, the aggregate",
                "reports/harness_failures.jsonl",
                "validated event",
            ),
        ) and _file_contains(
            root,
            "tools/tests/test_harness_failure_memory.py",
            (
                "test_cli_validate_events_writes_summary",
                "test_cli_from_events_materializes_aggregate_report_and_notes",
                "--from-events",
            ),
        ) and _file_contains(
            root,
            "tools/harness-failure-memory.py",
            (
                "--from-events",
                "materialize aggregate root report from validated --events-report rows",
                "cannot materialize aggregate for unknown root_cause_id",
            ),
        ):
            refreshed = {
                "current_status": "implemented_verified_local_evidence",
                "dispatch_ready": False,
                "expected_loop_cost": 0,
                "scheduled_loop": None,
                "blockers": [],
                "verification_commands": [
                    "python3 -m unittest tools.tests.test_harness_failure_memory -v",
                ],
                "evidence_paths": [
                    "docs/HARNESS_FAILURE_MEMORY.md",
                    "docs/schemas/harness_failure_event.v1.json",
                    "docs/schemas/harness_failure_event_summary.v1.json",
                    "tools/harness-failure-memory.py",
                    "tools/tests/test_harness_failure_memory.py",
                ],
                "status_notes": _append_note(
                    _safe_text(row.get("status_notes")),
                    "Local evidence shows the explicit --from-events aggregate materialization path, schema-backed event and summary contracts, the event validator/summary path, and fail-closed coverage all landed.",
                ),
                "open": False,
            }
            refreshed.update(
                _build_action_plan(
                    open_row=False,
                    actionable_now_commands=refreshed.get("verification_commands", []),
                    blocked_command_templates=[],
                )
            )
            return refreshed

    if row_id == "KLBQ-008":
        if _file_contains(
            root,
            "tools/memory-next-loop-dispatcher.py",
            (
                "skip_reason\": \"slot_reuse_blocked_pending_finalization",
                "lacks a valid task-finalization ledger row",
                "next_slot_id(inflight_slots, workpacks, blocked_slot_ids)",
            ),
        ) and _file_contains(
            root,
            "tools/tests/test_memory_next_loop_dispatcher.py",
            (
                "test_terminal_manifest_row_without_finalization_blocks_slot_reuse",
                "test_valid_finalization_clears_terminal_manifest_slot_for_reuse",
                "[\"slot-3\"]",
            ),
        ) and _file_contains(
            root,
            "docs/TASK_FINALIZATION_LEDGER.md",
            ("task-finalization-ledger.py audit-manifest",),
        ):
            refreshed = {
                "current_status": "implemented_verified_local_evidence",
                "dispatch_ready": False,
                "expected_loop_cost": 0,
                "scheduled_loop": None,
                "blockers": [],
                "verification_commands": [
                    "python3 -m unittest tools.tests.test_memory_next_loop_dispatcher -v",
                    "python3 -m unittest tools.tests.test_task_finalization_ledger -v",
                ],
                "evidence_paths": [
                    "docs/TASK_FINALIZATION_LEDGER.md",
                    "tools/task-finalization-ledger.py",
                    "tools/memory-next-loop-dispatcher.py",
                    "tools/tests/test_task_finalization_ledger.py",
                    "tools/tests/test_memory_next_loop_dispatcher.py",
                ],
                "status_notes": _append_note(
                    _safe_text(row.get("status_notes")),
                    "Local evidence shows terminal manifest rows without valid finalization reserve their slot id, block reuse, and valid finalization clears the slot for reuse.",
                ),
                "open": False,
            }
            refreshed.update(
                _build_action_plan(
                    open_row=False,
                    actionable_now_commands=refreshed.get("verification_commands", []),
                    blocked_command_templates=[],
                )
            )
            return refreshed

    if row_id == "KLBQ-010":
        impact_status_packet = _load_local_json(root, "reports/impact_contract_preflight_status_2026-05-05.json")
        if _impact_contract_packet_closes_klbq_010(impact_status_packet):
            return _klbq_010_from_status_packet(impact_status_packet, row)
        if (
            _file_contains(
                root,
                "tools/source-proof-record.py",
                (
                    "impact_contract_preflight",
                    "build_source_proof_preflight",
                    "route=\"source-proof\"",
                ),
            )
            and _file_contains(
                root,
                "tools/harness-scaffold-emitter.py",
                (
                    "impact_contract_preflight",
                    "harness_impact_preflight",
                    "route=\"harness-scaffold\"",
                ),
            )
            and _file_contains(
                root,
                "tools/exploit-memory-brief.py",
                (
                    "impact_contract_preflight",
                    "_exploit_memory_preflight",
                    "route=\"exploit-memory\"",
                    "planning-artifact-advisory-bypass",
                ),
            )
            and _file_contains(
                root,
                "tools/tests/test_source_proof_record.py",
                ("impact_contract_preflight", "source-proof"),
            )
            and _file_contains(
                root,
                "tools/tests/test_harness_scaffold_emitter.py",
                ("impact_contract_preflight", "harness-scaffold"),
            )
            and _file_contains(
                root,
                "tools/tests/test_exploit_memory_brief.py",
                ("impact_contract_preflight", "exploit-memory"),
            )
            and _file_contains(
                root,
                "tools/tests/test_pre_submit_impact_contract_check.py",
                ("impact-contract-missing", "impact-contract-explicit"),
            )
            and _file_contains(
                root,
                "tools/tests/test_agent_output_synthesizer_impact_contract.py",
                ("impact-contract-missing", "candidate_finding"),
            )
        ):
            refreshed = {
                "current_status": "implemented_verified_local_evidence",
                "dispatch_ready": False,
                "expected_loop_cost": 0,
                "scheduled_loop": None,
                "blockers": [],
                "verification_commands": [
                    "python3 -m unittest tools.tests.test_impact_contract_preflight tools.tests.test_source_proof_record tools.tests.test_harness_scaffold_emitter tools.tests.test_exploit_memory_brief tools.tests.test_agent_output_synthesizer_impact_contract tools.tests.test_pre_submit_impact_contract_check",
                ],
                "evidence_paths": [
                    "tools/impact-contract-preflight.py",
                    "tools/source-proof-record.py",
                    "tools/harness-scaffold-emitter.py",
                    "tools/exploit-memory-brief.py",
                    "tools/pre-submit-check.sh",
                    "tools/agent-output-synthesizer.py",
                    "tools/tests/test_source_proof_record.py",
                    "tools/tests/test_harness_scaffold_emitter.py",
                    "tools/tests/test_exploit_memory_brief.py",
                    "tools/tests/test_pre_submit_impact_contract_check.py",
                    "tools/tests/test_agent_output_synthesizer_impact_contract.py",
                ],
                "status_notes": _append_note(
                    _safe_text(row.get("status_notes")),
                    "Local evidence shows the shared impact-contract preflight decision is emitted on source-proof, harness-scaffold, exploit-memory, filing, and swarm-promotion routes; exploit-memory remains advisory-only.",
                ),
                "open": False,
            }
            refreshed.update(
                _build_action_plan(
                    open_row=False,
                    actionable_now_commands=refreshed.get("verification_commands", []),
                    blocked_command_templates=[],
                )
            )
            return refreshed
        if _file_contains(
            root,
            "docs/KNOWN_LIMITATIONS.md",
            (
                "Impact-first gates | Reduced, not resolved",
                "harness-scaffold",
                "source-proof-record",
                "pre-submit Check #32",
            ),
        ):
            return {
                "current_status": "partially_implemented_v0_pass_with_real_blockers_remaining",
                "status_notes": _append_note(
                    _safe_text(row.get("status_notes")),
                    "Local docs show impact-contract gates now cover several write/output surfaces, but the route-wide strict preflight is still not universal.",
                ),
                "open": True,
            }

    return {}


def _apply_local_row_refresh(root: Path, row: dict[str, Any]) -> dict[str, Any]:
    refreshed = dict(row)
    refreshed.update(_local_row_refresh(root, row))
    if not refreshed.get("open") and not _safe_text(refreshed.get("next_action_status")):
        refreshed.update(
            _build_action_plan(
                open_row=False,
                actionable_now_commands=_safe_list(refreshed.get("verification_commands")),
                blocked_command_templates=[],
            )
        )
    return refreshed


def _compact_scanner_action(action: dict[str, Any]) -> dict[str, Any]:
    return {
        "rank": action.get("rank"),
        "lane": _safe_text(action.get("lane")),
        "row_id": _safe_text(action.get("row_id")),
        "scanner_id": _safe_text(action.get("scanner_id")),
        "backend": _safe_text(action.get("backend")),
        "wiring_status": _safe_text(action.get("wiring_status")),
        "proof_status": _safe_text(action.get("proof_status")),
        "suggested_next_action": _safe_text(action.get("suggested_next_action")),
        "blockers": _dedupe_text(_safe_list(action.get("blockers"))),
        "source_paths": _dedupe_text(_safe_list(action.get("source_paths")))[:5],
        "suggested_commands": [
            {
                "command": _safe_text(command.get("command")),
                "reason": _safe_text(command.get("reason")),
            }
            for command in _safe_list(action.get("suggested_commands"))[:3]
            if isinstance(command, dict) and _safe_text(command.get("command"))
        ],
        "claim_guard": _safe_text(action.get("claim_guard")),
    }


def _scanner_owned_paths(root: Path, action: dict[str, Any]) -> list[str]:
    row_id = _safe_text(action.get("row_id"))
    candidates = _dedupe_text(_safe_list(action.get("source_paths")))
    owned: list[str] = []
    for candidate in candidates:
        path = Path(candidate)
        parts = path.parts
        if len(parts) >= 3 and parts[0] == "detectors" and parts[1] == "fixtures":
            prefix = str(Path(*parts[:3]))
            if prefix not in owned:
                owned.append(prefix)
            continue
        if candidate and candidate not in owned:
            owned.append(candidate)

    if row_id:
        tests_path = f"tools/tests/test_{row_id}.py"
        if tests_path not in owned:
            owned.append(tests_path)
        dsl_dir = root / "reference" / "patterns.dsl"
        dsl_slug = row_id.replace("_", "-").strip("-")
        if dsl_dir.is_dir():
            for match in sorted(dsl_dir.glob(f"{dsl_slug}*.yaml"))[:3]:
                rel = _rel_or_abs(root, match)
                if rel not in owned:
                    owned.append(rel)
    return owned[:12]


def _scanner_worker_slot(root: Path, action: dict[str, Any], slot_index: int) -> dict[str, Any]:
    row_id = _safe_text(action.get("row_id"))
    lane = _safe_text(action.get("lane"))
    model_hint = "gpt-5.5/high" if slot_index <= 2 else "gpt-5.4/high"
    if lane == "wire_backend_executor":
        model_hint = "gpt-5.5/xhigh"
    slot = {
        "slot_id": f"scanner-slot-{slot_index}",
        "task_kind": "end_to_end_scanner_burndown_closure",
        "row_id": row_id,
        "lane": lane,
        "rank": action.get("rank"),
        "backend": _safe_text(action.get("backend")),
        "model_hint": model_hint,
        "owned_paths": _scanner_owned_paths(root, action),
        "prompt_seed": (
            f"Own scanner burndown row `{row_id}` end to end: inspect DSL/detector/fixtures, "
            "materialize or repair vulnerable and clean fixture proof, run focused smoke/regression, "
            "and commit only owned row paths."
        ),
        "acceptance_criteria": [
            "positive fixture or runtime proof produces at least one expected detector hit",
            "clean fixture produces zero hits",
            "focused unittest or equivalent local smoke gate passes",
            "stale extraction_failure or advisory-only metadata is retired only for this owned row",
            "commit contains only owned row paths and no shared report/doc/memory refresh",
        ],
        "coordination_rules": [
            "workers implement; coordinator reviews, integrates, and refreshes shared memory at batch boundaries",
            "do not request review-only slots while executable scanner/harness closure rows remain",
            "do not claim exploit coverage or scanner completeness beyond checked local proof artifacts",
        ],
        "suggested_commands": [
            {
                "command": _safe_text(command.get("command")),
                "reason": _safe_text(command.get("reason")),
            }
            for command in _safe_list(action.get("suggested_commands"))[:3]
            if isinstance(command, dict) and _safe_text(command.get("command"))
        ],
    }
    slot.update(_scanner_slot_local_coordination(root, slot))
    return slot


def _git_dirty_paths(root: Path) -> list[str]:
    try:
        proc = subprocess.run(
            ["git", "status", "--short"],
            cwd=root,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return []
    if proc.returncode != 0:
        return []
    paths: list[str] = []
    for line in proc.stdout.splitlines():
        if len(line) < 4:
            continue
        path = line[3:].strip()
        if " -> " in path:
            path = path.rsplit(" -> ", 1)[-1].strip()
        if path:
            paths.append(path)
    return paths


def _slug(value: Any) -> str:
    text = re.sub(r"[^a-z0-9]+", "_", _safe_text(value).lower()).strip("_")
    while "__" in text:
        text = text.replace("__", "_")
    return text


def _path_within(path: str, prefix: str) -> bool:
    clean_path = path.strip().strip("/")
    clean_prefix = prefix.strip().strip("/")
    if not clean_path or not clean_prefix:
        return False
    return clean_path == clean_prefix or clean_path.startswith(clean_prefix.rstrip("/") + "/")


def _scanner_slot_dirty_matches(slot: dict[str, Any], dirty_paths: list[str]) -> list[str]:
    row_slug = _slug(slot.get("row_id"))
    row_hyphen = row_slug.replace("_", "-")
    owned_paths = [_safe_text(path) for path in _safe_list(slot.get("owned_paths")) if _safe_text(path)]
    matches: list[str] = []
    for path in dirty_paths:
        normalized = _slug(path)
        matched = any(_path_within(path, owned) for owned in owned_paths)
        if not matched and row_slug and len(row_slug) > 5:
            matched = row_slug in normalized or row_hyphen in path.lower()
        if matched and path not in matches:
            matches.append(path)
    return matches[:8]


def _scanner_slot_local_evidence(root: Path, slot: dict[str, Any]) -> tuple[list[str], dict[str, bool]]:
    row_slug = _slug(slot.get("row_id"))
    candidate_paths = [_safe_text(path) for path in _safe_list(slot.get("owned_paths")) if _safe_text(path)]
    if row_slug:
        candidate_paths.extend(
            [
                f"detectors/fixtures/{row_slug}",
                f"detectors/fixtures/{row_slug.replace('_', '-')}",
                f"tools/tests/test_{row_slug}.py",
            ]
        )
    existing: list[str] = []
    flags = {"fixture_dir_present": False, "smoke_json_present": False, "test_present": False}
    for rel in sorted(dict.fromkeys(candidate_paths)):
        path = root / rel
        if not path.exists():
            continue
        existing.append(rel)
        if rel.startswith("detectors/fixtures/") and path.is_dir():
            flags["fixture_dir_present"] = True
            smoke_files = sorted(path.glob("*smoke*.json"))
            if smoke_files:
                flags["smoke_json_present"] = True
                existing.extend(_rel_or_abs(root, item) for item in smoke_files[:3])
        if rel.startswith("tools/tests/test_") and path.is_file():
            flags["test_present"] = True
    return sorted(dict.fromkeys(existing))[:8], flags


def _scanner_slot_local_coordination(root: Path, slot: dict[str, Any]) -> dict[str, Any]:
    dirty_matches = _scanner_slot_dirty_matches(slot, _git_dirty_paths(root))
    evidence_paths, evidence_flags = _scanner_slot_local_evidence(root, slot)
    if dirty_matches:
        status = "claimed_dirty_worktree"
        note = "Matching uncommitted row paths exist in this checkout; do not redispatch until that worker commits or the scanner memory refreshes."
    elif evidence_flags["smoke_json_present"] and evidence_flags["test_present"]:
        status = "local_evidence_present_refresh_needed"
        note = "Local smoke/test evidence exists for this row; refresh scanner burndown before assigning it from a stale packet."
    elif evidence_paths:
        status = "local_partial_evidence_present"
        note = "Some local row artifacts exist; inspect before assigning because the scanner queue may be stale."
    else:
        status = "unclaimed_from_local_checkout"
        note = "No matching dirty paths or row-local proof artifacts were detected in this checkout."
    return {
        "local_coordination_status": status,
        "matching_dirty_paths": dirty_matches,
        "local_evidence_paths": evidence_paths,
        "coordination_note": note,
    }


def _scanner_coordination_guidance(
    skipped_worker_slots: list[dict[str, Any]],
    skipped_counts: dict[str, Any],
) -> dict[str, Any]:
    counts = {
        _safe_text(key): _safe_int(value) or 0
        for key, value in skipped_counts.items()
        if _safe_text(key) and (_safe_int(value) or 0) > 0
    }
    do_not_redispatch_statuses = [
        status
        for status in sorted(SCANNER_DO_NOT_REDISPATCH_STATUSES)
        if counts.get(status, 0)
        or any(_safe_text(row.get("skip_reason")) == status for row in skipped_worker_slots)
    ]
    refresh_statuses = [
        status
        for status in sorted(SCANNER_REFRESH_RECOMMENDED_STATUSES)
        if counts.get(status, 0)
        or any(_safe_text(row.get("skip_reason")) == status for row in skipped_worker_slots)
    ]
    sampled_row_ids = [
        _safe_text(row.get("row_id"))
        for row in skipped_worker_slots
        if _safe_text(row.get("skip_reason")) in SCANNER_DO_NOT_REDISPATCH_STATUSES
        and _safe_text(row.get("row_id"))
    ]
    refresh_recommended = bool(refresh_statuses)
    return {
        "do_not_redispatch_statuses": do_not_redispatch_statuses,
        "do_not_redispatch_sample_row_ids": sorted(dict.fromkeys(sampled_row_ids))[:10],
        "refresh_inventory_before_more_detector_assignments": refresh_recommended,
        "refresh_recommended_statuses": refresh_statuses,
        "reason": (
            "scanner-worker-next-rows skipped rows with committed or complete local evidence; "
            "refresh scanner inventory before assigning more detector work from stale memory"
            if refresh_recommended
            else "scanner skip samples only show dirty local claims; avoid those rows until commit or refresh"
            if do_not_redispatch_statuses
            else "no stale scanner skip signal was present"
        ),
    }


def _scanner_burndown_snapshot(root: Path, scanner_queue_path: Path) -> tuple[dict[str, Any], list[str]]:
    payload, issues = _load_json_object(scanner_queue_path)
    rel_path = _rel_or_abs(root, scanner_queue_path)
    if issues:
        return {
            "path": rel_path,
            "present": scanner_queue_path.is_file(),
            "status": "missing_or_invalid",
            "actionable_row_count": 0,
            "top_action_count": 0,
            "top_action_lane_counts": {},
            "lane_counts": {},
            "status_counts": {},
            "blocker_counts": {},
            "top_actions": [],
            "worker_slot_cap": SCANNER_WORKER_SLOT_CAP,
            "next_worker_slots": [],
            "strict_caveat": "Scanner burndown state is absent or invalid; do not infer detector readiness from this packet.",
        }, [f"scanner burndown queue unavailable: {issue}" for issue in issues]

    selector_snapshot = _scanner_selector_snapshot(root, scanner_queue_path, payload)
    if selector_snapshot is not None:
        return selector_snapshot, []

    raw_actions = [
        action
        for action in _safe_list(payload.get("actions"))[:SCANNER_WORKER_SLOT_SCAN_LIMIT]
        if isinstance(action, dict) and not bool(action.get("closed"))
    ]
    actions = [
        _compact_scanner_action(action)
        for action in raw_actions[:10]
    ]
    worker_slots: list[dict[str, Any]] = []
    skipped_worker_slots: list[dict[str, Any]] = []
    coordination_counts: dict[str, int] = {}
    scanned_count = 0
    for action in raw_actions:
        scanned_count += 1
        candidate_slot_index = len(worker_slots) + 1
        slot = _scanner_worker_slot(root, action, candidate_slot_index)
        status_key = _safe_text(slot.get("local_coordination_status")) or "unknown"
        coordination_counts[status_key] = coordination_counts.get(status_key, 0) + 1
        if status_key in ASSIGNABLE_SCANNER_COORDINATION_STATUSES:
            worker_slots.append(slot)
            if len(worker_slots) >= SCANNER_WORKER_SLOT_CAP:
                break
            continue
        skipped_slot = dict(slot)
        skipped_slot["slot_id"] = f"skipped-scanner-slot-{len(skipped_worker_slots) + 1}"
        skipped_slot["skip_reason"] = status_key
        skipped_worker_slots.append(skipped_slot)
    guidance = _scanner_coordination_guidance(skipped_worker_slots, coordination_counts)
    actionable_count = _safe_int(payload.get("actionable_row_count")) or 0
    top_action_count = _safe_int(payload.get("top_action_count")) or len(actions)
    status = "open_actions_present" if actionable_count else "no_actionable_rows_reported"
    return {
        "path": rel_path,
        "present": True,
        "schema": _safe_text(payload.get("schema")),
        "status": status,
        "actionable_row_count": actionable_count,
        "top_action_count": top_action_count,
        "top_action_lane_counts": _safe_dict(payload.get("top_action_lane_counts")),
        "lane_counts": _safe_dict(payload.get("lane_counts")),
        "status_counts": _safe_dict(payload.get("status_counts")),
        "blocker_counts": _safe_dict(payload.get("blocker_counts")),
        "top_actions": actions,
        "worker_slot_cap": SCANNER_WORKER_SLOT_CAP,
        "worker_slot_scan_limit": SCANNER_WORKER_SLOT_SCAN_LIMIT,
        "worker_slots_scanned": scanned_count,
        "next_worker_slots": worker_slots,
        "assignable_worker_slot_count": len(worker_slots),
        "skipped_worker_slots": skipped_worker_slots[:10],
        "skipped_worker_slot_count": len(skipped_worker_slots),
        "worker_slot_coordination_counts": dict(sorted(coordination_counts.items())),
        "scanner_coordination_guidance": guidance,
        "strict_caveat": "Scanner burndown actions are wiring/proof work items, not exploit proof or detector readiness claims.",
    }, []


def _scanner_active_claims_snapshot(root: Path, claims_path: Path) -> tuple[dict[str, Any], list[str]]:
    rel_path = _rel_or_abs(root, claims_path)
    if not claims_path.is_file():
        return {
            "path": rel_path,
            "present": False,
            "status": "missing_optional",
            "active": 0,
            "completed": 0,
            "active_claims": [],
            "strict_caveat": "No active scanner claim map is present; rely on selector slots only.",
        }, []
    payload, issues = _load_json_object(claims_path)
    if issues:
        return {
            "path": rel_path,
            "present": True,
            "status": "invalid",
            "active": 0,
            "completed": 0,
            "active_claims": [],
            "strict_caveat": "Scanner active-claim memory is invalid; do not infer worker ownership.",
        }, [f"scanner active claims unavailable: {issue}" for issue in issues]
    claims = [
        row for row in _safe_list(payload.get("active_claims"))
        if isinstance(row, dict)
    ]
    active_claims = [row for row in claims if _safe_text(row.get("status")) == "active"]
    completed_claims = [row for row in claims if _safe_text(row.get("status")) == "completed"]
    summary = _safe_dict(payload.get("summary"))
    summary_active = _safe_int(summary.get("active"))
    summary_completed = _safe_int(summary.get("completed"))
    return {
        "path": rel_path,
        "present": True,
        "schema": _safe_text(payload.get("schema")),
        "status": "present",
        "updated_at": _safe_text(payload.get("updated_at")),
        "active": summary_active if summary_active is not None else len(active_claims),
        "completed": summary_completed if summary_completed is not None else len(completed_claims),
        "active_claims": [
            {
                "agent_id": _safe_text(row.get("agent_id")),
                "row_id": _safe_text(row.get("row_id")),
                "status": _safe_text(row.get("status")) or "active",
            }
            for row in active_claims[:SCANNER_WORKER_SLOT_CAP]
        ],
        "strict_caveat": (
            "Active claims are coordination memory only. They prevent duplicate dispatch; "
            "they are not closure evidence, scanner completeness, or proof readiness."
        ),
    }, []


def _scanner_selector_snapshot(
    root: Path,
    scanner_queue_path: Path,
    payload: dict[str, Any],
) -> dict[str, Any] | None:
    selector_path = root / "tools" / "scanner-worker-next-rows.py"
    if not selector_path.is_file():
        return None
    try:
        spec = importlib.util.spec_from_file_location("scanner_worker_next_rows_for_klb_memory", selector_path)
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        state = module.local_state_from_git(root, scanner_queue_path)
        selector_report = module.build_next_rows(
            payload,
            state=state,
            limit=SCANNER_WORKER_SLOT_CAP,
            scan_limit=SCANNER_WORKER_SLOT_SCAN_LIMIT,
        )
    except Exception:
        return None

    worker_slots = [
        _scanner_selector_worker_slot(row, index)
        for index, row in enumerate(_safe_list(selector_report.get("rows"))[:SCANNER_WORKER_SLOT_CAP], start=1)
        if isinstance(row, dict)
    ]
    skipped_worker_slots = [
        _scanner_selector_skipped_slot(row, index)
        for index, row in enumerate(_safe_list(selector_report.get("skipped_samples"))[:10], start=1)
        if isinstance(row, dict)
    ]
    skipped_counts = {
        _safe_text(key): value
        for key, value in _safe_dict(_safe_dict(selector_report.get("selection")).get("skipped_counts")).items()
    }
    coordination_counts: dict[str, int] = {}
    for slot in worker_slots:
        key = _safe_text(slot.get("local_coordination_status")) or "unknown"
        coordination_counts[key] = coordination_counts.get(key, 0) + 1
    for key, value in skipped_counts.items():
        count = _safe_int(value) or 0
        coordination_counts[key] = coordination_counts.get(key, 0) + count
    guidance = _scanner_coordination_guidance(skipped_worker_slots, skipped_counts)
    actions = [
        _compact_scanner_action(action)
        for action in _safe_list(payload.get("actions"))[:10]
        if isinstance(action, dict) and not bool(action.get("closed"))
    ]
    selection = _safe_dict(selector_report.get("selection"))
    actionable_count = _safe_int(payload.get("actionable_row_count")) or 0
    top_action_count = _safe_int(payload.get("top_action_count")) or len(actions)
    status = "open_actions_present" if actionable_count else "no_actionable_rows_reported"
    return {
        "path": _rel_or_abs(root, scanner_queue_path),
        "present": True,
        "schema": _safe_text(payload.get("schema")),
        "status": status,
        "actionable_row_count": actionable_count,
        "top_action_count": top_action_count,
        "top_action_lane_counts": _safe_dict(payload.get("top_action_lane_counts")),
        "lane_counts": _safe_dict(payload.get("lane_counts")),
        "status_counts": _safe_dict(payload.get("status_counts")),
        "blocker_counts": _safe_dict(payload.get("blocker_counts")),
        "top_actions": actions,
        "worker_slot_cap": SCANNER_WORKER_SLOT_CAP,
        "worker_slot_scan_limit": SCANNER_WORKER_SLOT_SCAN_LIMIT,
        "worker_slots_scanned": _safe_int(selection.get("candidate_rows_scanned")) or 0,
        "next_worker_slots": worker_slots,
        "assignable_worker_slot_count": len(worker_slots),
        "skipped_worker_slots": skipped_worker_slots,
        "skipped_worker_slot_count": sum((_safe_int(value) or 0) for value in skipped_counts.values()),
        "worker_slot_coordination_counts": dict(sorted(coordination_counts.items())),
        "scanner_coordination_guidance": guidance,
        "scanner_worker_next_rows": {
            "schema": _safe_text(selector_report.get("schema")),
            "git_state": _safe_dict(selector_report.get("git_state")),
            "selection": selection,
        },
        "strict_caveat": "Scanner burndown actions are wiring/proof work items, not exploit proof or detector readiness claims.",
    }


def _scanner_selector_worker_slot(row: dict[str, Any], slot_index: int) -> dict[str, Any]:
    lane = _safe_text(row.get("lane"))
    model_hint = "gpt-5.5/high" if slot_index <= 2 else "gpt-5.4/high"
    if lane == "wire_backend_executor":
        model_hint = "gpt-5.5/xhigh"
    return {
        "slot_id": f"scanner-slot-{slot_index}",
        "task_kind": "end_to_end_scanner_burndown_closure",
        "row_id": _safe_text(row.get("row_id")),
        "lane": lane,
        "rank": row.get("queue_rank"),
        "backend": _safe_text(row.get("backend")),
        "model_hint": model_hint,
        "owned_paths": [_safe_text(path) for path in _safe_list(row.get("owned_paths")) if _safe_text(path)][:12],
        "prompt_seed": _safe_text(row.get("prompt_seed")),
        "acceptance_criteria": [
            _safe_text(item) for item in _safe_list(row.get("acceptance_criteria")) if _safe_text(item)
        ][:5],
        "coordination_rules": [
            "workers implement; coordinator reviews, integrates, and refreshes shared memory at batch boundaries",
            "do not request review-only slots while executable scanner/harness closure rows remain",
            "do not claim exploit coverage or scanner completeness beyond checked local proof artifacts",
        ],
        "suggested_commands": [
            {
                "command": _safe_text(command.get("command")),
                "reason": _safe_text(command.get("reason")),
            }
            for command in _safe_list(row.get("suggested_commands"))[:3]
            if isinstance(command, dict) and _safe_text(command.get("command"))
        ],
        "local_coordination_status": _safe_text(row.get("local_coordination_status")) or "unclaimed_from_local_checkout",
        "matching_dirty_paths": [],
        "local_evidence_paths": [],
        "coordination_note": "Selected by scanner-worker-next-rows after excluding dirty, already-committed, and locally evidenced rows.",
    }


def _scanner_selector_skipped_slot(row: dict[str, Any], slot_index: int) -> dict[str, Any]:
    status = _safe_text(row.get("local_coordination_status")) or "unknown"
    return {
        "slot_id": f"skipped-scanner-slot-{slot_index}",
        "row_id": _safe_text(row.get("row_id")),
        "lane": _safe_text(row.get("lane")),
        "rank": row.get("queue_rank"),
        "backend": _safe_text(row.get("backend")),
        "local_coordination_status": status,
        "skip_reason": status,
        "matching_dirty_paths": [
            _safe_text(path) for path in _safe_list(row.get("matching_dirty_paths")) if _safe_text(path)
        ][:8],
        "local_evidence_paths": [
            _safe_text(path) for path in _safe_list(row.get("local_evidence_paths")) if _safe_text(path)
        ][:8],
        "committed_after_queue_paths": [
            _safe_text(path) for path in _safe_list(row.get("committed_after_queue_paths")) if _safe_text(path)
        ][:8],
        "coordination_note": _safe_text(row.get("reason")),
    }


def _compact_commit_mining_disposition(item: dict[str, Any]) -> dict[str, Any]:
    evidence = _safe_list(item.get("completed_next_step_evidence"))
    first_evidence = _safe_dict(evidence[0]) if evidence and isinstance(evidence[0], dict) else {}
    return {
        "queue_index": item.get("queue_index"),
        "status": _safe_text(item.get("status")),
        "source_row_id": _safe_text(item.get("source_row_id")),
        "task_id": _safe_text(item.get("task_id")),
        "target": _safe_text(item.get("target")),
        "repo_identity": _safe_text(item.get("repo_identity")),
        "action_type": _safe_text(item.get("action_type")),
        "priority": _safe_text(item.get("priority")),
        "packet_status": _safe_text(item.get("packet_status")),
        "next_action": _safe_text(item.get("next_action")),
        "evidence_path": _safe_text(first_evidence.get("evidence_path")),
        "source_ref": _safe_text(first_evidence.get("source_ref")),
        "proof_boundary": _safe_text(item.get("proof_boundary")),
    }


def _commit_mining_source_disposition_snapshot(
    root: Path,
    source_disposition_path: Path,
) -> tuple[dict[str, Any], list[str]]:
    payload, issues = _load_json_object(source_disposition_path)
    rel_path = _rel_or_abs(root, source_disposition_path)
    if issues:
        return {
            "path": rel_path,
            "present": source_disposition_path.is_file(),
            "status": "missing_or_invalid",
            "queued_actionable_count": 0,
            "completed_next_step_count": 0,
            "source_packets_emitted": 0,
            "source_packets_seen": 0,
            "blocked_no_op_count": 0,
            "action_counts": {},
            "top_dispositions": [],
            "strict_caveat": "Commit-mining source disposition state is absent or invalid; do not infer scan-task completion from this packet.",
        }, [f"commit-mining source disposition unavailable: {issue}" for issue in issues]

    summary = _safe_dict(payload.get("summary"))
    queued = _safe_int(summary.get("queued_actionable_count")) or 0
    completed = _safe_int(summary.get("completed_next_step_count")) or 0
    if queued:
        status = "queued_actions_present"
    elif completed:
        status = "completed_next_steps_only"
    else:
        status = "no_disposition_rows_reported"
    dispositions = [
        _compact_commit_mining_disposition(item)
        for item in _safe_list(payload.get("disposition_queue"))[:8]
        if isinstance(item, dict)
    ]
    return {
        "path": rel_path,
        "present": True,
        "schema": _safe_text(payload.get("schema")),
        "status": status,
        "queued_actionable_count": queued,
        "completed_next_step_count": completed,
        "source_packets_emitted": _safe_int(summary.get("source_packets_emitted")) or 0,
        "source_packets_seen": _safe_int(summary.get("source_packets_seen")) or 0,
        "blocked_no_op_count": _safe_int(summary.get("blocked_no_op_count")) or 0,
        "action_counts": _safe_dict(summary.get("action_counts")),
        "top_dispositions": dispositions,
        "strict_caveat": "Commit-mining disposition rows are source-review routing/accounting only, not exploit proof, severity proof, or submission readiness.",
    }, []


def build_status_report(
    root: Path,
    burndown_path: Path,
    dispatch_path: Path,
    scanner_queue_path: Path | None = None,
    commit_mining_source_disposition_path: Path | None = None,
    scanner_active_claims_path: Path | None = None,
) -> dict[str, Any]:
    burndown, issues = _load_json_object(burndown_path)
    dispatch, dispatch_issues = _load_json_object(dispatch_path)
    issues.extend(dispatch_issues)
    scanner_queue_path = scanner_queue_path or default_scanner_burndown_queue_path(root)
    scanner_snapshot, scanner_issues = _scanner_burndown_snapshot(root, scanner_queue_path)
    issues.extend(scanner_issues)
    scanner_active_claims_path = scanner_active_claims_path or default_scanner_worker_active_claims_path(root)
    scanner_active_claims, scanner_active_claim_issues = _scanner_active_claims_snapshot(
        root,
        scanner_active_claims_path,
    )
    issues.extend(scanner_active_claim_issues)
    commit_mining_source_disposition_path = (
        commit_mining_source_disposition_path or default_commit_mining_source_disposition_path(root)
    )
    commit_mining_snapshot, commit_mining_issues = _commit_mining_source_disposition_snapshot(
        root,
        commit_mining_source_disposition_path,
    )
    issues.extend(commit_mining_issues)

    burndown_rows = [
        row for row in _safe_list(burndown.get("rows")) if isinstance(row, dict)
    ]
    burndown_by_id = {
        _safe_text(row.get("id")): row
        for row in burndown_rows
        if _safe_text(row.get("id"))
    }

    dispatch_items = [
        item for item in _safe_list(dispatch.get("work_items")) if isinstance(item, dict)
    ]
    dispatch_by_id = {
        _safe_text(item.get("limitation_id")): item
        for item in dispatch_items
        if _safe_text(item.get("limitation_id"))
    }

    focus_rows: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for item in dispatch_items:
        row_id = _safe_text(item.get("limitation_id"))
        if not row_id or row_id in seen_ids:
            continue
        if _safe_text(item.get("dispatch_lane")) not in FOCUS_LANES:
            continue
        burndown_row = burndown_by_id.get(row_id, {})
        focus_rows.append(
            _apply_local_row_refresh(
                root,
                _build_focus_row(root, row_id, burndown_row, item, source="dispatch_focus_lane"),
            )
        )
        seen_ids.add(row_id)

    related_rows: list[dict[str, Any]] = []
    for row in burndown_rows:
        row_id = _safe_text(row.get("id"))
        if not row_id or row_id in seen_ids:
            continue
        if row_id != "KLBQ-010" and not _owner_lane_mentions_harness_memory(row):
            continue
        related_rows.append(
            _apply_local_row_refresh(
                root,
                _build_focus_row(
                    root,
                    row_id,
                    row,
                    dispatch_by_id.get(row_id),
                    source="local_status_packet" if row_id == "KLBQ-010" else "owner_lane_harness_memory",
                ),
            )
        )
        seen_ids.add(row_id)

    focus_rows.sort(key=lambda row: (_safe_text(row.get("dispatch_lane")), _safe_text(row.get("id"))))
    related_rows.sort(key=lambda row: (_safe_text(row.get("dispatch_lane")), _safe_text(row.get("id"))))

    open_focus_rows = [row for row in focus_rows if row.get("open")]
    verified_focus_rows = [row for row in focus_rows if not row.get("open")]
    open_related_rows = [row for row in related_rows if row.get("open")]
    agent_actionability_rows = [
        {
            "id": _safe_text(row.get("id")),
            "dispatch_lane": _safe_text(row.get("dispatch_lane")),
            **_safe_dict(row.get("agent_actionability")),
        }
        for row in focus_rows + related_rows
        if _safe_dict(row.get("agent_actionability"))
    ]
    actionable_open_rows = [
        row
        for row in focus_rows + related_rows
        if row.get("open") and _safe_list(row.get("actionable_now_commands"))
    ]
    blocked_only_open_rows = [
        row
        for row in focus_rows + related_rows
        if row.get("open")
        and not _safe_list(row.get("actionable_now_commands"))
        and _safe_list(row.get("blocked_command_templates"))
    ]

    blocked_or_missing: list[dict[str, Any]] = []
    for row in focus_rows + related_rows:
        row_issues: list[str] = []
        if row.get("dispatch_lane") == "missing_dispatch_item":
            row_issues.append("dispatch work item is absent for this harness/memory row")
        is_open = bool(row.get("open"))
        for blocker in _safe_list(row.get("blockers")):
            text = _safe_text(blocker)
            if text and is_open and text not in row_issues:
                row_issues.append(text)
        for missing in _safe_list(row.get("missing_evidence_paths")):
            text = _safe_text(missing)
            if text:
                row_issues.append(f"missing local evidence: {text}")
        if row_issues:
            blocked_or_missing.append(
                {
                    "id": _safe_text(row.get("id")),
                    "dispatch_lane": _safe_text(row.get("dispatch_lane")),
                    "issues": row_issues,
                }
            )

    missing_inputs: list[str] = []
    if not burndown_path.is_file():
        missing_inputs.append(f"missing required burndown input: {burndown_path}")
    if not dispatch_path.is_file():
        missing_inputs.append(f"missing required dispatch input: {dispatch_path}")
    if not focus_rows:
        missing_inputs.append(
            "no harness_execution or memory_handoff rows were found in the dispatch report; this is not closure evidence"
        )
    if not focus_rows and not related_rows and burndown_path.is_file() and dispatch_path.is_file():
        missing_inputs.append(
            "no harness/memory-tagged known-limitations rows were found in the burndown queue; this is not closure evidence"
        )

    if open_focus_rows:
        integration_status = "open_rows_present"
    elif blocked_or_missing or missing_inputs:
        integration_status = "blocked_missing_inputs"
    else:
        integration_status = "no_closure_evidence"

    closure_allowed = (
        bool(focus_rows)
        and not open_focus_rows
        and not open_related_rows
        and not blocked_or_missing
        and not missing_inputs
        and all(_safe_list(row.get("evidence_paths")) for row in focus_rows)
    )

    return {
        "schema": SCHEMA,
        "date": _safe_text(burndown.get("date")) or _safe_text(dispatch.get("date")) or DEFAULT_DATE,
        "generated_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "worktree": _safe_text(burndown.get("worktree")) or _safe_text(dispatch.get("worktree")) or str(root),
        "branch": _safe_text(burndown.get("branch")) or _safe_text(dispatch.get("branch")),
        "source_inputs": {
            "burndown_queue": {
                "path": _rel_or_abs(root, burndown_path),
                "present": burndown_path.is_file(),
                "schema": _safe_text(burndown.get("schema")),
            },
            "dispatch_report": {
                "path": _rel_or_abs(root, dispatch_path),
                "present": dispatch_path.is_file(),
                "schema": _safe_text(dispatch.get("schema")),
            },
            "scanner_burndown_queue": {
                "path": scanner_snapshot.get("path"),
                "present": scanner_snapshot.get("present"),
                "schema": scanner_snapshot.get("schema", ""),
            },
            "scanner_worker_active_claims": {
                "path": scanner_active_claims.get("path"),
                "present": scanner_active_claims.get("present"),
                "schema": scanner_active_claims.get("schema", ""),
            },
            "commit_mining_source_disposition": {
                "path": commit_mining_snapshot.get("path"),
                "present": commit_mining_snapshot.get("present"),
                "schema": commit_mining_snapshot.get("schema", ""),
            },
        },
        "execution_priority_policy": EXECUTION_PRIORITY_POLICY,
        "focus_lanes": list(FOCUS_LANES),
        "integration_status": integration_status,
        "summary": {
            "focus_row_count": len(focus_rows),
            "open_focus_row_count": len(open_focus_rows),
            "verified_focus_row_count": len(verified_focus_rows),
            "related_harness_memory_row_count": len(related_rows),
            "open_related_harness_memory_row_count": len(open_related_rows),
            "blocked_or_missing_row_count": len(blocked_or_missing),
            "agent_actionability_row_count": len(agent_actionability_rows),
            "open_rows_with_actionable_now_commands": len(actionable_open_rows),
            "open_rows_blocked_only_by_runtime_inputs": len(blocked_only_open_rows),
            "missing_input_count": len(missing_inputs),
            "scanner_burndown_actionable_row_count": scanner_snapshot.get("actionable_row_count", 0),
            "scanner_burndown_top_action_count": scanner_snapshot.get("top_action_count", 0),
            "scanner_burndown_top_action_lane_counts": scanner_snapshot.get("top_action_lane_counts", {}),
            "scanner_worker_slot_cap": scanner_snapshot.get("worker_slot_cap", SCANNER_WORKER_SLOT_CAP),
            "scanner_worker_slot_count": len(_safe_list(scanner_snapshot.get("next_worker_slots"))),
            "active_scanner_worker_claim_count": scanner_active_claims.get("active", 0),
            "completed_scanner_worker_claim_count": scanner_active_claims.get("completed", 0),
            "skipped_scanner_worker_slot_count": scanner_snapshot.get("skipped_worker_slot_count", 0),
            "refresh_scanner_inventory_before_more_detector_assignments": bool(
                _safe_dict(scanner_snapshot.get("scanner_coordination_guidance")).get(
                    "refresh_inventory_before_more_detector_assignments"
                )
            ),
            "commit_mining_queued_actionable_count": commit_mining_snapshot.get("queued_actionable_count", 0),
            "commit_mining_completed_next_step_count": commit_mining_snapshot.get("completed_next_step_count", 0),
            "commit_mining_source_packets_emitted": commit_mining_snapshot.get("source_packets_emitted", 0),
            "lane_counts": {
                lane: len([row for row in focus_rows if _safe_text(row.get("dispatch_lane")) == lane])
                for lane in FOCUS_LANES
            },
        },
        "closure_claim": {
            "allowed": closure_allowed,
            "reason": (
                "all focus rows are row-level verified with extant local evidence"
                if closure_allowed
                else "open rows, blockers, missing inputs, or missing evidence remain; do not claim closure"
            ),
        },
        "strict_caveats": [
            "This packet is local status accounting only.",
            "Do not treat harness, memory, scaffold, or dispatch packets as exploit proof or submission proof.",
            "Absence of a harness/memory row in one input is not closure evidence by itself.",
            "Rust detector absence on non-Rust source is an applicability boundary, not a pass or exploit proof.",
            "Closure is not allowed unless row-level verified evidence exists for every relevant harness/memory row.",
            _safe_text(scanner_snapshot.get("strict_caveat")),
            _safe_text(scanner_active_claims.get("strict_caveat")),
            _safe_text(commit_mining_snapshot.get("strict_caveat")),
        ],
        "scanner_burndown_snapshot": scanner_snapshot,
        "scanner_worker_active_claims": scanner_active_claims,
        "commit_mining_source_disposition_snapshot": commit_mining_snapshot,
        "open_focus_rows": open_focus_rows,
        "verified_focus_rows": verified_focus_rows,
        "related_harness_memory_rows": related_rows,
        "agent_actionability_rows": agent_actionability_rows,
        "blocked_or_missing_rows": blocked_or_missing,
        "missing_inputs": missing_inputs,
        "issues": issues,
        "changed_paths": [
            "tools/known-limitations-harness-memory-status.py",
            "tools/klbq006-terminal-boundary.py",
            "tools/klbq006-solidity-replay-status.py",
            "tools/tests/test_known_limitations_harness_memory_status.py",
            "tools/tests/test_klbq006_terminal_boundary.py",
            "tools/tests/test_klbq006_solidity_replay_status.py",
            "docs/KLBQ_006_TERMINAL_BOUNDARY_2026-05-05.md",
            "docs/KLBQ_006_SOLIDITY_REPLAY_STATUS_2026-05-05.md",
            "reports/klbq_006_terminal_boundary_2026-05-05.json",
            "reports/klbq_006_solidity_replay_status_2026-05-05.json",
            "docs/KNOWN_LIMITATIONS_HARNESS_MEMORY_STATUS_2026-05-05.md",
            "reports/known_limitations_harness_memory_status_2026-05-05.json",
        ],
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = _safe_dict(report.get("summary"))
    lines = [
        "# Known Limitations Harness/Memory Status 2026-05-05",
        "",
        f"- Integration status: `{_safe_text(report.get('integration_status'))}`",
        f"- Closure claim allowed: `{bool(_safe_dict(report.get('closure_claim')).get('allowed'))}`",
        f"- Closure claim reason: `{_safe_text(_safe_dict(report.get('closure_claim')).get('reason'))}`",
        f"- Focus rows: `{summary.get('focus_row_count', 0)}`",
        f"- Open focus rows: `{summary.get('open_focus_row_count', 0)}`",
        f"- Related harness/memory rows outside focus lanes: `{summary.get('related_harness_memory_row_count', 0)}`",
        f"- Blocked or missing rows: `{summary.get('blocked_or_missing_row_count', 0)}`",
        f"- Agent actionability rows: `{summary.get('agent_actionability_row_count', 0)}`",
        f"- Open rows with exact commands available now: `{summary.get('open_rows_with_actionable_now_commands', 0)}`",
        f"- Open rows blocked only by runtime inputs: `{summary.get('open_rows_blocked_only_by_runtime_inputs', 0)}`",
        f"- Missing inputs: `{summary.get('missing_input_count', 0)}`",
        f"- Scanner burndown actionable rows: `{summary.get('scanner_burndown_actionable_row_count', 0)}`",
        f"- Scanner burndown top action lanes: `{summary.get('scanner_burndown_top_action_lane_counts', {})}`",
        f"- Scanner worker slots: `{summary.get('scanner_worker_slot_count', 0)}` / `{summary.get('scanner_worker_slot_cap', 0)}`",
        f"- Active scanner worker claims: `{summary.get('active_scanner_worker_claim_count', 0)}`",
        f"- Completed scanner worker claims: `{summary.get('completed_scanner_worker_claim_count', 0)}`",
        f"- Skipped scanner worker slots: `{summary.get('skipped_scanner_worker_slot_count', 0)}`",
        "- Refresh scanner inventory before more detector assignments: `"
        + str(bool(summary.get("refresh_scanner_inventory_before_more_detector_assignments"))).lower()
        + "`",
        f"- Commit-mining queued actions: `{summary.get('commit_mining_queued_actionable_count', 0)}`",
        f"- Commit-mining completed next steps: `{summary.get('commit_mining_completed_next_step_count', 0)}`",
        "",
        "## Execution Priority Policy",
        "",
        "- Priority order: `"
        + " > ".join(str(item) for item in _safe_list(_safe_dict(report.get("execution_priority_policy")).get("priority_order")))
        + "`",
        f"- Agent usage: `{_safe_text(_safe_dict(report.get('execution_priority_policy')).get('agent_usage'))}`",
        f"- Batch boundary rule: `{_safe_text(_safe_dict(report.get('execution_priority_policy')).get('batch_boundary_rule'))}`",
        "",
        "## Open Focus Rows",
        "",
        "| ID | Lane | Status | Action Status | Loop | Next Action | Blockers |",
        "| --- | --- | --- | --- | ---: | --- | --- |",
    ]
    open_rows = _safe_list(report.get("open_focus_rows"))
    for row in open_rows:
        blockers = "; ".join(_safe_list(row.get("blockers"))) or "-"
        next_action = _safe_text(row.get("next_action")) or "-"
        action_status = _safe_text(row.get("next_action_status")) or "unknown"
        lines.append(
            "| {id} | {lane} | {status} | {action_status} | {loop} | {next_action} | {blockers} |".format(
                id=_safe_text(row.get("id")),
                lane=_safe_text(row.get("dispatch_lane")),
                status=_safe_text(row.get("current_status")) or "unknown",
                action_status=action_status,
                loop=_safe_text(row.get("scheduled_loop")) or "-",
                next_action=next_action.replace("|", "/"),
                blockers=blockers.replace("|", "/"),
            )
        )
    if not open_rows:
        lines.append("| - | - | - | - | - | - | No open focus rows present in the current inputs |")

    lines.extend(["", "## Executable Next Actions", ""])
    executable_rows = [
        row
        for row in _safe_list(report.get("open_focus_rows")) + _safe_list(report.get("related_harness_memory_rows"))
        if _safe_list(row.get("actionable_now_commands")) or _safe_list(row.get("blocked_command_templates"))
    ]
    if executable_rows:
        for row in executable_rows:
            lines.append(f"- `{_safe_text(row.get('id'))}` [{_safe_text(row.get('next_action_status')) or 'unknown'}]")
            for command in _safe_list(row.get("actionable_now_commands")):
                lines.append(f"  - now: `{_safe_text(command)}`")
            for blocked in _safe_list(row.get("blocked_command_templates")):
                blocked_item = _safe_dict(blocked)
                missing_inputs = ", ".join(_safe_list(blocked_item.get("missing_inputs"))) or "unspecified"
                lines.append(
                    f"  - blocked template: `{_safe_text(blocked_item.get('command'))}` (missing: {missing_inputs})"
                )
    else:
        lines.append("- No executable next-action commands were derived from the current inputs.")

    scanner = _safe_dict(report.get("scanner_burndown_snapshot"))
    lines.extend(["", "## Scanner Burndown Snapshot", ""])
    lines.append(f"- Status: `{_safe_text(scanner.get('status')) or 'unknown'}`")
    lines.append(f"- Source: `{_safe_text(scanner.get('path')) or '-'}`")
    lines.append(f"- Actionable rows: `{scanner.get('actionable_row_count', 0)}`")
    lines.append(f"- Top action lane counts: `{scanner.get('top_action_lane_counts', {})}`")
    lines.append(
        "- Assignable worker slots: "
        f"`{scanner.get('assignable_worker_slot_count', 0)}` / `{scanner.get('worker_slot_cap', 0)}`"
    )
    lines.append(f"- Worker rows scanned: `{scanner.get('worker_slots_scanned', 0)}`")
    if scanner.get("worker_slot_coordination_counts"):
        lines.append(f"- Worker coordination counts: `{scanner.get('worker_slot_coordination_counts')}`")
    top_actions = _safe_list(scanner.get("top_actions"))
    if top_actions:
        lines.extend(
            [
                "",
                "| Rank | Lane | Row | Backend | Wiring | Proof | Next Action |",
                "| ---: | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for action in top_actions[:8]:
            action_row = _safe_dict(action)
            lines.append(
                "| {rank} | {lane} | {row_id} | {backend} | {wiring} | {proof} | {next_action} |".format(
                    rank=_safe_text(action_row.get("rank")) or "-",
                    lane=_safe_text(action_row.get("lane")) or "-",
                    row_id=_safe_text(action_row.get("row_id")).replace("|", "/") or "-",
                    backend=_safe_text(action_row.get("backend")) or "-",
                    wiring=_safe_text(action_row.get("wiring_status")) or "-",
                    proof=_safe_text(action_row.get("proof_status")) or "-",
                    next_action=_safe_text(action_row.get("suggested_next_action")).replace("|", "/") or "-",
                )
            )
    else:
        lines.append("- No scanner burndown actions were available in this packet.")

    worker_slots = _safe_list(scanner.get("next_worker_slots"))
    lines.extend(["", "## Scanner Worker Slots", ""])
    if worker_slots:
        lines.extend(
            [
                "| Slot | Row | Lane | Coordination | Model Hint | Owned Paths |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for slot in worker_slots[:8]:
            item = _safe_dict(slot)
            owned = ", ".join(_safe_list(item.get("owned_paths"))[:4]) or "-"
            lines.append(
                "| {slot_id} | {row_id} | {lane} | {coordination} | {model_hint} | {owned} |".format(
                    slot_id=_safe_text(item.get("slot_id")) or "-",
                    row_id=_safe_text(item.get("row_id")).replace("|", "/") or "-",
                    lane=_safe_text(item.get("lane")) or "-",
                    coordination=_safe_text(item.get("local_coordination_status")) or "-",
                    model_hint=_safe_text(item.get("model_hint")) or "-",
                    owned=owned.replace("|", "/"),
                )
            )
    else:
        lines.append("- No unclaimed scanner worker slots were derived from the current inputs.")

    active_claims = _safe_dict(report.get("scanner_worker_active_claims"))
    lines.extend(["", "## Active Scanner Worker Claims", ""])
    if active_claims.get("present"):
        lines.append(
            f"- Source: `{_safe_text(active_claims.get('path'))}`; updated `{_safe_text(active_claims.get('updated_at')) or '-'}`"
        )
        lines.append(
            f"- Active: `{active_claims.get('active', 0)}`; completed: `{active_claims.get('completed', 0)}`"
        )
        rows = _safe_list(active_claims.get("active_claims"))
        if rows:
            lines.extend(["", "| Agent | Row |", "| --- | --- |"])
            for row in rows[:8]:
                item = _safe_dict(row)
                lines.append(
                    f"| `{_safe_text(item.get('agent_id')) or '-'}` | `{_safe_text(item.get('row_id')) or '-'}` |"
                )
        else:
            lines.append("- No active claims are recorded in the claim map.")
    else:
        lines.append("- No active scanner claim map is present in this checkout.")

    skipped_worker_slots = _safe_list(scanner.get("skipped_worker_slots"))
    if skipped_worker_slots:
        lines.extend(
            [
                "",
                "## Skipped Scanner Worker Slots",
                "",
                "| Row | Rank | Coordination | Reason |",
                "| --- | ---: | --- | --- |",
            ]
        )
        for slot in skipped_worker_slots[:8]:
            item = _safe_dict(slot)
            lines.append(
                "| {row_id} | {rank} | {coordination} | {reason} |".format(
                    row_id=_safe_text(item.get("row_id")).replace("|", "/") or "-",
                    rank=_safe_text(item.get("rank")) or "-",
                    coordination=_safe_text(item.get("local_coordination_status")) or "-",
                    reason=_safe_text(item.get("coordination_note")).replace("|", "/") or "-",
                )
            )

    commit_mining = _safe_dict(report.get("commit_mining_source_disposition_snapshot"))
    lines.extend(["", "## Commit-Mining Source Disposition Snapshot", ""])
    lines.append(f"- Status: `{_safe_text(commit_mining.get('status')) or 'unknown'}`")
    lines.append(f"- Source: `{_safe_text(commit_mining.get('path')) or '-'}`")
    lines.append(f"- Queued actionable rows: `{commit_mining.get('queued_actionable_count', 0)}`")
    lines.append(f"- Completed next steps: `{commit_mining.get('completed_next_step_count', 0)}`")
    lines.append(f"- Source packets emitted: `{commit_mining.get('source_packets_emitted', 0)}`")
    top_dispositions = _safe_list(commit_mining.get("top_dispositions"))
    if top_dispositions:
        lines.extend(
            [
                "",
                "| Index | Status | Source Row | Target | Action | Packet | Next Action |",
                "| ---: | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for item in top_dispositions[:6]:
            disposition = _safe_dict(item)
            lines.append(
                "| {index} | {status} | {source_row} | {target} | {action} | {packet} | {next_action} |".format(
                    index=_safe_text(disposition.get("queue_index")) or "-",
                    status=_safe_text(disposition.get("status")).replace("|", "/") or "-",
                    source_row=_safe_text(disposition.get("source_row_id")).replace("|", "/") or "-",
                    target=_safe_text(disposition.get("target")).replace("|", "/") or "-",
                    action=_safe_text(disposition.get("action_type")).replace("|", "/") or "-",
                    packet=_safe_text(disposition.get("packet_status")).replace("|", "/") or "-",
                    next_action=_safe_text(disposition.get("next_action")).replace("|", "/") or "-",
                )
            )
    else:
        lines.append("- No commit-mining disposition rows were available in this packet.")

    lines.extend(["", "## Next Agent Decisions", ""])
    actionability_rows = _safe_list(report.get("agent_actionability_rows"))
    if actionability_rows:
        lines.extend(
            [
                "| ID | Lane | Decision | Local Replay | Required Input | Read First |",
                "| --- | --- | --- | --- | --- | --- |",
            ]
        )
        for row in actionability_rows:
            read_first = ", ".join(_safe_list(row.get("read_first"))[:3]) or "-"
            lines.append(
                "| {id} | {lane} | {decision} | {local_replay} | {required_input} | {read_first} |".format(
                    id=_safe_text(row.get("id")),
                    lane=_safe_text(row.get("dispatch_lane")),
                    decision=_safe_text(row.get("decision")),
                    local_replay="yes" if bool(row.get("can_dispatch_local_replay")) else "no",
                    required_input=(_safe_text(row.get("required_input")) or "-").replace("|", "/"),
                    read_first=read_first.replace("|", "/"),
                )
            )
    else:
        lines.append("- No row-level agent actionability packets were derived from the current inputs.")

    lines.extend(["", "## Blocked Or Missing", ""])
    blocked_rows = _safe_list(report.get("blocked_or_missing_rows"))
    if blocked_rows:
        for row in blocked_rows:
            issues = "; ".join(_safe_list(row.get("issues"))) or "-"
            lines.append(f"- `{_safe_text(row.get('id'))}` [{_safe_text(row.get('dispatch_lane'))}]: {issues}")
    else:
        lines.append("- No blocked-or-missing rows were derived from the current inputs.")

    lines.extend(["", "## Missing Inputs", ""])
    missing_inputs = _safe_list(report.get("missing_inputs"))
    if missing_inputs:
        for item in missing_inputs:
            lines.append(f"- {_safe_text(item)}")
    else:
        lines.append("- None.")

    lines.extend(["", "## Caveats", ""])
    for caveat in _safe_list(report.get("strict_caveats")):
        lines.append(f"- {_safe_text(caveat)}")
    return "\n".join(lines) + "\n"


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _emit_outputs(
    *,
    output_path: Path,
    docs_path: Path,
    report: dict[str, Any],
    markdown: str,
    write_outputs: bool,
) -> list[str]:
    if not write_outputs:
        return []
    _write_json(output_path, report)
    _write_text(docs_path, markdown)
    return [str(output_path), str(docs_path)]


def parse_args() -> argparse.Namespace:
    root = repo_root()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--burndown", type=Path, default=default_burndown_path(root), help="Known limitations burndown queue JSON")
    parser.add_argument("--dispatch", type=Path, default=default_dispatch_path(root), help="Known limitations dispatch JSON")
    parser.add_argument("--scanner-burndown", type=Path, default=default_scanner_burndown_queue_path(root), help="Scanner wiring burndown queue JSON")
    parser.add_argument(
        "--scanner-active-claims",
        type=Path,
        default=default_scanner_worker_active_claims_path(root),
        help="Scanner worker active-claims JSON",
    )
    parser.add_argument(
        "--commit-mining-source-disposition",
        type=Path,
        default=default_commit_mining_source_disposition_path(root),
        help="Commit-mining source disposition JSON",
    )
    parser.add_argument("--output", type=Path, default=default_output_path(root), help="Status packet JSON output")
    parser.add_argument("--docs", type=Path, default=default_docs_path(root), help="Status packet Markdown output")
    parser.add_argument("--print-json", action="store_true", help="Print generated JSON to stdout")
    parser.add_argument(
        "--no-write",
        action="store_true",
        help="Do not update the JSON/Markdown artifacts; useful for mid-loop probes before a clean batch-boundary refresh",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = repo_root()
    report = build_status_report(
        root,
        args.burndown,
        args.dispatch,
        args.scanner_burndown,
        args.commit_mining_source_disposition,
        args.scanner_active_claims,
    )
    markdown = render_markdown(report)
    _emit_outputs(
        output_path=args.output,
        docs_path=args.docs,
        report=report,
        markdown=markdown,
        write_outputs=not args.no_write,
    )
    if args.print_json:
        print(json.dumps(report, indent=2, sort_keys=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
