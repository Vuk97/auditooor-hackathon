#!/usr/bin/env python3
"""Build a next-loop dispatch plan from the known limitations burndown queue."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.known_limitations_dispatch.v1"
DEFAULT_DATE = "2026-05-05"
LANE_ORDER = {
    "memory_handoff": 0,
    "harness_execution": 1,
    "scanner_wiring": 2,
    "rust_detector_lift": 3,
    "commit_mining": 4,
    "docs_state": 5,
    "blocked_needs_source": 6,
    "blocked_needs_user_input": 7,
}
PRIORITY_POLICY = {
    "ordered_lanes": list(LANE_ORDER),
    "rule": (
        "Schedule memory handoff first, harness execution second, known-limitation "
        "burn-down lanes third, and docs/blocked maintenance only after those lanes."
    ),
    "known_limitation_burndown_lanes": [
        "scanner_wiring",
        "rust_detector_lift",
        "commit_mining",
    ],
}
LOOP_CAPACITY = 3
RANK_RE = re.compile(r"(\d+)")


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _latest_report_rel_path(root: Path, stem: str, fallback_rel: str) -> str:
    reports_dir = root / "reports"
    if not reports_dir.is_dir():
        return fallback_rel
    matches = sorted(reports_dir.glob(f"{stem}_*.json"), key=lambda path: path.name)
    if not matches:
        return fallback_rel
    return str(matches[-1].relative_to(root))


def _dated_docs_path_for_report(report_rel_path: str, report_stem: str, docs_prefix: str, fallback: str) -> str:
    pattern = rf"{re.escape(report_stem)}_(20\d{{2}}-\d{{2}}-\d{{2}})\.json$"
    match = re.search(pattern, report_rel_path)
    if not match:
        return fallback
    return f"docs/{docs_prefix}_{match.group(1)}.md"


def default_input_path(root: Path) -> Path:
    fallback_rel = f"reports/known_limitations_burndown_queue_{DEFAULT_DATE}.json"
    return root / _latest_report_rel_path(root, "known_limitations_burndown_queue", fallback_rel)


def default_output_path(root: Path) -> Path:
    return root / "reports" / f"known_limitations_dispatch_{DEFAULT_DATE}.json"


def default_docs_path(root: Path) -> Path:
    return root / "docs" / f"KNOWN_LIMITATIONS_DISPATCH_{DEFAULT_DATE}.md"


def default_impact_status_path(root: Path) -> Path:
    fallback_rel = f"reports/impact_contract_preflight_status_{DEFAULT_DATE}.json"
    return root / _latest_report_rel_path(root, "impact_contract_preflight_status", fallback_rel)


def default_detector_gap_provenance_path(root: Path) -> Path:
    fallback_rel = f"reports/detector_gap_regen_provenance_{DEFAULT_DATE}.json"
    return root / _latest_report_rel_path(root, "detector_gap_regen_provenance", fallback_rel)


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


def _load_json_object(path: Path) -> tuple[dict[str, Any], list[str]]:
    issues: list[str] = []
    if not path.is_file():
        issues.append(f"missing input report: {path}")
        return {}, issues
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except json.JSONDecodeError as exc:
        issues.append(f"invalid JSON in {path}: {exc}")
        return {}, issues
    except OSError as exc:
        issues.append(f"unable to read {path}: {exc}")
        return {}, issues
    if not isinstance(payload, dict):
        issues.append(f"expected object payload in {path}")
        return {}, issues
    return payload, issues


def _parse_loop_cost(raw: Any, implementation_status: str) -> int:
    if isinstance(raw, int):
        return max(0, raw)
    if isinstance(raw, float):
        return max(0, int(raw))
    text = _safe_text(raw).lower()
    match = RANK_RE.search(text)
    if match:
        return max(0, int(match.group(1)))
    if implementation_status == "implemented_v0":
        return 0
    return 1


def _combine_status(implementation_status: str, verification_status: str, row: dict[str, Any]) -> str:
    if implementation_status == "implemented_v0" and verification_status == "pass":
        return "implemented_verified"
    if implementation_status == "implemented_v0" and verification_status == "pass_with_real_blockers_remaining":
        return "implemented_verified_with_followup_blockers"
    if implementation_status == "implemented_v0" and verification_status:
        return f"implemented_{verification_status}"
    if implementation_status and verification_status:
        return f"{implementation_status}_{verification_status}"
    if implementation_status:
        return implementation_status
    if _safe_list(row.get("blocked_until")) or _safe_list(row.get("remaining_blockers")):
        return "open_blocked"
    return "open_unverified"


def _existing_paths(root: Path, candidates: list[Any]) -> tuple[list[str], list[str]]:
    seen_existing: set[str] = set()
    seen_missing: set[str] = set()
    existing: list[str] = []
    missing: list[str] = []
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


def _row_terms(row: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in (
        "id",
        "limitation",
        "implementation_status",
        "status_notes",
        "concrete_next_patch",
        "expected_capability_lift",
        "gating_test",
        "owner_lane",
        "loop_estimate",
        "verification_status",
    ):
        parts.append(_safe_text(row.get(key)))
    for key in ("blocked_until", "remaining_blockers", "local_evidence", "source_refs", "depends_on"):
        parts.extend(_safe_text(item) for item in _safe_list(row.get(key)))
    return " ".join(part.lower() for part in parts if part)


def _contains_any(text: str, needles: tuple[str, ...]) -> bool:
    return any(needle in text for needle in needles)


def _dispatch_lane(row: dict[str, Any]) -> str:
    text = _row_terms(row)
    owner_lane = _safe_text(row.get("owner_lane")).lower()
    if _contains_any(
        text,
        (
            "needs_human",
            "human input",
            "user input",
            "manual approval",
            "operator approval",
            "missing entrypoint",
        ),
    ):
        return "blocked_needs_user_input"
    if _contains_any(
        text,
        (
            "absent local roots",
            "source root",
            "source roots",
            "source-absent",
            "source replay remains blocked",
            "blocked kg",
            "blocked by absent local roots",
            "exact local source roots",
            "missing exact findings export",
            "exact solodit findings export",
        ),
    ):
        return "blocked_needs_source"
    if _contains_any(owner_lane, ("harness", "detector calibration", "precision")):
        return "harness_execution"
    if _contains_any(
        text,
        (
            "scanner",
            "dsl",
            "silent-detector",
            "scanner-wiring",
            "scanner wiring",
            "fake quarantine",
            "quarantine",
            "agent_found_not_detector_found",
            "scanner-autonomy",
        ),
    ):
        return "scanner_wiring"
    if _contains_any(text, ("rust", "cross-crate", "source-shape-only", "source shape")):
        return "rust_detector_lift"
    if _contains_any(
        text,
        (
            "source ref",
            "source replay",
            "commit mining",
            "github commit",
            "manifest fixture",
            "mutable refs",
        ),
    ):
        return "commit_mining"
    if _contains_any(
        text,
        (
            "memory recall",
            "memory-next-loop",
            "memory next-loop",
            "harness-failure memory",
            "harness failure memory",
            "finalization",
            "unknown-reason",
            "event ledger",
            "slot refill",
            "task-finalization",
            "task finalization",
        ),
    ):
        return "memory_handoff"
    if _contains_any(
        text,
        (
            "harness",
            "fixture",
            "precision",
            "rerun",
            "calibration",
            "binding-manifest",
            ".t.sol",
        ),
    ):
        return "harness_execution"
    return "docs_state"


def _primary_blocker(row: dict[str, Any], missing_evidence: list[str], current_status: str) -> str:
    remaining = [_safe_text(item) for item in _safe_list(row.get("remaining_blockers")) if _safe_text(item)]
    if remaining:
        return remaining[0]
    blocked_until = [_safe_text(item) for item in _safe_list(row.get("blocked_until")) if _safe_text(item)]
    if blocked_until:
        return f"Awaiting: {blocked_until[0]}"
    if missing_evidence:
        return f"missing local evidence: {missing_evidence[0]}"
    if current_status.startswith("implemented_verified"):
        return "No hard blocker in local evidence; keep regression coverage and accounting honest."
    return "Needs concrete local implementation evidence or a narrower executable gate."


def _dedupe_text(items: list[Any]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for item in items:
        text = _safe_text(item)
        if text and text not in seen:
            deduped.append(text)
            seen.add(text)
    return deduped


def _load_impact_status_override(root: Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    packet_path = default_impact_status_path(root)
    if not packet_path.is_file():
        return {}, []
    packet, issues = _load_json_object(packet_path)
    if not packet:
        return {}, issues
    limitation_id = _safe_text(packet.get("limitation_id"))
    if limitation_id != "KLBQ-010":
        return {}, [f"unexpected limitation_id in {packet_path}: {limitation_id or '(missing)'}"]
    return {limitation_id: {**packet, "_packet_path": str(packet_path.relative_to(root))}}, issues


def _load_detector_gap_provenance_override(root: Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    packet_path = default_detector_gap_provenance_path(root)
    if not packet_path.is_file():
        return {}, []
    packet, issues = _load_json_object(packet_path)
    if not packet:
        return {}, issues
    if _safe_text(packet.get("schema")) != "auditooor.detector_gap_regen_provenance.v1":
        return {}, [f"unexpected schema in {packet_path}: {_safe_text(packet.get('schema')) or '(missing)'}"]
    return {"KLBQ-001": {**packet, "_packet_path": str(packet_path.relative_to(root))}}, issues


def _load_local_status_overrides(root: Path) -> tuple[dict[str, dict[str, Any]], list[str]]:
    overrides: dict[str, dict[str, Any]] = {}
    issues: list[str] = []
    for loader in (_load_impact_status_override, _load_detector_gap_provenance_override):
        loaded, loaded_issues = loader(root)
        overrides.update(loaded)
        issues.extend(loaded_issues)
    return overrides, issues


def _status_packet_closes_row(packet: dict[str, Any]) -> bool:
    return (
        _safe_text(packet.get("schema")) == "auditooor.impact_contract_preflight_status.v1"
        and _safe_text(packet.get("implementation_status")).startswith("implemented_verified")
        and not bool(packet.get("open"))
        and not bool(packet.get("dispatch_ready"))
        and int(packet.get("expected_loop_cost") or 0) == 0
        and bool(packet.get("not_submission_evidence", True))
    )


def _apply_status_packet_override(row: dict[str, Any], packet: dict[str, Any]) -> dict[str, Any]:
    if _safe_text(packet.get("schema")) == "auditooor.detector_gap_regen_provenance.v1":
        return _apply_detector_gap_provenance_override(row, packet)
    if not _status_packet_closes_row(packet):
        return row
    packet_path = _safe_text(packet.get("_packet_path")) or f"reports/impact_contract_preflight_status_{DEFAULT_DATE}.json"
    docs_path = _dated_docs_path_for_report(
        packet_path,
        "impact_contract_preflight_status",
        "IMPACT_CONTRACT_PREFLIGHT_STATUS",
        f"docs/IMPACT_CONTRACT_PREFLIGHT_STATUS_{DEFAULT_DATE}.md",
    )
    evidence_paths = _dedupe_text(
        _safe_list(packet.get("evidence_paths"))
        + [packet_path, docs_path]
        + _safe_list(row.get("local_evidence"))
        + _safe_list(row.get("source_refs"))
    )
    verification_commands = _dedupe_text(_safe_list(packet.get("verification_commands")))
    closed_benefit = _safe_text(packet.get("closed_benefit"))
    refreshed = dict(row)
    refreshed.update(
        {
            "implementation_status": _safe_text(packet.get("implementation_status")),
            "verification_status": "",
            "status_notes": (
                f"{closed_benefit} Local accounting only; this is not exploit proof, source proof, or submission proof."
            ).strip(),
            "concrete_next_patch": (
                "Preserve the local impact-contract preflight status packet and route tests so proof-grade "
                "filing/promotion/source-proof/harness-scaffold paths stay fail-closed while exploit-memory remains advisory-only."
            ),
            "gating_test": " && ".join(verification_commands),
            "loop_estimate": "0 loops",
            "local_evidence": evidence_paths,
            "source_refs": [],
            "blocked_until": [],
            "remaining_blockers": [],
            "verification_commands": verification_commands,
            "not_submission_evidence": True,
            "local_status_packet": packet_path,
        }
    )
    return refreshed


def _detector_gap_provenance_overrides_row(packet: dict[str, Any]) -> bool:
    return (
        _safe_text(packet.get("schema")) == "auditooor.detector_gap_regen_provenance.v1"
        and bool(packet.get("fail_closed"))
        and not bool(packet.get("regenerated"))
        and _safe_text(packet.get("status")) == "blocked_missing_exact_findings_export"
    )


def _apply_detector_gap_provenance_override(row: dict[str, Any], packet: dict[str, Any]) -> dict[str, Any]:
    if _safe_text(row.get("id")) != "KLBQ-001" or not _detector_gap_provenance_overrides_row(packet):
        return row
    packet_path = _safe_text(packet.get("_packet_path")) or f"reports/detector_gap_regen_provenance_{DEFAULT_DATE}.json"
    docs_path = _dated_docs_path_for_report(
        packet_path,
        "detector_gap_regen_provenance",
        "DETECTOR_GAP_REGEN_PROVENANCE",
        f"docs/DETECTOR_GAP_REGEN_PROVENANCE_{DEFAULT_DATE}.md",
    )
    blocking_reason = _safe_text(packet.get("blocking_reason")) or (
        "The exact Solodit findings export is absent, so the current detector_gap report cannot be safely regenerated."
    )
    required_input = _safe_dict(packet.get("required_input"))
    required_description = _safe_text(required_input.get("description")) or "Exact local Solodit findings export"
    next_commands = _dedupe_text(_safe_list(packet.get("next_commands")))
    verification_commands = _dedupe_text(
        [
            "python3 -m unittest tools.tests.test_source_ref_replay_manifest tools.tests.test_detector_blindspot_scan -v",
            f"python3 -m json.tool {packet_path}",
        ]
        + next_commands
    )
    evidence_paths = _dedupe_text(
        [
            "tools/_run_gap_analysis.py",
            "tools/detector-blindspot-scan.py",
            "tools/source-ref-replay-manifest.py",
            "tools/tests/test_source_ref_replay_manifest.py",
            "tools/tests/test_detector_blindspot_scan.py",
            packet_path,
            docs_path,
            "reports/detector_gap.json",
        ]
        + _safe_list(row.get("local_evidence"))
        + _safe_list(row.get("source_refs"))
    )
    refreshed = dict(row)
    refreshed.update(
        {
            "implementation_status": "implemented_v0",
            "verification_status": "pass_with_real_blockers_remaining",
            "status_notes": (
                "Source-ref preservation is wired into both detector-gap generation paths: "
                "`tools/_run_gap_analysis.py` emits/applies the replay manifest before writing "
                "`reports/detector_gap.json`, and `tools/detector-blindspot-scan.py` emits/applies "
                "the companion manifest before report output. The current checked-in 98-row "
                "detector_gap remains fail-closed stale state because the exact raw findings export "
                "is absent locally."
            ),
            "concrete_next_patch": (
                "Provide the exact 98-row Solodit findings export locally, rerun "
                "`python3.13 tools/detector-blindspot-scan.py --data <absolute-path-to-solodit-findings-export.json> "
                "--max-findings 98` through the source-ref manifest path, then verify nonzero `github_ref` "
                "preservation before using the report for source replay."
            ),
            "gating_test": " && ".join(verification_commands),
            "loop_estimate": "1 loop",
            "local_evidence": evidence_paths,
            "source_refs": [],
            "blocked_until": [
                f"source replay remains blocked by absent exact findings export: {required_description}",
            ],
            "remaining_blockers": [
                blocking_reason,
                "Current reports/detector_gap.json has zero github_ref rows and must not be treated as source-ref-complete until regenerated from the exact raw export.",
            ],
            "verification_commands": verification_commands,
            "not_submission_evidence": True,
            "local_status_packet": packet_path,
        }
    )
    return refreshed


def _next_action(row: dict[str, Any], lane: str) -> str:
    direct = _safe_text(row.get("concrete_next_patch"))
    if direct:
        return direct
    limitation = _safe_text(row.get("limitation")) or _safe_text(row.get("id")) or "the row"
    if lane == "blocked_needs_source":
        return f"Acquire the missing local source roots or replay inputs for {limitation} before redispatching."
    if lane == "blocked_needs_user_input":
        return f"Turn {limitation} into an exact local command or binding before sending it back into execution."
    if lane == "scanner_wiring":
        return f"Close the scanner-wiring gap for {limitation} with fixtures, executor proof, or explicit quarantine."
    if lane == "rust_detector_lift":
        return f"Add runtime-backed Rust evidence for {limitation} so it is no longer source-shape-only."
    if lane == "harness_execution":
        return f"Produce a runnable harness artifact or a schema-valid blocked manifest for {limitation}."
    if lane == "commit_mining":
        return f"Resolve the source-ref or commit provenance gap for {limitation} with extant local artifacts."
    if lane == "memory_handoff":
        return f"Wire the memory/finalization contract for {limitation} into the next-loop executor."
    return f"Update the docs/state contract for {limitation} with executable local evidence."


def _priority_tier(
    source_rank: int,
    lane: str,
    current_status: str,
    expected_loop_cost: int,
) -> str:
    if current_status.startswith("implemented_verified") and expected_loop_cost == 0:
        return "P3"
    if lane in {"blocked_needs_source", "blocked_needs_user_input"}:
        return "P2" if source_rank <= 4 else "P3"
    if source_rank <= 2:
        return "P0"
    if source_rank <= 6:
        return "P1"
    if source_rank <= 8:
        return "P2"
    return "P3"


def _priority_score(
    source_rank: int,
    lane: str,
    current_status: str,
    expected_loop_cost: int,
) -> int:
    score = max(0, 120 - (source_rank * 8))
    if lane == "memory_handoff":
        score += 50
    elif lane == "harness_execution":
        score += 40
    elif lane == "scanner_wiring":
        score += 32
    elif lane == "rust_detector_lift":
        score += 28
    elif lane == "commit_mining":
        score += 20
    elif lane == "docs_state":
        score += 6
    elif lane == "blocked_needs_source":
        score -= 10
    elif lane == "blocked_needs_user_input":
        score -= 14
    if current_status.startswith("implemented_verified"):
        score -= 36
    elif current_status.startswith("implemented_"):
        score -= 18
    if expected_loop_cost == 0:
        score -= 12
    elif expected_loop_cost >= 2:
        score += 4
    return score


def _build_item(root: Path, row: dict[str, Any], index: int) -> dict[str, Any]:
    source_rank = int(row.get("rank") or index)
    limitation_id = _safe_text(row.get("id")) or f"KLBQ-UNSPECIFIED-{index:03d}"
    implementation_status = _safe_text(row.get("implementation_status"))
    verification_status = _safe_text(row.get("verification_status"))
    current_status = _combine_status(implementation_status, verification_status, row)
    expected_loop_cost = _parse_loop_cost(row.get("loop_estimate"), implementation_status)
    lane = _dispatch_lane(row)
    if current_status.startswith("implemented_verified") and expected_loop_cost == 0:
        lane = "docs_state"
    evidence_candidates = (
        _safe_list(row.get("local_evidence"))
        + _safe_list(row.get("source_refs"))
    )
    evidence_paths, missing_evidence_paths = _existing_paths(root, evidence_candidates)
    priority = _priority_tier(source_rank, lane, current_status, expected_loop_cost)
    priority_score = _priority_score(source_rank, lane, current_status, expected_loop_cost)
    blocker = _primary_blocker(row, missing_evidence_paths, current_status)
    dispatch_ready = lane not in {"blocked_needs_source", "blocked_needs_user_input"} and not (
        current_status.startswith("implemented_verified") and expected_loop_cost == 0
    )
    return {
        "limitation_id": limitation_id,
        "source_rank": source_rank,
        "current_status": current_status,
        "blocker": blocker,
        "dispatch_lane": lane,
        "next_action": _next_action(row, lane),
        "evidence_paths": evidence_paths,
        "missing_evidence_paths": missing_evidence_paths,
        "verification_commands": [
            _safe_text(command)
            for command in _safe_list(row.get("verification_commands"))
            if _safe_text(command)
        ],
        "priority": priority,
        "priority_score": priority_score,
        "expected_loop_cost": expected_loop_cost,
        "dispatch_ready": dispatch_ready,
        "limitation": _safe_text(row.get("limitation")),
        "owner_lane": _safe_text(row.get("owner_lane")),
        "status_notes": _safe_text(row.get("status_notes")),
        "depends_on": [_safe_text(item) for item in _safe_list(row.get("depends_on")) if _safe_text(item)],
    }


def _sorted_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        items,
        key=lambda item: (
            LANE_ORDER.get(item["dispatch_lane"], 999),
            item["priority_score"] * -1,
            item["source_rank"],
            item["limitation_id"],
        ),
    )


def _schedule_items(items: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    ready = [dict(item) for item in items if item["dispatch_ready"] and item["expected_loop_cost"] > 0]
    ready = _sorted_items(ready)
    loops: list[dict[str, Any]] = []
    for item in ready:
        cost = max(1, int(item["expected_loop_cost"]))
        placed = False
        for loop in loops:
            if loop["total_expected_loop_cost"] + cost <= LOOP_CAPACITY:
                loop["items"].append(item["limitation_id"])
                loop["lanes"].append(item["dispatch_lane"])
                loop["total_expected_loop_cost"] += cost
                item["scheduled_loop"] = loop["loop_index"]
                placed = True
                break
        if placed:
            continue
        loop_index = len(loops) + 1
        loops.append(
            {
                "loop_index": loop_index,
                "total_expected_loop_cost": cost,
                "items": [item["limitation_id"]],
                "lanes": [item["dispatch_lane"]],
            }
        )
        item["scheduled_loop"] = loop_index
    for loop in loops:
        loop["lanes"] = sorted(set(loop["lanes"]), key=lambda lane: LANE_ORDER.get(lane, 999))
    return ready, loops


def build_dispatch_report(root: Path, input_path: Path) -> dict[str, Any]:
    payload, issues = _load_json_object(input_path)
    status_overrides, status_issues = _load_local_status_overrides(root)
    issues.extend(status_issues)
    raw_rows = payload.get("rows", [])
    if raw_rows and not isinstance(raw_rows, list):
        issues.append("input report rows field is not a list")
        raw_rows = []
    rows = [
        _apply_status_packet_override(row, status_overrides.get(_safe_text(row.get("id")), {}))
        for row in _safe_list(raw_rows)
        if isinstance(row, dict)
    ]
    work_items = [_build_item(root, row, index) for index, row in enumerate(rows, start=1)]
    sorted_items = _sorted_items(work_items)
    ready_items, loop_schedule = _schedule_items(sorted_items)
    ready_lookup = {item["limitation_id"]: item["scheduled_loop"] for item in ready_items}
    for item in sorted_items:
        item["scheduled_loop"] = ready_lookup.get(item["limitation_id"])
    lane_counts: dict[str, int] = {lane: 0 for lane in LANE_ORDER}
    priority_counts: dict[str, int] = {}
    status_counts: dict[str, int] = {}
    for item in sorted_items:
        lane = item["dispatch_lane"]
        lane_counts[lane] = lane_counts.get(lane, 0) + 1
        priority = item["priority"]
        priority_counts[priority] = priority_counts.get(priority, 0) + 1
        status = item["current_status"]
        status_counts[status] = status_counts.get(status, 0) + 1
    blocked_items = [
        item["limitation_id"]
        for item in sorted_items
        if item["dispatch_lane"] in {"blocked_needs_source", "blocked_needs_user_input"}
    ]
    maintenance_items = [
        item["limitation_id"]
        for item in sorted_items
        if item["current_status"].startswith("implemented_verified") and item["expected_loop_cost"] == 0
    ]
    return {
        "schema": SCHEMA_VERSION,
        "date": payload.get("date") or DEFAULT_DATE,
        "generated_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "source_report": str(input_path.relative_to(root)) if input_path.is_relative_to(root) else str(input_path),
        "source_report_present": input_path.is_file(),
        "source_schema": _safe_text(payload.get("schema")),
        "worktree": _safe_text(payload.get("worktree")) or str(root),
        "branch": _safe_text(payload.get("branch")),
        "dispatch_lanes": list(LANE_ORDER),
        "priority_policy": PRIORITY_POLICY,
        "summary": {
            "known_limitations_total": len(sorted_items),
            "dispatch_ready_total": len([item for item in sorted_items if item["dispatch_ready"]]),
            "blocked_total": len(blocked_items),
            "maintenance_total": len(maintenance_items),
            "lane_counts": lane_counts,
            "priority_counts": priority_counts,
            "status_counts": status_counts,
            "loop_schedule_count": len(loop_schedule),
        },
        "loop_schedule": loop_schedule,
        "blocked_backlog": blocked_items,
        "maintenance_backlog": maintenance_items,
        "top_ready_now": [item["limitation_id"] for item in ready_items[:5]],
        "local_status_overrides": sorted(status_overrides),
        "issues": issues,
        "work_items": sorted_items,
        "changed_paths": [
            "tools/known-limitations-dispatch.py",
            "tools/tests/test_known_limitations_dispatch.py",
            "docs/KNOWN_LIMITATIONS_DISPATCH_2026-05-05.md",
            "reports/known_limitations_dispatch_2026-05-05.json",
        ],
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = _safe_dict(report.get("summary"))
    lines = [
        "# Known Limitations Dispatch 2026-05-05",
        "",
        f"- Source report: `{_safe_text(report.get('source_report'))}`",
        f"- Source report present: `{bool(report.get('source_report_present'))}`",
        f"- Generated at: `{_safe_text(report.get('generated_at'))}`",
        f"- Known limitations: `{summary.get('known_limitations_total', 0)}`",
        f"- Dispatch-ready items: `{summary.get('dispatch_ready_total', 0)}`",
        f"- Blocked items: `{summary.get('blocked_total', 0)}`",
        f"- Maintenance-only items: `{summary.get('maintenance_total', 0)}`",
        "",
        "## Next Loops",
        "",
        "| Loop | Cost | Items | Lanes |",
        "| --- | ---: | --- | --- |",
    ]
    for loop in _safe_list(report.get("loop_schedule")):
        loop_index = loop.get("loop_index", "?")
        cost = loop.get("total_expected_loop_cost", 0)
        items = ", ".join(_safe_list(loop.get("items"))) or "-"
        lanes = ", ".join(_safe_list(loop.get("lanes"))) or "-"
        lines.append(f"| {loop_index} | {cost} | {items} | {lanes} |")
    if len(lines) == 14:
        lines.append("| - | 0 | No dispatch-ready work items | - |")
    lines.extend(
        [
            "",
            "## Sorted Work Items",
            "",
            "| ID | Priority | Lane | Loop | Cost | Status | Blocker |",
            "| --- | --- | --- | ---: | ---: | --- | --- |",
        ]
    )
    for item in _safe_list(report.get("work_items")):
        lines.append(
            "| {id} | {priority} | {lane} | {loop} | {cost} | {status} | {blocker} |".format(
                id=_safe_text(item.get("limitation_id")),
                priority=_safe_text(item.get("priority")),
                lane=_safe_text(item.get("dispatch_lane")),
                loop=_safe_text(item.get("scheduled_loop")) or "-",
                cost=_safe_text(item.get("expected_loop_cost")),
                status=_safe_text(item.get("current_status")),
                blocker=_safe_text(item.get("blocker")).replace("|", "/"),
            )
        )
    lines.extend(["", "## Dispatch Notes", ""])
    for item in _safe_list(report.get("work_items")):
        evidence_paths = _safe_list(item.get("evidence_paths"))
        evidence = ", ".join(f"`{path}`" for path in evidence_paths[:4]) or "`(no extant local evidence paths found)`"
        loop_text = _safe_text(item.get("scheduled_loop")) or "blocked/maintenance"
        lines.append(
            f"- `{_safe_text(item.get('limitation_id'))}` [{_safe_text(item.get('dispatch_lane'))}] "
            f"loop `{loop_text}`: {_safe_text(item.get('next_action'))} "
            f"Evidence: {evidence}."
        )
    issues = _safe_list(report.get("issues"))
    if issues:
        lines.extend(["", "## Issues", ""])
        for issue in issues:
            lines.append(f"- {issue}")
    return "\n".join(lines) + "\n"


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    root = repo_root()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=default_input_path(root), help="Known limitations burndown queue JSON")
    parser.add_argument("--output", type=Path, default=default_output_path(root), help="Dispatch report JSON output")
    parser.add_argument("--docs", type=Path, default=default_docs_path(root), help="Dispatch report Markdown output")
    parser.add_argument("--print-json", action="store_true", help="Print the generated JSON report to stdout")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = repo_root()
    report = build_dispatch_report(root, args.input)
    markdown = render_markdown(report)
    _write_json(args.output, report)
    _write_text(args.docs, markdown)
    if args.print_json:
        print(json.dumps(report, indent=2, sort_keys=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
