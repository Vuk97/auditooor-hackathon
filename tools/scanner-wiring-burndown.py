#!/usr/bin/env python3
"""Build the next-action scanner wiring burn-down queue from a truth inventory."""
from __future__ import annotations

import argparse
import importlib.util
import json
import shlex
import sys
from collections import Counter
from pathlib import Path
from typing import Any


QUEUE_SCHEMA_VERSION = "auditooor.scanner_wiring_burndown_queue.v1"
BURNDOWN_SCHEMA_VERSION = "auditooor.scanner_wiring_burndown.v1"
DEFAULT_INVENTORY = Path("reports/scanner_wiring_truth_inventory_2026-05-05.json")
DEFAULT_ACTION_LIMIT = 50
DEFAULT_PER_LANE_LIMIT = 5
DEFAULT_WORKER_SLOT_CAP = 11
LANE_ORDER = {
    "retire_or_quarantine_fake": 0,
    "rust_detector_lift": 1,
    "wire_backend_executor": 2,
    "runtime_or_smoke_proof": 3,
    "add_fixture_or_proof": 4,
    "documentation_only": 5,
}
WORKER_MODEL_HINTS = {
    "retire_or_quarantine_fake": "gpt-5.4/high",
    "rust_detector_lift": "gpt-5.5/xhigh",
    "wire_backend_executor": "gpt-5.5/xhigh",
    "runtime_or_smoke_proof": "gpt-5.4/high",
    "add_fixture_or_proof": "gpt-5.4/high",
    "documentation_only": "gpt-5.4/medium",
}
FIXTURE_VULNERABLE_MARKERS = (
    "_vuln.",
    "_vulnerable.",
    "vuln.",
    "vulnerable.",
    "positive.",
    "_bad.",
    "_poc.",
)
FIXTURE_CLEAN_MARKERS = (
    "_clean.",
    "clean.",
    "negative.",
    "good.",
    "fixed.",
)


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValueError(f"expected object payload in {path}")
    return data


def _row_id(row: dict[str, Any]) -> str:
    value = str(row.get("scanner_id") or row.get("pattern_id") or "row").strip()
    return value or "row"


def _lane_for_status(status: str) -> str:
    if status in {"quarantined_fake", "in_dsl_fake_suspect"}:
        return "retire_or_quarantine_fake"
    if status == "rust_source_shape_only":
        return "rust_detector_lift"
    if status == "backend_executor_missing_or_tbd":
        return "wire_backend_executor"
    if status in {"generated_no_fixture", "dsl_only_or_unverified"}:
        return "add_fixture_or_proof"
    return "documentation_only"


def _claim_guard(row: dict[str, Any]) -> str:
    proof_status = str(row.get("proof_status", ""))
    wiring_status = str(row.get("wiring_status", ""))
    if proof_status == "detector_and_fixture_pair_present" and wiring_status == "wired_verified":
        return "Fixture-backed detector evidence exists; still cite concrete smoke/proof artifacts before claiming exploit coverage."
    return "Do not claim this scanner detects a real exploit until fixture-backed or runtime proof evidence exists."


def _action_text(lane: str, row: dict[str, Any]) -> tuple[str, str]:
    backend = str(row.get("backend") or "unknown")
    row_id = _row_id(row)
    status = str(row.get("wiring_status") or "unknown")
    if lane == "retire_or_quarantine_fake":
        return (
            f"Retire or quarantine {row_id}",
            "Remove it from active scanner memory and coverage claims, and only restore it with fresh proof-backed detector or fixture evidence.",
        )
    if lane == "rust_detector_lift":
        return (
            f"Lift Rust detector {row_id} beyond source-shape only",
            "Add vulnerable and clean fixtures plus runtime-semantic proof so the row is not treated as a Rust-only shape hint.",
        )
    if lane == "wire_backend_executor":
        return (
            f"Wire {backend} backend executor route",
            "Add or document the runnable backend executor path, then join that executor evidence to concrete detector rows before claiming coverage.",
        )
    if lane == "add_fixture_or_proof":
        if status == "dsl_only_or_unverified":
            return (
                f"Convert DSL row {row_id} into proof-backed coverage",
                "Bind the DSL row to a real detector, add vulnerable and clean fixtures, and attach smoke or execution proof.",
            )
        return (
            f"Add fixtures or proof for {row_id}",
            "Materialize vulnerable and clean fixtures and attach smoke or runtime proof before treating this scanner as wired.",
        )
    return (
        f"Keep {row_id} as documentation-only",
        "This row is reference material, not executable detector proof. Link it to concrete detector evidence if coverage is claimed elsewhere.",
    )


def _source_probe_command(source_paths: list[str]) -> str:
    trimmed = [path for path in source_paths[:3] if path]
    joined = " ".join(shlex.quote(path) for path in trimmed)
    return f"sed -n '1,220p' {joined}" if joined else ""


def _safe_commands(lane: str, row: dict[str, Any]) -> list[dict[str, str]]:
    row_id = _row_id(row)
    backend = str(row.get("backend") or "unknown")
    source_paths = [str(item) for item in row.get("source_paths", [])]
    commands: list[dict[str, str]] = []

    probe = _source_probe_command(source_paths)
    if probe:
        commands.append(
            {
                "command": probe,
                "reason": "Inspect the local source artifacts tied to this queue row before editing or retiring it.",
            }
        )

    if lane == "retire_or_quarantine_fake":
        commands.append(
            {
                "command": f"rg -n {shlex.quote(row_id)} detectors reference docs reports",
                "reason": "Find every local mention that still treats the fake or quarantined scanner as live coverage.",
            }
        )
    elif lane == "rust_detector_lift":
        commands.append(
            {
                "command": f"rg -n {shlex.quote(row_id)} detectors tools tools/tests",
                "reason": "Locate the Rust detector, related helpers, and any existing fixture or smoke scaffolding.",
            }
        )
    elif lane == "wire_backend_executor":
        commands.append(
            {
                "command": f"rg -n {shlex.quote(backend)} tools Makefile detectors",
                "reason": "Check whether a backend runner already exists under another name before adding executor wiring.",
            }
        )
    elif lane == "runtime_or_smoke_proof":
        commands.append(
            {
                "command": f"rg -n {shlex.quote(row_id)} detectors patterns/fixtures tools/tests",
                "reason": "Locate the detector, paired fixtures, and any local smoke harnesses before claiming runtime-backed coverage.",
            }
        )
    elif lane == "add_fixture_or_proof":
        commands.append(
            {
                "command": f"rg -n {shlex.quote(row_id)} detectors reference tools/tests",
                "reason": "Locate the detector or DSL row and any nearby fixture material that can close the proof gap.",
            }
        )
    return commands


def _blocked_command_templates(lane: str, row: dict[str, Any]) -> list[dict[str, Any]]:
    backend = str(row.get("backend") or "unknown")
    status = str(row.get("wiring_status") or "")
    if lane != "wire_backend_executor" and status != "backend_executor_gap_fail_closed":
        return []
    if backend != "move":
        return []
    return [
        {
            "command": "python3 tools/lang-detect.py --lang move <move-workspace> --log <move-workspace>/audit/move-detect.log",
            "missing_inputs": [
                "detectors/move_wave1/*.py runner-compatible Move detectors",
                "detectors/move_wave1/test_fixtures/test_detectors.sh or an equivalent shared Move harness",
            ],
            "unblock_criteria": [
                "shared Move executor loads the committed Move detector wave being claimed",
                "positive and clean Move fixtures pass through the shared harness locally",
                "truth inventory reports executor_signal_present_not_detector_proof instead of a fail-closed backend gap",
            ],
        },
        {
            "command": "bash detectors/move_wave2/test_fixtures/test_detectors.sh",
            "missing_inputs": [
                "detectors/move_wave2/test_fixtures/test_detectors.sh",
                "a harness that runs detectors/move_wave2/*.py run_text/scan_file entrypoints consistently",
            ],
            "unblock_criteria": [
                "every claimed Move detector has positive and clean fixture assertions",
                "the harness exits non-zero on dependency, parse, detector crash, vulnerable silence, or clean false-positive failures",
                "scanner wiring reports stop classifying move-backend-executor as fail-closed",
            ],
        },
    ]


def _priority_score(row: dict[str, Any], lane: str) -> int:
    score = int(row.get("memory_priority", 0))
    blockers = {str(item) for item in row.get("blockers", [])}
    proof_status = str(row.get("proof_status") or "")

    if lane == "retire_or_quarantine_fake":
        score += 200
    elif lane == "rust_detector_lift":
        score += 150
    elif lane == "wire_backend_executor":
        score += 125
    elif lane == "add_fixture_or_proof":
        score += 100

    if "must_not_count_as_wired_coverage" in blockers or "detector_must_not_count_as_wired" in blockers:
        score += 40
    if "rust_runtime_semantics_unverified" in blockers:
        score += 30
    if "positive_or_vulnerable_fixture_missing" in blockers:
        score += 20
    if "clean_or_negative_fixture_missing" in blockers:
        score += 10
    if proof_status in {"fake_or_suspect_dsl_evidence", "quarantined_or_fake_artifact", "quarantined_or_fake_detector_artifact"}:
        score += 25
    return score


def _normalize_action(row: dict[str, Any], rank: int) -> dict[str, Any]:
    lane = _lane_for_status(str(row.get("wiring_status") or "unknown"))
    title, detail = _action_text(lane, row)
    blocked_templates = _blocked_command_templates(lane, row)
    action = {
        "rank": rank,
        "lane": lane,
        "row_id": _row_id(row),
        "scanner_id": str(row.get("scanner_id") or ""),
        "pattern_id": str(row.get("pattern_id") or ""),
        "backend": str(row.get("backend") or "unknown"),
        "wiring_status": str(row.get("wiring_status") or "unknown"),
        "proof_status": str(row.get("proof_status") or ""),
        "memory_priority": int(row.get("memory_priority", 0)),
        "priority_score": _priority_score(row, lane),
        "action_title": title,
        "action_detail": detail,
        "claim_guard": _claim_guard(row),
        "source_paths": [str(item) for item in row.get("source_paths", [])],
        "blockers": [str(item) for item in row.get("blockers", [])],
        "suggested_next_action": str(row.get("suggested_next_action") or ""),
        "suggested_commands": _safe_commands(lane, row),
        "blocked_command_templates": blocked_templates,
        "advisory_only": row.get("proof_status") != "detector_and_fixture_pair_present",
    }
    return action


def _dedupe_actions(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for action in actions:
        key = (action["lane"], action["backend"], action["row_id"])
        existing = grouped.get(key)
        if existing is None:
            grouped[key] = dict(action)
            continue
        existing["memory_priority"] = max(existing["memory_priority"], action["memory_priority"])
        existing["priority_score"] = max(existing["priority_score"], action["priority_score"])
        existing["source_paths"] = sorted({*existing["source_paths"], *action["source_paths"]})
        existing["blockers"] = sorted({*existing["blockers"], *action["blockers"]})
        existing["blocked_command_templates"] = [
            *existing.get("blocked_command_templates", []),
            *[
                template
                for template in action.get("blocked_command_templates", [])
                if template not in existing.get("blocked_command_templates", [])
            ],
        ]
        existing["advisory_only"] = existing["advisory_only"] or action["advisory_only"]
    return list(grouped.values())


def _source_path_names(row: dict[str, Any]) -> str:
    return " ".join(Path(str(item)).name.lower() for item in row.get("source_paths", []))


def _has_fixture_markers(row: dict[str, Any]) -> tuple[bool, bool]:
    names = _source_path_names(row)
    has_vulnerable = any(marker in names for marker in FIXTURE_VULNERABLE_MARKERS)
    has_clean = any(marker in names for marker in FIXTURE_CLEAN_MARKERS)
    return has_vulnerable, has_clean


def _is_quarantine_closed(row: dict[str, Any]) -> bool:
    if str(row.get("wiring_status") or "") not in {"quarantined_fake", "in_dsl_fake_suspect"}:
        return False
    if str(row.get("evidence_kind") or "") == "quarantine_artifact":
        return True
    source_paths = [str(item).lower() for item in row.get("source_paths", [])]
    return any("quarantine" in path for path in source_paths)


def _is_backend_executor_fail_closed(row: dict[str, Any]) -> bool:
    return str(row.get("wiring_status") or "") == "backend_executor_gap_fail_closed"


def _is_wired_fixture_closed(row: dict[str, Any], *, has_vulnerable: bool, has_clean: bool) -> bool:
    if str(row.get("wiring_status") or "") != "wired_verified":
        return False
    if str(row.get("proof_status") or "") != "detector_and_fixture_pair_present":
        return False
    if not (has_vulnerable and has_clean):
        return False
    evidence_kind = str(row.get("evidence_kind") or "")
    if evidence_kind not in {"detector_python", "dsl_yaml_with_detector_fixture_pair"}:
        return False
    source_paths = [str(item).lower() for item in row.get("source_paths", [])]
    has_detector = any(path.endswith(".py") and "/detectors/" in f"/{path}" for path in source_paths)
    has_smoke = any(path.endswith("_smoke.json") or path.endswith("smoke.json") for path in source_paths)
    return has_detector and has_smoke


def _drop_fixture_gap_blockers(blockers: list[str], *, has_vulnerable: bool, has_clean: bool) -> list[str]:
    kept = list(blockers)
    if has_vulnerable:
        kept = [blocker for blocker in kept if blocker != "positive_or_vulnerable_fixture_missing"]
    if has_clean:
        kept = [blocker for blocker in kept if blocker != "clean_or_negative_fixture_missing"]
    return sorted(dict.fromkeys(kept))


def _missing_evidence(row: dict[str, Any], *, has_vulnerable: bool, has_clean: bool) -> list[str]:
    status = str(row.get("wiring_status") or "")
    if status == "backend_executor_missing_or_tbd":
        return ["backend_executor_route"]
    if status == "backend_executor_gap_fail_closed":
        return ["shared_backend_executor", "positive_clean_backend_harness"]
    if status == "in_dsl_fake_suspect":
        return ["proof_backed_detector_or_fixture_evidence"]
    if status == "rust_source_shape_only":
        missing = []
        if not has_vulnerable:
            missing.append("positive_or_vulnerable_fixture")
        if not has_clean:
            missing.append("clean_or_negative_fixture")
        missing.append("rust_runtime_semantics_proof")
        return missing
    if status == "generated_no_fixture":
        if has_vulnerable and has_clean:
            return ["runtime_or_smoke_proof"]
        missing = []
        if not has_vulnerable:
            missing.append("positive_or_vulnerable_fixture")
        if not has_clean:
            missing.append("clean_or_negative_fixture")
        return missing or ["runtime_or_smoke_proof"]
    if status == "wired_verified" and has_vulnerable and has_clean:
        source_paths = [str(item).lower() for item in row.get("source_paths", [])]
        if not any(path.endswith("_smoke.json") or path.endswith("smoke.json") for path in source_paths):
            return ["runtime_or_smoke_proof"]
    return []


def _burndown_lane(row: dict[str, Any], *, has_vulnerable: bool, has_clean: bool) -> str:
    status = str(row.get("wiring_status") or "")
    if status in {"generated_no_fixture", "wired_verified"} and has_vulnerable and has_clean:
        return "runtime_or_smoke_proof"
    return _lane_for_status(status)


def _burndown_category(row: dict[str, Any], *, has_vulnerable: bool, has_clean: bool) -> str:
    status = str(row.get("wiring_status") or "")
    if _is_quarantine_closed(row):
        return "closed_quarantine"
    if _is_backend_executor_fail_closed(row):
        return "closed_backend_gap_fail_closed"
    if _is_wired_fixture_closed(row, has_vulnerable=has_vulnerable, has_clean=has_clean):
        return "closed_wired_fixture_pair"
    if status == "in_dsl_fake_suspect":
        return "fake_dsl_requires_quarantine"
    if status == "backend_executor_missing_or_tbd":
        return "backend_executor_route_missing"
    if status == "rust_source_shape_only":
        return "rust_runtime_semantics_unverified"
    if status == "generated_no_fixture" and has_vulnerable and has_clean:
        return "runtime_or_smoke_proof_missing"
    if status == "wired_verified" and has_vulnerable and has_clean:
        return "runtime_or_smoke_proof_missing"
    if status == "generated_no_fixture":
        return "fixture_pair_missing"
    return "documentation_only"


def _burndown_title(row: dict[str, Any], category: str) -> tuple[str, str]:
    row_id = _row_id(row)
    backend = str(row.get("backend") or "unknown")
    if category == "closed_quarantine":
        return (
            f"Keep {row_id} in quarantine-only memory",
            "This row is already isolated under quarantine-only evidence paths and should stay excluded from wired coverage claims.",
        )
    if category == "closed_wired_fixture_pair":
        return (
            f"Keep {row_id} as fixture-backed wired coverage",
            "Local detector code and vulnerable/clean fixture paths are visible; retain concrete smoke evidence before making runtime claims.",
        )
    if category == "closed_backend_gap_fail_closed":
        return (
            f"Keep {row_id} fail-closed until shared backend executor exists",
            "Local detector artifacts exist, but no shared backend executor and positive/clean harness route is locally visible; do not spend top queue priority on this as runnable support.",
        )
    if category == "runtime_or_smoke_proof_missing":
        return (
            f"Prove runtime coverage for {row_id}",
            "A local clean/vulnerable fixture pair is already visible; the remaining gap is runnable smoke or runtime proof before promotion to wired coverage.",
        )
    if category == "fixture_pair_missing":
        return (
            f"Finish fixture pair for {row_id}",
            "Local detector evidence exists, but the vulnerable and clean fixture pair is still incomplete.",
        )
    if category == "backend_executor_route_missing":
        return (
            f"Wire {backend} backend executor route",
            "No runnable or documented backend executor route is locally visible for this backend.",
        )
    if category == "rust_runtime_semantics_unverified":
        return (
            f"Lift Rust detector {row_id} beyond source-shape only",
            "The detector is still source-shape-only until runtime semantics and fixture-backed proof land.",
        )
    if category == "fake_dsl_requires_quarantine":
        return (
            f"Quarantine suspect DSL row {row_id}",
            "The DSL evidence is fake or suspect and must not be treated as live wired coverage.",
        )
    return (
        f"Keep {row_id} as documentation-only",
        "This row does not provide executable detector proof.",
    )


def _normalize_burndown_row(row: dict[str, Any], rank: int) -> dict[str, Any]:
    has_vulnerable, has_clean = _has_fixture_markers(row)
    category = _burndown_category(row, has_vulnerable=has_vulnerable, has_clean=has_clean)
    lane = _burndown_lane(row, has_vulnerable=has_vulnerable, has_clean=has_clean)
    title, detail = _burndown_title(row, category)
    blockers = _drop_fixture_gap_blockers(
        [str(item) for item in row.get("blockers", [])],
        has_vulnerable=has_vulnerable,
        has_clean=has_clean,
    )
    closed = category in {"closed_quarantine", "closed_wired_fixture_pair", "closed_backend_gap_fail_closed"}
    blocked_templates = _blocked_command_templates(lane, row)
    action = {
        "rank": rank,
        "lane": lane,
        "category": category,
        "closed": closed,
        "row_id": _row_id(row),
        "scanner_id": str(row.get("scanner_id") or ""),
        "pattern_id": str(row.get("pattern_id") or ""),
        "backend": str(row.get("backend") or "unknown"),
        "wiring_status": str(row.get("wiring_status") or "unknown"),
        "proof_status": str(row.get("proof_status") or ""),
        "memory_priority": int(row.get("memory_priority", 0)),
        "priority_score": _priority_score(row, lane),
        "action_title": title,
        "action_detail": detail,
        "claim_guard": _claim_guard(row),
        "source_paths": [str(item) for item in row.get("source_paths", [])],
        "blockers": blockers,
        "missing_evidence": _missing_evidence(row, has_vulnerable=has_vulnerable, has_clean=has_clean),
        "fixture_pair_visible_from_source_paths": has_vulnerable and has_clean,
        "fixture_gap_closed_from_local_paths": str(row.get("wiring_status") or "") == "generated_no_fixture"
        and has_vulnerable
        and has_clean,
        "suggested_next_action": str(row.get("suggested_next_action") or ""),
        "suggested_commands": _safe_commands(lane, row),
        "next_command": _safe_commands(lane, row)[0]["command"] if _safe_commands(lane, row) else "",
        "blocked_command_templates": blocked_templates,
        "advisory_only": row.get("proof_status") != "detector_and_fixture_pair_present",
    }
    return action


def _dedupe_burndown_rows(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for action in actions:
        key = (action["backend"], action["row_id"])
        existing = grouped.get(key)
        if existing is None:
            grouped[key] = dict(action)
            continue
        if action["closed"] != existing["closed"]:
            preferred = action if not action["closed"] else existing
        else:
            preferred = action if action["priority_score"] > existing["priority_score"] else existing
        merged = dict(preferred)
        merged["memory_priority"] = max(existing["memory_priority"], action["memory_priority"])
        merged["priority_score"] = max(existing["priority_score"], action["priority_score"])
        merged["source_paths"] = sorted({*existing["source_paths"], *action["source_paths"]})
        merged["blockers"] = sorted({*existing["blockers"], *action["blockers"]})
        merged["missing_evidence"] = sorted({*existing["missing_evidence"], *action["missing_evidence"]})
        merged["blocked_command_templates"] = [
            *existing.get("blocked_command_templates", []),
            *[
                template
                for template in action.get("blocked_command_templates", [])
                if template not in existing.get("blocked_command_templates", [])
            ],
        ]
        merged["fixture_pair_visible_from_source_paths"] = (
            existing["fixture_pair_visible_from_source_paths"] or action["fixture_pair_visible_from_source_paths"]
        )
        merged["fixture_gap_closed_from_local_paths"] = (
            existing["fixture_gap_closed_from_local_paths"] or action["fixture_gap_closed_from_local_paths"]
        )
        merged["advisory_only"] = existing["advisory_only"] or action["advisory_only"]
        if not merged["next_command"]:
            merged["next_command"] = action["next_command"]
        grouped[key] = merged
    return list(grouped.values())


def _bounded_lane_mix(
    actions: list[dict[str, Any]],
    *,
    action_limit: int,
    per_lane_limit: int,
) -> list[dict[str, Any]]:
    if action_limit <= 0:
        return []

    buckets = {lane: [action for action in actions if action["lane"] == lane] for lane in LANE_ORDER}
    selected: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for lane in LANE_ORDER:
        for action in buckets[lane][:per_lane_limit]:
            key = (action["backend"], action["row_id"])
            if key in seen:
                continue
            selected.append(action)
            seen.add(key)
            if len(selected) >= action_limit:
                return selected

    for action in actions:
        key = (action["backend"], action["row_id"])
        if key in seen:
            continue
        selected.append(action)
        seen.add(key)
        if len(selected) >= action_limit:
            break
    return selected


def _row_test_path(row_id: str) -> str:
    slug = "".join(ch if ch.isalnum() else "_" for ch in row_id.lower()).strip("_")
    while "__" in slug:
        slug = slug.replace("__", "_")
    return f"tools/tests/test_{slug or 'scanner_row'}.py"


def _action_row_id(action: dict[str, Any]) -> str:
    return str(action.get("row_id") or _row_id(action)).strip() or "row"


def _dsl_path_guess(row_id: str) -> str:
    return f"reference/patterns.dsl/{row_id.replace('_', '-')}.yaml"


def _worker_owned_paths(action: dict[str, Any]) -> list[str]:
    row_id = _action_row_id(action)
    owned: list[str] = []
    for source in action.get("source_paths", []):
        text = str(source).strip()
        if not text:
            continue
        path = Path(text)
        parts = path.parts
        if len(parts) >= 3 and parts[0] == "detectors" and parts[1] == "fixtures":
            text = str(Path(*parts[:3]))
        if text not in owned:
            owned.append(text)

    for expected in (_dsl_path_guess(row_id), _row_test_path(row_id)):
        if expected not in owned:
            owned.append(expected)
    return owned[:12]


def _worker_slot(action: dict[str, Any], slot_index: int) -> dict[str, Any]:
    lane = str(action.get("lane") or "add_fixture_or_proof")
    row_id = _action_row_id(action)
    return {
        "slot_id": f"scanner-slot-{slot_index}",
        "task_kind": "end_to_end_scanner_burndown_closure",
        "row_id": row_id,
        "rank": action.get("rank"),
        "lane": lane,
        "backend": str(action.get("backend") or "unknown"),
        "model_hint": WORKER_MODEL_HINTS.get(lane, "gpt-5.4/high"),
        "owned_paths": _worker_owned_paths(action),
        "prompt_seed": (
            f"Own scanner burndown row `{row_id}` end to end: inspect the reference DSL, "
            "generated detector, fixtures, smoke status, and focused tests; close the "
            "proof gap if feasible; commit only owned row paths."
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
            "do not spend worker slots on review-only work while executable closure rows remain",
            "do not claim exploit coverage or scanner completeness beyond checked local proof artifacts",
        ],
        "suggested_commands": action.get("suggested_commands", [])[:3],
    }


def _worker_slots(actions: list[dict[str, Any]], *, slot_cap: int = DEFAULT_WORKER_SLOT_CAP) -> list[dict[str, Any]]:
    return [_worker_slot(action, index) for index, action in enumerate(actions[:slot_cap], start=1)]


def build_burndown_queue(
    inventory: dict[str, Any],
    *,
    action_limit: int = DEFAULT_ACTION_LIMIT,
    per_lane_limit: int = DEFAULT_PER_LANE_LIMIT,
) -> dict[str, Any]:
    rows = inventory.get("rows", [])
    if not isinstance(rows, list):
        raise ValueError("inventory rows must be a list")

    input_rows = [row for row in rows if isinstance(row, dict)]
    normalized = [
        _normalize_action(row, 0)
        for row in input_rows
        if not _is_quarantine_closed(row) and not _is_backend_executor_fail_closed(row)
    ]
    unique_actions = _dedupe_actions(normalized)
    unique_actions.sort(
        key=lambda row: (
            LANE_ORDER[row["lane"]],
            -row["priority_score"],
            row["backend"],
            row["row_id"],
            row["source_paths"],
        )
    )
    for index, row in enumerate(unique_actions, start=1):
        row["rank"] = index

    effective_limit = max(0, action_limit)
    effective_per_lane_limit = max(0, per_lane_limit)
    top_actions = unique_actions[:effective_limit]
    worker_slots = _worker_slots(top_actions)
    top_lane_counts = Counter(row["lane"] for row in top_actions)
    status_counts = Counter(str(row.get("wiring_status") or "unknown") for row in input_rows)
    lane_counts = Counter(action["lane"] for action in normalized)
    unique_lane_counts = Counter(action["lane"] for action in unique_actions)
    blocker_counts = Counter(
        blocker
        for row in rows
        if isinstance(row, dict)
        for blocker in row.get("blockers", [])
    )
    lane_top_actions = {
        lane: [action for action in unique_actions if action["lane"] == lane][:effective_per_lane_limit]
        for lane in LANE_ORDER
    }

    return {
        "schema": QUEUE_SCHEMA_VERSION,
        "source_inventory_schema": str(inventory.get("schema") or ""),
        "source_inventory_limit": inventory.get("limit"),
        "source_inventory_item_count": inventory.get("item_count"),
        "source_inventory_total_row_count": inventory.get("total_row_count"),
        "source_inventory_truncated": bool(inventory.get("truncated", False)),
        "action_limit": effective_limit,
        "per_lane_limit": effective_per_lane_limit,
        "total_rows_seen": len(input_rows),
        "actionable_row_count": len(normalized),
        "unique_action_count": len(unique_actions),
        "top_action_count": len(top_actions),
        "truncated": len(top_actions) < len(unique_actions),
        "blocker_counts": dict(sorted(blocker_counts.items())),
        "status_counts": dict(sorted(status_counts.items())),
        "lane_counts": dict(sorted(lane_counts.items())),
        "unique_action_lane_counts": dict(sorted(unique_lane_counts.items())),
        "top_action_lane_counts": dict(sorted(top_lane_counts.items())),
        "worker_slot_cap": DEFAULT_WORKER_SLOT_CAP,
        "worker_slot_count": len(worker_slots),
        "next_worker_slots": worker_slots,
        "actions": top_actions,
        "lane_top_actions": lane_top_actions,
    }


def build_burndown_report(
    inventory: dict[str, Any],
    *,
    action_limit: int = DEFAULT_ACTION_LIMIT,
    per_lane_limit: int = DEFAULT_PER_LANE_LIMIT,
) -> dict[str, Any]:
    rows = inventory.get("rows", [])
    if not isinstance(rows, list):
        raise ValueError("inventory rows must be a list")

    normalized = [_normalize_burndown_row(row, 0) for row in rows if isinstance(row, dict)]
    unique_rows = _dedupe_burndown_rows(normalized)
    open_actions = [row for row in unique_rows if not row["closed"]]
    closed_rows = [row for row in unique_rows if row["closed"]]

    open_actions.sort(
        key=lambda row: (
            LANE_ORDER[row["lane"]],
            -row["priority_score"],
            row["backend"],
            row["row_id"],
            row["source_paths"],
        )
    )
    closed_rows.sort(
        key=lambda row: (
            row["backend"],
            row["row_id"],
            row["source_paths"],
        )
    )
    for index, row in enumerate(open_actions, start=1):
        row["rank"] = index

    effective_limit = max(0, action_limit)
    effective_per_lane_limit = max(0, per_lane_limit)
    lane_top_actions = {
        lane: [action for action in open_actions if action["lane"] == lane][:effective_per_lane_limit]
        for lane in LANE_ORDER
    }
    top_actions = _bounded_lane_mix(
        open_actions,
        action_limit=effective_limit,
        per_lane_limit=effective_per_lane_limit,
    )
    for index, row in enumerate(top_actions, start=1):
        row["rank"] = index
    worker_slots = _worker_slots(top_actions)
    blocker_counts = Counter(row["category"] for row in open_actions)
    lane_counts = Counter(row["lane"] for row in open_actions)
    status_counts = Counter(str(row.get("wiring_status") or "unknown") for row in open_actions)
    closure_counts = Counter(row["category"] for row in closed_rows)
    closure_samples = closed_rows[: min(10, len(closed_rows))]
    fixture_gap_closed = sum(1 for row in open_actions if row["fixture_gap_closed_from_local_paths"])
    fixture_visible = sum(1 for row in open_actions if row["fixture_pair_visible_from_source_paths"])

    return {
        "schema": BURNDOWN_SCHEMA_VERSION,
        "source_inventory_schema": str(inventory.get("schema") or ""),
        "source_inventory_limit": inventory.get("limit"),
        "source_inventory_item_count": inventory.get("item_count"),
        "source_inventory_total_row_count": inventory.get("total_row_count"),
        "source_inventory_truncated": bool(inventory.get("truncated", False)),
        "action_limit": effective_limit,
        "per_lane_limit": effective_per_lane_limit,
        "total_rows_seen": len(normalized),
        "unique_row_count": len(unique_rows),
        "open_action_count": len(open_actions),
        "closed_row_count": len(closed_rows),
        "top_action_count": len(top_actions),
        "truncated": len(top_actions) < len(open_actions),
        "open_lane_counts": dict(sorted(lane_counts.items())),
        "open_status_counts": dict(sorted(status_counts.items())),
        "blocker_counts": dict(sorted(blocker_counts.items())),
        "closed_row_counts": dict(sorted(closure_counts.items())),
        "closed_gap_counts": {
            "fixture_pair_gap_closed_from_local_paths": fixture_gap_closed,
            "rows_with_local_fixture_pair_visible": fixture_visible,
        },
        "worker_slot_cap": DEFAULT_WORKER_SLOT_CAP,
        "worker_slot_count": len(worker_slots),
        "next_worker_slots": worker_slots,
        "actions": top_actions,
        "lane_top_actions": lane_top_actions,
        "closed_samples": closure_samples,
    }


def _append_worker_slots_markdown(lines: list[str], slots: list[dict[str, Any]]) -> None:
    lines.extend(["", "## Next Worker Slots", ""])
    if not slots:
        lines.append("- None")
        return
    lines.extend(
        [
            "| Slot | Row | Lane | Model Hint | Owned Paths |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for slot in slots:
        owned = ", ".join(str(path) for path in slot.get("owned_paths", [])[:4]) or "-"
        lines.append(
            "| {slot_id} | {row_id} | {lane} | {model_hint} | {owned} |".format(
                slot_id=slot.get("slot_id", "-"),
                row_id=str(slot.get("row_id", "-")).replace("|", "/"),
                lane=slot.get("lane", "-"),
                model_hint=slot.get("model_hint", "-"),
                owned=owned.replace("|", "/"),
            )
        )


def render_markdown(queue: dict[str, Any], *, inventory_path: Path) -> str:
    lines = [
        "# Scanner Wiring Burndown Queue (2026-05-05)",
        "",
        f"- Source inventory: `{inventory_path}`",
        f"- Source schema: `{queue.get('source_inventory_schema', '')}`",
        f"- Source rows seen: `{queue.get('total_rows_seen', 0)}`",
        f"- Unique actions after dedupe: `{queue.get('unique_action_count', 0)}`",
        f"- Top actions emitted: `{queue.get('top_action_count', 0)}` of `{queue.get('unique_action_count', 0)}` unique actions",
        f"- Worker slots emitted: `{queue.get('worker_slot_count', 0)}` of `{queue.get('worker_slot_cap', DEFAULT_WORKER_SLOT_CAP)}`",
        f"- Source inventory truncated before queueing: `{queue.get('source_inventory_truncated', False)}`",
        f"- Queue truncated by action limit: `{queue.get('truncated', False)}`",
        "",
        "## Counts by lane",
        "",
    ]
    for lane, count in queue.get("lane_counts", {}).items():
        lines.append(f"- `{lane}`: {count}")
    lines.extend(["", "## Unique action counts by lane", ""])
    for lane, count in queue.get("unique_action_lane_counts", {}).items():
        lines.append(f"- `{lane}`: {count}")
    lines.extend(["", "## Counts by status", ""])
    for status, count in queue.get("status_counts", {}).items():
        lines.append(f"- `{status}`: {count}")
    lines.extend(["", "## Blockers", ""])
    for blocker, count in queue.get("blocker_counts", {}).items():
        lines.append(f"- `{blocker}`: {count}")
    lines.extend(["", "## Global top actions", ""])
    for action in queue.get("actions", []):
        lines.append(
            f"{action['rank']}. `{action['lane']}` `{action['row_id']}` ({action['backend']}, `{action['wiring_status']}`): {action['action_detail']}"
        )
        lines.append(f"   Guard: {action['claim_guard']}")
        if action["blockers"]:
            lines.append(f"   Blockers: {', '.join(action['blockers'])}")
        if action["source_paths"]:
            lines.append(f"   Sources: {', '.join(action['source_paths'])}")
        if action["suggested_commands"]:
            for command in action["suggested_commands"]:
                lines.append(f"   Command: `{command['command']}`")
                lines.append(f"   Why: {command['reason']}")
        for template in action.get("blocked_command_templates", []):
            lines.append(f"   Blocked template: `{template['command']}`")
            lines.append(f"   Missing inputs: {', '.join(template.get('missing_inputs', []))}")
    lines.extend(["", "## Lane heads", ""])
    for lane, lane_actions in queue.get("lane_top_actions", {}).items():
        lines.append(f"### `{lane}`")
        if not lane_actions:
            lines.append("- None")
            continue
        for action in lane_actions:
            lines.append(
                f"- `{action['row_id']}` ({action['backend']}, `{action['wiring_status']}`): {', '.join(action['blockers']) or 'no blockers listed'}"
            )
            for command in action["suggested_commands"]:
                lines.append(f"  - `{command['command']}`")
            for template in action.get("blocked_command_templates", []):
                lines.append(f"  - blocked: `{template['command']}`")
    _append_worker_slots_markdown(lines, queue.get("next_worker_slots", []))
    lines.append("")
    return "\n".join(lines)


def render_burndown_markdown(report: dict[str, Any], *, inventory_path: Path) -> str:
    lines = [
        "# Scanner Wiring Burndown (2026-05-05)",
        "",
        f"- Source inventory: `{inventory_path}`",
        f"- Source schema: `{report.get('source_inventory_schema', '')}`",
        f"- Source rows seen: `{report.get('total_rows_seen', 0)}`",
        f"- Unique rows after dedupe: `{report.get('unique_row_count', 0)}`",
        f"- Open blocker rows: `{report.get('open_action_count', 0)}`",
        f"- Closed rows: `{report.get('closed_row_count', 0)}`",
        f"- Top blocker rows emitted: `{report.get('top_action_count', 0)}` of `{report.get('open_action_count', 0)}` open rows",
        f"- Worker slots emitted: `{report.get('worker_slot_count', 0)}` of `{report.get('worker_slot_cap', DEFAULT_WORKER_SLOT_CAP)}`",
        f"- Source inventory truncated before burndown: `{report.get('source_inventory_truncated', False)}`",
        f"- Burndown truncated by action limit: `{report.get('truncated', False)}`",
        "",
        "## Closed This Pass",
        "",
    ]
    for category, count in report.get("closed_row_counts", {}).items():
        lines.append(f"- `{category}`: {count}")
    for category, count in report.get("closed_gap_counts", {}).items():
        lines.append(f"- `{category}`: {count}")

    lines.extend(["", "## Remaining Blockers", ""])
    for blocker, count in report.get("blocker_counts", {}).items():
        lines.append(f"- `{blocker}`: {count}")

    lines.extend(["", "## Open Lanes", ""])
    for lane, count in report.get("open_lane_counts", {}).items():
        lines.append(f"- `{lane}`: {count}")

    lines.extend(["", "## Blocker Packet", ""])
    for action in report.get("actions", []):
        lines.append(
            f"{action['rank']}. `{action['category']}` `{action['row_id']}` ({action['backend']}, `{action['wiring_status']}`): {action['action_detail']}"
        )
        lines.append(f"   Missing evidence: {', '.join(action['missing_evidence']) or 'none listed'}")
        lines.append(f"   Guard: {action['claim_guard']}")
        if action["blockers"]:
            lines.append(f"   Blockers: {', '.join(action['blockers'])}")
        if action["source_paths"]:
            lines.append(f"   Sources: {', '.join(action['source_paths'])}")
        if action["next_command"]:
            lines.append(f"   Next command: `{action['next_command']}`")
        for template in action.get("blocked_command_templates", []):
            lines.append(f"   Blocked template: `{template['command']}`")
            lines.append(f"   Missing inputs: {', '.join(template.get('missing_inputs', []))}")
        if action["fixture_gap_closed_from_local_paths"]:
            lines.append("   Note: Local source paths already contain both clean and vulnerable fixture markers.")

    lines.extend(["", "## Closed Samples", ""])
    if not report.get("closed_samples"):
        lines.append("- None")
    else:
        for row in report.get("closed_samples", []):
            lines.append(f"- `{row['row_id']}` ({row['backend']}): {row['action_detail']}")
            for template in row.get("blocked_command_templates", [])[:1]:
                lines.append(f"  - Blocked template: `{template['command']}`")
    _append_worker_slots_markdown(lines, report.get("next_worker_slots", []))
    lines.append("")
    return "\n".join(lines)


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _inventory_report_compatible(path: Path) -> bool:
    try:
        payload = _load_json(path)
    except (OSError, ValueError, json.JSONDecodeError):
        return False
    return str(payload.get("schema") or "") == "auditooor.scanner_wiring_truth_inventory.v1"


def _latest_report_path(repo_root: Path) -> Path:
    reports_root = repo_root / "reports"
    if not reports_root.is_dir():
        return repo_root / DEFAULT_INVENTORY
    candidates = sorted(
        reports_root.glob("scanner_wiring_truth_inventory*.json"),
        key=lambda path: (path.stat().st_mtime, path.name),
        reverse=True,
    )
    for candidate in candidates:
        if _inventory_report_compatible(candidate):
            return candidate
    return repo_root / DEFAULT_INVENTORY


def _load_live_inventory(repo_root: Path, limit: int) -> dict[str, Any]:
    tool_path = repo_root / "tools" / "scanner-wiring-truth-inventory.py"
    if not tool_path.is_file():
        raise FileNotFoundError(f"scanner wiring truth inventory tool not found: {tool_path}")
    spec = importlib.util.spec_from_file_location("scanner_wiring_truth_inventory_live", tool_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not import {tool_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules["scanner_wiring_truth_inventory_live"] = module
    spec.loader.exec_module(module)
    return module.build_inventory(repo_root, limit=limit)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "inventory",
        nargs="?",
        type=Path,
        help="scanner wiring truth inventory JSON; defaults to latest compatible report unless --refresh-from-repo is set",
    )
    parser.add_argument("--repo-root", type=Path, default=Path("."), help="repo root for report discovery and live refresh")
    parser.add_argument("--refresh-from-repo", action="store_true", help="build a fresh scanner wiring inventory from --repo-root before queueing")
    parser.add_argument("--live-inventory-limit", type=int, default=12_000, help="row limit when --refresh-from-repo is used")
    parser.add_argument("--json-out", type=Path, help="optional path to write queue JSON")
    parser.add_argument("--md-out", type=Path, help="optional path to write markdown summary")
    parser.add_argument(
        "--mode",
        choices=("queue", "burndown"),
        default="queue",
        help="output compatibility queue or reconciled burndown report",
    )
    parser.add_argument(
        "--action-limit",
        type=int,
        default=DEFAULT_ACTION_LIMIT,
        help=f"max actions to emit (default: {DEFAULT_ACTION_LIMIT})",
    )
    parser.add_argument(
        "--per-lane-limit",
        type=int,
        default=DEFAULT_PER_LANE_LIMIT,
        help=f"max lane-head actions to emit per lane (default: {DEFAULT_PER_LANE_LIMIT})",
    )
    parser.add_argument("--print-json", action="store_true", help="print queue JSON to stdout")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    repo_root = args.repo_root.resolve()
    if args.refresh_from_repo:
        inventory = _load_live_inventory(repo_root, args.live_inventory_limit)
        inventory_label = f"live:{repo_root}"
    else:
        inventory_path = args.inventory if args.inventory else _latest_report_path(repo_root)
        if not inventory_path.is_absolute():
            inventory_path = repo_root / inventory_path
        inventory = _load_json(inventory_path)
        try:
            inventory_label = str(inventory_path.resolve().relative_to(repo_root))
        except (OSError, ValueError):
            inventory_label = str(inventory_path)

    if args.mode == "burndown":
        payload = build_burndown_report(
            inventory,
            action_limit=args.action_limit,
            per_lane_limit=args.per_lane_limit,
        )
        markdown = render_burndown_markdown(payload, inventory_path=Path(inventory_label))
    else:
        payload = build_burndown_queue(
            inventory,
            action_limit=args.action_limit,
            per_lane_limit=args.per_lane_limit,
        )
        markdown = render_markdown(payload, inventory_path=Path(inventory_label))
    payload["source_inventory_path"] = inventory_label
    encoded = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        _write_json(args.json_out, payload)
    if args.md_out:
        _write_text(args.md_out, markdown)
    if args.print_json or not args.json_out:
        sys.stdout.write(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
