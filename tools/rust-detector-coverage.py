#!/usr/bin/env python3
"""Build a Rust detector coverage/lift inventory from local repo evidence.

This is a structural inventory. It counts detector files, fixture pairs, and
current runner-hook reachability. It does not claim exploit coverage
completeness.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.rust_detector_coverage.v1"
DEFAULT_REPORT = Path("reports/rust_detector_coverage_2026-05-05.json")
DEFAULT_TRUTH_REPORT = Path("reports/scanner_wiring_truth_inventory_2026-05-05.json")
DEFAULT_BURNDOWN_REPORT = Path("reports/scanner_wiring_burndown_queue_2026-05-05.json")


@dataclass(frozen=True)
class DetectorRow:
    detector_id: str
    detector_path: str
    detector_group: str
    nested_detector: bool
    has_positive_fixture: bool
    has_negative_fixture: bool
    fixture_pair_present: bool
    positive_fixture: str
    negative_fixture: str
    selectable_via_rust_detect_only: bool
    selectable_via_inventory_smoke_rust: bool
    selectable_via_make_rust_fixture_detector: bool
    listed_in_full_regression_script: bool
    missing_fixture: bool
    missing_runner_hook: bool
    runner_gaps: list[str]
    truth_inventory_wiring_status: str
    truth_inventory_proof_status: str
    truth_inventory_blockers: list[str]
    burndown_rank: int | None
    burndown_priority_score: int | None
    suggested_next_action: str
    next_files: list[str]
    next_commands: list[str]
    priority_score: int


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _json_object(path: Path) -> dict[str, Any]:
    payload = _read_json(path)
    return payload if isinstance(payload, dict) else {}


def _loop_marker(path: Path) -> int:
    match = re.search(r"(?:^|[-_])(?:r|l|loop)(\d+)(?:[-_.]|$)", path.name.lower())
    return int(match.group(1)) if match else 0


def _report_sort_key(path: Path, payload: dict[str, Any] | None = None) -> tuple[str, int, int, int, str]:
    dates = re.findall(r"\d{4}-\d{2}-\d{2}", path.name)
    packet = payload or {}
    return (
        dates[-1] if dates else "",
        _loop_marker(path),
        _safe_int(packet.get("item_count") or packet.get("unique_action_count") or packet.get("actionable_row_count")),
        _safe_int(packet.get("total_row_count") or packet.get("top_action_count")),
        path.name,
    )


def _truth_report_compatible(payload: dict[str, Any]) -> bool:
    return (
        str(payload.get("schema") or "") == "auditooor.scanner_wiring_truth_inventory.v1"
        and isinstance(payload.get("rows"), list)
    )


def _burndown_report_compatible(payload: dict[str, Any]) -> bool:
    if str(payload.get("schema") or "") != "auditooor.scanner_wiring_burndown_queue.v1":
        return False
    if isinstance(payload.get("actions"), list) and payload["actions"]:
        return True
    lane_top_actions = payload.get("lane_top_actions")
    if not isinstance(lane_top_actions, dict):
        return False
    return any(isinstance(rows, list) and rows for rows in lane_top_actions.values())


def _latest_report_path(
    root: Path,
    stem: str,
    fallback_rel: Path,
    *,
    validator: Any,
) -> Path:
    reports_dir = root / "reports"
    if reports_dir.is_dir():
        candidates: list[tuple[Path, dict[str, Any]]] = []
        for path in reports_dir.glob(f"{stem}_*.json"):
            payload = _json_object(path)
            if validator(payload):
                candidates.append((path, payload))
        if candidates:
            return max(candidates, key=lambda item: _report_sort_key(item[0], item[1]))[0]
    return root / fallback_rel


def _path_label(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (OSError, ValueError):
        return str(path)


def _load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        raise FileNotFoundError(f"could not import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _live_scanner_inputs(root: Path, *, limit: int) -> tuple[dict[str, Any], dict[str, Any]]:
    truth_mod = _load_module(
        "rust_detector_coverage_truth_inventory",
        root / "tools" / "scanner-wiring-truth-inventory.py",
    )
    burndown_mod = _load_module(
        "rust_detector_coverage_burndown",
        root / "tools" / "scanner-wiring-burndown.py",
    )
    inventory = truth_mod.build_inventory(root, limit=limit)
    burndown = burndown_mod.build_burndown_queue(
        inventory,
        action_limit=max(limit, 0),
        per_lane_limit=max(limit, 0),
    )
    return inventory, burndown


def _rel(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except (OSError, ValueError):
        return str(path)


def _detector_files(detectors_dir: Path) -> list[Path]:
    out: list[Path] = []
    for path in sorted(detectors_dir.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        if path.name == "__init__.py" or path.name.startswith("_"):
            continue
        out.append(path)
    return out


def _fixture_index(fixtures_dir: Path) -> tuple[list[Path], dict[str, dict[str, Path]]]:
    fixture_files = sorted(path for path in fixtures_dir.glob("*.rs") if path.is_file())
    by_detector: dict[str, dict[str, Path]] = {}
    for path in fixture_files:
        match = re.match(r"(?P<detector>.+)_(?P<kind>positive|negative)\.rs$", path.name)
        if not match:
            continue
        entry = by_detector.setdefault(match.group("detector"), {})
        entry[match.group("kind")] = path
    return fixture_files, by_detector


def _makefile_targets(makefile_path: Path) -> dict[str, str]:
    text = _read_text(makefile_path)
    if not text:
        return {}
    targets: dict[str, str] = {}
    current: str | None = None
    body: list[str] = []
    for raw_line in text.splitlines():
        if raw_line and not raw_line.startswith((" ", "\t")) and ":" in raw_line:
            candidate = raw_line.split(":", 1)[0].strip()
            if candidate and not candidate.startswith(".") and " " not in candidate:
                if current is not None:
                    targets[current] = "\n".join(body)
                current = candidate
                body = []
                continue
        if current is not None:
            body.append(raw_line)
    if current is not None:
        targets[current] = "\n".join(body)
    return targets


def _regression_script_ids(script_path: Path) -> list[str]:
    text = _read_text(script_path)
    if not text:
        return []
    ids: list[str] = []
    inside = False
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not inside:
            if line.startswith("DETECTORS=("):
                inside = True
                tail = line[len("DETECTORS=("):].strip()
                if tail and tail != ")":
                    ids.extend(tail.split())
                continue
        else:
            if line == ")":
                break
            if line:
                ids.extend(line.split())
    return ids


def _script_uses_report_backed_regression_list(script_path: Path) -> bool:
    text = _read_text(script_path)
    return "rust-fixture-regression-list.py" in text


def _report_backed_regression_ids(report_path: Path) -> set[str]:
    payload = _read_json(report_path)
    if not isinstance(payload, dict):
        return set()
    rows = payload.get("per_detector")
    if not isinstance(rows, list):
        return set()

    out: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        detector_id = str(row.get("detector_id") or "")
        if not detector_id:
            continue
        if row.get("fixture_pair_present") is not True:
            continue
        if row.get("nested_detector") is True:
            continue
        if row.get("detector_group") not in (None, "rust_wave1"):
            continue
        out.add(detector_id)
    return out


def _rust_detect_selectable_path(path: Path, detectors_dir: Path) -> bool:
    rel = path.relative_to(detectors_dir)
    if len(rel.parts) == 1:
        return True
    return True


def _truth_rows_from_payload(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for row in payload.get("rows", []):
        if not isinstance(row, dict):
            continue
        scanner_id = row.get("scanner_id")
        if not scanner_id:
            continue
        joined = " ".join(row.get("source_paths", []))
        if "detectors/rust_wave1/" not in joined:
            continue
        out[str(scanner_id)] = row
    return out


def _truth_rows(path: Path) -> dict[str, dict[str, Any]]:
    payload = _read_json(path)
    if not isinstance(payload, dict):
        return {}
    return _truth_rows_from_payload(payload)


def _burndown_actions_from_payload(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    actions = payload.get("actions", [])
    if isinstance(actions, list):
        for row in actions:
            if not isinstance(row, dict):
                continue
            if row.get("backend") != "rust":
                continue
            detector_id = str(row.get("scanner_id") or row.get("row_id") or "")
            if detector_id:
                out[detector_id] = row
    lane_top = payload.get("lane_top_actions", {})
    if isinstance(lane_top, dict):
        for row in lane_top.get("rust_detector_lift", []):
            if not isinstance(row, dict):
                continue
            detector_id = str(row.get("scanner_id") or row.get("row_id") or "")
            if detector_id and detector_id not in out:
                out[detector_id] = row
    return out


def _burndown_actions(path: Path) -> dict[str, dict[str, Any]]:
    payload = _read_json(path)
    if not isinstance(payload, dict):
        return {}
    return _burndown_actions_from_payload(payload)


def _inventory_smoke_rust_status(targets: dict[str, str], repo_root: Path) -> dict[str, Any]:
    target_body = targets.get("inventory-smoke-detector", "")
    rust_applicable = "inventory-smoke-rust.py" in target_body
    return {
        "make_target_present": "inventory-smoke-detector" in targets,
        "rust_applicable": rust_applicable,
        "evidence": (
            "Makefile inventory-smoke-detector target invokes Rust tooling"
            if rust_applicable
            else "Makefile inventory-smoke-detector target does not invoke tools/inventory-smoke-rust.py"
        ),
        "standalone_tool_present": (repo_root / "tools" / "inventory-smoke-rust.py").exists(),
    }


def _row_group(path: Path, detectors_dir: Path) -> str:
    relative = path.relative_to(detectors_dir)
    if len(relative.parts) == 1:
        return "rust_wave1"
    return relative.parts[0]


def _next_action(
    detector_id: str,
    detector_path: str,
    positive_fixture: str,
    negative_fixture: str,
    fixture_pair_present: bool,
    selectable_via_rust_detect: bool,
    selectable_via_make: bool,
    listed_in_script: bool,
    truth_row: dict[str, Any] | None,
    inventory_smoke_rust_supported: bool,
) -> tuple[str, list[str], list[str]]:
    next_files = [detector_path]
    next_commands: list[str] = []

    if not fixture_pair_present:
        if positive_fixture:
            next_files.append(positive_fixture)
        if negative_fixture:
            next_files.append(negative_fixture)
        if selectable_via_rust_detect:
            action = "add positive/negative Rust fixtures, then validate with the supported single-detector hook"
            if selectable_via_make:
                next_commands.append(f"make rust-fixture-detector DETECTOR={detector_id}")
            else:
                next_commands.append(
                    "python3 tools/rust-detect.py detectors/rust_wave1/test_fixtures "
                    f"--only {detector_id} --file {positive_fixture}"
                )
        else:
            action = "add the fixture pair and fix Rust subdirectory detector discovery before claiming runner coverage"
            next_files.extend(
                [
                    "tools/rust-detect.py",
                    "tools/inventory-smoke-rust.py",
                    "detectors/rust_wave1/test_fixtures/test_detectors.sh",
                ]
            )
            next_commands.append(f"rg -n \"{detector_id}\" tools/rust-detect.py tools/inventory-smoke-rust.py detectors/rust_wave1/test_fixtures/test_detectors.sh")
        return action, _uniq(next_files), _uniq(next_commands)

    if not selectable_via_rust_detect:
        action = "fix Rust subdirectory detector discovery so these detectors can be selected and batch-smoked"
        next_files.extend(
            [
                "tools/rust-detect.py",
                "tools/inventory-smoke-rust.py",
                "detectors/rust_wave1/test_fixtures/test_detectors.sh",
            ]
        )
        next_commands.append(f"rg -n \"glob\\(\\\"\\*\\.py\\\"\\)|rglob\\(\" tools/rust-detect.py tools/inventory-smoke-rust.py")
        return action, _uniq(next_files), _uniq(next_commands)

    if not listed_in_script:
        action = "add this fixture-backed detector to the Rust full-regression shell list"
        next_files.append("detectors/rust_wave1/test_fixtures/test_detectors.sh")
        if selectable_via_make:
            next_commands.append(f"make rust-fixture-detector DETECTOR={detector_id}")
        if inventory_smoke_rust_supported:
            next_commands.append("python3 tools/inventory-smoke-rust.py --output-dir /tmp/auditooor-rust-smoke")
        return action, _uniq(next_files), _uniq(next_commands)

    if truth_row and truth_row.get("wiring_status") == "rust_source_shape_only":
        action = "keep the fixture-backed row but add runtime/cfg/trait proof before claiming deeper Rust semantics"
        if selectable_via_make:
            next_commands.append(f"make rust-fixture-detector DETECTOR={detector_id}")
        return action, _uniq(next_files), _uniq(next_commands)

    action = "no immediate lift required from wiring evidence; keep the detector in regression and single-detector smoke"
    if selectable_via_make:
        next_commands.append(f"make rust-fixture-detector DETECTOR={detector_id}")
    return action, _uniq(next_files), _uniq(next_commands)


def _uniq(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def _priority_score(
    *,
    missing_fixture: bool,
    missing_runner_hook: bool,
    nested_detector: bool,
    listed_in_script: bool,
    truth_row: dict[str, Any] | None,
    burndown_row: dict[str, Any] | None,
) -> int:
    score = 0
    if missing_fixture:
        score += 200
    if missing_runner_hook:
        score += 120
    if nested_detector:
        score += 40
    if not listed_in_script:
        score += 20
    if truth_row and truth_row.get("wiring_status") == "rust_source_shape_only":
        score += 30
    if burndown_row and isinstance(burndown_row.get("priority_score"), int):
        score += int(burndown_row["priority_score"])
    return score


def _normalized_truth_status(
    truth_row: dict[str, Any] | None,
    *,
    fixture_pair_present: bool,
    selectable_via_rust_detect: bool,
) -> tuple[str, str, list[str]]:
    if not truth_row:
        return "", "", []

    wiring_status = str(truth_row.get("wiring_status", ""))
    proof_status = str(truth_row.get("proof_status", ""))
    blockers = [
        str(blocker)
        for blocker in truth_row.get("blockers", [])
        if blocker
    ]

    if fixture_pair_present:
        blockers = [
            blocker
            for blocker in blockers
            if blocker
            not in {
                "clean_or_negative_fixture_missing",
                "positive_or_vulnerable_fixture_missing",
            }
        ]
        if proof_status == "rust_detector_without_fixture_pair":
            proof_status = "fixture_pair_present_but_runner_unverified"

    if fixture_pair_present and not selectable_via_rust_detect:
        blockers.append("rust_subdirectory_loader_unreachable")

    return wiring_status, proof_status, _uniq(blockers)


def build_inventory(
    repo_root: Path,
    *,
    truth_report: Path | None = None,
    burndown_report: Path | None = None,
    refresh_scanner_inputs: bool = False,
    live_inventory_limit: int = 12_000,
    top_n: int = 20,
) -> dict[str, Any]:
    root = repo_root.resolve()
    detectors_dir = root / "detectors" / "rust_wave1"
    fixtures_dir = detectors_dir / "test_fixtures"
    makefile_path = root / "Makefile"
    regression_script_path = fixtures_dir / "test_detectors.sh"
    rust_detect_path = root / "tools" / "rust-detect.py"
    inventory_smoke_rust_path = root / "tools" / "inventory-smoke-rust.py"

    detector_files = _detector_files(detectors_dir)
    top_level_dir = detectors_dir
    top_level_loader_count = sum(1 for path in detector_files if path.parent == top_level_dir)
    rust_detect_loader_count = sum(
        1 for path in detector_files if _rust_detect_selectable_path(path, detectors_dir)
    )
    nested_loader_count = len(detector_files) - rust_detect_loader_count
    fixture_files, fixture_index = _fixture_index(fixtures_dir)
    targets = _makefile_targets(makefile_path)
    regression_script_ids = set(_regression_script_ids(regression_script_path))
    report_backed_regression_list = _script_uses_report_backed_regression_list(regression_script_path)
    report_backed_regression_ids = (
        _report_backed_regression_ids(root / DEFAULT_REPORT)
        if report_backed_regression_list
        else set()
    )
    if refresh_scanner_inputs:
        truth_payload, burndown_payload = _live_scanner_inputs(root, limit=live_inventory_limit)
        truth_map = _truth_rows_from_payload(truth_payload)
        burndown_map = _burndown_actions_from_payload(burndown_payload)
        truth_source = f"live:{root}"
        burndown_source = f"live:{root}"
    else:
        truth_path = truth_report or _latest_report_path(
            root,
            "scanner_wiring_truth_inventory",
            DEFAULT_TRUTH_REPORT,
            validator=_truth_report_compatible,
        )
        burndown_path = burndown_report or _latest_report_path(
            root,
            "scanner_wiring_burndown_queue",
            DEFAULT_BURNDOWN_REPORT,
            validator=_burndown_report_compatible,
        )
        truth_payload = _json_object(truth_path)
        burndown_payload = _json_object(burndown_path)
        truth_map = _truth_rows_from_payload(truth_payload)
        burndown_map = _burndown_actions_from_payload(burndown_payload)
        truth_source = _path_label(truth_path, root)
        burndown_source = _path_label(burndown_path, root)
    scanner_input_warnings = []
    if truth_payload.get("truncated") is True:
        scanner_input_warnings.append(
            "scanner truth inventory is truncated; Rust truth-status joins may omit lower-priority detector rows"
        )

    rust_detect_present = rust_detect_path.exists()
    inventory_smoke_rust_present = inventory_smoke_rust_path.exists()
    rust_fixture_make_present = "rust-fixture-detector" in targets
    inventory_smoke_make_status = _inventory_smoke_rust_status(targets, root)

    rows: list[DetectorRow] = []
    for path in detector_files:
        detector_id = path.stem
        group = _row_group(path, detectors_dir)
        nested = path.parent != detectors_dir
        pair = fixture_index.get(detector_id, {})
        pos_path = pair.get("positive")
        neg_path = pair.get("negative")
        pos_rel = _rel(pos_path, root) if pos_path else f"detectors/rust_wave1/test_fixtures/{detector_id}_positive.rs"
        neg_rel = _rel(neg_path, root) if neg_path else f"detectors/rust_wave1/test_fixtures/{detector_id}_negative.rs"
        has_positive = pos_path is not None and pos_path.exists()
        has_negative = neg_path is not None and neg_path.exists()
        fixture_pair_present = has_positive and has_negative

        selectable_via_rust_detect = rust_detect_present and _rust_detect_selectable_path(path, detectors_dir)
        selectable_via_inventory_smoke_rust = inventory_smoke_rust_present
        selectable_via_make = rust_fixture_make_present and selectable_via_rust_detect
        listed_in_script = detector_id in regression_script_ids or (
            detector_id in report_backed_regression_ids and fixture_pair_present and selectable_via_make
        )

        runner_gaps: list[str] = []
        if not selectable_via_rust_detect:
            runner_gaps.append("tools/rust-detect.py --only does not load this nested detector path")
        if not selectable_via_inventory_smoke_rust:
            runner_gaps.append("tools/inventory-smoke-rust.py does not reach this detector path")
        if not selectable_via_make:
            runner_gaps.append("make rust-fixture-detector cannot reach this detector through the current rust-detect loader")
        if not listed_in_script:
            runner_gaps.append("detectors/rust_wave1/test_fixtures/test_detectors.sh does not list or dynamically include this detector")

        truth_row = truth_map.get(detector_id)
        burndown_row = burndown_map.get(detector_id)

        missing_fixture = not fixture_pair_present
        missing_runner_hook = bool(runner_gaps)
        priority = _priority_score(
            missing_fixture=missing_fixture,
            missing_runner_hook=missing_runner_hook,
            nested_detector=nested,
            listed_in_script=listed_in_script,
            truth_row=truth_row,
            burndown_row=burndown_row,
        )
        action, next_files, next_commands = _next_action(
            detector_id,
            _rel(path, root),
            pos_rel,
            neg_rel,
            fixture_pair_present,
            selectable_via_rust_detect,
            selectable_via_make,
            listed_in_script,
            truth_row,
            inventory_smoke_make_status["standalone_tool_present"],
        )
        truth_wiring_status, truth_proof_status, truth_blockers = _normalized_truth_status(
            truth_row,
            fixture_pair_present=fixture_pair_present,
            selectable_via_rust_detect=selectable_via_rust_detect,
        )

        rows.append(
            DetectorRow(
                detector_id=detector_id,
                detector_path=_rel(path, root),
                detector_group=group,
                nested_detector=nested,
                has_positive_fixture=has_positive,
                has_negative_fixture=has_negative,
                fixture_pair_present=fixture_pair_present,
                positive_fixture=pos_rel,
                negative_fixture=neg_rel,
                selectable_via_rust_detect_only=selectable_via_rust_detect,
                selectable_via_inventory_smoke_rust=selectable_via_inventory_smoke_rust,
                selectable_via_make_rust_fixture_detector=selectable_via_make,
                listed_in_full_regression_script=listed_in_script,
                missing_fixture=missing_fixture,
                missing_runner_hook=missing_runner_hook,
                runner_gaps=runner_gaps,
                truth_inventory_wiring_status=truth_wiring_status,
                truth_inventory_proof_status=truth_proof_status,
                truth_inventory_blockers=truth_blockers,
                burndown_rank=(
                    burndown_row.get("rank")
                    if burndown_row and isinstance(burndown_row.get("rank"), int)
                    else None
                ),
                burndown_priority_score=(
                    burndown_row.get("priority_score")
                    if burndown_row and isinstance(burndown_row.get("priority_score"), int)
                    else None
                ),
                suggested_next_action=action,
                next_files=next_files,
                next_commands=next_commands,
                priority_score=priority,
            )
        )

    rows.sort(
        key=lambda row: (
            -row.priority_score,
            row.detector_id,
        )
    )

    missing_fixture_rows = [row for row in rows if row.missing_fixture]
    missing_runner_rows = [row for row in rows if row.missing_runner_hook]
    paired_rows = [row for row in rows if row.fixture_pair_present]
    script_rows = [row for row in rows if row.listed_in_full_regression_script]

    summary_actions = []
    for row in rows[: max(top_n, 0)]:
        summary_actions.append(
            {
                "detector_id": row.detector_id,
                "priority_score": row.priority_score,
                "suggested_next_action": row.suggested_next_action,
                "next_files": row.next_files,
                "next_commands": row.next_commands,
            }
        )

    return {
        "schema": SCHEMA_VERSION,
        "repo_root": str(root),
        "scanner_inputs": {
            "truth_report": truth_source,
            "burndown_report": burndown_source,
            "refreshed_from_repo": refresh_scanner_inputs,
            "live_inventory_limit": live_inventory_limit if refresh_scanner_inputs else None,
            "truth_inventory_truncated": bool(truth_payload.get("truncated", False)),
            "truth_inventory_total_row_count": truth_payload.get("total_row_count"),
            "truth_inventory_item_count": truth_payload.get("item_count"),
            "warnings": scanner_input_warnings,
        },
        "detector_count": {
            "total": len(rows),
            "top_level_loader_visible": top_level_loader_count,
            "rust_detect_loader_visible": rust_detect_loader_count,
            "nested_outside_current_loader": nested_loader_count,
        },
        "fixture_count": {
            "fixture_files": len(fixture_files),
            "fixture_pairs": sum(1 for pair in fixture_index.values() if "positive" in pair and "negative" in pair),
            "detectors_with_fixture_pair": len(paired_rows),
        },
        "runner_status": {
            "rust_detect_py_present": rust_detect_present,
            "inventory_smoke_rust_py_present": inventory_smoke_rust_present,
            "rust_fixture_make_target_present": rust_fixture_make_present,
            "inventory_smoke_make_target": inventory_smoke_make_status,
            "full_regression_script_present": regression_script_path.exists(),
            "full_regression_uses_report_backed_list": report_backed_regression_list,
            "full_regression_report_backed_candidate_count": len(report_backed_regression_ids),
            "single_detector_loader_supported_count": sum(
                1 for row in rows if row.selectable_via_rust_detect_only
            ),
            "single_detector_loader_missing_count": sum(
                1 for row in rows if not row.selectable_via_rust_detect_only
            ),
            "inventory_smoke_rust_supported_count": sum(
                1 for row in rows if row.selectable_via_inventory_smoke_rust
            ),
            "make_rust_fixture_supported_count": sum(
                1 for row in rows if row.selectable_via_make_rust_fixture_detector
            ),
            "full_regression_script_covered_count": len(script_rows),
            "full_regression_script_missing_count": len(rows) - len(script_rows),
        },
        "missing_fixture": {
            "count": len(missing_fixture_rows),
            "detectors": [asdict(row) for row in missing_fixture_rows],
        },
        "missing_runner_hook": {
            "count": len(missing_runner_rows),
            "single_detector_loader_missing_count": sum(
                1 for row in rows if not row.selectable_via_rust_detect_only
            ),
            "full_regression_script_missing_count": sum(
                1 for row in rows if not row.listed_in_full_regression_script
            ),
            "detectors": [asdict(row) for row in missing_runner_rows],
        },
        "suggested_next_action": summary_actions,
        "per_detector": [asdict(row) for row in rows],
    }


def _render_markdown(payload: dict[str, Any], *, top_n: int) -> str:
    lines = [
        "# Rust Detector Coverage Inventory — 2026-05-05",
        "",
        "Generated from live repo evidence by `tools/rust-detector-coverage.py`.",
        "",
        "This inventory counts detector files, fixture pairs, and runner-hook reachability. It does not claim exploit coverage completeness.",
        "",
        "## Scanner Inputs",
        "",
        f"- Truth inventory: `{payload.get('scanner_inputs', {}).get('truth_report', '')}`",
        f"- Burndown queue: `{payload.get('scanner_inputs', {}).get('burndown_report', '')}`",
        f"- Refreshed from repo: `{payload.get('scanner_inputs', {}).get('refreshed_from_repo', False)}`",
        f"- Truth inventory truncated: `{payload.get('scanner_inputs', {}).get('truth_inventory_truncated', False)}`",
        "",
        "## Summary",
        "",
    ]
    for warning in payload.get("scanner_inputs", {}).get("warnings", []):
        lines.insert(11, f"- Warning: {warning}")
    detector_count = payload["detector_count"]
    fixture_count = payload["fixture_count"]
    runner_status = payload["runner_status"]
    lines.extend(
        [
            f"- Detectors: **{detector_count['total']}** total, **{detector_count['rust_detect_loader_visible']}** visible to the current `tools/rust-detect.py` loader, **{detector_count['nested_outside_current_loader']}** nested outside that loader.",
            f"- Fixtures: **{fixture_count['fixture_pairs']}** positive/negative pairs across **{fixture_count['fixture_files']}** `.rs` files.",
            f"- Missing fixture pairs: **{payload['missing_fixture']['count']}** detectors.",
            f"- Single-detector Rust runner coverage: **{runner_status['single_detector_loader_supported_count']}/{detector_count['total']}**.",
            f"- `make rust-fixture-detector` coverage: **{runner_status['make_rust_fixture_supported_count']}/{detector_count['total']}**.",
            f"- Full regression shell coverage: **{runner_status['full_regression_script_covered_count']}/{detector_count['total']}**.",
        ]
    )
    if runner_status["full_regression_uses_report_backed_list"]:
        lines.append(
            "- Full regression shell coverage is report-backed via `tools/rust-fixture-regression-list.py`; generated residual assertion mismatches are exercised as `XFAIL`, not hidden."
        )
    inventory_smoke_status = runner_status["inventory_smoke_make_target"]
    if inventory_smoke_status["make_target_present"]:
        lines.append(
            "- `make inventory-smoke-detector` is not listed as a Rust command here because the current Makefile target does not invoke `tools/inventory-smoke-rust.py`."
        )
    lines.extend(
        [
            "",
            "## Live Validation",
            "",
            "- Supported today: `make rust-fixture-detector DETECTOR=two_step_admin_missing` passed on both positive and negative fixtures.",
            "- Supported today: exact `rust-detect.py --only <detector>` selection reaches nested/subdirectory detector paths.",
            "- Full-regression gaps, when present, are static hard-registration work for fixture-backed nested rows, not loader reachability gaps.",
            "",
            "## Top Follow-Up Rows",
            "",
            "Rows are priority-sorted coverage follow-ups. Rows marked `no immediate lift required` are regression-covered reference checks, not open runner gaps.",
            "",
            "| detector | gap | next files | next commands |",
            "|---|---|---|---|",
        ]
    )
    for row in payload["suggested_next_action"][:top_n]:
        files = "<br>".join(row["next_files"])
        commands = "<br>".join(f"`{command}`" for command in row["next_commands"]) or "—"
        lines.append(
            f"| `{row['detector_id']}` | {row['suggested_next_action']} | {files} | {commands} |"
        )

    missing_fixture = payload["missing_fixture"]["detectors"]
    lines.extend(
        [
            "",
            "## Missing Fixture Rows",
            "",
            "| detector | path | gap |",
            "|---|---|---|",
        ]
    )
    for row in missing_fixture:
        gap = []
        if not row["has_positive_fixture"]:
            gap.append("positive")
        if not row["has_negative_fixture"]:
            gap.append("negative")
        lines.append(
            f"| `{row['detector_id']}` | `{row['detector_path']}` | {', '.join(gap)} |"
        )

    paired_not_script = [
        row
        for row in payload["per_detector"]
        if row["fixture_pair_present"] and not row["listed_in_full_regression_script"]
    ]
    lines.extend(
        [
            "",
            "## Full Regression Gaps",
            "",
            f"- Fixture-backed detectors missing from `detectors/rust_wave1/test_fixtures/test_detectors.sh`: **{len(paired_not_script)}**.",
            f"- Single-detector loader misses confined to Rust subdirectory detector paths: **{runner_status['single_detector_loader_missing_count']}**.",
            "",
            "The exact detector rows are in `reports/rust_detector_coverage_2026-05-05.json` under `missing_runner_hook.detectors` and `per_detector`.",
        ]
    )
    return "\n".join(lines) + "\n"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repo_root", nargs="?", default=".", help="repo root to scan")
    parser.add_argument("--json-out", type=Path, help="write JSON report")
    parser.add_argument("--md-out", type=Path, help="write Markdown summary")
    parser.add_argument("--truth-report", type=Path, help="optional scanner wiring truth inventory JSON")
    parser.add_argument("--burndown-report", type=Path, help="optional scanner wiring burndown JSON")
    parser.add_argument(
        "--refresh-scanner-inputs",
        action="store_true",
        help="build fresh scanner truth and burndown inputs from the repo before computing Rust coverage",
    )
    parser.add_argument("--live-inventory-limit", type=int, default=12_000, help="row limit for --refresh-scanner-inputs")
    parser.add_argument("--top", type=int, default=20, help="top lift rows to include in markdown/summary")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    payload = build_inventory(
        Path(args.repo_root),
        truth_report=args.truth_report,
        burndown_report=args.burndown_report,
        refresh_scanner_inputs=args.refresh_scanner_inputs,
        live_inventory_limit=args.live_inventory_limit,
        top_n=args.top,
    )
    encoded = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        _write(args.json_out, encoded)
    else:
        sys.stdout.write(encoded)
    if args.md_out:
        _write(args.md_out, _render_markdown(payload, top_n=args.top))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
