#!/usr/bin/env python3
"""Build a bounded detector fixture/proof gap queue from scanner wiring evidence.

The queue is intentionally conservative: rows without fixture/proof evidence
are repair or retirement tasks, not detector-validity claims.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import shlex
import sys
from collections import Counter
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "auditooor.detector_proof_gap_queue.v1"
REPORT_DATE = "2026-05-05"
DEFAULT_INVENTORY = Path("reports/scanner_wiring_truth_inventory_2026-05-05.json")
DEFAULT_BURNDOWN = Path("reports/scanner_wiring_burndown_queue_2026-05-05.json")
DEFAULT_SECTION_LIMIT = 10
DEFAULT_FULL_THROTTLE_LIMIT = 24

SECTIONS = (
    "fixture_needed",
    "backend_needed",
    "rust_lift_needed",
    "retire_fake_candidate",
    "proof_verified",
    "docs_only",
)

SECTION_ORDER = {name: index for index, name in enumerate(SECTIONS)}
FULL_THROTTLE_QUOTAS = {
    "rust_lift_needed": 6,
    "backend_needed": 4,
    "fixture_needed": 8,
    "retire_fake_candidate": 3,
    "proof_verified": 2,
    "docs_only": 1,
}

PROOF_GUARD_UNPROVEN = (
    "No validity claim: fixture/proof evidence is missing or incomplete. "
    "Use this row only as a repair, wiring, or retirement task."
)
PROOF_GUARD_VERIFIED = (
    "Fixture/proof evidence is present in local paths, but this is not an exploit-validity claim; "
    "cite the concrete fixture/proof artifacts when using the detector."
)


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object in {path}")
    return payload


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
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


def _inventory_report_compatible(payload: dict[str, Any]) -> bool:
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
    except ValueError:
        return str(path)


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _row_id(row: dict[str, Any]) -> str:
    value = str(row.get("scanner_id") or row.get("pattern_id") or "row").strip()
    return value or "row"


def _kind_paths(row: dict[str, Any], suffixes: tuple[str, ...]) -> list[str]:
    return [
        path
        for path in [str(item) for item in row.get("source_paths", [])]
        if path.lower().endswith(suffixes)
    ]


def _detector_paths(row: dict[str, Any]) -> list[str]:
    return _kind_paths(row, (".py",))


def _fixture_paths(row: dict[str, Any]) -> list[str]:
    marker_words = ("fixture", "test_fixtures", "_fixtures", "_positive.", "_negative.", "_vulnerable.", "_clean.")
    paths = []
    for path in [str(item) for item in row.get("source_paths", [])]:
        low = path.lower()
        if any(marker in low for marker in marker_words):
            paths.append(path)
    return sorted(set(paths))


def _has_positive_fixture(row: dict[str, Any]) -> bool:
    return any(marker in path.lower() for path in _fixture_paths(row) for marker in ("positive", "vulnerable", "vuln", "bad"))


def _has_clean_fixture(row: dict[str, Any]) -> bool:
    return any(marker in path.lower() for path in _fixture_paths(row) for marker in ("negative", "clean", "good", "fixed"))


def _section_for_row(row: dict[str, Any]) -> str:
    status = str(row.get("wiring_status") or "")
    proof = str(row.get("proof_status") or "")
    if status == "wired_verified" and proof == "detector_and_fixture_pair_present":
        return "proof_verified"
    if status == "documentation_only":
        return "docs_only"
    if status in {"quarantined_fake", "in_dsl_fake_suspect"}:
        return "retire_fake_candidate"
    if status == "backend_executor_missing_or_tbd":
        return "backend_needed"
    if status == "rust_source_shape_only" or (
        str(row.get("backend") or "") == "rust" and "rust_runtime_semantics_unverified" in row.get("blockers", [])
    ):
        return "rust_lift_needed"
    return "fixture_needed"


def _action_for_section(section: str, row: dict[str, Any]) -> str:
    row_id = _row_id(row)
    backend = str(row.get("backend") or "unknown")
    if section == "fixture_needed":
        return "add vulnerable/positive and clean/negative fixture evidence, then attach smoke or runtime proof"
    if section == "backend_needed":
        return f"wire or document the runnable {backend} backend executor before claiming scanner coverage"
    if section == "rust_lift_needed":
        return "lift the Rust row from source-shape matching to runtime-semantic proof with fixture coverage"
    if section == "retire_fake_candidate":
        return "retire, quarantine, or explicitly restore only with fresh fixture/proof-backed evidence"
    if section == "proof_verified":
        return "keep as fixture-backed evidence and link a smoke/proof artifact when cited"
    if section == "docs_only":
        return "keep as documentation unless it is bound to concrete detector, fixture, and executor evidence"
    return f"inspect {row_id}"


def _base_test_harness_command(row: dict[str, Any], repo_root: Path | None) -> str:
    scanner_id = _row_id(row)
    detector_paths = _detector_paths(row)
    if not detector_paths:
        return ""

    first = detector_paths[0]
    parts = Path(first).parts
    if len(parts) >= 2 and parts[0] == "detectors":
        wave = parts[1]
        harness = Path("detectors") / wave / "test_fixtures" / "test_detectors.sh"
        if wave == "rust_wave1":
            return f"bash {shlex.quote(str(harness))} --detector={shlex.quote(scanner_id)}"
        if repo_root is None or (repo_root / harness).is_file():
            return f"bash {shlex.quote(str(harness))}"

    if first.startswith("detectors/") and str(row.get("backend") or "") == "solidity":
        return "JOBS=1 bash detectors/test_fixtures/run_tests.sh"
    return ""


def _suggested_inspection_command(row: dict[str, Any]) -> str:
    paths = [str(item) for item in row.get("source_paths", []) if item][:4]
    if paths:
        return "sed -n '1,220p' " + " ".join(shlex.quote(path) for path in paths)
    row_id = _row_id(row)
    return f"rg -n {shlex.quote(row_id)} detectors reference tools docs reports"


def _suggested_search_command(row: dict[str, Any], section: str) -> str:
    row_id = _row_id(row)
    if section == "backend_needed":
        return f"rg -n {shlex.quote(str(row.get('backend') or row_id))} tools detectors docs reports"
    return f"rg -n {shlex.quote(row_id)} detectors reference tools tools/tests docs reports"


def _actionability_score(row: dict[str, Any], section: str, burndown_by_key: dict[tuple[str, str], dict[str, Any]]) -> int:
    score = int(row.get("memory_priority", 0))
    blockers = {str(item) for item in row.get("blockers", [])}
    source_paths = [str(item) for item in row.get("source_paths", [])]
    detector_paths = _detector_paths(row)
    fixture_paths = _fixture_paths(row)
    key = (section, _row_id(row))

    score += {
        "rust_lift_needed": 180,
        "backend_needed": 165,
        "fixture_needed": 150,
        "retire_fake_candidate": 90,
        "proof_verified": 50,
        "docs_only": 20,
    }.get(section, 0)

    if detector_paths:
        score += 40
    if fixture_paths:
        score += 25
    if _has_positive_fixture(row):
        score += 15
    if _has_clean_fixture(row):
        score += 15
    if source_paths:
        score += 10
    if str(row.get("backend") or "unknown") not in {"", "unknown"}:
        score += 10
    if "rust_runtime_semantics_unverified" in blockers:
        score += 30
    if "positive_or_vulnerable_fixture_missing" in blockers:
        score += 18
    if "clean_or_negative_fixture_missing" in blockers:
        score += 12
    if key in burndown_by_key:
        score += 20
    if section == "fixture_needed" and str(row.get("evidence_kind") or "") == "dsl_yaml":
        score -= 25
    if section == "docs_only":
        score -= 30
    return score


def _normalise_item(
    row: dict[str, Any],
    *,
    section: str,
    score: int,
    repo_root: Path | None,
    burndown_action: dict[str, Any] | None,
) -> dict[str, Any]:
    proof_status = str(row.get("proof_status") or "")
    wiring_status = str(row.get("wiring_status") or "")
    item = {
        "section": section,
        "queue_id": _row_id(row),
        "scanner_id": str(row.get("scanner_id") or ""),
        "pattern_id": str(row.get("pattern_id") or ""),
        "backend": str(row.get("backend") or "unknown"),
        "evidence_kind": str(row.get("evidence_kind") or ""),
        "wiring_status": wiring_status,
        "proof_status": proof_status,
        "actionability_score": score,
        "action": _action_for_section(section, row),
        "claim_guard": PROOF_GUARD_VERIFIED if section == "proof_verified" else PROOF_GUARD_UNPROVEN,
        "source_paths": [str(item) for item in row.get("source_paths", [])],
        "detector_paths": _detector_paths(row),
        "fixture_paths": _fixture_paths(row),
        "has_positive_fixture": _has_positive_fixture(row),
        "has_clean_fixture": _has_clean_fixture(row),
        "blockers": [str(item) for item in row.get("blockers", [])],
        "suggested_next_action": str(row.get("suggested_next_action") or ""),
        "suggested_inspection_command": _suggested_inspection_command(row),
        "suggested_search_command": _suggested_search_command(row, section),
        "suggested_test_command": _base_test_harness_command(row, repo_root),
        "advisory_only": section != "proof_verified",
    }
    if burndown_action:
        item["source_burndown_lane"] = str(burndown_action.get("lane") or "")
        item["source_burndown_rank"] = burndown_action.get("rank")
    return item


def _dedupe_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        section = _section_for_row(row)
        key = (section, str(row.get("backend") or "unknown"), _row_id(row))
        existing = grouped.get(key)
        if existing is None:
            grouped[key] = dict(row)
            continue
        existing["memory_priority"] = max(int(existing.get("memory_priority", 0)), int(row.get("memory_priority", 0)))
        existing["source_paths"] = sorted({*existing.get("source_paths", []), *row.get("source_paths", [])})
        existing["blockers"] = sorted({*existing.get("blockers", []), *row.get("blockers", [])})
        if existing.get("proof_status") != "detector_and_fixture_pair_present" and row.get("proof_status"):
            existing["proof_status"] = row["proof_status"]
    return list(grouped.values())


def _burndown_index(burndown: dict[str, Any] | None) -> dict[tuple[str, str], dict[str, Any]]:
    if not burndown:
        return {}
    index: dict[tuple[str, str], dict[str, Any]] = {}
    for action in burndown.get("actions", []):
        if not isinstance(action, dict):
            continue
        lane = str(action.get("lane") or "")
        section = {
            "add_fixture_or_proof": "fixture_needed",
            "wire_backend_executor": "backend_needed",
            "rust_detector_lift": "rust_lift_needed",
            "retire_or_quarantine_fake": "retire_fake_candidate",
            "documentation_only": "docs_only",
        }.get(lane, "")
        if section:
            index[(section, str(action.get("row_id") or action.get("scanner_id") or action.get("pattern_id") or "row"))] = action
    for lane_actions in burndown.get("lane_top_actions", {}).values():
        if not isinstance(lane_actions, list):
            continue
        for action in lane_actions:
            if isinstance(action, dict):
                lane = str(action.get("lane") or "")
                section = {
                    "add_fixture_or_proof": "fixture_needed",
                    "wire_backend_executor": "backend_needed",
                    "rust_detector_lift": "rust_lift_needed",
                    "retire_or_quarantine_fake": "retire_fake_candidate",
                    "documentation_only": "docs_only",
                }.get(lane, "")
                if section:
                    index.setdefault(
                        (section, str(action.get("row_id") or action.get("scanner_id") or action.get("pattern_id") or "row")),
                        action,
                    )
    return index


def _section_payload(items: list[dict[str, Any]], limit: int) -> dict[str, Any]:
    rows = items[:limit]
    return {
        "total_available": len(items),
        "emitted": len(rows),
        "truncated": len(rows) < len(items),
        "rows": rows,
    }


def _source_burndown_rank(item: dict[str, Any]) -> int:
    try:
        rank = int(item.get("source_burndown_rank"))
    except (TypeError, ValueError):
        return 1_000_000
    return rank if rank > 0 else 1_000_000


def _item_priority_key(item: dict[str, Any]) -> tuple[Any, ...]:
    return (
        _source_burndown_rank(item),
        -int(item["actionability_score"]),
        item["backend"],
        item["queue_id"],
        item["source_paths"],
    )


def _full_throttle_items(by_section: dict[str, list[dict[str, Any]]], limit: int) -> list[dict[str, Any]]:
    selected: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for section in ("rust_lift_needed", "backend_needed", "fixture_needed", "retire_fake_candidate", "proof_verified", "docs_only"):
        quota = FULL_THROTTLE_QUOTAS.get(section, 0)
        for item in by_section.get(section, [])[:quota]:
            key = (item["section"], item["queue_id"])
            if key not in seen:
                selected.append(item)
                seen.add(key)
            if len([row for row in selected if row["section"] == section]) >= quota:
                break

    remaining = [
        item
        for section in SECTIONS
        for item in by_section.get(section, [])
        if (item["section"], item["queue_id"]) not in seen
    ]
    remaining.sort(key=lambda item: (SECTION_ORDER[item["section"]], *_item_priority_key(item)))
    for item in remaining:
        if len(selected) >= limit:
            break
        selected.append(item)
    selected = selected[: max(0, limit)]
    for index, item in enumerate(selected, start=1):
        item["full_throttle_rank"] = index
    return selected


def build_gap_queue(
    inventory: dict[str, Any],
    burndown: dict[str, Any] | None = None,
    *,
    section_limit: int = DEFAULT_SECTION_LIMIT,
    full_throttle_limit: int = DEFAULT_FULL_THROTTLE_LIMIT,
    repo_root: Path | None = None,
) -> dict[str, Any]:
    rows = inventory.get("rows", [])
    if not isinstance(rows, list):
        raise ValueError("inventory rows must be a list")

    effective_section_limit = max(0, section_limit)
    effective_full_limit = max(0, full_throttle_limit)
    burndown_by_key = _burndown_index(burndown)
    unique_rows = _dedupe_rows([row for row in rows if isinstance(row, dict)])

    by_section: dict[str, list[dict[str, Any]]] = {section: [] for section in SECTIONS}
    for row in unique_rows:
        section = _section_for_row(row)
        if section not in by_section:
            continue
        queue_id = _row_id(row)
        burndown_action = burndown_by_key.get((section, queue_id))
        score = _actionability_score(row, section, burndown_by_key)
        by_section[section].append(
            _normalise_item(
                row,
                section=section,
                score=score,
                repo_root=repo_root,
                burndown_action=burndown_action,
            )
        )

    for section, items in by_section.items():
        items.sort(key=_item_priority_key)
        for rank, item in enumerate(items, start=1):
            item["section_rank"] = rank

    status_counts = Counter(str(row.get("wiring_status") or "unknown") for row in unique_rows)
    backend_counts = Counter(str(row.get("backend") or "unknown") for row in unique_rows)
    blocker_counts = Counter(
        str(blocker)
        for row in unique_rows
        for blocker in row.get("blockers", [])
    )
    section_counts = {section: len(items) for section, items in by_section.items()}

    sections = {
        section: _section_payload(by_section[section], effective_section_limit)
        for section in SECTIONS
    }
    full_throttle = _full_throttle_items(by_section, effective_full_limit)

    payload = {
        "schema": SCHEMA_VERSION,
        "report_date": REPORT_DATE,
        "source_inventory_schema": str(inventory.get("schema") or ""),
        "source_inventory_limit": inventory.get("limit"),
        "source_inventory_item_count": inventory.get("item_count"),
        "source_inventory_total_row_count": inventory.get("total_row_count"),
        "source_inventory_truncated": bool(inventory.get("truncated", False)),
        "source_burndown_schema": str((burndown or {}).get("schema") or ""),
        "source_burndown_unique_action_count": (burndown or {}).get("unique_action_count"),
        "section_limit": effective_section_limit,
        "full_throttle_limit": effective_full_limit,
        "total_unique_rows_seen": len(unique_rows),
        "section_counts": section_counts,
        "status_counts": dict(sorted(status_counts.items())),
        "backend_counts": dict(sorted(backend_counts.items())),
        "blocker_counts": dict(sorted(blocker_counts.items())),
        "claim_policy": "Never claim detector validity without fixture/proof evidence; unverified rows are repair, wiring, documentation, or retirement tasks.",
        "full_throttle": {
            "emitted": len(full_throttle),
            "rows": full_throttle,
            "section_counts": dict(sorted(Counter(item["section"] for item in full_throttle).items())),
        },
        "sections": sections,
    }
    for section in SECTIONS:
        payload[section] = sections[section]
    return payload


def render_markdown(queue: dict[str, Any], *, inventory_path: str, burndown_path: str) -> str:
    lines = [
        f"# Detector Proof Gap Queue ({REPORT_DATE})",
        "",
        f"- Source inventory: `{inventory_path}`",
        f"- Source burn-down queue: `{burndown_path or 'not provided'}`",
        f"- Source rows seen after dedupe: `{queue.get('total_unique_rows_seen', 0)}`",
        f"- Source inventory truncated: `{queue.get('source_inventory_truncated', False)}`",
        f"- Claim policy: {queue.get('claim_policy', '')}",
        "",
        "## Section Counts",
        "",
    ]
    for section in SECTIONS:
        lines.append(f"- `{section}`: {queue.get('section_counts', {}).get(section, 0)}")

    lines.extend(["", "## Full Throttle Queue", ""])
    for item in queue.get("full_throttle", {}).get("rows", []):
        lines.append(
            f"{item['full_throttle_rank']}. `{item['section']}` `{item['queue_id']}` "
            f"({item['backend']}, `{item['wiring_status']}`): {item['action']}"
        )
        lines.append(f"   Guard: {item['claim_guard']}")
        if item.get("source_paths"):
            lines.append(f"   Sources: {', '.join(item['source_paths'][:5])}")
        if item.get("suggested_test_command"):
            lines.append(f"   Test: `{item['suggested_test_command']}`")
        lines.append(f"   Inspect: `{item['suggested_inspection_command']}`")

    lines.extend(["", "## Sections", ""])
    for section in SECTIONS:
        payload = queue.get("sections", {}).get(section, {})
        lines.append(f"### `{section}`")
        lines.append(
            f"- Emitted `{payload.get('emitted', 0)}` of `{payload.get('total_available', 0)}`; "
            f"truncated: `{payload.get('truncated', False)}`"
        )
        for item in payload.get("rows", []):
            lines.append(
                f"- rank {item['section_rank']}: `{item['queue_id']}` "
                f"score `{item['actionability_score']}` status `{item['wiring_status']}`"
            )
            if item.get("suggested_test_command"):
                lines.append(f"  Test: `{item['suggested_test_command']}`")
            lines.append(f"  Guard: {item['claim_guard']}")
        lines.append("")
    return "\n".join(lines)


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
        "--inventory",
        type=Path,
        help="scanner wiring truth inventory JSON; defaults to the latest compatible reports/scanner_wiring_truth_inventory_*.json",
    )
    parser.add_argument(
        "--burndown",
        type=Path,
        help="optional scanner burn-down queue JSON; defaults to the latest compatible reports/scanner_wiring_burndown_queue_*.json",
    )
    parser.add_argument("--repo-root", type=Path, default=Path("."), help="repo root for command inference and optional live inventory")
    parser.add_argument("--refresh-from-repo", action="store_true", help="build a fresh full inventory from --repo-root before queueing")
    parser.add_argument("--live-inventory-limit", type=int, default=12000, help="row limit when --refresh-from-repo is used")
    parser.add_argument("--section-limit", type=int, default=DEFAULT_SECTION_LIMIT)
    parser.add_argument("--full-throttle-limit", type=int, default=DEFAULT_FULL_THROTTLE_LIMIT)
    parser.add_argument("--json-out", type=Path, help="optional deterministic JSON output path")
    parser.add_argument("--md-out", type=Path, help="optional markdown output path")
    parser.add_argument("--print-json", action="store_true", help="print queue JSON to stdout")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    repo_root = args.repo_root.resolve()
    if args.refresh_from_repo:
        inventory = _load_live_inventory(repo_root, args.live_inventory_limit)
        inventory_label = f"live:{repo_root}"
    else:
        if args.inventory:
            inventory_path = args.inventory if args.inventory.is_absolute() else repo_root / args.inventory
        else:
            inventory_path = _latest_report_path(
                repo_root,
                "scanner_wiring_truth_inventory",
                DEFAULT_INVENTORY,
                validator=_inventory_report_compatible,
            )
        inventory = _load_json(inventory_path)
        inventory_label = _path_label(inventory_path, repo_root)

    burndown: dict[str, Any] | None = None
    burndown_label = ""
    if args.burndown:
        burndown_path = args.burndown if args.burndown.is_absolute() else repo_root / args.burndown
    else:
        burndown_path = _latest_report_path(
            repo_root,
            "scanner_wiring_burndown_queue",
            DEFAULT_BURNDOWN,
            validator=_burndown_report_compatible,
        )
    if burndown_path.is_file():
        burndown = _load_json(burndown_path)
        burndown_label = _path_label(burndown_path, repo_root)

    queue = build_gap_queue(
        inventory,
        burndown,
        section_limit=args.section_limit,
        full_throttle_limit=args.full_throttle_limit,
        repo_root=repo_root,
    )
    queue["source_inventory_path"] = inventory_label
    queue["source_burndown_path"] = burndown_label
    encoded = json.dumps(queue, indent=2, sort_keys=True) + "\n"
    if args.json_out:
        _write_json(args.json_out, queue)
    if args.md_out:
        _write_text(args.md_out, render_markdown(queue, inventory_path=inventory_label, burndown_path=burndown_label))
    if args.print_json or not args.json_out:
        sys.stdout.write(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
