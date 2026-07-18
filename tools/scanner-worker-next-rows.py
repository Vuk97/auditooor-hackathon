#!/usr/bin/env python3
"""Select unclaimed scanner burndown rows from a stale local queue."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


SCHEMA = "auditooor.scanner_worker_next_rows.v1"
QUEUE_SCHEMA = "auditooor.scanner_wiring_burndown_queue.v1"
DEFAULT_DATE = "2026-05-05"
DEFAULT_LIMIT = 5
DEFAULT_SCAN_LIMIT = 200
DEFAULT_QUEUE = f"reports/scanner_wiring_burndown_queue_{DEFAULT_DATE}.json"
DEFAULT_ACTIVE_CLAIMS = f"reports/scanner_worker_active_claims_{DEFAULT_DATE}.json"

COMPLETE_EVIDENCE_MARKERS = (
    "smoke",
    "positive",
    "negative",
    "clean",
    "vuln",
    "vulnerable",
    "fixed",
)
PASSING_SMOKE_STATUSES = {
    "smoke_pass",
    "passed",
    "pass",
    "passed_smoke",
    "passed_vulnerable_clean_smoke",
}
SMOKE_SCHEMA = "auditooor.canonical_detector_fixture_smoke.v1"
SMOKE_POSITIVE_REF_KEYS = (
    "positive_fixture",
    "positive_fixture_path",
    "vulnerable_fixture",
    "vulnerable_fixture_path",
)
SMOKE_CLEAN_REF_KEYS = (
    "clean_fixture",
    "clean_fixture_path",
    "negative_fixture",
    "negative_fixture_path",
)
DOCUMENTATION_ONLY_LANE = "documentation_only"
DOCUMENTATION_ONLY_DEFERRED_STATUS = "deferred_documentation_only"
COMPLETED_CLAIM_STATUSES = {"closed", "complete", "completed", "done"}
FAILED_CLAIM_STATUSES = {"failed"}
PROMPT_MODE_LOCAL_ONLY = "local-only"
PROMPT_MODE_COMMIT = "commit"
PROMPT_MODES = (PROMPT_MODE_LOCAL_ONLY, PROMPT_MODE_COMMIT)
SLITHER_BACKENDS = {"", "unknown", "solidity", "slither", "slither_source_shape", "vyper"}


@dataclass(frozen=True)
class LocalState:
    repo_root: str = ""
    branch: str = "unknown"
    head: str = "unknown"
    dirty_paths: frozenset[str] = frozenset()
    existing_paths: frozenset[str] = frozenset()
    committed_after_queue_paths: frozenset[str] = frozenset()
    queue_baseline_commit: str = ""
    active_claimed_row_ids: frozenset[str] = frozenset()
    completed_claimed_row_ids: frozenset[str] = frozenset()
    failed_claimed_row_ids: frozenset[str] = frozenset()


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _safe_text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _safe_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _safe_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _safe_int(value: Any) -> int:
    if isinstance(value, bool):
        return 0
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _strict_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _queue_loop_marker(path: Path) -> int:
    markers = re.findall(r"(?:^|[_-])l(\d+)(?:[_-]|$)", path.stem.lower())
    return max((_safe_int(marker) for marker in markers), default=0)


def _report_sort_key(path: Path, payload: dict[str, Any] | None = None) -> tuple[str, int, int, int, str]:
    dates = re.findall(r"\d{4}-\d{2}-\d{2}", path.name)
    packet = payload or {}
    return (
        dates[-1] if dates else "",
        _queue_loop_marker(path),
        _safe_int(packet.get("actionable_row_count")),
        _safe_int(packet.get("top_action_count")),
        path.name,
    )


def _json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _scanner_queue_report_compatible(payload: dict[str, Any]) -> bool:
    if _safe_text(payload.get("schema")) != QUEUE_SCHEMA:
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
    fallback_rel: str,
    *,
    validator: Any = None,
) -> Path:
    reports_dir = root / "reports"
    if reports_dir.is_dir():
        candidates: list[tuple[Path, dict[str, Any]]] = []
        for path in reports_dir.glob(f"{stem}_*.json"):
            payload = _json_object(path)
            if validator is not None and not validator(payload):
                continue
            candidates.append((path, payload))
        if candidates:
            return max(candidates, key=lambda item: _report_sort_key(item[0], item[1]))[0]
    return root / fallback_rel


def _claim_status(row: dict[str, Any]) -> str:
    return _safe_text(
        row.get("claim_status")
        or row.get("status")
        or row.get("state")
        or row.get("worker_status")
        or "active"
    ).lower()


def _truthy_open_status(row: dict[str, Any]) -> bool:
    raw = _claim_status(row)
    if raw in {"", "active"}:
        return True
    return raw not in {
        "closed",
        "complete",
        "completed",
        "done",
        "released",
        "cancelled",
        "canceled",
        "failed",
        "stale_released",
    }


def _claim_row_id(row: Any) -> str:
    if isinstance(row, str):
        return _slug(row)
    if not isinstance(row, dict) or not _truthy_open_status(row):
        return ""
    return _slug(row.get("row_id") or row.get("scanner_id") or row.get("pattern_id") or row.get("id"))


def _completed_claim_row_id(row: Any) -> str:
    if not isinstance(row, dict) or _claim_status(row) not in COMPLETED_CLAIM_STATUSES:
        return ""
    return _slug(row.get("row_id") or row.get("scanner_id") or row.get("pattern_id") or row.get("id"))


def _failed_claim_row_id(row: Any) -> str:
    if not isinstance(row, dict) or _claim_status(row) not in FAILED_CLAIM_STATUSES:
        return ""
    return _slug(row.get("row_id") or row.get("scanner_id") or row.get("pattern_id") or row.get("id"))


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


def _row_id(action: dict[str, Any]) -> str:
    return _safe_text(action.get("row_id") or action.get("scanner_id") or action.get("pattern_id") or "row") or "row"


def _test_path(row_id: str) -> str:
    return f"tools/tests/test_{_slug(row_id) or 'scanner_row'}.py"


def _fixture_dirs(row_id: str) -> list[str]:
    slug = _slug(row_id)
    if not slug:
        return []
    hyphen = slug.replace("_", "-")
    dirs = [f"detectors/fixtures/{slug}"]
    if hyphen != slug:
        dirs.append(f"detectors/fixtures/{hyphen}")
    return dirs


def _dsl_path(row_id: str) -> str:
    return f"reference/patterns.dsl/{_slug(row_id).replace('_', '-')}.yaml"


def _safe_repo_relative_path(root: Path, raw: Any) -> str:
    text = _safe_text(raw)
    if not text:
        return ""
    candidate = Path(text).expanduser()
    resolved = candidate.resolve() if candidate.is_absolute() else (root / candidate).resolve()
    try:
        return resolved.relative_to(root.resolve()).as_posix()
    except ValueError:
        return ""


def _safe_source_path_text(raw: Any) -> str:
    text = _safe_text(raw)
    if not text:
        return ""
    path = Path(text).expanduser()
    if path.is_absolute() or ".." in path.parts:
        return ""
    return path.as_posix()


def _dsl_backend(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return ""
    match = re.search(r"(?m)^\s*backend\s*:\s*([A-Za-z0-9_-]+)\s*(?:#.*)?$", text)
    return _safe_text(match.group(1)).lower() if match else ""


def _dsl_status(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return ""
    for key in ("status", "wiring_status", "proof_status"):
        match = re.search(rf"(?m)^\s*{re.escape(key)}\s*:\s*(.+?)\s*$", text)
        if not match:
            continue
        value = _safe_text(match.group(1).split("#", 1)[0]).strip("\"'").lower()
        if "documentation" in value and "only" in value:
            return DOCUMENTATION_ONLY_LANE
    return ""


def _backend_candidates(action: dict[str, Any], row_id: str, root: Path | None = None) -> list[str]:
    candidates = [_dsl_path(row_id)]
    for raw in _safe_list(action.get("source_paths")):
        text = _safe_text(raw)
        if not text.endswith((".yaml", ".yml")):
            continue
        if root is not None:
            text = _safe_repo_relative_path(root, text)
        else:
            text = _safe_source_path_text(text)
        if text and text not in candidates:
            candidates.append(text)
    return candidates


def resolved_backend_for_action(action: dict[str, Any], root: Path | None = None) -> str:
    row_id = _row_id(action)
    if root is not None:
        for raw in _backend_candidates(action, row_id, root=root):
            path = root / raw
            backend = _dsl_backend(path)
            if backend:
                return backend
    return _safe_text(action.get("backend")).lower() or "unknown"


def resolved_lane_for_action(action: dict[str, Any], root: Path | None = None) -> str:
    row_id = _row_id(action)
    if root is not None:
        for raw in _backend_candidates(action, row_id, root=root):
            path = root / raw
            status = _dsl_status(path)
            if status:
                return status
    return _safe_text(action.get("lane"))


def _backend_verification_guidance(backend: str) -> str:
    normalized = _safe_text(backend).lower()
    if normalized in SLITHER_BACKENDS:
        return (
            "Verification: run py_compile for touched Python, the focused unittest, and direct positive/clean "
            "fixture smoke through detectors/run_custom.py with AUDITOOOR_FIXTURE_SMOKE_MODE=1 and cache bypass."
        )
    if normalized == "anchor":
        return (
            "Verification: run py_compile for touched Python, the focused unittest, and positive/clean workspace "
            "smoke through tools/anchor-detector-runner.py --workspace <fixture-workspace> --out <tmp-json>."
        )
    if normalized == "cosmos":
        return (
            "Verification: run py_compile for touched Python, the focused unittest, and a bounded smoke through "
            "tools/cosmos-detector-runner.py against the row-local Go fixture/workspace."
        )
    if normalized == "reth":
        return (
            "Verification: run py_compile for touched Python, the focused unittest, and a bounded smoke through "
            "tools/reth-detector-runner.py against the row-local Rust fixture/workspace."
        )
    if normalized == "rust":
        return (
            "Verification: run py_compile for touched Python, the focused unittest, and a bounded smoke through "
            "tools/rust-detector-runner.py and/or tools/rust-source-graph.py against the row-local Rust fixture/workspace."
        )
    if normalized == "go":
        return (
            "Verification: run py_compile for touched Python, the focused unittest, and a bounded smoke through "
            "tools/go-detector-runner.py against the row-local Go fixture/workspace."
        )
    if normalized in {"move", "circom", "geth_runtime", "documentation_only"}:
        return (
            f"Verification: this row declares backend `{normalized}`. Use the row's backend-specific local runner "
            "or fixture harness if one exists; if no executor exists, close the slice as a backend-executor gap "
            "instead of forcing Solidity/Slither smoke."
        )
    return (
        f"Verification: backend `{normalized or 'unknown'}` is not mapped here. Use the row's local runner if visible; "
        "otherwise report a backend-routing gap without forcing Solidity/Slither smoke."
    )


def _advisory_template_command(command: str, reason: str) -> dict[str, Any]:
    return {
        "command": command,
        "reason": reason,
        "advisory_only": True,
        "runnable": False,
        "execution_boundary": (
            "Template command for operator planning only; fill placeholders and rerun normal local gates "
            "before execution."
        ),
    }


def _hacker_logic_handoff(row_id: str) -> dict[str, Any]:
    detector = _slug(row_id).replace("_", "-")
    return {
        "purpose": (
            "After the row has honest positive/clean proof, route any real workspace hit into "
            "attacker-action and proof-obligation work instead of stopping at scanner coverage."
        ),
        "required_before_handoff": [
            "row-local positive/clean smoke or equivalent focused proof passed",
            "actual audit workspace hit exists in engage_report.json or an exact source file is known",
            "submission_posture remains NOT_SUBMIT_READY until source/OOS/dupe/PoC proof passes",
        ],
        "commands": [
            _advisory_template_command(
                "make audit WS=<audit-workspace> FORCE=1",
                "refresh engage_report.json so the detector hit enters the canonical audit artifact chain",
            ),
            _advisory_template_command(
                "make engage-report-mcp-feed WS=<audit-workspace>",
                "load bounded detector clusters through MCP before worker dispatch",
            ),
            _advisory_template_command(
                (
                    "make detector-hit-action-graph WS=<audit-workspace> "
                    f"DETECTOR={detector} FILE=<workspace-relative-file> "
                    "OUT=<audit-workspace>/.auditooor/detector_action_graph.json"
                ),
                "convert the detector hit into attacker goal, precondition, transition, impact probe, and proof obligations",
            ),
            _advisory_template_command(
                (
                    "make hacker-brief WS=<audit-workspace> LANE=<lane-id> "
                    "FILES='<workspace-relative-source-files>'"
                ),
                "turn the detector/action-graph context plus MCP recall into lane questions for source review",
            ),
            _advisory_template_command(
                "make chained-attack-plans WS=<audit-workspace>",
                "look for anchored multi-hop candidates after local exploit/swarm/big-loss artifacts exist",
            ),
            _advisory_template_command(
                "make proof-obligation-queue WS=<audit-workspace>",
                "collect action-graph obligations, brief questions, and chain blockers into proof tasks",
            ),
        ],
    }


def _is_legacy_wave13_broken_path(path: str) -> bool:
    parts = Path(path).parts
    return len(parts) >= 3 and parts[0] == "detectors" and parts[1] == "wave13_broken"


def _is_smoke_path(path: str) -> bool:
    return "smoke" in Path(path).name.lower() and path.lower().endswith(".json")


def _is_positive_path(path: str) -> bool:
    name = Path(path).name.lower()
    return any(marker in name for marker in ("positive", "vuln", "vulnerable"))


def _is_clean_path(path: str) -> bool:
    name = Path(path).name.lower()
    return any(marker in name for marker in ("clean", "negative", "fixed"))


def owned_paths_for_action(action: dict[str, Any]) -> list[str]:
    row_id = _row_id(action)
    owned: list[str] = []
    for raw in _safe_list(action.get("source_paths")):
        text = _safe_source_path_text(raw)
        if not text:
            continue
        path = Path(text)
        parts = path.parts
        if len(parts) >= 3 and parts[0] == "detectors" and parts[1] == "fixtures":
            text = str(Path(*parts[:3]))
        if text not in owned:
            owned.append(text)

    for candidate in [*_fixture_dirs(row_id), _test_path(row_id), _dsl_path(row_id)]:
        if candidate and candidate not in owned:
            owned.append(candidate)
    return owned[:16]


def _matches_row(path: str, row_id: str, owned_paths: Iterable[str]) -> bool:
    row_slug = _slug(row_id)
    row_hyphen = row_slug.replace("_", "-")
    if any(_path_within(path, owned) for owned in owned_paths):
        return True
    if row_slug and len(row_slug) > 5:
        normalized = _slug(path)
        return row_slug in normalized or row_hyphen in path.lower()
    return False


def _matching_paths(
    paths: Iterable[str],
    row_id: str,
    owned_paths: list[str],
    *,
    limit: int | None = 12,
) -> list[str]:
    matches: list[str] = []
    for path in sorted({_safe_text(item) for item in paths if _safe_text(item)}):
        if _matches_row(path, row_id, owned_paths):
            matches.append(path)
    if limit is None:
        return matches
    return matches[: max(0, limit)]


def _evidence_snapshot(state: LocalState, row_id: str, owned_paths: list[str]) -> dict[str, Any]:
    fixture_dirs = _fixture_dirs(row_id)
    row_existing_all = _matching_paths(state.existing_paths, row_id, owned_paths + fixture_dirs, limit=None)
    test_paths = [
        path
        for path in row_existing_all
        if path == _test_path(row_id) or path.startswith("tools/tests/test_")
    ]
    fixture_paths = [
        path
        for path in row_existing_all
        if any(_path_within(path, fixture_dir) for fixture_dir in fixture_dirs)
    ]
    legacy_proof_paths = [
        path
        for path in row_existing_all
        if _is_legacy_wave13_broken_path(path)
        and (_is_smoke_path(path) or _is_positive_path(path) or _is_clean_path(path))
    ]
    proof_paths = sorted(set(fixture_paths + legacy_proof_paths))
    smoke_paths = [path for path in proof_paths if _is_smoke_path(path)]
    positive_paths = [path for path in proof_paths if _is_positive_path(path)]
    clean_paths = [path for path in proof_paths if _is_clean_path(path)]
    smoke_validation = {
        path: _validate_smoke_metadata(state, path, row_id)
        for path in smoke_paths
    }
    valid_smoke_paths = [
        path
        for path, verdict in smoke_validation.items()
        if verdict.get("valid")
    ]
    if state.repo_root:
        complete = bool(test_paths) and bool(valid_smoke_paths)
    else:
        complete = bool(test_paths) and (bool(smoke_paths) or (bool(positive_paths) and bool(clean_paths)))
    committed_matches = _matching_paths(state.committed_after_queue_paths, row_id, owned_paths + fixture_dirs)
    committed_evidence = [
        path
        for path in committed_matches
        if path in test_paths
        or path.startswith("tools/tests/test_")
        or any(marker in Path(path).name.lower() for marker in COMPLETE_EVIDENCE_MARKERS)
        or path.endswith(".py")
    ]
    return {
        "existing_paths": row_existing_all[:20],
        "test_paths": test_paths,
        "smoke_paths": smoke_paths,
        "valid_smoke_paths": valid_smoke_paths,
        "smoke_validation": smoke_validation,
        "positive_paths": positive_paths,
        "clean_paths": clean_paths,
        "fixture_paths": fixture_paths,
        "legacy_proof_paths": legacy_proof_paths,
        "complete_local_evidence": complete,
        "committed_after_queue_paths": committed_matches,
        "committed_evidence_paths": committed_evidence,
    }


def _validate_smoke_metadata(state: LocalState, smoke_path: str, row_id: str) -> dict[str, Any]:
    if not state.repo_root:
        return {"valid": False, "reason": "repo_root_unavailable"}
    root = Path(state.repo_root)
    path = root / smoke_path
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"valid": False, "reason": "smoke_json_unreadable"}
    if not isinstance(payload, dict):
        return {"valid": False, "reason": "smoke_json_not_object"}
    if _safe_text(payload.get("schema")) != SMOKE_SCHEMA:
        return {"valid": False, "reason": "smoke_json_schema_mismatch"}

    status = _safe_text(payload.get("status")).lower()
    fixture_id = _safe_text(payload.get("fixture_id")).lower()
    detector_slug = _safe_text(payload.get("detector_slug")).lower()
    pattern = _safe_text(payload.get("pattern")).lower()
    row_slug = _slug(row_id)
    row_hyphen = row_slug.replace("_", "-")
    identity_text = " ".join([fixture_id, detector_slug, pattern, smoke_path.lower()])

    if row_slug and row_slug not in _slug(identity_text) and row_hyphen not in identity_text:
        return {"valid": False, "reason": "smoke_json_row_identity_mismatch"}
    if status not in PASSING_SMOKE_STATUSES:
        return {"valid": False, "reason": "smoke_json_status_not_pass"}
    has_hit_counters = "positive_hits" in payload or "vulnerable_hits" in payload or "clean_hits" in payload
    if has_hit_counters:
        positive_values = [
            value
            for value in (
                _strict_int(payload.get("positive_hits")),
                _strict_int(payload.get("vulnerable_hits")),
            )
            if value is not None
        ]
        clean_hits = _strict_int(payload.get("clean_hits"))
        if clean_hits is None:
            return {"valid": False, "reason": "smoke_json_hit_counters_not_integer"}
        if not positive_values:
            return {"valid": False, "reason": "smoke_json_hit_counters_not_integer"}
        positive_hits = max(positive_values)
        if positive_hits <= 0:
            return {"valid": False, "reason": "smoke_json_positive_hits_missing"}
        if clean_hits != 0:
            return {"valid": False, "reason": "smoke_json_clean_hits_nonzero"}
        return {
            "valid": True,
            "reason": "passed_smoke_metadata",
            "positive_hits": positive_hits,
            "clean_hits": clean_hits,
            "status": status,
        }
    fixture_refs = _smoke_fixture_refs(root, path, payload)
    if fixture_refs["positive"] and fixture_refs["clean"]:
        return {
            "valid": True,
            "reason": "passed_smoke_metadata_fixture_refs",
            "positive_fixture_refs": fixture_refs["positive"],
            "clean_fixture_refs": fixture_refs["clean"],
            "status": status,
        }
    return {"valid": False, "reason": "smoke_json_fixture_refs_missing"}


def _resolve_smoke_fixture_ref(root: Path, smoke_path: Path, raw: Any) -> str:
    text = _safe_text(raw)
    if not text:
        return ""
    candidate = Path(text).expanduser()
    search_paths = [candidate.resolve()] if candidate.is_absolute() else [
        (root / candidate).resolve(),
        (smoke_path.parent / candidate).resolve(),
    ]
    for resolved in search_paths:
        try:
            rel = resolved.relative_to(root.resolve())
        except ValueError:
            continue
        try:
            resolved.relative_to(smoke_path.parent.resolve())
        except ValueError:
            continue
        if resolved.exists():
            return rel.as_posix()
    return ""


def _smoke_fixture_refs(root: Path, smoke_path: Path, payload: dict[str, Any]) -> dict[str, list[str]]:
    refs = {"positive": [], "clean": []}
    for key in SMOKE_POSITIVE_REF_KEYS:
        value = _resolve_smoke_fixture_ref(root, smoke_path, payload.get(key))
        if value:
            refs["positive"].append(value)
    for key in SMOKE_CLEAN_REF_KEYS:
        value = _resolve_smoke_fixture_ref(root, smoke_path, payload.get(key))
        if value:
            refs["clean"].append(value)
    fixtures = payload.get("fixtures")
    if isinstance(fixtures, dict):
        for key in ("positive", "vulnerable"):
            value = _resolve_smoke_fixture_ref(root, smoke_path, fixtures.get(key))
            if value:
                refs["positive"].append(value)
        for key in ("clean", "negative"):
            value = _resolve_smoke_fixture_ref(root, smoke_path, fixtures.get(key))
            if value:
                refs["clean"].append(value)
    return {
        "positive": sorted(set(refs["positive"])),
        "clean": sorted(set(refs["clean"])),
    }


def classify_action(action: dict[str, Any], state: LocalState) -> dict[str, Any]:
    row_id = _row_id(action)
    owned_paths = owned_paths_for_action(action)
    dirty_matches = _matching_paths(state.dirty_paths, row_id, owned_paths)
    evidence = _evidence_snapshot(state, row_id, owned_paths)
    if _slug(row_id) in state.active_claimed_row_ids:
        status = "claimed_active_registry"
        dispatchable = False
        reason = "row is already assigned in the active scanner worker claims registry"
    elif _slug(row_id) in state.completed_claimed_row_ids:
        status = "claimed_completed_registry"
        dispatchable = False
        reason = "row is already recorded complete in the scanner worker claims registry"
    elif _slug(row_id) in state.failed_claimed_row_ids:
        status = "claimed_failed_registry_cooldown"
        dispatchable = False
        reason = "row has a failed scanner worker claim; require manual cleanup or reroute before redispatch"
    elif evidence["committed_evidence_paths"]:
        status = "already_committed"
        dispatchable = False
        reason = "row-local evidence paths were committed after the queue baseline"
    elif evidence["complete_local_evidence"]:
        status = "local_evidence_present_refresh_needed"
        dispatchable = False
        reason = "row-local smoke/test or fixture/test evidence already exists; refresh scanner memory before dispatch"
    elif dirty_matches:
        status = "claimed_dirty_worktree"
        dispatchable = False
        reason = "matching dirty row paths exist in this checkout"
    else:
        status = "unclaimed_from_local_checkout"
        dispatchable = True
        reason = "no matching dirty paths, post-queue commits, or complete local proof evidence detected"

    return {
        "row_id": row_id,
        "status": status,
        "dispatchable": dispatchable,
        "reason": reason,
        "owned_paths": owned_paths,
        "matching_dirty_paths": dirty_matches,
        "local_evidence": evidence,
    }


def lane_defer_reason(action: dict[str, Any], *, include_documentation_only: bool) -> str:
    lane = _safe_text(action.get("lane"))
    if lane == DOCUMENTATION_ONLY_LANE and not include_documentation_only:
        return (
            "documentation_only rows are deferred by default while executable scanner/KLB rows are active; "
            "pass --include-documentation-only for a docs pass"
        )
    return ""


def _worker_prompt(
    action: dict[str, Any],
    classification: dict[str, Any],
    *,
    prompt_mode: str = PROMPT_MODE_LOCAL_ONLY,
    backend: str = "unknown",
) -> str:
    row_id = classification["row_id"]
    owned_paths = "\n".join(f"- {path}" for path in _safe_list(classification.get("owned_paths")))
    source_paths = "\n".join(
        f"- {text}" for text in (_safe_source_path_text(path) for path in _safe_list(action.get("source_paths"))) if text
    )
    source_block = f"\nSource paths from queue:\n{source_paths}\n" if source_paths else ""
    lines = [
        "You are working in the repo checkout that generated this scanner worker row.",
        "You are not alone in the codebase: do not revert or overwrite edits made by others, "
        "and do not touch files outside your owned row paths unless absolutely required and explicitly explained.",
        "",
        "Top priority: known-limitation burndown with end-to-end executable closure.",
        "",
        f"Owned row: {row_id}",
        f"Declared backend: {backend}",
        "Owned paths:",
        owned_paths,
        source_block.rstrip(),
        "Task: repair/close this scanner row end to end. Inspect the existing detector, DSL, fixtures, "
        "and nearby repo patterns. If the row is broken/generated/syntax-broken, replace it with the "
        "narrowest honest row-local detector or proof path that can pass one positive fixture and one clean fixture.",
        "",
        "Required artifacts: canonical underscore fixture directory, hyphenated fixture mirror when applicable, "
        "smoke metadata, focused unittest or equivalent local smoke gate, and a reference DSL artifact.",
        "",
        "Claim discipline: mark submission_posture NOT_SUBMIT_READY unless you have real corpus-backed exploit evidence. "
        "Do not claim exploit coverage, impact, or broad detector completeness from fixture-smoke/source-shape proof.",
        "",
        _backend_verification_guidance(backend),
        "",
        "Hacker-logic handoff: once row-local proof is honest, report the exact detector slug and source-file "
        "template needed to run detector-hit-action-graph, hacker-brief, chained-attack-plans, and "
        "proof-obligation-queue in the target audit workspace. The handoff is advisory only; it is not a "
        "severity or submission-readiness claim.",
        "",
    ]
    if prompt_mode == PROMPT_MODE_COMMIT:
        lines.extend(
            [
                "Commit discipline: before staging, run git diff --cached --name-only. If unrelated paths are already "
                "staged, leave them untouched. Stage only your owned paths, then commit with git commit --only -- "
                "<owned pathspecs> so the commit ignores unrelated staged files. Re-run git diff --cached --name-only "
                "and git show --name-only --oneline HEAD after commit; the new commit must contain only owned paths. "
                "If git commit --only cannot commit your owned row cleanly, stop and report the blocking staged paths.",
                "",
                "Commit only your owned paths with a clear message. Final response must include commit hash, files changed, "
                "commands run, positive/clean hit counts, and residual risk.",
            ]
        )
    else:
        lines.extend(
            [
                "Local-only discipline: do not run GitHub commands, do not push/fetch/pull/clone, do not open PRs, "
                "do not request approval/escalation, and do not commit. If a command would require approval, skip it "
                "and report the blocker.",
                "",
                "Final response must include files changed, commands run, positive/clean hit counts if measured, "
                "residual risk, and blockers. Do not include a commit hash.",
            ]
        )
    return "\n".join(lines)


def _prompt_seed(row_id: str, prompt_mode: str) -> str:
    tail = "run focused local verification, and leave changes uncommitted for local review"
    if prompt_mode == PROMPT_MODE_COMMIT:
        tail = "run focused local verification, and commit only owned row paths"
    return (
        f"Own scanner burndown row `{row_id}` end to end: inspect DSL/detector/fixtures, "
        f"close the narrow proof gap if feasible, {tail}."
    )


def _acceptance_criteria(prompt_mode: str) -> list[str]:
    criteria = [
        "positive fixture or runtime proof produces at least one expected detector hit",
        "clean fixture produces zero hits",
        "focused unittest or equivalent local smoke gate passes",
        "stale extraction_failure or advisory-only metadata is retired only for this owned row",
    ]
    if prompt_mode == PROMPT_MODE_COMMIT:
        criteria.extend(
            [
                "pre-commit staged-file check is handled without committing unrelated staged paths",
                "commit contains only owned row paths and no shared report/doc/memory refresh",
            ]
        )
    else:
        criteria.extend(
            [
                "no GitHub, network, approval/escalation, or commit commands are required",
                "final response reports changed files, verification, blockers, and residual risk",
            ]
        )
    return criteria


def _compact_action(
    action: dict[str, Any],
    classification: dict[str, Any],
    emitted_rank: int,
    *,
    prompt_mode: str = PROMPT_MODE_LOCAL_ONLY,
    backend: str = "unknown",
) -> dict[str, Any]:
    return {
        "slot_id": f"scanner-next-{emitted_rank}",
        "row_id": classification["row_id"],
        "queue_rank": action.get("rank"),
        "lane": _safe_text(action.get("lane")),
        "backend": backend or "unknown",
        "wiring_status": _safe_text(action.get("wiring_status")) or "unknown",
        "proof_status": _safe_text(action.get("proof_status")),
        "local_coordination_status": classification["status"],
        "owned_paths": classification["owned_paths"],
        "source_paths": [
            text for text in (_safe_source_path_text(path) for path in _safe_list(action.get("source_paths"))) if text
        ],
        "suggested_next_action": _safe_text(action.get("suggested_next_action")),
        "suggested_commands": [
            _advisory_template_command(
                _safe_text(command.get("command")),
                _safe_text(command.get("reason")),
            )
            for command in _safe_list(action.get("suggested_commands"))[:3]
            if isinstance(command, dict) and _safe_text(command.get("command"))
        ],
        "prompt_mode": prompt_mode,
        "prompt_seed": _prompt_seed(classification["row_id"], prompt_mode),
        "worker_prompt": _worker_prompt(action, classification, prompt_mode=prompt_mode, backend=backend),
        "acceptance_criteria": _acceptance_criteria(prompt_mode),
        "hacker_logic_handoff": _hacker_logic_handoff(classification["row_id"]),
        "claim_guard": _safe_text(action.get("claim_guard")),
    }


def _queue_actions(queue: dict[str, Any]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    actions: list[dict[str, Any]] = []

    def append(action: Any) -> None:
        if not isinstance(action, dict) or bool(action.get("closed")):
            return
        key = (_row_id(action), _safe_text(action.get("backend")), _safe_text(action.get("lane")))
        if key in seen:
            return
        seen.add(key)
        actions.append(action)

    for action in _safe_list(queue.get("actions")):
        append(action)
    for lane_actions in _safe_dict(queue.get("lane_top_actions")).values():
        for action in _safe_list(lane_actions):
            append(action)

    actions.sort(
        key=lambda action: (
            _safe_int(action.get("rank")),
            _safe_text(action.get("lane")),
            _safe_text(action.get("backend")),
            _row_id(action),
        )
    )
    return actions


def _iter_queue_action_rows(queue: dict[str, Any]) -> Iterable[tuple[str, Any]]:
    for index, action in enumerate(_safe_list(queue.get("actions"))):
        yield f"actions[{index}]", action
    for lane, lane_actions in _safe_dict(queue.get("lane_top_actions")).items():
        for index, action in enumerate(_safe_list(lane_actions)):
            yield f"lane_top_actions[{lane!r}][{index}]", action


def _validate_queue_payload(queue: dict[str, Any]) -> None:
    schema = _safe_text(queue.get("schema"))
    if schema != QUEUE_SCHEMA:
        raise ValueError(f"unsupported scanner queue schema: {schema or '<missing>'}")
    if "actions" in queue and not isinstance(queue.get("actions"), list):
        raise ValueError("scanner queue field `actions` must be a list when present")
    if "lane_top_actions" in queue and not isinstance(queue.get("lane_top_actions"), dict):
        raise ValueError("scanner queue field `lane_top_actions` must be an object when present")
    has_actions = isinstance(queue.get("actions"), list)
    lane_top_actions = _safe_dict(queue.get("lane_top_actions"))
    has_lane_actions = any(isinstance(rows, list) for rows in lane_top_actions.values())
    if not has_actions and not has_lane_actions:
        raise ValueError("scanner queue must contain `actions` or `lane_top_actions`")
    for label, action in _iter_queue_action_rows(queue):
        if not isinstance(action, dict):
            raise ValueError(f"scanner queue row {label} must be an object")
        if action.get("rank") not in (None, "") and _strict_int(action.get("rank")) is None:
            raise ValueError(f"scanner queue row {label} has non-integer rank")


def build_next_rows(
    queue: dict[str, Any],
    *,
    state: LocalState,
    root: Path | None = None,
    limit: int = DEFAULT_LIMIT,
    scan_limit: int = DEFAULT_SCAN_LIMIT,
    include_documentation_only: bool = False,
    prompt_mode: str = PROMPT_MODE_LOCAL_ONLY,
) -> dict[str, Any]:
    _validate_queue_payload(queue)
    selected: list[dict[str, Any]] = []
    skipped_samples: list[dict[str, Any]] = []
    active_claims_with_local_evidence: list[dict[str, Any]] = []
    skipped_counts: dict[str, int] = {}
    scanned = 0
    actions = _queue_actions(queue)
    backend_root = root or Path(__file__).resolve().parents[1]

    for action in actions[: max(0, scan_limit)]:
        scanned += 1
        backend = resolved_backend_for_action(action, backend_root)
        effective_lane = resolved_lane_for_action(action, backend_root)
        lane_action = {**action, "lane": effective_lane}
        deferred_reason = lane_defer_reason(lane_action, include_documentation_only=include_documentation_only)
        if deferred_reason:
            status = DOCUMENTATION_ONLY_DEFERRED_STATUS
            skipped_counts[status] = skipped_counts.get(status, 0) + 1
            if len(skipped_samples) < 20:
                skipped_samples.append(
                    {
                        "row_id": _row_id(action),
                        "queue_rank": action.get("rank"),
                        "lane": effective_lane,
                        "backend": backend,
                        "local_coordination_status": status,
                        "reason": deferred_reason,
                        "matching_dirty_paths": [],
                        "committed_after_queue_paths": [],
                        "local_evidence_paths": [],
                    }
                )
            continue
        classification = classify_action(action, state)
        status = classification["status"]
        if classification["dispatchable"]:
            selected.append(
                _compact_action(
                    lane_action,
                    classification,
                    len(selected) + 1,
                    prompt_mode=prompt_mode,
                    backend=backend,
                )
            )
            if len(selected) >= max(0, limit):
                break
            continue
        skipped_counts[status] = skipped_counts.get(status, 0) + 1
        evidence = classification["local_evidence"]
        if (
            status == "claimed_active_registry"
            and len(active_claims_with_local_evidence) < 20
            and (evidence["complete_local_evidence"] or evidence["committed_evidence_paths"])
        ):
            active_claims_with_local_evidence.append(
                {
                    "row_id": classification["row_id"],
                    "queue_rank": action.get("rank"),
                    "complete_local_evidence": evidence["complete_local_evidence"],
                    "committed_evidence_paths": evidence["committed_evidence_paths"],
                    "local_evidence_paths": evidence["existing_paths"],
                    "reason": (
                        "active claim has row-local evidence; check worker status before keeping it reserved"
                    ),
                }
            )
        if len(skipped_samples) < 20:
            skipped_samples.append(
                {
                    "row_id": classification["row_id"],
                    "queue_rank": action.get("rank"),
                    "lane": _safe_text(action.get("lane")),
                    "backend": backend,
                    "local_coordination_status": status,
                    "reason": classification["reason"],
                    "matching_dirty_paths": classification["matching_dirty_paths"],
                    "committed_after_queue_paths": classification["local_evidence"]["committed_after_queue_paths"],
                    "local_evidence_paths": classification["local_evidence"]["existing_paths"],
                }
            )

    return {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "source_queue_schema": _safe_text(queue.get("schema")),
        "source_queue_actionable_row_count": queue.get("actionable_row_count"),
        "source_queue_top_action_count": queue.get("top_action_count"),
        "selection": {
            "limit": max(0, limit),
            "scan_limit": max(0, scan_limit),
            "include_documentation_only": include_documentation_only,
            "prompt_mode": prompt_mode,
            "candidate_rows_seen": len(actions),
            "candidate_rows_scanned": scanned,
            "selected_count": len(selected),
            "skipped_counts": dict(sorted(skipped_counts.items())),
            "active_claims_with_local_evidence_count": len(active_claims_with_local_evidence),
        },
        "git_state": {
            "branch": state.branch,
            "head": state.head,
            "queue_baseline_commit": state.queue_baseline_commit,
            "dirty_path_count": len(state.dirty_paths),
            "committed_after_queue_path_count": len(state.committed_after_queue_paths),
            "active_claimed_row_count": len(state.active_claimed_row_ids),
            "completed_claimed_row_count": len(state.completed_claimed_row_ids),
            "failed_claimed_row_count": len(state.failed_claimed_row_ids),
        },
        "rows": selected,
        "skipped_samples": skipped_samples,
        "active_claims_with_local_evidence": active_claims_with_local_evidence,
        "strict_caveat": "Rows are scanner wiring/proof work items only; they are not exploit proof, detector completeness, or submission evidence.",
    }


def _git(root: Path, *args: str) -> str:
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=root,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        return ""
    if proc.returncode != 0:
        return ""
    return proc.stdout.rstrip("\n")


def _dirty_paths(root: Path) -> frozenset[str]:
    paths: list[str] = []
    for line in _git(root, "status", "--short").splitlines():
        if len(line) < 4:
            continue
        path = line[3:].strip()
        if " -> " in path:
            path = path.rsplit(" -> ", 1)[-1].strip()
        if path:
            paths.append(path)
    return frozenset(paths)


def _tracked_and_untracked_paths(root: Path) -> frozenset[str]:
    raw = _git(root, "ls-files", "-co", "--exclude-standard")
    paths: set[str] = set()
    for line in raw.splitlines():
        path = line.strip()
        if not path:
            continue
        paths.add(path)
        parent = Path(path).parent
        while str(parent) not in {"", "."}:
            paths.add(str(parent))
            parent = parent.parent
    return frozenset(paths)


def _claim_rows(path: Path) -> list[Any]:
    if not path.is_file():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    rows: list[Any] = []
    if isinstance(payload, list):
        rows = payload
    elif isinstance(payload, dict):
        for key in ("active_claims", "claims", "rows", "items", "assignments"):
            value = payload.get(key)
            if isinstance(value, list):
                rows.extend(value)
        if not rows:
            rows.append(payload)
    return rows


def _active_claimed_row_ids(path: Path) -> frozenset[str]:
    rows = _claim_rows(path)
    return frozenset(row_id for row_id in (_claim_row_id(row) for row in rows) if row_id)


def _completed_claimed_row_ids(path: Path) -> frozenset[str]:
    rows = _claim_rows(path)
    return frozenset(row_id for row_id in (_completed_claim_row_id(row) for row in rows) if row_id)


def _failed_claimed_row_ids(path: Path) -> frozenset[str]:
    rows = _claim_rows(path)
    return frozenset(row_id for row_id in (_failed_claim_row_id(row) for row in rows) if row_id)


def _rel_or_abs(root: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)


def _committed_after_queue_paths(root: Path, queue_path: Path) -> tuple[frozenset[str], str]:
    rel_queue = _rel_or_abs(root, queue_path)
    baseline = _git(root, "log", "-1", "--format=%H", "--", rel_queue)
    if not baseline:
        return frozenset(), ""
    head = _git(root, "rev-parse", "HEAD")
    if not head or head == baseline:
        return frozenset(), baseline[:12]
    raw = _git(root, "diff", "--name-only", f"{baseline}..HEAD", "--")
    paths = frozenset(line.strip() for line in raw.splitlines() if line.strip())
    return paths, baseline[:12]


def local_state_from_git(
    root: Path,
    queue_path: Path,
    active_claims_path: Path | None = None,
) -> LocalState:
    committed_paths, baseline = _committed_after_queue_paths(root, queue_path)
    claims_path = active_claims_path
    if claims_path is None:
        claims_path = root / DEFAULT_ACTIVE_CLAIMS
    elif not claims_path.is_absolute():
        claims_path = root / claims_path
    return LocalState(
        repo_root=str(root),
        branch=_git(root, "branch", "--show-current") or _git(root, "rev-parse", "--abbrev-ref", "HEAD") or "unknown",
        head=(_git(root, "rev-parse", "--short", "HEAD") or "unknown"),
        dirty_paths=_dirty_paths(root),
        existing_paths=_tracked_and_untracked_paths(root),
        committed_after_queue_paths=committed_paths,
        queue_baseline_commit=baseline,
        active_claimed_row_ids=_active_claimed_row_ids(claims_path),
        completed_claimed_row_ids=_completed_claimed_row_ids(claims_path),
        failed_claimed_row_ids=_failed_claimed_row_ids(claims_path),
    )


def render_markdown(report: dict[str, Any]) -> str:
    selection = _safe_dict(report.get("selection"))
    git_state = _safe_dict(report.get("git_state"))
    lines = [
        "# Scanner Worker Next Rows",
        "",
        f"- Selected rows: `{selection.get('selected_count', 0)}`",
        f"- Scanned rows: `{selection.get('candidate_rows_scanned', 0)}` of `{selection.get('candidate_rows_seen', 0)}`",
        f"- Branch/head: `{git_state.get('branch', 'unknown')}` @ `{git_state.get('head', 'unknown')}`",
        f"- Dirty paths: `{git_state.get('dirty_path_count', 0)}`",
        f"- Post-queue committed paths: `{git_state.get('committed_after_queue_path_count', 0)}`",
        f"- Active claimed rows: `{git_state.get('active_claimed_row_count', 0)}`",
        f"- Completed claimed rows: `{git_state.get('completed_claimed_row_count', 0)}`",
        f"- Failed claimed rows: `{git_state.get('failed_claimed_row_count', 0)}`",
        f"- Active claims with local evidence: `{selection.get('active_claims_with_local_evidence_count', 0)}`",
        f"- Skipped counts: `{selection.get('skipped_counts', {})}`",
        "",
        "## Rows",
        "",
    ]
    if not report.get("rows"):
        lines.append("- None")
    for row in _safe_list(report.get("rows")):
        if not isinstance(row, dict):
            continue
        lines.append(
            f"- `{row.get('slot_id')}` `{row.get('row_id')}` ({row.get('lane')}, {row.get('backend')}, queue rank `{row.get('queue_rank')}`)"
        )
        owned = ", ".join(_safe_list(row.get("owned_paths"))[:4])
        if owned:
            lines.append(f"  Owned: `{owned}`")
        commands = _safe_list(row.get("suggested_commands"))
        if commands and isinstance(commands[0], dict):
            lines.append(f"  Command: `{commands[0].get('command')}`")
    if report.get("skipped_samples"):
        lines.extend(["", "## Skipped Samples", ""])
        for sample in _safe_list(report.get("skipped_samples"))[:8]:
            if isinstance(sample, dict):
                lines.append(
                    f"- `{sample.get('row_id')}`: `{sample.get('local_coordination_status')}` ({sample.get('reason')})"
                )
    lines.append("")
    return "\n".join(lines)


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected object JSON in {path}")
    return payload


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_worker_prompts(root: Path, prompt_dir: Path, report: dict[str, Any]) -> None:
    out_dir = prompt_dir if prompt_dir.is_absolute() else root / prompt_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    report["worker_prompt_dir"] = _rel_or_abs(root, out_dir)
    for row in _safe_list(report.get("rows")):
        if not isinstance(row, dict):
            continue
        slot = _slug(row.get("slot_id")) or "scanner_next"
        row_slug = _slug(row.get("row_id")) or "row"
        path = out_dir / f"{slot}_{row_slug}.md"
        _write_text(path, _safe_text(row.get("worker_prompt")).rstrip() + "\n")
        row["worker_prompt_path"] = _rel_or_abs(root, path)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--queue", type=Path, default=None)
    parser.add_argument(
        "--active-claims",
        type=Path,
        default=None,
        help=(
            "optional JSON registry of in-flight scanner row assignments; rows listed there "
            "are skipped before dirty-path evidence exists"
        ),
    )
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    parser.add_argument("--scan-limit", type=int, default=DEFAULT_SCAN_LIMIT)
    parser.add_argument(
        "--include-documentation-only",
        action="store_true",
        help="allow documentation_only rows to be selected for an explicit docs/batch-boundary pass",
    )
    parser.add_argument(
        "--prompt-mode",
        choices=PROMPT_MODES,
        default=PROMPT_MODE_LOCAL_ONLY,
        help=(
            "worker prompt discipline. local-only avoids commit/GitHub/approval instructions; "
            "commit emits the older commit-only-owned-paths checkpoint prompt"
        ),
    )
    parser.add_argument(
        "--local-only-prompt",
        dest="prompt_mode",
        action="store_const",
        const=PROMPT_MODE_LOCAL_ONLY,
        help="explicit alias for --prompt-mode local-only",
    )
    parser.add_argument("--markdown", action="store_true", help="print concise markdown instead of JSON")
    parser.add_argument("--json-out", type=Path, help="optional path to write JSON output")
    parser.add_argument("--md-out", type=Path, help="optional path to write markdown output")
    parser.add_argument("--prompt-out-dir", type=Path, help="optional directory to write one worker prompt per row")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        root = args.repo_root.resolve()
        queue_arg = args.queue or _latest_report_path(
            root,
            "scanner_wiring_burndown_queue",
            DEFAULT_QUEUE,
            validator=_scanner_queue_report_compatible,
        )
        queue_path = queue_arg if queue_arg.is_absolute() else root / queue_arg
        queue = _load_json(queue_path)
        claims_arg = args.active_claims or _latest_report_path(
            root,
            "scanner_worker_active_claims",
            DEFAULT_ACTIVE_CLAIMS,
        )
        active_claims_path = claims_arg if claims_arg.is_absolute() else root / claims_arg
        state = local_state_from_git(root, queue_path, active_claims_path=active_claims_path)
        report = build_next_rows(
            queue,
            state=state,
            root=root,
            limit=args.limit,
            scan_limit=args.scan_limit,
            include_documentation_only=args.include_documentation_only,
            prompt_mode=args.prompt_mode,
        )
        report["source_queue_path"] = _rel_or_abs(root, queue_path)
        report["active_claims_path"] = _rel_or_abs(root, active_claims_path)
        if args.prompt_out_dir:
            _write_worker_prompts(root, args.prompt_out_dir, report)
        if args.json_out:
            json_out = args.json_out if args.json_out.is_absolute() else root / args.json_out
            _write_json(json_out, report)
        markdown = render_markdown(report)
        if args.md_out:
            md_out = args.md_out if args.md_out.is_absolute() else root / args.md_out
            _write_text(md_out, markdown)
        if args.markdown:
            print(markdown, end="")
        else:
            print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"scanner-worker-next-rows: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
