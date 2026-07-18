#!/usr/bin/env python3
"""Build and optionally execute a bounded mechanical scanner autonomy plan.

This PR560 bridge consumes the current scanner-facing inventories:

* semantic scanner inventory rows
* Rust runtime-semantic blocker rows
* agent recall detector tasks
* fixture materialization manifests

It ranks the shortest local/mechanical work that can move manual triage into
detector/scanner lanes. It is intentionally conservative: dry-run planning is
the default, execution is opt-in, only allowlisted repo-local commands run, and
all outputs stay advisory/NOT_SUBMIT_READY.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import shlex
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "auditooor.scanner_autonomy_executor.v1"
EXECUTION_SCHEMA = "auditooor.scanner_autonomy_execution.v1"
SCAFFOLDED_EVIDENCE_CLASS = "scaffolded_unverified"
ADVISORY_LIMITATIONS = [
    "scanner autonomy rows are mechanical planning/execution records only",
    "executed commands may create fixture/smoke artifacts but do not prove exploit impact",
    "detector coverage still requires vulnerable fixture, clean fixture, and smoke output",
    "Rust runtime rows remain source-shape only until runtime dispatch/cfg/trait semantics are resolved",
    "all rows remain NOT_SUBMIT_READY with severity none until exact impact proof and gates pass",
]
ALLOWLISTED_TOOL_PATHS = {
    "tools/semantic-scanner-inventory.py",
    "tools/semantic-fixture-smoke-tasks.py",
    "tools/semantic-fixture-smoke-gate.py",
    "tools/agent-recall-detector-queue.py",
    "tools/rust-runtime-semantic-blockers.py",
    "tools/p1-fixture-extractor.py",
}


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _records(payload: dict[str, Any], key: str) -> list[dict[str, Any]]:
    value = payload.get(key)
    return [row for row in value if isinstance(row, dict)] if isinstance(value, list) else []


def _safe_rel(path: Path, root: Path) -> str:
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except (OSError, ValueError):
        return str(path)


def _resolve(workspace: Path, raw: Any) -> str:
    value = str(raw or "").strip()
    if not value:
        return ""
    path = Path(value).expanduser()
    return str(path if path.is_absolute() else (workspace / path).resolve())


def _fixture_manifests(workspace: Path) -> list[tuple[Path, dict[str, Any]]]:
    roots = [workspace / "detectors" / "fixtures", workspace / "detectors" / "test_fixtures"]
    rows: list[tuple[Path, dict[str, Any]]] = []
    for root in roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*_manifest.json")):
            payload = _read_json(path)
            if payload:
                rows.append((path, payload))
    return rows


def _manifest_status(workspace: Path, manifest: dict[str, Any]) -> tuple[str, list[str]]:
    blockers: list[str] = []
    positive = Path(_resolve(workspace, manifest.get("positive_fixture_path")))
    clean = Path(_resolve(workspace, manifest.get("clean_fixture_path")))
    smoke = Path(_resolve(workspace, manifest.get("smoke_record_path")))
    has_command = bool(manifest.get("argv") or manifest.get("shell_command"))
    if positive and not positive.is_file():
        blockers.append("positive_fixture_missing")
    if clean and not clean.is_file():
        blockers.append("clean_fixture_missing")
    if smoke and not smoke.is_file():
        blockers.append("smoke_record_missing")
    if (
        blockers == ["smoke_record_missing"]
        and str(manifest.get("materialization_status") or "") == "fixture_pair_materialized_canonical_smoke_blocked"
    ):
        return "fixture_pair_materialized_canonical_smoke_blocked", blockers
    if not has_command and blockers:
        blockers.append("no_materialization_command")
    if not blockers:
        return "fixture_artifacts_present", []
    if has_command:
        return "fixture_manifest_runnable", blockers
    return "fixture_manifest_blocked", blockers


def _safe_command(argv: Sequence[str], repo_root: Path) -> tuple[bool, list[str]]:
    if not argv:
        return False, ["empty_command"]
    normalized = list(argv)
    launcher = Path(normalized[0]).name
    if launcher.startswith("python") and len(normalized) > 1:
        tool = normalized[1]
    else:
        tool = normalized[0]
    tool_path = Path(tool)
    if tool_path.is_absolute():
        try:
            tool_rel = str(tool_path.resolve().relative_to(repo_root))
        except ValueError:
            return False, ["tool_outside_repo"]
    else:
        tool_rel = str(tool_path)
    if tool_rel not in ALLOWLISTED_TOOL_PATHS:
        return False, [f"tool_not_allowlisted:{tool_rel}"]
    for part in normalized:
        if any(token in str(part) for token in (";", "&&", "||", "`", "$(")):
            return False, ["shell_metacharacter_blocked"]
    if "tools/p1-fixture-extractor.py" in tool_rel:
        joined = " ".join(normalized)
        if "--mock-dispatcher" not in joined and "--fixture-dir" in joined:
            # The extractor may call model-backed runners. Require explicit
            # operator environment consent before the executor runs it.
            import os

            if not (
                os.environ.get("AUDITOOOR_LLM_NETWORK_CONSENT") == "1"
                or os.environ.get("ADVERSARIAL_LIVE_CONSENT") == "1"
                or os.environ.get("AUDITOOOR_P1_FIXTURE_MOCK_DISPATCHER")
            ):
                return False, ["missing_fixture_extraction_consent"]
    return True, []


def _task(
    idx: int,
    *,
    source: str,
    source_id: str,
    lane: str,
    priority: int,
    reason: str,
    command: Sequence[str] | None = None,
    artifact: str = "",
    blockers: Sequence[str] = (),
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    row = {
        "task_id": f"SAE-{idx:03d}",
        "source": source,
        "source_id": source_id,
        "action_lane": lane,
        "priority": priority,
        "reason": reason,
        "source_artifact": artifact,
        "argv": [str(part) for part in command or []],
        "runnable": bool(command),
        "blockers": sorted({str(item) for item in blockers if str(item)}),
        "coverage_claim": "none_scanner_autonomy_only",
        "evidence_class": SCAFFOLDED_EVIDENCE_CLASS,
        "advisory_only": True,
        "promotion_allowed": False,
        "severity": "none",
        "selected_impact": "",
        "submission_posture": "NOT_SUBMIT_READY",
        "impact_contract_required": True,
    }
    if extra:
        row.update(extra)
    safe, safety_blockers = _safe_command(row["argv"], ROOT) if row["argv"] else (False, ["no_command"])
    row["execution_allowed"] = bool(row["argv"]) and safe
    row["execution_blockers"] = safety_blockers
    return row


def _semantic_tasks(workspace: Path, start: int) -> list[dict[str, Any]]:
    payload = _read_json(workspace / ".auditooor" / "semantic_scanner_inventory.json")
    rows: list[dict[str, Any]] = []
    for row in _records(payload, "detector_fixture_task_queue"):
        task_type = str(row.get("task_type") or "")
        if task_type in {"detector_rewrite_with_fixture_pair", "fixture_pair_before_detector_rewrite"}:
            command = [
                sys.executable,
                "tools/semantic-fixture-smoke-tasks.py",
                "--workspace",
                str(workspace),
                "--materialize-manifests",
            ]
            lane = "materialize_semantic_fixture_manifest"
            priority = 40
        elif task_type == "coverage_to_detector_worklist":
            command = [sys.executable, "tools/semantic-scanner-inventory.py", "--workspace", str(workspace)]
            lane = "refresh_semantic_inventory_after_worklist"
            priority = 15
        else:
            command = []
            lane = "manual_source_review_or_kill"
            priority = 5
        rows.append(_task(
            start + len(rows),
            source="semantic_scanner_inventory",
            source_id=str(row.get("queue_id") or row.get("inventory_id") or ""),
            lane=lane,
            priority=priority,
            reason=f"semantic task `{task_type}` can be advanced mechanically",
            command=command,
            artifact=str(workspace / ".auditooor" / "semantic_scanner_inventory.json"),
            blockers=row.get("promotion_blockers", []),
            extra={
                "suggested_detector_slug": row.get("suggested_detector_slug", ""),
                "fixture_task": row.get("fixture_task", {}),
            },
        ))
    return rows


def _rust_tasks(workspace: Path, start: int) -> list[dict[str, Any]]:
    payload = _read_json(workspace / ".auditooor" / "rust_runtime_semantic_blockers.json")
    rows: list[dict[str, Any]] = []
    for row in _records(payload, "items"):
        lane = str(row.get("action_lane") or "")
        if lane == "safe_detectorization_handoff":
            priority = 30
            reason = "Rust source shape is narrow enough for fixture-first detectorization"
        else:
            priority = 10
            reason = "Rust runtime semantic blocker needs source/runtime adjudication"
        rows.append(_task(
            start + len(rows),
            source="rust_runtime_semantic_blockers",
            source_id=str(row.get("queue_id") or row.get("source_id") or row.get("item_id") or ""),
            lane=lane or "rust_runtime_blocker",
            priority=priority,
            reason=reason,
            command=[],
            artifact=str(workspace / ".auditooor" / "rust_runtime_semantic_blockers.json"),
            blockers=row.get("blocker_ids", []),
            extra={
                "detectorization_handoff": row.get("detectorization_handoff", {}),
                "next_command": row.get("next_command", ""),
                "runtime_component_family": row.get("runtime_component_family", ""),
            },
        ))
    return rows


def _agent_tasks(workspace: Path, start: int) -> list[dict[str, Any]]:
    payload = _read_json(workspace / ".auditooor" / "agent_recall_detector_tasks.json")
    rows: list[dict[str, Any]] = []
    for row in _records(payload, "tasks"):
        task_type = str(row.get("task_type") or "")
        if task_type == "detector_task":
            priority = 35
            lane = "agent_recall_detector_fixture"
            command = [sys.executable, "tools/agent-recall-detector-queue.py", "--workspace", str(workspace)]
        elif task_type == "source_proof_task":
            priority = 20
            lane = "agent_recall_source_proof"
            command = []
        else:
            priority = 3
            lane = "agent_recall_terminal_blocker"
            command = []
        rows.append(_task(
            start + len(rows),
            source="agent_recall_detector_tasks",
            source_id=str(row.get("task_id") or ""),
            lane=lane,
            priority=priority,
            reason=str(row.get("reason") or f"agent recall {task_type} row"),
            command=command,
            artifact=str(workspace / ".auditooor" / "agent_recall_detector_tasks.json"),
            blockers=row.get("terminal_blockers", []),
            extra={
                "terminal_state": row.get("terminal_state", ""),
                "provider_classifications": row.get("provider_classifications", []),
                "next_command": row.get("next_command", ""),
            },
        ))
    return rows


def _fixture_tasks(workspace: Path, start: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path, manifest in _fixture_manifests(workspace):
        status, blockers = _manifest_status(workspace, manifest)
        argv = manifest.get("argv") if isinstance(manifest.get("argv"), list) else []
        if not argv and manifest.get("shell_command"):
            argv = shlex.split(str(manifest.get("shell_command") or ""))
        priority = 50 if status == "fixture_manifest_runnable" else 25 if status == "fixture_artifacts_present" else 1
        rows.append(_task(
            start + len(rows),
            source="fixture_manifest",
            source_id=str(manifest.get("fixture_id") or path.stem),
            lane=status,
            priority=priority,
            reason="fixture manifest is the shortest path to local detector smoke evidence",
            command=argv if status == "fixture_manifest_runnable" else [],
            artifact=_safe_rel(path, ROOT),
            blockers=blockers,
            extra={
                "detector_slug": manifest.get("detector_slug", ""),
                "positive_fixture_path": manifest.get("positive_fixture_path", ""),
                "clean_fixture_path": manifest.get("clean_fixture_path", ""),
                "smoke_record_path": manifest.get("smoke_record_path", ""),
            },
        ))
    return rows


def _semantic_detector_smoke_tasks(workspace: Path, start: int) -> list[dict[str, Any]]:
    payload = _read_json(workspace / ".auditooor" / "semantic_detector_smoke_executor.json")
    rows: list[dict[str, Any]] = []
    for row in _records(payload, "rows"):
        status = str(row.get("status") or "")
        argument = str(row.get("argument") or row.get("queue_id") or "")
        passed = status == "passed_vulnerable_clean_smoke"
        blockers = [] if passed else [str(row.get("reason") or "semantic_detector_smoke_not_executed")]
        task = _task(
            start + len(rows),
            source="semantic_detector_smoke_executor",
            source_id=argument,
            lane="covered_by_prior_detector_smoke" if passed else "terminal_detector_smoke_blocker",
            priority=70 if passed else 55,
            reason=(
                "EF/DX detector has prior vulnerable/clean smoke evidence"
                if passed else
                "detector smoke cannot be executed because extraction did not produce a fixture/detector pair"
            ),
            command=[],
            artifact=str(workspace / ".auditooor" / "semantic_detector_smoke_executor.json"),
            blockers=blockers,
            extra={
                "detector_paths": row.get("detector_paths", []),
                "positive_fixture": row.get("positive_fixture", ""),
                "clean_fixture": row.get("clean_fixture", ""),
                "prior_smoke_status": status,
                "prior_smoke_covered": passed,
                "coverage_claim": "detector_fixture_smoke_only",
                "evidence_class": "executed_with_manifest" if passed else SCAFFOLDED_EVIDENCE_CLASS,
            },
        )
        if passed:
            task["runnable"] = True
            task["execution_allowed"] = True
            task["execution_blockers"] = []
        rows.append(task)
    return rows


def _provider_output_summary(tasks: list[dict[str, Any]]) -> dict[str, Any]:
    provider_rows = [
        row for row in tasks
        if row.get("source") == "agent_recall_detector_tasks"
        and row.get("provider_classifications")
    ]
    classification_counts: Counter[str] = Counter()
    for row in provider_rows:
        for item in row.get("provider_classifications") or []:
            classification_counts[str(item)] += 1
    return {
        "provider_derived_task_count": len(provider_rows),
        "provider_classification_counts": dict(sorted(classification_counts.items())),
        "external_provider_invoked_by_executor": False,
        "provider_invocation_note": "executor consumes local provider-derived artifacts only; it does not call Kimi/Minimax itself",
    }


def _remaining_execution_records(workspace: Path) -> dict[str, dict[str, Any]]:
    """Load bounded EP fixture-manifest executions, keyed by stable task id/source id."""
    payload = _read_json(workspace / ".auditooor" / "scanner_autonomy_remaining_execution_ep.json")
    records: dict[str, dict[str, Any]] = {}
    for row in _records(payload, "rows"):
        for key in (str(row.get("task_id") or ""), str(row.get("source_id") or "")):
            if key:
                records[key] = row
    return records


def _extract_hint_command(text: str) -> str:
    match = re.search(r"save full output:\s*([^\n\r]+)", text)
    return match.group(1).strip() if match else ""


def _classify_fixture_failure(task: dict[str, Any], remaining: dict[str, Any]) -> dict[str, Any]:
    """Turn the old generic EP failure bucket into exact terminal blockers."""
    ep_status = str(remaining.get("status") or "terminal_ep_unknown")
    text = "\n".join(
        str(remaining.get(key) or "")
        for key in ("stdout_tail", "stderr_tail")
    )
    lower = text.lower()
    if ep_status == "terminal_cannot_run":
        return {
            "status": "terminal_fixture_command_cannot_run",
            "blocker": "terminal_cannot_run",
            "terminal_evidence_status": "terminal_blocker",
            "next_command": " ".join(shlex.quote(str(part)) for part in task.get("argv") or []),
        }
    if any(token in lower for token in (
        "solc failed",
        "identifier already declared",
        "function cannot be declared as view",
        "this expression is not callable",
        "not callable",
    )):
        return {
            "status": "terminal_generated_fixture_compile_failure",
            "blocker": "generated_fixture_compile_failure",
            "terminal_evidence_status": "terminal_blocker",
            "next_command": " ".join(shlex.quote(str(part)) for part in task.get("argv") or []),
        }
    if "vuln: expected >=1 hit" in lower or "vulnerable: expected >=1 hit" in lower:
        return {
            "status": "terminal_vulnerable_fixture_no_detector_hit",
            "blocker": "vulnerable_fixture_no_detector_hit",
            "terminal_evidence_status": "terminal_blocker",
            "next_command": _extract_hint_command(text) or " ".join(shlex.quote(str(part)) for part in task.get("argv") or []),
        }
    if "clean: expected 0 hits" in lower:
        return {
            "status": "terminal_clean_fixture_false_positive",
            "blocker": "clean_fixture_false_positive",
            "terminal_evidence_status": "terminal_blocker",
            "next_command": _extract_hint_command(text) or " ".join(shlex.quote(str(part)) for part in task.get("argv") or []),
        }
    if any(token in lower for token in ("cannot-run:", "source-unlocatable", "missing-detector-argument", "no-consent")):
        return {
            "status": "terminal_fixture_extraction_prerequisite_missing",
            "blocker": "fixture_extraction_prerequisite_missing",
            "terminal_evidence_status": "terminal_blocker",
            "next_command": " ".join(shlex.quote(str(part)) for part in task.get("argv") or []),
        }
    return {
        "status": "terminal_fixture_extraction_unclassified_failure",
        "blocker": ep_status,
        "terminal_evidence_status": "terminal_blocker",
        "next_command": " ".join(shlex.quote(str(part)) for part in task.get("argv") or []),
    }


def _fixture_smoke_passed(workspace: Path, task: dict[str, Any]) -> bool:
    smoke_path = Path(_resolve(workspace, task.get("smoke_record_path")))
    if not smoke_path.is_file():
        return False
    payload = _read_json(smoke_path)
    status = str(payload.get("status") or "")
    positive_hits = payload.get("positive_hits")
    clean_hits = payload.get("clean_hits")
    try:
        positive_count = int(positive_hits)
        clean_count = int(clean_hits)
    except (TypeError, ValueError):
        return status == "passed_vulnerable_clean_smoke"
    return status == "passed_vulnerable_clean_smoke" and positive_count >= 1 and clean_count == 0


def _classify_no_command(task: dict[str, Any]) -> dict[str, Any]:
    """Replace opaque no-command rows with exact terminal local blockers."""
    source = str(task.get("source") or "")
    lane = str(task.get("action_lane") or "")
    reason = str(task.get("reason") or "")
    terminal_state = str(task.get("terminal_state") or "")
    next_command = str(task.get("next_command") or "")
    if source == "rust_runtime_semantic_blockers":
        return {
            "status": "terminal_no_local_command_runtime_semantic_blocker",
            "blockers": ["runtime_semantics_require_source_or_harness_adjudication"],
            "next_command": next_command or "make rust-runtime-semantic-blockers WS=<workspace> GENERATE=1",
        }
    if source == "fixture_manifest" and lane == "fixture_pair_materialized_canonical_smoke_blocked":
        return {
            "status": "terminal_fixture_pair_materialized_canonical_smoke_blocked",
            "blockers": ["canonical_detector_fixture_path_guard_blocks_smoke"],
            "next_command": (
                "replay the materialized fixture pair from a non-skipped temp/staging path "
                "or add explicit fixture-path smoke override support before promotion"
            ),
        }
    if source == "agent_recall_detector_tasks":
        hay = " ".join([lane, reason, terminal_state, next_command]).lower()
        if "non_detectorizable" in hay or "internal tool code" in hay:
            status = "terminal_no_local_command_non_detectorizable"
            blocker = "agent_recall_row_not_smart_contract_detector_work"
        elif "duplicate" in hay or "oos" in hay or "kill" in hay or "not-a-bug" in hay:
            status = "terminal_no_local_command_killed_duplicate_or_oos"
            blocker = "agent_recall_row_terminal_kill_or_oos"
        elif "source-proof" in hay or "source proof" in hay:
            status = "terminal_no_local_command_source_proof_required"
            blocker = "source_line_or_invariant_proof_required_before_detector_work"
        elif "harness" in hay or "poc" in hay or "replay" in hay:
            status = "terminal_no_local_command_harness_required"
            blocker = "harness_or_replay_execution_required_before_detector_work"
        elif "smoke proof" in hay or "detectorized" in hay or "semantic inventory row has vulnerable/clean" in hay:
            status = "terminal_no_local_command_already_detectorized"
            blocker = "already_has_detector_smoke_or_requires_full_corpus_accounting"
        else:
            status = "terminal_no_local_command_agent_recall_exact_next_command"
            blocker = "agent_recall_terminal_next_command_required"
        return {
            "status": status,
            "blockers": [blocker],
            "next_command": next_command or "record terminal recall disposition or add fixture-backed detector proof",
        }
    return {
        "status": "terminal_no_local_command_exact_next_command" if next_command else "terminal_no_local_command_missing_next_command",
        "blockers": ["no_local_executable_command"],
        "next_command": next_command,
    }


def _stop_condition_summary(tasks: list[dict[str, Any]]) -> dict[str, Any]:
    blocker_counts: Counter[str] = Counter()
    execution_blocker_counts: Counter[str] = Counter()
    for row in tasks:
        for blocker in row.get("blockers") or []:
            blocker_counts[str(blocker)] += 1
        for blocker in row.get("execution_blockers") or []:
            execution_blocker_counts[str(blocker)] += 1
    return {
        "manual_triage_items_mechanically_accounted": len(tasks),
        "runnable_local_command_items": sum(1 for row in tasks if row.get("runnable")),
        "allowlisted_execution_items": sum(1 for row in tasks if row.get("execution_allowed")),
        "fixture_manifest_items": sum(1 for row in tasks if row.get("source") == "fixture_manifest"),
        "semantic_detector_smoke_items": sum(1 for row in tasks if row.get("source") == "semantic_detector_smoke_executor"),
        "semantic_detector_smoke_covered_items": sum(
            1 for row in tasks
            if row.get("source") == "semantic_detector_smoke_executor" and row.get("prior_smoke_covered")
        ),
        "semantic_inventory_items": sum(1 for row in tasks if row.get("source") == "semantic_scanner_inventory"),
        "agent_recall_items": sum(1 for row in tasks if row.get("source") == "agent_recall_detector_tasks"),
        "rust_runtime_items": sum(1 for row in tasks if row.get("source") == "rust_runtime_semantic_blockers"),
        "top_promotion_blockers": dict(sorted(blocker_counts.most_common(12))),
        "execution_blocker_counts": dict(sorted(execution_blocker_counts.items())),
        "closed_or_reduced_stop_conditions": [
            "scanner owners get one ranked queue instead of hand-merging semantic, Rust, recall, and fixture artifacts",
            "fixture manifests are separated into runnable/local-blocked rows with explicit consent/dependency blockers",
            "source-shape detectorization rows stay advisory and cannot be mistaken for proof",
            "top-N starvation is reduced by reserving representation for every populated source lane",
            "prior vulnerable/clean detector smoke rows are consumed as execution accounting without rerunning or claiming exploit proof",
        ],
    }


def build_plan(workspace: Path, *, limit: int) -> dict[str, Any]:
    groups = [
        _semantic_detector_smoke_tasks(workspace, 1),
        _fixture_tasks(workspace, 1),
        _semantic_tasks(workspace, 1),
        _agent_tasks(workspace, 1),
        _rust_tasks(workspace, 1),
    ]
    candidates = [row for group in groups for row in group]
    for group in groups:
        group.sort(key=lambda row: (-int(row["priority"]), row["source"], row["source_id"]))
    tasks: list[dict[str, Any]] = []
    selected_keys: set[tuple[str, str, str]] = set()

    # Keep the top-50 useful but not mono-lane: every populated source gets a
    # small slice before the rest is filled by global priority.
    per_source_floor = min(5, max(1, limit // max(1, len([group for group in groups if group]))))
    for group in groups:
        for row in group[:per_source_floor]:
            if len(tasks) >= limit:
                break
            key = (str(row.get("source")), str(row.get("source_id")), str(row.get("action_lane")))
            if key in selected_keys:
                continue
            selected_keys.add(key)
            tasks.append(dict(row))
    remaining = [
        row for row in candidates
        if (str(row.get("source")), str(row.get("source_id")), str(row.get("action_lane"))) not in selected_keys
    ]
    remaining.sort(key=lambda row: (-int(row["priority"]), row["source"], row["source_id"]))
    for row in remaining:
        if len(tasks) >= limit:
            break
        tasks.append(dict(row))
    lane_counts = Counter(str(row.get("action_lane") or "unknown") for row in tasks)
    source_counts = Counter(str(row.get("source") or "unknown") for row in tasks)
    for idx, row in enumerate(tasks, start=1):
        row["task_id"] = f"SAE-{idx:03d}"
    return {
        "schema": SCHEMA,
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "workspace": str(workspace),
        "limit": limit,
        "candidate_count": len(candidates),
        "task_count": len(tasks),
        "truncated": len(candidates) > limit,
        "runnable_count": sum(1 for row in tasks if row["runnable"]),
        "execution_allowed_count": sum(1 for row in tasks if row["execution_allowed"]),
        "lane_counts": dict(sorted(lane_counts.items())),
        "source_counts": dict(sorted(source_counts.items())),
        "provider_output_summary": _provider_output_summary(tasks),
        "stop_condition_summary": _stop_condition_summary(tasks),
        "coverage_claim": "none_scanner_autonomy_only",
        "evidence_class": SCAFFOLDED_EVIDENCE_CLASS,
        "advisory_only": True,
        "promotion_allowed": False,
        "severity": "none",
        "selected_impact": "",
        "submission_posture": "NOT_SUBMIT_READY",
        "impact_contract_required": True,
        "limitations": list(ADVISORY_LIMITATIONS),
        "source_artifacts": {
            "semantic_scanner_inventory": str(workspace / ".auditooor" / "semantic_scanner_inventory.json"),
            "rust_runtime_semantic_blockers": str(workspace / ".auditooor" / "rust_runtime_semantic_blockers.json"),
            "agent_recall_detector_tasks": str(workspace / ".auditooor" / "agent_recall_detector_tasks.json"),
            "semantic_detector_smoke_executor": str(workspace / ".auditooor" / "semantic_detector_smoke_executor.json"),
            "fixture_manifest_globs": [
                "detectors/fixtures/**/*_manifest.json",
                "detectors/test_fixtures/**/*_manifest.json",
            ],
        },
        "workspace_neutral": True,
        "workspace_assumptions": [
            "scanner inputs are discovered from workspace-local .auditooor and detectors fixture artifacts",
            "repo-local allowlisted tools may be executed from the coordinator checkout",
            "no project, contest, or Base-specific names are required by the planner",
        ],
        "tasks": tasks,
    }


def execute_plan(plan: dict[str, Any], *, workspace: Path, max_execute: int, timeout: int) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    executed_argv: dict[tuple[str, ...], dict[str, Any]] = {}
    remaining_records = _remaining_execution_records(workspace)
    for task in plan.get("tasks", []):
        if len(rows) >= max_execute:
            break
        if not isinstance(task, dict):
            continue
        argv = [str(part) for part in task.get("argv", [])]
        argv_key = tuple(argv)
        base_row = {
            "task_id": task.get("task_id", ""),
            "source": task.get("source", ""),
            "source_id": task.get("source_id", ""),
            "action_lane": task.get("action_lane", ""),
            "reason": task.get("reason", ""),
            "source_artifact": task.get("source_artifact", ""),
            "promotion_blockers": task.get("blockers", []),
            "next_command": task.get("next_command", ""),
            "argv": argv,
            "evidence_class": SCAFFOLDED_EVIDENCE_CLASS,
            "promotion_allowed": False,
            "submission_posture": "NOT_SUBMIT_READY",
        }
        if task.get("source") == "semantic_detector_smoke_executor":
            if task.get("prior_smoke_covered"):
                rows.append({
                    **base_row,
                    "returncode": 0,
                    "status": "covered_by_prior_detector_smoke",
                    "stdout_tail": "",
                    "stderr_tail": "",
                    "execution_blockers": [],
                    "detector_paths": task.get("detector_paths", []),
                    "positive_fixture": task.get("positive_fixture", ""),
                    "clean_fixture": task.get("clean_fixture", ""),
                    "coverage_claim": "detector_fixture_smoke_only",
                    "evidence_class": "executed_with_manifest",
                })
            else:
                rows.append({
                    **base_row,
                    "returncode": None,
                    "status": "terminal_detector_smoke_blocker",
                    "stdout_tail": "",
                    "stderr_tail": "",
                    "execution_blockers": task.get("blockers", []),
                    "coverage_claim": "none_scanner_autonomy_only",
                })
            continue
        # SAE-* task ids are regenerated whenever the selected plan order
        # changes. Fixture ids are stable across reruns, so prefer source_id to
        # avoid attributing an old EP outcome to the wrong manifest row.
        if task.get("source") == "fixture_manifest" and _fixture_smoke_passed(workspace, task):
            row = {
                **base_row,
                "returncode": 0,
                "status": "executed_ok_smoke_passed",
                "stdout_tail": "",
                "stderr_tail": "",
                "execution_blockers": [],
                "covered_by_manifest_smoke_record": task.get("smoke_record_path", ""),
                "coverage_claim": "fixture_extraction_smoke_only",
                "evidence_class": "executed_with_manifest",
                "terminal_evidence_status": "",
            }
            executed_argv[argv_key] = row
            rows.append(row)
            continue
        if task.get("source") == "fixture_manifest" and task.get("action_lane") == "fixture_pair_materialized_canonical_smoke_blocked":
            classified = _classify_no_command(task)
            rows.append({
                **base_row,
                "returncode": None,
                "status": classified["status"],
                "stdout_tail": "",
                "stderr_tail": "",
                "execution_blockers": classified["blockers"],
                "next_command": classified["next_command"],
                "coverage_claim": "fixture_pair_compiles_but_canonical_smoke_blocked",
                "evidence_class": SCAFFOLDED_EVIDENCE_CLASS,
                "terminal_evidence_status": "terminal_blocker",
            })
            continue
        remaining = (
            remaining_records.get(str(task.get("source_id") or ""))
            or remaining_records.get(str(task.get("task_id") or ""))
        )
        if task.get("source") == "fixture_manifest" and remaining:
            ep_status = str(remaining.get("status") or "terminal_ep_unknown")
            if ep_status == "executed_ok_smoke_passed":
                status = "executed_ok_smoke_passed"
                execution_blockers: list[str] = []
                next_command = task.get("next_command", "")
                evidence_class = "executed_with_manifest"
                coverage_claim = "fixture_extraction_smoke_only"
                terminal_evidence_status = ""
            else:
                classified = _classify_fixture_failure(task, remaining)
                status = str(classified["status"])
                execution_blockers = [str(classified["blocker"])]
                next_command = str(classified.get("next_command") or "")
                evidence_class = SCAFFOLDED_EVIDENCE_CLASS
                coverage_claim = "none_scanner_autonomy_only"
                terminal_evidence_status = str(classified["terminal_evidence_status"])
            row = {
                **base_row,
                "returncode": remaining.get("returncode"),
                "status": status,
                "stdout_tail": remaining.get("stdout_tail", ""),
                "stderr_tail": remaining.get("stderr_tail", ""),
                "execution_blockers": execution_blockers,
                "covered_by_ep_artifact": str(workspace / ".auditooor" / "scanner_autonomy_remaining_execution_ep.json"),
                "ep_elapsed_sec": remaining.get("elapsed_sec"),
                "next_command": next_command,
                "coverage_claim": coverage_claim,
                "evidence_class": evidence_class,
                "terminal_evidence_status": terminal_evidence_status,
            }
            executed_argv[argv_key] = row
            rows.append(row)
            continue
        if not task.get("execution_allowed"):
            if not argv:
                classified = _classify_no_command(task)
                rows.append({
                    **base_row,
                    "returncode": None,
                    "status": classified["status"],
                    "stdout_tail": "",
                    "stderr_tail": "",
                    "execution_blockers": classified["blockers"],
                    "next_command": classified["next_command"],
                    "coverage_claim": "none_scanner_autonomy_only",
                    "terminal_evidence_status": "terminal_blocker",
                })
                continue
            rows.append({
                **base_row,
                "returncode": None,
                "status": "blocked_not_allowlisted",
                "stdout_tail": "",
                "stderr_tail": "",
                "execution_blockers": task.get("execution_blockers", []),
            })
            continue
        if argv_key in executed_argv:
            prior = executed_argv[argv_key]
            rows.append({
                **base_row,
                "returncode": prior.get("returncode"),
                "status": "covered_by_prior_execution",
                "covered_by_task_id": prior.get("task_id", ""),
                "covered_by_status": prior.get("status", ""),
                "stdout_tail": "",
                "stderr_tail": "",
            })
            continue
        proc = subprocess.run(
            argv,
            cwd=str(ROOT),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=timeout,
        )
        row = {
            **base_row,
            "returncode": proc.returncode,
            "status": "executed_ok" if proc.returncode == 0 else "executed_failed",
            "stdout_tail": proc.stdout[-2000:],
            "stderr_tail": proc.stderr[-2000:],
        }
        executed_argv[argv_key] = row
        rows.append(row)
    status_counts = Counter(str(row["status"]) for row in rows)
    exact_terminal_fixture_count = sum(
        count for status, count in status_counts.items()
        if status.startswith("terminal_fixture_")
        or status in {
            "terminal_generated_fixture_compile_failure",
            "terminal_vulnerable_fixture_no_detector_hit",
            "terminal_clean_fixture_false_positive",
            "terminal_fixture_pair_materialized_canonical_smoke_blocked",
        }
    )
    exact_terminal_no_command_count = sum(
        count for status, count in status_counts.items()
        if status.startswith("terminal_no_local_command_")
    )
    allowlisted_outcome_count = (
        status_counts.get("executed_ok", 0)
        + status_counts.get("executed_failed", 0)
        + status_counts.get("executed_ok_smoke_passed", 0)
        + status_counts.get("executed_smoke_or_extraction_failed", 0)
        + status_counts.get("terminal_cannot_run", 0)
        + exact_terminal_fixture_count
        + exact_terminal_no_command_count
        + status_counts.get("covered_by_prior_execution", 0)
        + status_counts.get("covered_by_prior_detector_smoke", 0)
    )
    terminal_outcome_count = (
        status_counts.get("terminal_detector_smoke_blocker", 0)
        + status_counts.get("terminal_cannot_run", 0)
        + status_counts.get("executed_smoke_or_extraction_failed", 0)
        + exact_terminal_fixture_count
        + exact_terminal_no_command_count
    )
    prior_detector_smoke_count = status_counts.get("covered_by_prior_detector_smoke", 0)
    effective_executed_count = len(executed_argv) + prior_detector_smoke_count
    return {
        "schema": EXECUTION_SCHEMA,
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "workspace": str(workspace),
        "plan_task_count": int(plan.get("task_count") or 0),
        "max_execute": max_execute,
        "outcome_count": len(rows),
        "executed_count": len(executed_argv),
        "effective_executed_count": effective_executed_count,
        "prior_detector_smoke_execution_count": prior_detector_smoke_count,
        "unique_command_execution_count": len(executed_argv),
        "terminal_outcome_count": terminal_outcome_count,
        "allowlisted_outcome_count": allowlisted_outcome_count,
        "allowlisted_outcome_pct": round(
            (allowlisted_outcome_count / max(1, int(plan.get("task_count") or 0))) * 100,
            2,
        ),
        "status_counts": dict(sorted(status_counts.items())),
        "evidence_class": SCAFFOLDED_EVIDENCE_CLASS,
        "advisory_only": True,
        "promotion_allowed": False,
        "severity": "none",
        "selected_impact": "",
        "submission_posture": "NOT_SUBMIT_READY",
        "rows": rows,
    }


def render_markdown(payload: dict[str, Any]) -> str:
    lines = [
        "# Scanner Autonomy Plan",
        "",
        "Ranked mechanical scanner/detector work pulled from semantic inventory, Rust blockers, agent recall tasks, and fixture manifests.",
        "Rows are advisory only and do not promote findings.",
        "",
        f"- task count: `{payload['task_count']}`",
        f"- candidates before limit: `{payload['candidate_count']}`",
        f"- limit: `{payload['limit']}`",
        f"- runnable: `{payload['runnable_count']}`",
        f"- execution allowed: `{payload['execution_allowed_count']}`",
        f"- submission posture: `{payload['submission_posture']}`",
        "",
        "## Lanes",
        "",
    ]
    for lane, count in payload.get("lane_counts", {}).items():
        lines.append(f"- `{lane}`: {count}")
    lines.extend([
        "",
        "## Tasks",
        "",
        "| Task | Priority | Source | Lane | Runnable | Allowed | Blockers |",
        "|---|---:|---|---|---|---|---|",
    ])
    for row in payload.get("tasks", []):
        blockers = ",".join(row.get("blockers") or row.get("execution_blockers") or [])
        lines.append("| `{}` | {} | `{}` | `{}` | `{}` | `{}` | `{}` |".format(
            row.get("task_id", ""),
            row.get("priority", 0),
            row.get("source", ""),
            row.get("action_lane", ""),
            str(row.get("runnable", False)).lower(),
            str(row.get("execution_allowed", False)).lower(),
            blockers[:120],
        ))
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=Path.cwd())
    parser.add_argument("--limit", type=int, default=200)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--max-execute", type=int, default=5)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--out-json", type=Path)
    parser.add_argument("--out-md", type=Path)
    parser.add_argument("--execution-json", type=Path)
    parser.add_argument("--print-json", action="store_true")
    args = parser.parse_args(argv)

    workspace = args.workspace.expanduser().resolve()
    if not workspace.is_dir():
        print(f"[scanner-autonomy-executor] workspace not found: {workspace}", file=sys.stderr)
        return 2
    plan = build_plan(workspace, limit=max(0, args.limit))
    out_json = args.out_json or workspace / ".auditooor" / "scanner_autonomy_plan.json"
    out_md = args.out_md or workspace / ".auditooor" / "scanner_autonomy_plan.md"
    _write_json(out_json, plan)
    _write_text(out_md, render_markdown(plan))
    if args.execute:
        execution = execute_plan(
            plan,
            workspace=workspace,
            max_execute=max(0, args.max_execute),
            timeout=max(1, args.timeout),
        )
        _write_json(args.execution_json or workspace / ".auditooor" / "scanner_autonomy_execution.json", execution)
    if args.print_json:
        print(json.dumps(plan, indent=2, sort_keys=True))
    else:
        print(f"[scanner-autonomy-executor] OK tasks={plan['task_count']} runnable={plan['runnable_count']} json={out_json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
