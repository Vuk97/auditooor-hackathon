#!/usr/bin/env python3
"""Summarize the latest ``make audit-run-full`` manifest state.

The helper is intentionally read-only. It parses
``<workspace>/.auditooor/audit_run_full_manifest.jsonl`` and reports whether
the latest run can be treated as audit certification evidence. Bounded runs
are successful terminal runs, but never certification-complete evidence.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SCHEMA = "auditooor.audit_run_full_status.v1"
DEFAULT_MANIFEST = ".auditooor/audit_run_full_manifest.jsonl"
DEFAULT_G15_LAST_RESULT = ".auditooor/g15_hunt_coverage_gate_last_result.json"
AUDIT_DEEP_MANIFEST_TOOL = Path(__file__).with_name("audit-deep-manifest.py")
AUDIT_COMPLETENESS_TOOL = Path(__file__).with_name("audit-completeness-check.py")
ENGINE_HARNESS_PROOF_TOOL = Path(__file__).with_name("engine-harness-proof-check.py")
PASS_AUDIT_COMPLETE_VERDICT = "pass-audit-complete"

COMPLETE_EVENT = "complete"
UNCERTIFIED_COMPLETE_STATUS = "uncertified-complete"
BOUNDED_COMPLETE_EVENT = "bounded-complete"
FAILURE_EVENTS = {"fail", "stage-fail"}
RUN_TERMINAL_EVENTS = {COMPLETE_EVENT, BOUNDED_COMPLETE_EVENT, *FAILURE_EVENTS}
STAGE_TERMINAL_EVENTS = {"stage-pass", "stage-fail", "stage-warn"}
MANDATORY_CERTIFICATION_STAGES = (
    "mcp-preflight",
    "intake-truth",
    "hunt-full",
    "novel-chain-hunt",
    "corpus-driven-hunt",
    "hunt-coverage",
    "post-coverage-chain-synth",
    "exploit-conversion-loop",
    "prove-top-leads",
    "cvl-spec-risk-scan",
    "audit-complete",
    "production-pipeline-check",
    "deep-freshness",
)
ADVISORY_PROOF_STAGES = frozenset({"exploit-conversion-loop", "prove-top-leads"})
G15_PASS_VERDICTS = {"pass-coverage-met", "ok-rebuttal"}
INVARIANT_DENOMINATOR_PARTIAL_BLOCKER = "invariant-denominator-partial-execution"
TYPED_DEEP_SKIP_SOURCE = "stage_skips.json"
TYPED_DEEP_SKIP_PATH = ".auditooor/stage_skips.json"
SUBMISSION_STATUS_DIRS = ("staging", "paste_ready", "ready", "held")
SUBMISSION_TRACKER_BASENAMES = {"README.md", "SUBMISSIONS.md"}
POST_CERT_FINDING_STATUS_PIPELINE_INCOMPLETE = "pipeline-incomplete"
POST_CERT_FINDING_STATUS_ZERO_CANDIDATES = "audit-certified-zero-candidates"
POST_CERT_FINDING_STATUS_BACKLOG = "audit-certified-finding-backlog"
STALE_RUNNING_AFTER_SECONDS = 60 * 60
STALE_RUNNING_STATUS = "stale-running"
DEEP_ENGINE_PROCESS_MARKERS = (
    " halmos ",
    "/halmos ",
    " echidna ",
    "/echidna ",
    " medusa ",
    "/medusa ",
    "halmos-runner.sh",
    "echidna-campaign.sh",
    "medusa-fuzz.sh",
)
DEEP_ENGINE_STALE_SUPPRESSION_STAGES = {
    "hunt-full",
    "audit-deep",
    "audit-deep-full",
    "deep-freshness",
}


def _parse_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        value = value.strip()
        if value:
            try:
                return int(value, 10)
            except ValueError:
                return None
    return None


def _parse_float(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        value = value.strip()
        if value:
            try:
                return float(value)
            except ValueError:
                return None
    return None


def _load_jsonl(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    try:
        raw_lines = path.read_text(encoding="utf-8").splitlines()
    except FileNotFoundError:
        return rows, [{"line": None, "error": "manifest-missing", "path": str(path)}]
    except OSError as exc:
        return rows, [
            {"line": None, "error": f"manifest-read-error:{exc.__class__.__name__}", "path": str(path)}
        ]

    for idx, line in enumerate(raw_lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            row = json.loads(stripped)
        except json.JSONDecodeError as exc:
            errors.append({"line": idx, "error": "json-decode-error", "message": str(exc)})
            continue
        if not isinstance(row, dict):
            errors.append({"line": idx, "error": "json-row-not-object"})
            continue
        rows.append(row)
    return rows, errors


def _load_json_object(path: Path) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, None
    except OSError as exc:
        return None, {"path": str(path), "error": f"read-error:{exc.__class__.__name__}"}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        return None, {"path": str(path), "error": "json-decode-error", "message": str(exc)}
    if not isinstance(payload, dict):
        return None, {"path": str(path), "error": "json-not-object"}
    return payload, None


def _latest_run_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not rows:
        return []
    last_start_index: int | None = None
    for idx, row in enumerate(rows):
        if row.get("event") == "start":
            last_start_index = idx
    if last_start_index is None:
        return rows
    return rows[last_start_index:]


def _latest_run_id(run_rows: list[dict[str, Any]]) -> str | None:
    for row in run_rows:
        value = row.get("run_id")
        if isinstance(value, str) and value.strip():
            return value.strip()
    for row in reversed(run_rows):
        value = row.get("run_id")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _start_row(run_rows: list[dict[str, Any]]) -> dict[str, Any]:
    for row in run_rows:
        if row.get("event") == "start":
            return row
    return {}


def _active_or_latest_stage(run_rows: list[dict[str, Any]]) -> tuple[str | None, str | None]:
    stage_status: dict[str, str] = {}
    latest_stage: str | None = None
    active_stage: str | None = None

    for row in run_rows:
        event = str(row.get("event") or "")
        if event in RUN_TERMINAL_EVENTS and event not in STAGE_TERMINAL_EVENTS:
            active_stage = None
            continue
        stage = row.get("stage")
        if not isinstance(stage, str) or not stage.strip():
            continue
        stage = stage.strip()
        latest_stage = stage
        if event == "stage-start":
            stage_status[stage] = "started"
            active_stage = stage
        elif event in STAGE_TERMINAL_EVENTS:
            stage_status[stage] = event
            if active_stage == stage:
                active_stage = None
        elif event in RUN_TERMINAL_EVENTS:
            active_stage = None

    return active_stage or latest_stage, active_stage


def _active_stage_start_row(run_rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    active_stage: str | None = None
    active_row: dict[str, Any] | None = None

    for row in run_rows:
        event = str(row.get("event") or "")
        if event in RUN_TERMINAL_EVENTS and event not in STAGE_TERMINAL_EVENTS:
            active_stage = None
            active_row = None
            continue
        stage = row.get("stage")
        if not isinstance(stage, str) or not stage.strip():
            continue
        stage = stage.strip()
        if event == "stage-start":
            active_stage = stage
            active_row = row
        elif event in STAGE_TERMINAL_EVENTS and active_stage == stage:
            active_stage = None
            active_row = None
        elif event in RUN_TERMINAL_EVENTS:
            active_stage = None
            active_row = None

    return active_row


def _terminal_row(run_rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    terminal: dict[str, Any] | None = None
    for row in run_rows:
        event = row.get("event")
        if event in RUN_TERMINAL_EVENTS:
            terminal = row
    return terminal


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _parse_timestamp_utc(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _stale_running_summary(
    active_stage_row: dict[str, Any] | None,
    *,
    workspace: Path | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "stale": False,
        "threshold_seconds": STALE_RUNNING_AFTER_SECONDS,
        "age_seconds": None,
        "timestamp_utc": None,
        "live_deep_engine_processes": [],
        "suppressed_by_live_deep_engine": False,
    }
    if not active_stage_row:
        return summary
    timestamp = _parse_timestamp_utc(active_stage_row.get("timestamp_utc"))
    if timestamp is None:
        return summary
    current = (now or _now_utc()).astimezone(timezone.utc)
    age_seconds = int((current - timestamp).total_seconds())
    summary["age_seconds"] = age_seconds
    summary["timestamp_utc"] = active_stage_row.get("timestamp_utc")
    summary["stale"] = age_seconds > STALE_RUNNING_AFTER_SECONDS
    active_stage = str(active_stage_row.get("stage") or "").strip()
    if (
        summary["stale"]
        and workspace is not None
        and active_stage in DEEP_ENGINE_STALE_SUPPRESSION_STAGES
    ):
        live_processes = _live_deep_engine_processes(workspace)
        if live_processes:
            summary["stale"] = False
            summary["suppressed_by_live_deep_engine"] = True
            summary["live_deep_engine_processes"] = live_processes[:5]
    return summary


def _live_deep_engine_processes(workspace: Path) -> list[dict[str, Any]]:
    workspace_text = str(workspace.resolve())
    try:
        proc = subprocess.run(
            ["ps", "-Aww", "-o", "pid=,ppid=,command="],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []

    current_pid = os.getpid()
    matches: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) < 3:
            continue
        pid_text, ppid_text, command = parts
        pid = _parse_int(pid_text)
        if pid is None or pid == current_pid:
            continue
        if workspace_text not in command:
            continue
        marker = next((item for item in DEEP_ENGINE_PROCESS_MARKERS if item in f" {command} "), None)
        if marker is None:
            continue
        matches.append(
            {
                "pid": pid,
                "ppid": _parse_int(ppid_text),
                "marker": marker.strip(),
                "command": command[:500],
            }
        )
    return matches


def _completion_row_run_id_matches(
    complete_row: dict[str, Any] | None,
    run_id: str | None,
) -> bool:
    if not complete_row or not run_id:
        return False
    return str(complete_row.get("run_id") or "") == str(run_id)


def _completion_proof_ok(
    complete_row: dict[str, Any] | None,
    *,
    run_id: str | None = None,
) -> bool:
    if not complete_row:
        return False
    if run_id is not None and not _completion_row_run_id_matches(complete_row, run_id):
        return False
    mode = str(complete_row.get("deep_engine_completion_mode") or "")
    verdict = str(complete_row.get("deep_engine_freshness_verdict") or "")
    if mode == "fresh-manifest" and verdict == "pass-fresh-deep-manifest":
        paths = complete_row.get("fresh_manifest_paths")
        return isinstance(paths, list) and bool(paths)
    if mode == "typed-skip" and verdict == "pass-explicit-deep-skip":
        return _typed_skip_fields_ok(complete_row)
    return False


def _typed_skip_fields_ok(row: dict[str, Any]) -> bool:
    reason = str(row.get("deep_engine_skip_reason") or "").strip()
    key = str(row.get("deep_engine_skip_key") or "").strip()
    source = str(row.get("deep_engine_skip_source") or "").strip()
    path = str(row.get("deep_engine_skip_path") or "").strip()
    return bool(
        reason
        and key == "NO_AUDIT_DEEP_REASON"
        and source == TYPED_DEEP_SKIP_SOURCE
        and path == TYPED_DEEP_SKIP_PATH
    )


def _normalize_manifest_path(path: object, workspace: Path) -> str | None:
    text = str(path or "").strip()
    if not text:
        return None
    parsed = Path(text)
    if parsed.is_absolute():
        try:
            return parsed.resolve().relative_to(workspace.resolve()).as_posix()
        except (OSError, ValueError):
            return parsed.as_posix()
    return parsed.as_posix()


def _completion_proof_matches_live(
    proof_row: dict[str, Any] | None,
    live_result: dict[str, Any] | None,
    workspace: Path,
    *,
    run_id: str | None = None,
) -> bool:
    if not proof_row or not live_result or live_result.get("ok") is not True:
        return False
    if run_id is not None and str(proof_row.get("run_id") or "") != str(run_id):
        return False
    mode = str(proof_row.get("deep_engine_completion_mode") or "")
    verdict = str(proof_row.get("deep_engine_freshness_verdict") or "")
    live_verdict = str(live_result.get("verdict") or "")
    if mode == "fresh-manifest" and verdict == "pass-fresh-deep-manifest":
        backed_paths = _backed_live_fresh_manifest_paths(live_result, workspace, run_id=run_id)
        if live_verdict != "pass-fresh-deep-manifest" or not backed_paths:
            return False
        claimed_paths = {
            normalized
            for path in (proof_row.get("fresh_manifest_paths") or [])
            if (normalized := _normalize_manifest_path(path, workspace))
        }
        return bool(claimed_paths) and claimed_paths == backed_paths
    if mode == "typed-skip" and verdict == "pass-explicit-deep-skip":
        if live_verdict != "pass-explicit-deep-skip":
            return False
        skip = live_result.get("skip")
        if isinstance(skip, dict):
            return (
                _typed_skip_fields_ok(proof_row)
                and str(proof_row.get("deep_engine_skip_reason") or "").strip()
                == str(skip.get("reason") or "").strip()
                and str(proof_row.get("deep_engine_skip_key") or "").strip()
                == str(skip.get("key") or "").strip()
                and str(proof_row.get("deep_engine_skip_source") or "").strip()
                == str(skip.get("source") or "").strip()
                and str(proof_row.get("deep_engine_skip_path") or "").strip()
                == str(skip.get("path") or "").strip()
            )
        return False
    return False


def _backed_live_fresh_manifest_paths(
    live_result: dict[str, Any] | None,
    workspace: Path,
    *,
    run_id: str | None = None,
) -> set[str]:
    if not live_result or live_result.get("ok") is not True:
        return set()
    if str(live_result.get("verdict") or "") != "pass-fresh-deep-manifest":
        return set()
    claimed_paths = {
        normalized
        for path in (live_result.get("fresh_manifest_paths") or [])
        if (normalized := _normalize_manifest_path(path, workspace))
    }
    if not claimed_paths:
        return set()
    summaries = live_result.get("source_manifest_summaries")
    if not isinstance(summaries, list):
        return set()
    backed_paths: set[str] = set()
    for summary in summaries:
        if not isinstance(summary, dict):
            continue
        if summary.get("fresh") is not True:
            continue
        if summary.get("completion_source_eligible") is not True:
            continue
        if summary.get("execution_ok") is not True:
            continue
        if summary.get("workspace_matches") is not True:
            continue
        if run_id is not None and summary.get("run_id_matches_current") is not True:
            continue
        normalized = _normalize_manifest_path(summary.get("path"), workspace)
        if normalized is not None:
            backed_paths.add(normalized)
    if backed_paths != claimed_paths:
        return set()
    return backed_paths


def _live_freshness_requires_engine_harness_proof(
    live_result: dict[str, Any] | None,
    *,
    run_id: str | None = None,
) -> bool:
    if not live_result or live_result.get("ok") is not True:
        return False
    if str(live_result.get("verdict") or "") != "pass-fresh-deep-manifest":
        return False
    summaries = live_result.get("source_manifest_summaries")
    if not isinstance(summaries, list):
        return False
    for summary in summaries:
        if not isinstance(summary, dict):
            continue
        if summary.get("fresh") is not True:
            continue
        if summary.get("completion_source_eligible") is not True:
            continue
        if summary.get("execution_ok") is not True:
            continue
        if summary.get("workspace_matches") is not True:
            continue
        if run_id is not None and summary.get("run_id_matches_current") is not True:
            continue
        if str(summary.get("kind") or "") in {"solidity-deep-audit", "solidity-deep-all-harnesses"}:
            return True
    return False


def _live_engine_harness_proof(workspace: Path) -> dict[str, Any]:
    try:
        module_name = "engine_harness_proof_for_status"
        spec = importlib.util.spec_from_file_location(module_name, ENGINE_HARNESS_PROOF_TOOL)
        if spec is None or spec.loader is None:
            return {
                "ok": False,
                "verdict": "error",
                "reason": "engine-harness-proof-check import failed",
                "proven": [],
                "unproven": [],
                "advisory_only": False,
            }
        module = importlib.util.module_from_spec(spec)
        previous_module = sys.modules.get(module_name)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
        finally:
            if previous_module is not None:
                sys.modules[module_name] = previous_module
            else:
                sys.modules.pop(module_name, None)
        result = module.evaluate(workspace)
    except Exception as exc:
        return {
            "ok": False,
            "verdict": "error",
            "reason": f"engine-harness-proof-check failed: {exc.__class__.__name__}",
            "proven": [],
            "unproven": [],
            "advisory_only": False,
        }
    if not isinstance(result, dict):
        return {
            "ok": False,
            "verdict": "error",
            "reason": "engine-harness-proof-check returned non-object",
            "proven": [],
            "unproven": [],
            "advisory_only": False,
        }
    proven = result.get("proven") if isinstance(result.get("proven"), list) else []
    unproven = result.get("unproven") if isinstance(result.get("unproven"), list) else []
    return {
        "ok": result.get("verdict") == "pass-engine-harness-proof",
        "verdict": result.get("verdict"),
        "reason": result.get("reason"),
        "proven_count": len(proven),
        "unproven_count": len(unproven),
        "proven": proven[:20],
        "unproven": unproven[:20],
        "advisory_only": bool(result.get("advisory_only")),
    }


def _live_deep_freshness(
    workspace: Path,
    manifest_path: Path,
    run_id: str | None,
) -> dict[str, Any] | None:
    if not run_id:
        return None
    try:
        spec = importlib.util.spec_from_file_location(
            "audit_deep_manifest_for_status",
            AUDIT_DEEP_MANIFEST_TOOL,
        )
        if spec is None or spec.loader is None:
            return {"ok": False, "verdict": "error", "reason": "audit-deep-manifest import failed"}
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        result = module.check_freshness(
            workspace,
            audit_run_manifest=manifest_path,
            run_id=run_id,
            require_full_invariant_denominator=True,
        )
    except Exception as exc:
        return {
            "ok": False,
            "verdict": "error",
            "reason": f"audit-deep-manifest live check failed: {exc.__class__.__name__}",
        }
    if not isinstance(result, dict):
        return {"ok": False, "verdict": "error", "reason": "audit-deep-manifest returned non-object"}
    source_summaries: list[dict[str, Any]] = []
    runner_errors: list[dict[str, Any]] = []
    for source in result.get("source_manifests") or []:
        if not isinstance(source, dict):
            continue
        detail = source.get("execution_detail")
        summary: dict[str, Any] = {
            "path": source.get("path"),
            "kind": source.get("kind"),
            "fresh": source.get("fresh"),
            "run_id": source.get("run_id"),
            "timestamp_utc": source.get("timestamp_utc"),
            "run_id_matches_current": source.get("run_id_matches_current"),
            "run_id_mismatch": source.get("run_id_mismatch"),
            "run_id_missing": source.get("run_id_missing"),
            "workspace_matches": source.get("workspace_matches"),
            "schema_matches": source.get("schema_matches"),
            "completion_source_eligible": source.get("completion_source_eligible"),
            "execution_ok": source.get("execution_ok"),
            "execution_reason": source.get("execution_reason"),
        }
        if isinstance(detail, dict):
            summary["runner_artifact_error_count"] = detail.get("runner_artifact_error_count", 0)
            summary["invariant_denominator_check_count"] = detail.get(
                "invariant_denominator_check_count",
                0,
            )
            summary["invariant_denominator_error_count"] = detail.get(
                "invariant_denominator_error_count",
                0,
            )
            summary["invariant_denominator_checks"] = detail.get("invariant_denominator_checks") or []
            summary["invariant_denominator_errors"] = detail.get("invariant_denominator_errors") or []
            for error in detail.get("runner_artifact_errors") or []:
                if isinstance(error, dict):
                    runner_errors.append(error)
        source_summaries.append(summary)
    return {
        "ok": result.get("ok") is True,
        "verdict": result.get("verdict"),
        "reason": result.get("reason"),
        "fresh_manifest_paths": result.get("fresh_manifest_paths") or [],
        "blocking_manifest_paths": result.get("blocking_manifest_paths") or [],
        "run_id": result.get("run_id"),
        "skip": result.get("skip") if isinstance(result.get("skip"), dict) else None,
        "source_manifest_summaries": source_summaries,
        "runner_artifact_error_count": len(runner_errors),
        "runner_artifact_errors": runner_errors,
    }


def _live_audit_completeness(workspace: Path) -> dict[str, Any]:
    try:
        module_name = "audit_completeness_for_status"
        spec = importlib.util.spec_from_file_location(module_name, AUDIT_COMPLETENESS_TOOL)
        if spec is None or spec.loader is None:
            return {
                "ok": False,
                "verdict": "error",
                "reason": "audit-completeness-check import failed",
                "failures": ["error"],
                "signals": [],
            }
        module = importlib.util.module_from_spec(spec)
        previous_module = sys.modules.get(module_name)
        sys.modules[module_name] = module
        try:
            spec.loader.exec_module(module)
        finally:
            if previous_module is not None:
                sys.modules[module_name] = previous_module
            else:
                sys.modules.pop(module_name, None)
        result = module.evaluate(workspace)
    except Exception as exc:
        return {
            "ok": False,
            "verdict": "error",
            "reason": f"audit-completeness live check failed: {exc.__class__.__name__}",
            "failures": ["error"],
            "signals": [],
        }
    if not isinstance(result, dict):
        return {
            "ok": False,
            "verdict": "error",
            "reason": "audit-completeness-check returned non-object",
            "failures": ["error"],
            "signals": [],
        }

    signals: list[dict[str, Any]] = []
    for signal in result.get("signals") or []:
        if not isinstance(signal, dict):
            continue
        signals.append(
            {
                "signal": signal.get("signal"),
                "ok": signal.get("ok"),
                "raw_ok": signal.get("raw_ok"),
                "verdict": signal.get("verdict"),
                "reason": signal.get("reason"),
                "policy": signal.get("policy"),
                "hard_required": signal.get("hard_required"),
                "artifact_present": signal.get("artifact_present"),
                "artifact_requirement": signal.get("artifact_requirement"),
            }
        )

    verdict = str(result.get("verdict") or "")
    return {
        "ok": verdict == PASS_AUDIT_COMPLETE_VERDICT,
        "verdict": verdict or None,
        "reason": result.get("reason"),
        "failures": result.get("failures") if isinstance(result.get("failures"), list) else [],
        "rebutted": result.get("rebutted") if isinstance(result.get("rebutted"), list) else [],
        "coverage_warn": result.get("coverage_warn"),
        "rubric_coverage_warn": result.get("rubric_coverage_warn"),
        "hunt_trust_warn": result.get("hunt_trust_warn"),
        "signals": signals,
    }


def _invariant_denominator_warnings(live_result: dict[str, Any] | None) -> list[dict[str, Any]]:
    warnings: list[dict[str, Any]] = []
    if not live_result:
        return warnings
    summaries = live_result.get("source_manifest_summaries") or []
    if not isinstance(summaries, list):
        return warnings
    for summary in summaries:
        if not isinstance(summary, dict):
            continue
        source_kind = summary.get("kind")
        checks = summary.get("invariant_denominator_checks")
        if not isinstance(checks, list):
            continue
        error_map: dict[tuple[str | None, str | None], str | None] = {}
        errors = summary.get("invariant_denominator_errors") or []
        if isinstance(errors, list):
            for row in errors:
                if not isinstance(row, dict):
                    continue
                key = (
                    str(row.get("denominator_field")) if row.get("denominator_field") else None,
                    str(row.get("executed_field")) if row.get("executed_field") else None,
                )
                error_map[key] = str(row.get("reason") or "").strip() or None

        for row in checks:
            if not isinstance(row, dict):
                continue
            denominator_count = _parse_int(row.get("denominator_count"))
            executed_count = _parse_int(row.get("executed_count"))
            if denominator_count is None or denominator_count <= 0:
                continue
            if executed_count is not None and executed_count >= denominator_count:
                continue
            denominator_field = (
                str(row.get("denominator_field")) if row.get("denominator_field") else None
            )
            executed_field = str(row.get("executed_field")) if row.get("executed_field") else None
            reason = error_map.get((denominator_field, executed_field))
            if reason is None:
                reason = "executed_count_missing" if executed_count is None else "denominator_exceeds_executed"
            warnings.append(
                {
                    "source_kind": source_kind,
                    "label": row.get("label"),
                    "denominator_field": denominator_field,
                    "denominator_count": denominator_count,
                    "executed_field": executed_field,
                    "executed_count": executed_count,
                    "strict_required": row.get("strict_required"),
                    "reason": reason,
                }
            )
    return warnings


def _live_deep_proof_ok(
    live_result: dict[str, Any] | None,
    workspace: Path,
    *,
    run_id: str | None = None,
    engine_harness_proof: dict[str, Any] | None = None,
) -> bool:
    if not live_result or live_result.get("ok") is not True:
        return False
    if run_id is not None and str(live_result.get("run_id") or "") != str(run_id):
        return False
    verdict = str(live_result.get("verdict") or "")
    if verdict == "pass-explicit-deep-skip":
        return True
    if verdict != "pass-fresh-deep-manifest":
        return False
    if not _backed_live_fresh_manifest_paths(live_result, workspace, run_id=run_id):
        return False
    if _live_freshness_requires_engine_harness_proof(live_result, run_id=run_id):
        return bool(engine_harness_proof and engine_harness_proof.get("ok") is True)
    return True


def _latest_stage_deep_proof_row(run_rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    proof_row: dict[str, Any] | None = None
    for row in run_rows:
        if row.get("event") != "stage-pass":
            continue
        if _completion_proof_ok(row):
            proof_row = row
    return proof_row


def _stage_statuses(run_rows: list[dict[str, Any]]) -> dict[str, str]:
    statuses: dict[str, str] = {}
    for row in run_rows:
        stage = row.get("stage")
        event = row.get("event")
        if not isinstance(stage, str) or not stage.strip() or event not in STAGE_TERMINAL_EVENTS:
            continue
        statuses[stage.strip()] = str(event)
    return statuses


def _stage_warnings(run_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    warnings: list[dict[str, Any]] = []
    for row in run_rows:
        if row.get("event") != "stage-warn":
            continue
        warnings.append(
            {
                "stage": row.get("stage"),
                "rc": row.get("rc"),
                "reason": row.get("reason"),
                "enforce_autonomous_proof_conversion": row.get("enforce_autonomous_proof_conversion"),
            }
        )
    return warnings


def _stage_satisfies_certification(stage: str, status: str | None) -> bool:
    if stage in ADVISORY_PROOF_STAGES:
        return status in {"stage-pass", "stage-warn"}
    return status == "stage-pass"


def _g15_summary(workspace: Path, run_id: str | None) -> dict[str, Any] | None:
    path = workspace / DEFAULT_G15_LAST_RESULT
    payload, error = _load_json_object(path)
    if error:
        return {
            "path": str(path),
            "error": error,
            "present": False,
            "matches_latest_run": False,
        }
    if payload is None:
        return None
    sidecar_run_id = str(payload.get("run_id") or "")
    matches_latest_run = bool(run_id and sidecar_run_id == run_id)
    return {
        "path": str(path),
        "present": True,
        "matches_latest_run": matches_latest_run,
        "run_id": sidecar_run_id or None,
        "generated_at_utc": payload.get("generated_at_utc"),
        "strict": payload.get("strict"),
        "min_coverage": payload.get("min_coverage"),
        "verdict": payload.get("verdict"),
        "reason": payload.get("reason"),
        "covered": payload.get("covered"),
        "total_units": payload.get("total_units"),
        "coverage_fraction": payload.get("coverage_fraction"),
        "queued_not_scanned_count": len(payload.get("queued_not_scanned") or []),
        "detector_only_not_queued_count": len(payload.get("detector_only_not_queued") or []),
        "unlogged_uncovered_count": len(payload.get("unlogged_uncovered") or []),
    }


def _g15_passed(g15: dict[str, Any] | None) -> bool:
    if not g15:
        return False
    verdict = str(g15.get("verdict") or "")
    if verdict == "ok-rebuttal":
        return g15.get("matches_latest_run") is True
    if verdict != "pass-coverage-met":
        return False
    total_units = _parse_int(g15.get("total_units"))
    covered = _parse_int(g15.get("covered"))
    min_coverage = _parse_float(g15.get("min_coverage"))
    coverage_fraction = _parse_float(g15.get("coverage_fraction"))
    return (
        g15.get("matches_latest_run") is True
        and g15.get("strict") is True
        and min_coverage == 1.0
        and coverage_fraction == 1.0
        and total_units is not None
        and total_units > 0
        and covered == total_units
        and _parse_int(g15.get("queued_not_scanned_count")) == 0
        and _parse_int(g15.get("detector_only_not_queued_count")) == 0
        and _parse_int(g15.get("unlogged_uncovered_count")) == 0
    )


def _count_submission_drafts(workspace: Path) -> dict[str, Any]:
    submissions = workspace / "submissions"
    status_counts: dict[str, int] = {}
    total = 0
    if not submissions.exists():
        return {"present": False, "status_counts": status_counts, "total": total}
    for status in SUBMISSION_STATUS_DIRS:
        base = submissions / status
        count = 0
        if base.is_dir():
            for path in base.rglob("*.md"):
                if path.name in SUBMISSION_TRACKER_BASENAMES:
                    continue
                if path.parent != base and path.stem != path.parent.name:
                    continue
                if path.parent == base and path.name.endswith(".hardening.md"):
                    continue
                count += 1
        status_counts[status] = count
        total += count
    return {"present": True, "status_counts": status_counts, "total": total}


def summarize_manifest(workspace: Path, manifest: Path | None = None) -> dict[str, Any]:
    manifest_path = manifest or workspace / DEFAULT_MANIFEST
    rows, parse_errors = _load_jsonl(manifest_path)
    run_rows = _latest_run_rows(rows)
    start = _start_row(run_rows)
    run_id = _latest_run_id(run_rows)
    max_functions = _parse_int(start.get("max_functions"))
    full_scope = max_functions == 0
    current_stage, active_stage = _active_or_latest_stage(run_rows)
    active_stage_row = _active_stage_start_row(run_rows)
    stale_running = _stale_running_summary(active_stage_row, workspace=workspace)
    terminal = _terminal_row(run_rows)
    terminal_event = str(terminal.get("event")) if terminal else None
    terminal_stage = None
    if terminal:
        terminal_stage = str(terminal.get("stage") or terminal_event)

    successful_terminal = bool(terminal_event in {COMPLETE_EVENT, BOUNDED_COMPLETE_EVENT})
    complete_row = terminal if terminal and terminal.get("event") == COMPLETE_EVENT else None
    terminal_complete = complete_row is not None
    completion_row_run_id_matches = _completion_row_run_id_matches(complete_row, run_id)
    completion_proof_ok = _completion_proof_ok(complete_row, run_id=run_id)
    stage_deep_proof_row = _latest_stage_deep_proof_row(run_rows)
    should_live_check_deep = bool(run_id)
    live_deep_freshness = (
        _live_deep_freshness(workspace, manifest_path, run_id)
        if should_live_check_deep
        else None
    )
    live_engine_harness_proof = (
        _live_engine_harness_proof(workspace)
        if _live_freshness_requires_engine_harness_proof(live_deep_freshness, run_id=run_id)
        else None
    )
    live_audit_completeness = _live_audit_completeness(workspace) if terminal_complete else None
    live_audit_complete = bool(
        live_audit_completeness
        and live_audit_completeness.get("ok") is True
        and live_audit_completeness.get("verdict") == PASS_AUDIT_COMPLETE_VERDICT
    )
    live_deep_proof_ok = _live_deep_proof_ok(
        live_deep_freshness,
        workspace,
        run_id=run_id,
        engine_harness_proof=live_engine_harness_proof,
    )
    completion_proof_matches_live = _completion_proof_matches_live(
        complete_row,
        live_deep_freshness,
        workspace,
        run_id=run_id,
    )
    terminal_deep_proof_ok = completion_proof_ok and live_deep_proof_ok and completion_proof_matches_live
    stage_deep_proof_ok = _completion_proof_matches_live(
        stage_deep_proof_row,
        live_deep_freshness,
        workspace,
        run_id=run_id,
    )
    invariant_denominator_warnings = _invariant_denominator_warnings(live_deep_freshness)
    g15 = _g15_summary(workspace, run_id)
    stage_statuses = _stage_statuses(run_rows)
    missing_mandatory_stage_passes = [
        stage
        for stage in MANDATORY_CERTIFICATION_STAGES
        if not _stage_satisfies_certification(stage, stage_statuses.get(stage))
    ]
    stage_warnings = _stage_warnings(run_rows)
    blocking_stage_warnings = [
        warning for warning in stage_warnings if str(warning.get("stage") or "") not in ADVISORY_PROOF_STAGES
    ]
    advisory_proof_warnings = [
        warning for warning in stage_warnings if str(warning.get("stage") or "") in ADVISORY_PROOF_STAGES
    ]

    blockers: list[str] = []
    if not rows:
        blockers.append("manifest-missing-or-empty")
    if not successful_terminal:
        blockers.append("latest-run-not-terminal-complete")
    if terminal_event == BOUNDED_COMPLETE_EVENT:
        blockers.append("bounded-terminal-not-certifying")
    if max_functions is None:
        blockers.append("max-functions-unknown")
    elif not full_scope:
        blockers.append("bounded-run")
    if terminal_complete and not terminal_deep_proof_ok:
        blockers.append("missing-current-run-deep-proof")
    if terminal_complete and not completion_row_run_id_matches:
        blockers.append("terminal-run-id-mismatch")
    if (
        terminal_complete
        and complete_row
        and complete_row.get("deep_engine_completion_mode") == "typed-skip"
        and not _typed_skip_fields_ok(complete_row)
    ):
        blockers.append("terminal-deep-skip-not-typed")
    if terminal_complete and completion_proof_ok and not live_deep_proof_ok:
        blockers.append("live-current-run-deep-proof-failed")
    if terminal_complete and completion_proof_ok and live_deep_proof_ok and not completion_proof_matches_live:
        blockers.append("terminal-deep-proof-live-mismatch")
    if not terminal_complete and stage_deep_proof_row is not None and not live_deep_proof_ok:
        blockers.append("live-stage-deep-proof-failed")
    if terminal_complete and missing_mandatory_stage_passes:
        blockers.append("missing-mandatory-stage-passes")
    if terminal_complete and blocking_stage_warnings:
        blockers.append("stage-warn-present")
    if terminal_complete and invariant_denominator_warnings:
        blockers.append(INVARIANT_DENOMINATOR_PARTIAL_BLOCKER)
    if terminal_complete and not live_audit_complete:
        blockers.append("live-audit-completeness-failed")
    if not terminal and stale_running.get("stale") is True:
        blockers.append("stale-running-active-stage")
    if terminal_complete:
        if not g15:
            blockers.append("missing-g15-hunt-coverage-result")
        elif g15.get("matches_latest_run") is not True:
            blockers.append("stale-g15-hunt-coverage-result")
        elif not _g15_passed(g15):
            total_units = _parse_int(g15.get("total_units"))
            if (
                str(g15.get("verdict") or "") in G15_PASS_VERDICTS
                and total_units is not None
                and total_units <= 0
            ):
                blockers.append("zero-g15-coverage-denominator")
            else:
                blockers.append("failing-g15-hunt-coverage-result")

    certification_complete = (
        terminal_complete
        and full_scope
        and terminal_deep_proof_ok
        and not missing_mandatory_stage_passes
        and not blocking_stage_warnings
        and live_audit_complete
        and not invariant_denominator_warnings
        and _g15_passed(g15)
    )
    submission_drafts = _count_submission_drafts(workspace)
    finding_backlog_count = int(submission_drafts.get("total") or 0)
    if not certification_complete:
        post_certification_finding_status = POST_CERT_FINDING_STATUS_PIPELINE_INCOMPLETE
    elif finding_backlog_count > 0:
        post_certification_finding_status = POST_CERT_FINDING_STATUS_BACKLOG
    else:
        post_certification_finding_status = POST_CERT_FINDING_STATUS_ZERO_CANDIDATES

    status = "running"
    if terminal_event == COMPLETE_EVENT:
        status = "complete" if certification_complete else UNCERTIFIED_COMPLETE_STATUS
    elif terminal_event == BOUNDED_COMPLETE_EVENT:
        status = "bounded-complete"
    elif terminal_event in FAILURE_EVENTS:
        status = "failed"
    elif stale_running.get("stale") is True:
        status = STALE_RUNNING_STATUS
    elif not rows:
        status = "missing"

    return {
        "schema": SCHEMA,
        "workspace": str(workspace),
        "manifest": str(manifest_path),
        "latest_run_id": run_id,
        "max_functions": max_functions,
        "full_scope": full_scope,
        "current_stage": current_stage,
        "active_stage": active_stage,
        "stale_running": stale_running,
        "terminal_event": terminal_event,
        "terminal_stage": terminal_stage,
        "successful_terminal": successful_terminal,
        "terminal_complete": terminal_complete,
        "deep_engine_completion_mode": complete_row.get("deep_engine_completion_mode")
        if complete_row
        else None,
        "deep_engine_freshness_verdict": complete_row.get("deep_engine_freshness_verdict")
        if complete_row
        else None,
        "terminal_run_id_matches_latest": completion_row_run_id_matches,
        "terminal_deep_proof_matches_live": completion_proof_matches_live,
        "stage_deep_proof_claimed": stage_deep_proof_row is not None,
        "stage_deep_proof": stage_deep_proof_ok,
        "stage_deep_proof_event": stage_deep_proof_row.get("event") if stage_deep_proof_row else None,
        "stage_deep_proof_stage": stage_deep_proof_row.get("stage") if stage_deep_proof_row else None,
        "stage_deep_engine_completion_mode": stage_deep_proof_row.get("deep_engine_completion_mode")
        if stage_deep_proof_row
        else None,
        "stage_deep_engine_freshness_verdict": stage_deep_proof_row.get("deep_engine_freshness_verdict")
        if stage_deep_proof_row
        else None,
        "terminal_deep_proof": terminal_deep_proof_ok,
        "current_run_deep_proof": terminal_deep_proof_ok,
        "live_deep_freshness": live_deep_freshness,
        "live_deep_proof": live_deep_proof_ok,
        "live_engine_harness_proof": live_engine_harness_proof,
        "live_audit_completeness": live_audit_completeness,
        "live_audit_completeness_verdict": live_audit_completeness.get("verdict")
        if live_audit_completeness
        else None,
        "live_audit_complete": live_audit_complete,
        "certification_complete": certification_complete,
        "certification_blockers": blockers,
        "mandatory_certification_stages": list(MANDATORY_CERTIFICATION_STAGES),
        "stage_statuses": stage_statuses,
        "missing_mandatory_stage_passes": missing_mandatory_stage_passes,
        "stage_warnings": stage_warnings,
        "blocking_stage_warnings": blocking_stage_warnings,
        "advisory_proof_warnings": advisory_proof_warnings,
        "advisory_proof_stages": sorted(ADVISORY_PROOF_STAGES),
        "invariant_denominator_warnings": invariant_denominator_warnings,
        "g15_hunt_coverage": g15,
        "submission_drafts": submission_drafts,
        "finding_backlog_count": finding_backlog_count,
        "post_certification_finding_status": post_certification_finding_status,
        "status": status,
        "parse_errors": parse_errors,
        "row_count": len(rows),
        "latest_run_row_count": len(run_rows),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("workspace", help="Audit workspace path.")
    parser.add_argument(
        "--manifest",
        help="Override manifest path. Defaults to <workspace>/.auditooor/audit_run_full_manifest.jsonl.",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON. This is the default.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    workspace = Path(args.workspace).expanduser().resolve()
    manifest = Path(args.manifest).expanduser().resolve() if args.manifest else None
    payload = summarize_manifest(workspace, manifest)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
