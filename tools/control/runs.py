"""Read-only workspace run manifest and execution-state inventory.

This module answers a narrow question for control-plane callers: which durable
artifacts show that a tool actually ran, and which artifacts are only plans,
scaffolds, skips, or blockers. It does not mutate the workspace.
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

try:  # Package import in tests, top-level import when loaded by tools/auditooorctl.py.
    from tools import execution_manifest_proof as _execution_manifest_proof
except ModuleNotFoundError:  # pragma: no cover - exercised by CLI script import mode.
    import execution_manifest_proof as _execution_manifest_proof  # type: ignore[no-redef]


command_evidence_counts = _execution_manifest_proof.command_evidence_counts
is_strict_proved_execution_manifest = _execution_manifest_proof.is_strict_proved_execution_manifest
strict_proof_blockers = _execution_manifest_proof.strict_proof_blockers


def _validate_bound_sources(manifest: dict[str, Any], workspace: Path) -> dict[str, Any]:
    """Apply shared binding validation while retaining legacy absent/empty input."""
    supplied = "bound_sources" in manifest
    bound_sources = manifest.get("bound_sources")
    if not supplied or bound_sources in (None, []):
        return {"supplied": supplied, "valid": True, "entries": [], "errors": []}
    validator = getattr(_execution_manifest_proof, "bound_source_validation", None)
    if validator is None:
        return {
            "supplied": True,
            "valid": False,
            "entries": [],
            "errors": ["bound_source_validation_unavailable"],
        }
    try:
        result = validator(manifest, workspace)
    except Exception as exc:  # pragma: no cover - defensive boundary for shared code.
        return {
            "supplied": True,
            "valid": False,
            "entries": [],
            "errors": [f"bound_source_validation_error:{exc.__class__.__name__}"],
        }
    if not isinstance(result, dict):
        return {
            "supplied": True,
            "valid": False,
            "entries": [],
            "errors": ["bound_source_validation_invalid_result"],
        }
    errors = [str(error) for error in result.get("errors") or []]
    if result.get("valid") is not True and not errors:
        errors.append("bound_source_validation_invalid")
    return {**result, "supplied": True, "valid": result.get("valid") is True, "errors": errors}


RUN_MANIFEST_SCHEMA = "auditooor.run_manifest.v1"

STATIC_ARTIFACTS: tuple[tuple[str, str], ...] = (
    ("engage", "engage_report.md"),
    ("audit-deep", ".audit_logs/audit_deep_report.md"),
    ("audit-deep", ".audit_logs/audit_deep_all_manifest.json"),
    ("audit-deep", ".audit_logs/audit_deep_all_report.md"),
    ("audit-closeout", ".audit_logs/audit_closeout_manifest.json"),
    ("rust-scan", "scanners/rust/SCAN_RUST_SUMMARY.json"),
    ("live-topology", "live_topology_checks.json"),
)

PLANNED_STATUSES = {
    "dry_run",
    "dry-run",
    "generated",
    "planned",
    "scaffolded",
    "scaffolded_unverified",
    "todo",
}
BLOCKED_STATUSES = {
    "blocked",
    "blocked_path",
    "error",
    "failed",
    "failure",
    "hard_fail",
    "invalid",
    "missing",
}
EXECUTED_STATUSES = {
    "done",
    "executed",
    "ok",
    "pass",
    "passed",
    "proved",
    "success",
}
PARTIAL_STATUSES = {
    "partial",
    "skipped",
    "skipped_budget",
    "skipped_inapplicable",
    "success_warn",
    "warn",
    "warning",
    "warnings",
}


def _rel(path: Path, workspace: Path) -> str:
    try:
        return path.relative_to(workspace).as_posix()
    except ValueError:
        return path.as_posix()


def _read_json(path: Path) -> tuple[Any | None, list[str], list[str]]:
    try:
        return json.loads(path.read_text(encoding="utf-8")), [], []
    except FileNotFoundError:
        return None, [], ["artifact_missing"]
    except json.JSONDecodeError as exc:
        return None, [], [f"invalid_json:{exc.lineno}:{exc.colno}"]
    except OSError as exc:
        return None, [], [f"read_error:{exc.__class__.__name__}"]


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _status_state(statuses: list[str]) -> str:
    normalized = {status.strip().lower() for status in statuses if status.strip()}
    if not normalized:
        return "executed"
    if normalized & BLOCKED_STATUSES:
        return "blocked"
    if normalized <= PLANNED_STATUSES:
        return "planned"
    if normalized & PLANNED_STATUSES:
        return "partial"
    if normalized & PARTIAL_STATUSES:
        return "partial"
    if normalized <= EXECUTED_STATUSES:
        return "executed"
    return "partial"


def _base_row(
    tool: str,
    artifact_path: str,
    execution_state: str,
    *,
    proof_counted: bool = False,
    warnings: list[str] | None = None,
    blockers: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "tool": tool,
        "artifact_path": artifact_path,
        "execution_state": execution_state,
        "proof_counted": proof_counted,
        "warnings": sorted(set(warnings or [])),
        "blockers": sorted(set(blockers or [])),
    }


def _classify_text_report(tool: str, path: Path, workspace: Path) -> dict[str, Any]:
    text = _read_text(path).lower()
    warnings: list[str] = []
    blockers: list[str] = []
    state = "executed"
    if "done with issues" in text or "\nfail" in text or " failed" in text:
        state = "blocked"
        blockers.append("report_contains_failure_marker")
    elif "done with warnings" in text or "warning" in text:
        state = "partial"
        warnings.append("report_contains_warning_marker")
    return _base_row(tool, _rel(path, workspace), state, warnings=warnings, blockers=blockers)


def _classify_audit_deep_manifest(path: Path, workspace: Path) -> dict[str, Any]:
    payload, warnings, blockers = _read_json(path)
    statuses: list[str] = []
    if not isinstance(payload, dict):
        blockers.append("manifest_not_object")
        return _base_row("audit-deep", _rel(path, workspace), "blocked", warnings=warnings, blockers=blockers)
    if payload.get("dry_run") is True:
        statuses.append("planned")
        warnings.append("manifest_marked_dry_run")
    profiles = payload.get("profiles")
    if isinstance(profiles, list):
        for idx, profile in enumerate(profiles):
            if not isinstance(profile, dict):
                statuses.append("invalid")
                blockers.append(f"profile_{idx}_not_object")
                continue
            status = str(profile.get("status") or "").strip()
            if status:
                statuses.append(status)
            exit_code = profile.get("exit_code")
            if isinstance(exit_code, int) and exit_code != 0:
                statuses.append("failed")
                blockers.append(f"profile_{profile.get('profile') or idx}_exit_{exit_code}")
    else:
        status = str(payload.get("status") or payload.get("execution_state") or "").strip()
        if status:
            statuses.append(status)
        warnings.append("manifest_profiles_missing")
    state = _status_state(statuses)
    if state == "partial":
        warnings.append("audit_deep_manifest_partial")
    return _base_row("audit-deep", _rel(path, workspace), state, warnings=warnings, blockers=blockers)


def _classify_generic_manifest(tool: str, path: Path, workspace: Path) -> dict[str, Any]:
    payload, warnings, blockers = _read_json(path)
    statuses: list[str] = []
    if not isinstance(payload, dict):
        blockers.append("manifest_not_object")
        return _base_row(tool, _rel(path, workspace), "blocked", warnings=warnings, blockers=blockers)
    for key in ("execution_state", "status", "result", "final_result"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            statuses.append(value)
    if payload.get("dry_run") is True:
        statuses.append("planned")
        warnings.append("manifest_marked_dry_run")
    for key in ("warnings", "missing_tools"):
        value = payload.get(key)
        if isinstance(value, list) and value:
            warnings.append(f"{key}:{len(value)}")
    for key in ("blockers", "errors", "failures"):
        value = payload.get(key)
        if isinstance(value, list) and value:
            blockers.append(f"{key}:{len(value)}")
            statuses.append("blocked")
    return _base_row(tool, _rel(path, workspace), _status_state(statuses), warnings=warnings, blockers=blockers)


def _classify_live_topology(path: Path, workspace: Path) -> dict[str, Any]:
    payload, warnings, blockers = _read_json(path)
    statuses: list[str] = []
    if not isinstance(payload, dict):
        blockers.append("manifest_not_object")
        return _base_row("live-topology", _rel(path, workspace), "blocked", warnings=warnings, blockers=blockers)
    rows = payload.get("rows")
    if not isinstance(rows, list):
        rows = payload.get("results")
    if isinstance(rows, list):
        if not rows:
            warnings.append("live_topology_rows_empty")
            statuses.append("planned")
        for idx, row in enumerate(rows):
            if not isinstance(row, dict):
                blockers.append(f"row_{idx}_not_object")
                statuses.append("invalid")
                continue
            status = str(row.get("execution_state") or row.get("status") or row.get("result") or "")
            if status:
                statuses.append(status)
            if row.get("dry_run") is True:
                statuses.append("planned")
            if row.get("blocked") is True:
                statuses.append("blocked")
    else:
        warnings.append("live_topology_rows_missing")
    return _base_row("live-topology", _rel(path, workspace), _status_state(statuses), warnings=warnings, blockers=blockers)


def _classify_poc_execution(path: Path, workspace: Path) -> dict[str, Any]:
    payload, warnings, blockers = _read_json(path)
    if not isinstance(payload, dict):
        blockers.append("manifest_not_object")
        return _base_row("poc-execution", _rel(path, workspace), "blocked", warnings=warnings, blockers=blockers)
    final_result = str(payload.get("final_result") or payload.get("result") or "").strip().lower()
    impact_assertion = str(payload.get("impact_assertion") or "").strip().lower()
    proof_counted = is_strict_proved_execution_manifest(payload)
    proof_blockers = set(strict_proof_blockers(payload))
    bound_sources = _validate_bound_sources(payload, workspace)
    bound_source_errors = list(bound_sources.get("errors") or [])
    if bound_sources.get("supplied") and not bound_sources.get("valid"):
        proof_counted = False
        blockers.extend(bound_source_errors)
    command_counts = command_evidence_counts(payload)
    statuses = [final_result] if final_result else []
    if not final_result:
        statuses.append("planned")
        warnings.append("final_result_missing")
    if final_result and final_result != "proved":
        blockers.append(f"final_result_{final_result}")
    if impact_assertion and impact_assertion != "exploit_impact":
        blockers.append(f"impact_assertion_{impact_assertion}")
    elif not impact_assertion:
        warnings.append("impact_assertion_missing")
    if final_result == "proved" and impact_assertion == "exploit_impact":
        if "evidence_class_executed_with_manifest" in proof_blockers:
            blockers.append("evidence_class_not_executed_with_manifest")
        if "commands_attempted" in proof_blockers:
            blockers.append("commands_attempted")
        elif "commands_attempted_structured" in proof_blockers:
            blockers.append("commands_attempted_structured")
        elif "commands_attempted_nonempty_command" in proof_blockers:
            blockers.append("commands_attempted_nonempty_command")
        if "commands_attempted_pass_exit_0" in proof_blockers:
            blockers.append("commands_attempted_pass_exit_0")
        if command_counts["bool_exit_code_count"] and command_counts["passing_command_count"] <= 0:
            blockers.append("command_exit_code_bool")
    return _base_row(
        "poc-execution",
        _rel(path, workspace),
        _status_state(statuses),
        proof_counted=proof_counted,
        warnings=warnings,
        blockers=blockers,
    )


def discover_run_rows(workspace: str | Path) -> list[dict[str, Any]]:
    """Return normalized rows for existing run artifacts under ``workspace``."""
    ws = Path(workspace).expanduser()
    if not ws.exists():
        return [
            _base_row(
                "workspace",
                ws.as_posix(),
                "missing_workspace",
                blockers=["workspace_missing"],
            )
        ]
    if not ws.is_dir():
        return [
            _base_row(
                "workspace",
                ws.as_posix(),
                "blocked",
                blockers=["workspace_not_directory"],
            )
        ]

    rows: list[dict[str, Any]] = []
    for tool, rel_path in STATIC_ARTIFACTS:
        path = ws / rel_path
        if not path.exists():
            continue
        if path.suffix == ".md":
            rows.append(_classify_text_report(tool, path, ws))
        elif rel_path == ".audit_logs/audit_deep_all_manifest.json":
            rows.append(_classify_audit_deep_manifest(path, ws))
        elif rel_path == "live_topology_checks.json":
            rows.append(_classify_live_topology(path, ws))
        else:
            rows.append(_classify_generic_manifest(tool, path, ws))

    for path in sorted(ws.glob("poc_execution/**/execution_manifest.json")):
        rows.append(_classify_poc_execution(path, ws))
    return rows


def summarize_runs(workspace: str | Path) -> dict[str, Any]:
    """Summarize discovered run artifacts and proof-counted manifests."""
    rows = discover_run_rows(workspace)
    by_state = Counter(str(row["execution_state"]) for row in rows)
    by_tool = Counter(str(row["tool"]) for row in rows)
    proof_counted = sum(1 for row in rows if row.get("proof_counted") is True)
    return {
        "schema": RUN_MANIFEST_SCHEMA,
        "workspace": str(Path(workspace).expanduser()),
        "artifact_count": len(rows),
        "counts_by_execution_state": dict(sorted(by_state.items())),
        "counts_by_tool": dict(sorted(by_tool.items())),
        "proof_counted": {
            "true": proof_counted,
            "false": len(rows) - proof_counted,
        },
        "rows": rows,
    }


__all__ = ["RUN_MANIFEST_SCHEMA", "discover_run_rows", "summarize_runs"]
