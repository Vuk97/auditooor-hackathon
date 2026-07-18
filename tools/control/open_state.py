#!/usr/bin/env python3
"""Durable open-state writer for future ``auditooorctl open`` flows.

The module is intentionally local and non-executing: it reads existing control
artifacts, builds dry-run command metadata, and writes
``.auditooor/control/state.json`` only when ``write_open_state`` is called.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .gaps import score_known_capability_gaps
from .providers import build_provider_tasks, calibrate_provider_tasks
from .report import PROOF_BOUNDARY, build_control_report
from .runner import build_execution_plan
from .state import collect_state


SCHEMA = "auditooor.control.open_state.v1"
DEFAULT_RELATIVE_PATH = ".auditooor/control/state.json"


def collect_open_state(
    workspace: str | Path,
    *,
    generated_at: str | None = None,
    cwd: str | Path | None = None,
) -> dict[str, Any]:
    """Return a durable open-state packet without writing it."""

    ws = Path(workspace).expanduser().resolve()
    snapshot = collect_state(ws)
    gap_report = score_known_capability_gaps(
        snapshot["workspace"],
        status=snapshot.get("status") or {},
        candidates=snapshot.get("candidates") or [],
        runs=(snapshot.get("runs") or {}).get("rows") or [],
        next_actions=snapshot.get("next_actions") or [],
    )
    provider_tasks = calibrate_provider_tasks(
        build_provider_tasks(
            snapshot["workspace"],
            candidates=snapshot.get("candidates") or [],
            runs=(snapshot.get("runs") or {}).get("rows") or [],
            next_actions=snapshot.get("next_actions") or [],
        )
    )
    command_plan = build_execution_plan(
        snapshot["workspace"],
        snapshot.get("next_actions") or [],
        cwd=cwd,
    )
    report = build_control_report(
        snapshot,
        gaps=gap_report,
        provider_tasks=provider_tasks,
        execution_plan=command_plan,
    )

    return {
        "schema": SCHEMA,
        "workspace": snapshot["workspace"],
        "target_name": snapshot.get("target_name") or ws.name,
        "generated_at": generated_at or snapshot.get("generated_at") or _utc_now(),
        "snapshot_summary": _snapshot_summary(snapshot, report),
        "gap_summary": _gap_summary(gap_report),
        "provider_task_summary": _provider_task_summary(report.get("provider_task_routing") or {}),
        "command_plan_summary": _command_plan_summary(report.get("dry_run_command_plan") or {}),
        "proof_boundary": PROOF_BOUNDARY,
    }


def write_open_state(
    workspace: str | Path,
    *,
    out_path: str | Path | None = None,
    generated_at: str | None = None,
    cwd: str | Path | None = None,
) -> dict[str, Any]:
    """Write ``.auditooor/control/state.json`` and return path plus payload.

    Repeated calls are idempotent: if the workspace-derived state is unchanged,
    the existing ``generated_at`` value and file content are preserved.
    """

    ws = Path(workspace).expanduser().resolve()
    path = Path(out_path).expanduser() if out_path is not None else ws / DEFAULT_RELATIVE_PATH
    payload = collect_open_state(ws, generated_at=generated_at, cwd=cwd)
    existing = _read_existing(path)
    if existing and _without_generated_at(existing) == _without_generated_at(payload):
        payload["generated_at"] = existing.get("generated_at") or payload["generated_at"]

    rendered = render_json(payload)
    if not path.exists() or path.read_text(encoding="utf-8") != rendered:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(rendered, encoding="utf-8")
    return {"path": path.resolve().as_posix(), "state": payload}


def render_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _snapshot_summary(snapshot: dict[str, Any], report: dict[str, Any]) -> dict[str, Any]:
    status = snapshot.get("status") if isinstance(snapshot.get("status"), dict) else {}
    readiness = status.get("readiness") if isinstance(status.get("readiness"), dict) else {}
    artifacts = status.get("artifacts") if isinstance(status.get("artifacts"), dict) else {}
    runs = snapshot.get("runs") if isinstance(snapshot.get("runs"), dict) else {}
    return {
        "schema": snapshot.get("schema"),
        "status_schema": status.get("schema"),
        "target_name": snapshot.get("target_name"),
        "readiness": _readiness_statuses(readiness),
        "artifact_status": _artifact_statuses(artifacts),
        "candidate_count": len(_dict_rows(snapshot.get("candidates"))),
        "run_count": int(runs.get("run_count") or len(_dict_rows(runs.get("rows")))),
        "next_action_count": len(_dict_rows(snapshot.get("next_actions"))),
        "readiness_status": (report.get("readiness") or {}).get("status"),
        "readiness_reasons": list((report.get("readiness") or {}).get("reasons") or []),
    }


def _gap_summary(gap_report: dict[str, Any]) -> dict[str, Any]:
    rows = _dict_rows(gap_report.get("rows"))
    return {
        "schema": gap_report.get("schema"),
        "gap_count": int(gap_report.get("gap_count") or len(rows)),
        "counts_by_priority": dict(gap_report.get("counts_by_priority") or {}),
        "p0": _priority_rows(rows, "P0"),
        "p1": _priority_rows(rows, "P1"),
        "p2_count": len([row for row in rows if str(row.get("priority") or "").upper() == "P2"]),
    }


def _provider_task_summary(provider_report: dict[str, Any]) -> dict[str, Any]:
    by_provider = provider_report.get("by_provider")
    return {
        "task_count": int(provider_report.get("task_count") or 0),
        "by_provider": dict(by_provider) if isinstance(by_provider, dict) else {},
        "tasks": _dict_rows(provider_report.get("tasks")),
    }


def _command_plan_summary(command_plan: dict[str, Any]) -> dict[str, Any]:
    return {
        "dry_run": bool(command_plan.get("dry_run", True)),
        "would_execute": bool(command_plan.get("would_execute", False)),
        "command_count": int(command_plan.get("command_count") or 0),
        "counts_by_classification": dict(command_plan.get("counts_by_classification") or {}),
        "commands": _dict_rows(command_plan.get("commands")),
    }


def _readiness_statuses(readiness: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in sorted(readiness.items()):
        if isinstance(value, dict):
            out[str(key)] = str(value.get("status") or "unknown")
        else:
            out[str(key)] = str(value or "unknown")
    return out


def _artifact_statuses(artifacts: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in sorted(artifacts.items()):
        if isinstance(value, dict):
            out[str(key)] = str(value.get("status") or "unknown")
        else:
            out[str(key)] = "unknown"
    return out


def _priority_rows(rows: list[dict[str, Any]], priority: str) -> list[dict[str, Any]]:
    return [
        {
            "id": str(row.get("id") or ""),
            "category": str(row.get("category") or ""),
            "title": str(row.get("title") or ""),
            "reason": str(row.get("reason") or ""),
            "next_command": str(row.get("next_command") or ""),
        }
        for row in rows
        if str(row.get("priority") or "").upper() == priority
    ]


def _dict_rows(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(row) for row in value if isinstance(row, dict)]


def _read_existing(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) and payload.get("schema") == SCHEMA else None


def _without_generated_at(payload: dict[str, Any]) -> dict[str, Any]:
    stripped = dict(payload)
    stripped.pop("generated_at", None)
    return stripped


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


__all__ = [
    "SCHEMA",
    "DEFAULT_RELATIVE_PATH",
    "collect_open_state",
    "render_json",
    "write_open_state",
]
