#!/usr/bin/env python3
"""Markdown and JSON-friendly control-plane takeover reports.

This module is intentionally a pure renderer. It accepts already-collected
snapshot, gap, provider-task, and dry-run execution-plan packets and composes a
concise handoff for an operator or Claude worker. It does not inspect the
filesystem, execute commands, or call external services.
"""
from __future__ import annotations

import json
from collections import Counter
from typing import Any, Iterable


SCHEMA = "auditooor.control.report.v1"

PROOF_BOUNDARY = (
    "Only durable local artifacts with executed, proof_counted run rows count as "
    "submission proof. Provider output, dry-run commands, generated scaffolds, "
    "scanner summaries, and this report are planning context until locally "
    "executed and recorded with impact assertions."
)


def build_control_report(
    snapshot: dict[str, Any],
    *,
    gaps: dict[str, Any] | Iterable[dict[str, Any]] | None = None,
    provider_tasks: Iterable[dict[str, Any]] | None = None,
    execution_plan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return a JSON-serializable takeover packet from control-plane inputs."""

    gap_rows = _gap_rows(gaps)
    candidate_blockers = _candidate_blockers(snapshot.get("candidates") or [])
    proof_runs = _proof_counted_runs(snapshot.get("runs") or {})
    p0_gaps = _priority_gaps(gap_rows, "P0")
    p1_gaps = _priority_gaps(gap_rows, "P1")
    provider_summary = _provider_routing(provider_tasks or [])
    dry_run_plan = _dry_run_plan(execution_plan or {})
    readiness = _readiness(snapshot, candidate_blockers, proof_runs, p0_gaps, p1_gaps)

    return {
        "schema": SCHEMA,
        "workspace": str(snapshot.get("workspace") or ""),
        "target_name": str(snapshot.get("target_name") or ""),
        "generated_at": snapshot.get("generated_at"),
        "readiness": readiness,
        "candidate_blockers": candidate_blockers,
        "proof_counted_runs": proof_runs,
        "p0_gaps": p0_gaps,
        "p1_gaps": p1_gaps,
        "provider_task_routing": provider_summary,
        "dry_run_command_plan": dry_run_plan,
        "proof_boundary": PROOF_BOUNDARY,
    }


def render_json(report: dict[str, Any]) -> str:
    """Render a report packet as stable pretty JSON."""

    return json.dumps(report, indent=2, sort_keys=True) + "\n"


def render_markdown(report: dict[str, Any]) -> str:
    """Render a report packet as a concise Markdown takeover packet."""

    target = _text(report.get("target_name")) or _text(report.get("workspace")) or "workspace"
    readiness = report.get("readiness") if isinstance(report.get("readiness"), dict) else {}
    lines = [
        f"# Control Takeover Packet: {target}",
        "",
        "## Readiness",
        f"- status: {_text(readiness.get('status')) or 'unknown'}",
    ]
    for reason in _list(readiness.get("reasons")):
        lines.append(f"- blocker: {reason}")
    if not _list(readiness.get("reasons")):
        lines.append("- blocker: none recorded")

    lines.extend(["", "## Candidate Blockers"])
    candidate_blockers = _list_of_dicts(report.get("candidate_blockers"))
    if candidate_blockers:
        for row in candidate_blockers:
            blockers = ", ".join(_list(row.get("blockers"))) or "unspecified"
            lines.append(f"- {row.get('id')}: {blockers}")
    else:
        lines.append("- none recorded")

    proof = report.get("proof_counted_runs") if isinstance(report.get("proof_counted_runs"), dict) else {}
    lines.extend(
        [
            "",
            "## Proof-Counted Runs",
            f"- count: {int(proof.get('count') or 0)}",
        ]
    )
    proof_rows = _list_of_dicts(proof.get("rows"))
    if proof_rows:
        for row in proof_rows:
            lines.append(f"- {row.get('tool')}: {row.get('artifact_path')}")
    else:
        lines.append("- none recorded")

    lines.extend(["", "## P0/P1 Gaps"])
    for label in ("p0_gaps", "p1_gaps"):
        rows = _list_of_dicts(report.get(label))
        lines.append(f"- {label.replace('_', ' ').upper()}: {len(rows)}")
        for row in rows:
            lines.append(f"  - {row.get('id')}: {row.get('title') or row.get('reason')}")

    routing = report.get("provider_task_routing") if isinstance(report.get("provider_task_routing"), dict) else {}
    lines.extend(["", "## Provider Task Routing"])
    by_provider = routing.get("by_provider") if isinstance(routing.get("by_provider"), dict) else {}
    if by_provider:
        for provider in sorted(by_provider):
            row = by_provider[provider]
            lines.append(
                "- {provider}: {count} task(s), {blocked} blocked, kinds={kinds}".format(
                    provider=provider,
                    count=int(row.get("count") or 0),
                    blocked=int(row.get("blocked") or 0),
                    kinds=", ".join(_list(row.get("task_kinds"))) or "none",
                )
            )
    else:
        lines.append("- none recorded")

    plan = report.get("dry_run_command_plan") if isinstance(report.get("dry_run_command_plan"), dict) else {}
    lines.extend(["", "## Dry-Run Command Plan"])
    lines.append(f"- command_count: {int(plan.get('command_count') or 0)}")
    for row in _list_of_dicts(plan.get("commands")):
        lines.append(f"- [{row.get('classification')}] {row.get('command')}")
        for blocker in _list(row.get("blockers")):
            lines.append(f"  - blocked: {blocker}")

    lines.extend(["", "## Proof Boundary", _text(report.get("proof_boundary")) or PROOF_BOUNDARY])
    return "\n".join(lines) + "\n"


def _readiness(
    snapshot: dict[str, Any],
    candidate_blockers: list[dict[str, Any]],
    proof_runs: dict[str, Any],
    p0_gaps: list[dict[str, Any]],
    p1_gaps: list[dict[str, Any]],
) -> dict[str, Any]:
    reasons: list[str] = []
    status_packet = snapshot.get("status") if isinstance(snapshot.get("status"), dict) else {}
    status_readiness = _status_readiness(status_packet)

    for key, value in status_readiness.items():
        if value not in {"ready", "present", "executed", "executed_unknown"}:
            reasons.append(f"{key}_readiness={value}")
    if p0_gaps:
        reasons.append(f"p0_gaps={len(p0_gaps)}")
    if candidate_blockers:
        reasons.append(f"candidate_blockers={len(candidate_blockers)}")
    if int(proof_runs.get("count") or 0) == 0:
        reasons.append("proof_counted_runs=0")

    if p0_gaps or candidate_blockers or int(proof_runs.get("count") or 0) == 0:
        status = "blocked"
    elif p1_gaps:
        status = "needs_p1_closure"
    else:
        status = "ready_for_codex_gate"

    return {
        "status": status,
        "reasons": _stable_unique(reasons),
        "status_readiness": status_readiness,
        "p0_gap_count": len(p0_gaps),
        "p1_gap_count": len(p1_gaps),
        "candidate_blocker_count": len(candidate_blockers),
        "proof_counted_run_count": int(proof_runs.get("count") or 0),
    }


def _status_readiness(status: dict[str, Any]) -> dict[str, str]:
    readiness = status.get("readiness")
    if not isinstance(readiness, dict):
        return {}
    out: dict[str, str] = {}
    for key, value in sorted(readiness.items()):
        if isinstance(value, dict):
            out[str(key)] = _text(value.get("status")) or "unknown"
        else:
            out[str(key)] = _text(value) or "unknown"
    return out


def _candidate_blockers(candidates: Iterable[Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        blockers = _list(candidate.get("paste_ready_blockers") or candidate.get("blockers"))
        if not blockers:
            continue
        rows.append(
            {
                "id": _text(candidate.get("id") or candidate.get("candidate_id") or "candidate"),
                "title": _text(candidate.get("title") or candidate.get("claim")),
                "status": _text(candidate.get("status")),
                "severity": _text(candidate.get("severity")),
                "blockers": blockers,
            }
        )
    return sorted(rows, key=lambda row: (row["id"], row["title"]))


def _proof_counted_runs(runs: dict[str, Any]) -> dict[str, Any]:
    rows = [
        {
            "tool": _text(row.get("tool")),
            "artifact_path": _text(row.get("artifact_path")),
            "execution_state": _text(row.get("execution_state")),
            "warnings": _list(row.get("warnings")),
        }
        for row in _list_of_dicts(runs.get("rows"))
        if row.get("proof_counted") is True
    ]
    by_tool = Counter(row["tool"] or "unknown" for row in rows)
    return {
        "count": len(rows),
        "by_tool": dict(sorted(by_tool.items())),
        "rows": sorted(rows, key=lambda row: (row["tool"], row["artifact_path"])),
    }


def _gap_rows(gaps: dict[str, Any] | Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    if gaps is None:
        return []
    if isinstance(gaps, dict):
        return _list_of_dicts(gaps.get("rows"))
    return _list_of_dicts(gaps)


def _priority_gaps(gaps: list[dict[str, Any]], priority: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in gaps:
        if _text(row.get("priority")).upper() != priority:
            continue
        rows.append(
            {
                "id": _text(row.get("id")),
                "category": _text(row.get("category")),
                "title": _text(row.get("title")),
                "reason": _text(row.get("reason")),
                "evidence": _list(row.get("evidence"))[:5],
                "next_command": _text(row.get("next_command")),
                "stop_condition": _text(row.get("stop_condition")),
            }
        )
    return sorted(rows, key=lambda row: (row["category"], row["id"]))


def _provider_routing(tasks: Iterable[dict[str, Any]]) -> dict[str, Any]:
    by_provider: dict[str, dict[str, Any]] = {}
    rows: list[dict[str, Any]] = []
    for task in _list_of_dicts(tasks):
        provider = _text(task.get("provider")) or "unknown"
        kind = _text(task.get("task_kind")) or "task"
        status = _text(task.get("calibration_status")) or ("blocked" if _list(task.get("blockers")) else "ready")
        provider_row = by_provider.setdefault(
            provider,
            {"count": 0, "blocked": 0, "task_kinds": [], "top_tasks": []},
        )
        provider_row["count"] += 1
        if status == "blocked":
            provider_row["blocked"] += 1
        if kind not in provider_row["task_kinds"]:
            provider_row["task_kinds"].append(kind)
        if len(provider_row["top_tasks"]) < 3:
            provider_row["top_tasks"].append(_text(task.get("id")) or _text(task.get("title")))
        rows.append(
            {
                "id": _text(task.get("id")),
                "provider": provider,
                "task_kind": kind,
                "subject_id": _text(task.get("subject_id")),
                "title": _text(task.get("title")),
                "priority": _int(task.get("priority")),
                "calibration_status": status,
                "blockers": _stable_unique(_list(task.get("calibration_blockers")) + _list(task.get("blockers"))),
                "proof_boundary": _text(task.get("proof_boundary")),
            }
        )
    for provider_row in by_provider.values():
        provider_row["task_kinds"] = sorted(provider_row["task_kinds"])
        provider_row["top_tasks"] = [item for item in provider_row["top_tasks"] if item]
    return {
        "task_count": len(rows),
        "by_provider": dict(sorted(by_provider.items())),
        "tasks": sorted(rows, key=lambda row: (row["priority"], row["provider"], row["id"]))[:12],
    }


def _dry_run_plan(plan: dict[str, Any]) -> dict[str, Any]:
    commands: list[dict[str, Any]] = []
    for row in _list_of_dicts(plan.get("commands")):
        commands.append(
            {
                "command": _text(row.get("command")),
                "classification": _text(row.get("classification")),
                "command_hash": _text(row.get("command_hash")),
                "blockers": _list(row.get("blockers")),
            }
        )
    return {
        "dry_run": bool(plan.get("dry_run", True)),
        "would_execute": bool(plan.get("would_execute", False)),
        "command_count": int(plan.get("command_count") or len(commands)),
        "counts_by_classification": dict(plan.get("counts_by_classification") or {}),
        "commands": commands,
    }


def _list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    if isinstance(value, (list, tuple, set)):
        return [_text(item) for item in value if _text(item)]
    return [_text(value)] if _text(value) else []


def _list_of_dicts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, (list, tuple)):
        return []
    return [dict(row) for row in value if isinstance(row, dict)]


def _stable_unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        text = _text(value)
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


__all__ = [
    "SCHEMA",
    "PROOF_BOUNDARY",
    "build_control_report",
    "render_json",
    "render_markdown",
]
