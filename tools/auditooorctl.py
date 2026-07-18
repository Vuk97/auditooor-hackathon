#!/usr/bin/env python3
"""Small local auditooor control-plane CLI.

Most subcommands are read-only planners.  Commands that write or execute are
explicitly gated by flags such as ``--write`` or ``--execute`` and remain local.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
REPO_ROOT = ROOT.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from control.candidate_normalize import discover_normalized_candidate_rows  # noqa: E402
from control.candidates import discover_candidates, paste_ready_blockers  # noqa: E402
from control.deployment_timeline import (  # noqa: E402
    collect_deployment_timeline,
    render_json as render_deployment_timeline_json,
    write_timeline,
)
from control.dirty import classify_git_status, list_worktrees  # noqa: E402
from control.gaps import render_human as render_gaps_human, score_known_capability_gaps  # noqa: E402
from control.handoff import render_handoff  # noqa: E402
from control.next_actions import rank_next_actions  # noqa: E402
from control.open_state import collect_open_state, render_json as render_open_state_json, write_open_state  # noqa: E402
from control.providers import build_provider_tasks, calibrate_provider_tasks  # noqa: E402
from control.report import (  # noqa: E402
    build_control_report,
    render_json as render_report_json,
    render_markdown as render_report_markdown,
)
from control.run_gate import build_run_gate_plan, execute_run_gate, write_run_gate_manifest  # noqa: E402
from control.runner import build_execution_plan, write_execution_plan  # noqa: E402
from control.runs import discover_run_rows, summarize_runs  # noqa: E402
from control.state import collect_state, render_json as render_state_json, write_state  # noqa: E402
from control.status import collect_status, render_human, render_json  # noqa: E402
from control.workpacks import (  # noqa: E402
    build_workpack_report,
    render_json as render_workpacks_json,
    render_markdown as render_workpacks_markdown,
)


def _json(payload: Any) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="auditooorctl")
    subparsers = parser.add_subparsers(dest="command", required=True)

    status = subparsers.add_parser(
        "status",
        help="print read-only workspace readiness and artifact status",
    )
    status.add_argument("workspace", help="workspace path to inspect")
    status.add_argument("--json", action="store_true", help="emit JSON")

    candidates = subparsers.add_parser(
        "candidates",
        help="print normalized candidate registry and paste-ready blockers",
    )
    candidates.add_argument("workspace", help="workspace path to inspect")
    candidates.add_argument(
        "--normalize",
        action="store_true",
        help="normalize wave promotion_candidates.json artifacts instead of the control registry",
    )
    candidates.add_argument("--json", action="store_true", help="emit JSON")

    runs = subparsers.add_parser(
        "runs",
        help="print normalized run/proof manifest inventory",
    )
    runs.add_argument("workspace", help="workspace path to inspect")
    runs.add_argument("--json", action="store_true", help="emit JSON")

    dirty = subparsers.add_parser(
        "dirty",
        help="classify dirty files and registered worktrees without cleanup",
    )
    dirty.add_argument("repo", help="git repository path to inspect")
    dirty.add_argument("--json", action="store_true", help="emit JSON")

    next_cmd = subparsers.add_parser(
        "next",
        help="rank fail-closed next actions from status, candidate, and run state",
    )
    next_cmd.add_argument("workspace", help="workspace path to inspect")
    next_cmd.add_argument("--json", action="store_true", help="emit JSON")

    gaps = subparsers.add_parser(
        "gaps",
        help="print evidence-backed known capability gap rows from snapshot state",
    )
    gaps.add_argument("workspace", help="workspace path to inspect")
    gaps.add_argument("--json", action="store_true", help="emit JSON")

    providers = subparsers.add_parser(
        "providers",
        help="print provider-routed tasks from candidates, runs, and next actions",
    )
    providers.add_argument("workspace", help="workspace path to inspect")
    providers.add_argument("--json", action="store_true", help="emit JSON")

    workpacks = subparsers.add_parser(
        "workpacks",
        help="build bounded read-only provider workpacks from snapshot/gaps/providers",
    )
    workpacks.add_argument("workspace", help="workspace path to inspect")
    workpacks.add_argument("--out", help="optional path to write the JSON workpack report")
    workpacks.add_argument("--json", action="store_true", help="emit JSON")

    plan = subparsers.add_parser(
        "plan",
        help="build a dry-run execution plan from ranked next actions",
    )
    plan.add_argument("workspace", help="workspace path to inspect")
    plan.add_argument("--out", help="optional path to write the JSON dry-run plan")
    plan.add_argument("--json", action="store_true", help="emit JSON")

    report = subparsers.add_parser(
        "report",
        help="render a control-plane takeover report from snapshot/gaps/providers/plan",
    )
    report.add_argument("workspace", help="workspace path to inspect")
    report.add_argument("--json", action="store_true", help="emit JSON")

    open_state = subparsers.add_parser(
        "open",
        help="build or explicitly write durable .auditooor/control/state.json",
    )
    open_state.add_argument("workspace", help="workspace path to inspect")
    open_state.add_argument("--write", action="store_true", help="write state.json instead of previewing only")
    open_state.add_argument("--out", help="optional state output path when --write is set")
    open_state.add_argument("--json", action="store_true", help="emit JSON")

    run_gate = subparsers.add_parser(
        "run-gate",
        help="build or explicitly execute an upstream-equivalent gate plan for one candidate",
    )
    run_gate.add_argument("workspace", help="workspace path to inspect")
    run_gate.add_argument("--candidate-file", help="candidate JSON file to gate")
    run_gate.add_argument("--candidate-id", help="candidate id to resolve from a candidate report/registry")
    run_gate.add_argument("--candidate-report", help="normalized candidate report JSON")
    run_gate.add_argument("--out", help="optional path to write the run-gate manifest")
    run_gate.add_argument("--execute", action="store_true", help="explicitly execute the gate command")
    run_gate.add_argument("--json", action="store_true", help="emit JSON")

    timeline = subparsers.add_parser(
        "deployment-timeline",
        help="build an offline audit-pin vs live-deployment timeline packet",
    )
    timeline.add_argument("workspace", help="workspace path to inspect")
    timeline.add_argument("--asset", help="asset name label")
    timeline.add_argument("--repo", help="local asset git repo path")
    timeline.add_argument("--bug-commit", help="candidate bug-introducing commit")
    timeline.add_argument("--deployment-root", action="append", default=[], help="deployment evidence root")
    timeline.add_argument("--network", default="base", help="network label for follow-up commands")
    timeline.add_argument("--out", help="optional path to write the timeline JSON")
    timeline.add_argument("--json", action="store_true", help="emit JSON")

    handoff = subparsers.add_parser(
        "handoff",
        help="render a concise takeover packet for another operator",
    )
    handoff.add_argument("workspace", help="workspace path to inspect")
    handoff.add_argument("--audience", default="claude", help="handoff audience label")

    snapshot = subparsers.add_parser(
        "snapshot",
        help="emit a full read-only control-plane state snapshot",
    )
    snapshot.add_argument("workspace", help="workspace path to inspect")
    snapshot.add_argument("--out", help="optional path to write the JSON snapshot")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "status":
        snapshot = collect_status(args.workspace)
        # Inject vault freshness into snapshot for display
        vault_stamp_path = REPO_ROOT / "obsidian-vault" / ".last_sync.json"
        if vault_stamp_path.exists():
            try:
                vault_stamp = json.loads(vault_stamp_path.read_text())
                snapshot["vault_status"] = {
                    "last_sync": vault_stamp.get("generated", "unknown"),
                    "total_notes": vault_stamp.get("total_notes", 0),
                    "refresh_command": "make vault-refresh",
                }
            except Exception:
                pass
        else:
            snapshot["vault_status"] = {
                "last_sync": None,
                "total_notes": 0,
                "refresh_command": "make vault-refresh  # vault not yet built",
            }
        if args.json:
            sys.stdout.write(render_json(snapshot))
        else:
            human_out = render_human(snapshot)
            vault_info = snapshot.get("vault_status", {})
            vault_line = (
                f"\nvault: last_sync={vault_info.get('last_sync') or 'never'}"
                f"  notes={vault_info.get('total_notes', 0)}"
                f"  cmd={vault_info.get('refresh_command', 'make vault-refresh')}"
            )
            sys.stdout.write(human_out + vault_line + "\n")
        return 0
    if args.command == "candidates":
        if args.normalize:
            rows = discover_normalized_candidate_rows(args.workspace)
            payload = {
                "schema": "auditooor.control.normalized_candidates.v1",
                "workspace": str(Path(args.workspace).expanduser()),
                "candidate_count": len(rows),
                "candidates": rows,
            }
            if args.json:
                sys.stdout.write(_json(payload))
            else:
                sys.stdout.write(_render_normalized_candidates(rows) + "\n")
            return 0
        rows = []
        for candidate in discover_candidates(args.workspace):
            row = candidate.to_dict()
            row["paste_ready_blockers"] = paste_ready_blockers(candidate)
            rows.append(row)
        if args.json:
            sys.stdout.write(_json({"schema": "auditooor.control.candidates.v1", "candidates": rows}))
        else:
            sys.stdout.write(_render_candidates(rows) + "\n")
        return 0
    if args.command == "runs":
        summary = summarize_runs(args.workspace)
        if args.json:
            sys.stdout.write(_json(summary))
        else:
            sys.stdout.write(_render_runs(summary) + "\n")
        return 0
    if args.command == "dirty":
        payload = {
            "schema": "auditooor.control.dirty.v1",
            "repo": str(Path(args.repo).expanduser()),
            "dirty_files": classify_git_status(args.repo),
            "worktrees": list_worktrees(args.repo),
        }
        if args.json:
            sys.stdout.write(_json(payload))
        else:
            sys.stdout.write(_render_dirty(payload) + "\n")
        return 0
    if args.command == "next":
        status = collect_status(args.workspace)
        candidates = [
            {**candidate.to_dict(), "paste_ready_blockers": paste_ready_blockers(candidate)}
            for candidate in discover_candidates(args.workspace)
        ]
        runs = discover_run_rows(args.workspace)
        actions = rank_next_actions(args.workspace, status, candidates, runs)
        if args.json:
            sys.stdout.write(
                _json(
                    {
                        "schema": "auditooor.control.next_actions.v1",
                        "workspace": str(Path(args.workspace).expanduser()),
                        "actions": actions,
                    }
                )
            )
        else:
            sys.stdout.write(_render_next(actions) + "\n")
        return 0
    if args.command == "gaps":
        snapshot = collect_state(args.workspace)
        report = score_known_capability_gaps(
            snapshot["workspace"],
            status=snapshot.get("status") or {},
            candidates=snapshot.get("candidates") or [],
            runs=(snapshot.get("runs") or {}).get("rows") or [],
            next_actions=snapshot.get("next_actions") or [],
        )
        if args.json:
            sys.stdout.write(_json(report))
        else:
            sys.stdout.write(render_gaps_human(report) + "\n")
        return 0
    if args.command == "providers":
        snapshot = collect_state(args.workspace)
        tasks = calibrate_provider_tasks(
            build_provider_tasks(
                snapshot["workspace"],
                candidates=snapshot.get("candidates") or [],
                runs=(snapshot.get("runs") or {}).get("rows") or [],
                next_actions=snapshot.get("next_actions") or [],
            )
        )
        payload = {
            "schema": "auditooor.control.providers.v1",
            "workspace": snapshot["workspace"],
            "task_count": len(tasks),
            "tasks": tasks,
        }
        if args.json:
            sys.stdout.write(_json(payload))
        else:
            sys.stdout.write(_render_providers(tasks) + "\n")
        return 0
    if args.command == "workpacks":
        snapshot = collect_state(args.workspace)
        gaps_report = score_known_capability_gaps(
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
        report = build_workpack_report(
            snapshot["workspace"],
            provider_tasks=provider_tasks,
            gap_rows=gaps_report,
        )
        if args.out:
            out = Path(args.out).expanduser()
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(render_workpacks_json(report), encoding="utf-8")
        if args.json:
            sys.stdout.write(render_workpacks_json(report))
        else:
            sys.stdout.write(render_workpacks_markdown(report))
        return 0
    if args.command == "plan":
        snapshot = collect_state(args.workspace)
        if args.out:
            payload = write_execution_plan(
                args.out,
                snapshot["workspace"],
                snapshot.get("next_actions") or [],
                cwd=Path.cwd(),
            )
        else:
            payload = build_execution_plan(
                snapshot["workspace"],
                snapshot.get("next_actions") or [],
                cwd=Path.cwd(),
            )
        if args.json:
            sys.stdout.write(_json(payload))
        else:
            sys.stdout.write(_render_plan(payload) + "\n")
        return 0
    if args.command == "report":
        snapshot = collect_state(args.workspace)
        gaps_report = score_known_capability_gaps(
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
        execution_plan = build_execution_plan(
            snapshot["workspace"],
            snapshot.get("next_actions") or [],
            cwd=Path.cwd(),
        )
        report_payload = build_control_report(
            snapshot,
            gaps=gaps_report,
            provider_tasks=provider_tasks,
            execution_plan=execution_plan,
        )
        if args.json:
            sys.stdout.write(render_report_json(report_payload))
        else:
            sys.stdout.write(render_report_markdown(report_payload))
        return 0
    if args.command == "open":
        if args.write:
            payload = write_open_state(args.workspace, out_path=args.out, cwd=Path.cwd())
        else:
            payload = {"path": None, "state": collect_open_state(args.workspace, cwd=Path.cwd())}
        if args.json:
            sys.stdout.write(_json(payload))
        else:
            sys.stdout.write(_render_open_state(payload) + "\n")
        return 0
    if args.command == "run-gate":
        if args.execute:
            payload = execute_run_gate(
                args.workspace,
                candidate_file=args.candidate_file,
                candidate_id=args.candidate_id,
                candidate_report=args.candidate_report,
                cwd=Path.cwd(),
            )
        else:
            payload = build_run_gate_plan(
                args.workspace,
                candidate_file=args.candidate_file,
                candidate_id=args.candidate_id,
                candidate_report=args.candidate_report,
                cwd=Path.cwd(),
            )
        if args.out:
            write_run_gate_manifest(args.out, payload)
        if args.json:
            sys.stdout.write(_json(payload))
        else:
            sys.stdout.write(_render_run_gate(payload) + "\n")
        return 0
    if args.command == "deployment-timeline":
        payload = collect_deployment_timeline(
            args.workspace,
            asset=args.asset,
            repo_path=args.repo,
            bug_commit=args.bug_commit,
            deployment_roots=args.deployment_root,
            network=args.network,
        )
        if args.out:
            write_timeline(payload, args.out)
        if args.json:
            sys.stdout.write(render_deployment_timeline_json(payload))
        else:
            sys.stdout.write(_render_deployment_timeline(payload) + "\n")
        return 0
    if args.command == "handoff":
        status = collect_status(args.workspace)
        candidates = [
            {**candidate.to_dict(), "paste_ready_blockers": paste_ready_blockers(candidate)}
            for candidate in discover_candidates(args.workspace)
        ]
        runs = discover_run_rows(args.workspace)
        actions = rank_next_actions(args.workspace, status, candidates, runs)
        sys.stdout.write(render_handoff(args.workspace, status, candidates, runs, actions, audience=args.audience))
        return 0
    if args.command == "snapshot":
        snapshot = collect_state(args.workspace)
        if args.out:
            write_state(snapshot, args.out)
        sys.stdout.write(render_state_json(snapshot))
        return 0
    parser.error(f"unknown command: {args.command}")
    return 2


def _render_candidates(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "candidates: none"
    lines = [f"candidates: {len(rows)}"]
    for row in rows:
        blockers = row.get("paste_ready_blockers") or []
        blockers_text = "paste-ready" if not blockers else "blocked: " + ", ".join(blockers)
        lines.append(
            "{id}: {severity} / {status} / proof={proof} / {blockers}".format(
                id=row.get("id") or "candidate",
                severity=row.get("severity") or "unrated",
                status=row.get("status") or "unknown",
                proof=row.get("proof_state") or "unknown",
                blockers=blockers_text,
            )
        )
    return "\n".join(lines)


def _render_normalized_candidates(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "normalized candidates: none"
    lines = [f"normalized candidates: {len(rows)}"]
    for row in rows[:20]:
        errors = row.get("errors") or []
        suffix = "" if not errors else " errors=" + ",".join(str(error) for error in errors[:3])
        lines.append(
            "{id}: {severity} / {status} / proof={proof} / source={source}{suffix}".format(
                id=row.get("id") or "candidate",
                severity=row.get("severity") or "unrated",
                status=row.get("status") or "unknown",
                proof=row.get("proof_state") or "unknown",
                source=row.get("source_file") or "",
                suffix=suffix,
            )
        )
    if len(rows) > 20:
        lines.append(f"... {len(rows) - 20} more normalized candidates")
    return "\n".join(lines)


def _render_runs(summary: dict[str, Any]) -> str:
    proof = summary.get("proof_counted", {})
    lines = [
        f"run artifacts: {summary.get('artifact_count', 0)}",
        f"proof-counted: {proof.get('true', 0)}",
    ]
    for state, count in (summary.get("counts_by_execution_state") or {}).items():
        lines.append(f"{state}: {count}")
    return "\n".join(lines)


def _render_dirty(payload: dict[str, Any]) -> str:
    dirty_files = payload.get("dirty_files") or []
    worktrees = payload.get("worktrees") or []
    lines = [f"dirty files: {len(dirty_files)}", f"registered worktrees: {len(worktrees)}"]
    for row in dirty_files[:12]:
        lines.append(f"{row.get('status')}: {row.get('path')} ({row.get('role')})")
    if len(dirty_files) > 12:
        lines.append(f"... {len(dirty_files) - 12} more dirty rows")
    return "\n".join(lines)


def _render_next(actions: list[dict[str, Any]]) -> str:
    lines = [f"next actions: {len(actions)}"]
    for action in actions[:12]:
        lines.append(
            "P{priority}: {reason} -> {command}".format(
                priority=action.get("priority"),
                reason=action.get("reason"),
                command=action.get("command"),
            )
        )
    if len(actions) > 12:
        lines.append(f"... {len(actions) - 12} more actions")
    return "\n".join(lines)


def _render_providers(tasks: list[dict[str, Any]]) -> str:
    if not tasks:
        return "provider tasks: none"
    lines = [f"provider tasks: {len(tasks)}"]
    for task in tasks[:12]:
        blockers = task.get("calibration_blockers") or []
        status = task.get("calibration_status") or "unknown"
        if blockers:
            status = f"{status}: " + ", ".join(str(blocker) for blocker in blockers[:3])
        lines.append(
            "P{priority}: {provider}/{kind} {subject} -> {status}".format(
                priority=task.get("priority"),
                provider=task.get("provider"),
                kind=task.get("task_kind"),
                subject=task.get("subject_id"),
                status=status,
            )
        )
    if len(tasks) > 12:
        lines.append(f"... {len(tasks) - 12} more tasks")
    return "\n".join(lines)


def _render_plan(payload: dict[str, Any]) -> str:
    commands = payload.get("commands") or []
    counts = payload.get("counts_by_classification") or {}
    lines = [
        f"dry-run commands: {payload.get('command_count', len(commands))}",
        "classes: "
        + ", ".join(f"{key}={value}" for key, value in sorted(counts.items())),
    ]
    for row in commands[:12]:
        blockers = row.get("blockers") or []
        suffix = "" if not blockers else " blocked: " + ", ".join(str(blocker) for blocker in blockers)
        lines.append(f"{row.get('classification')}: {row.get('command')}{suffix}")
    if len(commands) > 12:
        lines.append(f"... {len(commands) - 12} more commands")
    return "\n".join(lines)


def _render_open_state(payload: dict[str, Any]) -> str:
    state = payload.get("state") or {}
    summary = state.get("snapshot_summary") or {}
    readiness = summary.get("readiness_status") or "unknown"
    path = payload.get("path") or "(preview only)"
    return "\n".join(
        [
            f"open-state: {state.get('schema') or 'unknown'}",
            f"workspace: {state.get('workspace') or ''}",
            f"readiness: {readiness}",
            f"path: {path}",
        ]
    )


def _render_run_gate(payload: dict[str, Any]) -> str:
    blockers = payload.get("blocked_reasons") or payload.get("execution_blockers") or []
    lines = [
        f"run-gate: {payload.get('candidate_id') or 'candidate'}",
        f"dry-run: {payload.get('dry_run')}",
        f"would_execute: {payload.get('would_execute')}",
        f"command: {payload.get('command_text') or (payload.get('command') or {}).get('text') or ''}",
    ]
    if blockers:
        lines.append("blocked: " + ", ".join(str(blocker) for blocker in blockers))
    return "\n".join(lines)


def _render_deployment_timeline(payload: dict[str, Any]) -> str:
    asset = payload.get("asset") or {}
    bug = payload.get("bug") or {}
    risk = payload.get("risk_window") or {}
    flags = payload.get("uncertainty_flags") or []
    lines = [
        f"deployment timeline: {asset.get('name') or 'asset'}",
        f"asset pin: {(asset.get('pin') or {}).get('short_commit') or 'unknown'}",
        f"bug commit: {bug.get('short_commit') or bug.get('introduced_commit') or 'unknown'}",
        f"risk status: {risk.get('status') or 'unknown'}",
    ]
    if flags:
        lines.append("uncertainty: " + ", ".join(str(flag) for flag in flags[:8]))
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
