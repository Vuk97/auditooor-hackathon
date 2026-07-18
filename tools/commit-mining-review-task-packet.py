#!/usr/bin/env python3
"""Emit bounded advisory review-task packets from source-disposition rows."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parents[1]
DEFAULT_DATE = "2026-05-05"
DEFAULT_IN = REPO / "reports" / f"commit_mining_source_disposition_{DEFAULT_DATE}.json"
DEFAULT_OUT = REPO / "reports" / f"commit_mining_review_task_packet_{DEFAULT_DATE}.json"
DEFAULT_MD = REPO / "docs" / f"COMMIT_MINING_REVIEW_TASK_PACKET_{DEFAULT_DATE}.md"
SCHEMA = "auditooor.commit_mining_review_task_packet.v1"
TASK_SCHEMA = "auditooor.commit_mining_review_task.v1"
INPUT_SCHEMA = "auditooor.commit_mining_source_disposition.v1"
DEFAULT_MAX_TASKS = 3
DEFAULT_TERMINAL_EVIDENCE_GLOBS = (
    "reports/*_proof_execution_*.json",
    "reports/*_detector_*.json",
    "reports/*_source_review_*.json",
)
TERMINAL_DISPOSITION_MARKERS = (
    "blocked_for_exploitability_or_submission",
    "regression_only",
    "source_review_only",
    "killed",
    "duplicate",
    "oos",
    "not_a_bug",
    "false_positive",
)
ELIGIBLE_ACTIONS = (
    "narrow_consensus_patch_review",
    "prover_service_review",
)
ACTION_LANES = {
    "narrow_consensus_patch_review": "bounded_consensus_patch_review_task",
    "prover_service_review": "bounded_prover_service_review_task",
}
ACTION_LABELS = {
    "narrow_consensus_patch_review": "Narrow consensus patch review",
    "prover_service_review": "Prover-service review",
}
DISALLOWED_CLAIMS = (
    "exploitability finding",
    "severity finding",
    "impact finding",
    "detector promotion finding",
    "submission readiness finding",
)
PROOF_BOUNDARY = (
    "This packet only routes bounded follow-up review tasks. It does not make "
    "exploitability, severity, impact, detector-promotion, or submission-readiness findings."
)


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object: {path}")
    return payload


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _strings(value: Any, *, limit: int | None = None) -> list[str]:
    rows = [str(item) for item in _as_list(value) if str(item or "").strip()]
    return rows[:limit] if limit is not None else rows


def _rel(path: Path, repo: Path) -> str:
    try:
        return path.resolve().relative_to(repo.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def _stable_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", value.strip()).strip("-")
    return slug or "review-task"


def _deterministic_generated_at(payload: dict[str, Any], input_path: Path | None) -> str:
    raw = str(payload.get("generated_at_utc") or "").strip()
    if raw:
        return raw
    raw = str(payload.get("date") or "").strip()
    if raw:
        return f"{raw}T00:00:00+00:00"
    if input_path is not None:
        match = re.search(r"(\d{4}-\d{2}-\d{2})", input_path.name)
        if match:
            return f"{match.group(1)}T00:00:00+00:00"
    return f"{DEFAULT_DATE}T00:00:00+00:00"


def _review_objective(action_type: str) -> str:
    if action_type == "narrow_consensus_patch_review":
        return (
            "Inspect only the bounded consensus patch files and directories, record "
            "source-review observations, and split any later proof work into a separate task."
        )
    if action_type == "prover_service_review":
        return (
            "Inspect only the bounded prover-service files and directories, record "
            "service-boundary observations, and split any later proof work into a separate task."
        )
    raise ValueError(f"unsupported action type: {action_type}")


def _allowed_actions(action_type: str) -> list[str]:
    if action_type == "narrow_consensus_patch_review":
        return [
            "inspect the bounded consensus patch files and directories",
            "record advisory source-review notes about consensus or state-transition behavior",
            "queue any later proof work as a separate follow-up task",
        ]
    if action_type == "prover_service_review":
        return [
            "inspect the bounded prover-service files and directories",
            "record advisory source-review notes about proof, hashing, storage, or service boundaries",
            "queue any later proof work as a separate follow-up task",
        ]
    raise ValueError(f"unsupported action type: {action_type}")


def _review_prompts(action_type: str, focus: list[str]) -> list[str]:
    prompts: list[str] = []
    if action_type == "narrow_consensus_patch_review":
        prompts.extend(
            [
                "What changed in fork-gating, consensus inputs, or state-transition assumptions inside the bounded files?",
                "Do the bounded edits alter validation, serialization, or configuration behavior that later proof work should isolate?",
            ]
        )
    elif action_type == "prover_service_review":
        prompts.extend(
            [
                "What changed at the prover-service boundary, especially around proof material, backends, storage, or networking?",
                "Do the bounded edits add tests or fixtures that narrow the later proof questions without answering them outright?",
            ]
        )
    if "state_transition" in focus:
        prompts.append("Which state-transition preconditions or invariants should a later proof task verify separately?")
    elif "proof_or_hashing" in focus:
        prompts.append("Which proof, hashing, or backend assumptions should a later proof task verify separately?")
    elif focus:
        prompts.append(
            f"Which {focus[0]} assumptions inside the bounded files should be tracked for a later proof-oriented follow-up?"
        )
    else:
        prompts.append("Which bounded-file assumptions should be preserved for any later proof-oriented follow-up?")
    return prompts[:3]


def _task_sort_key(item: dict[str, Any]) -> tuple[int, str, str]:
    queue_index = item.get("queue_index")
    try:
        order = int(queue_index)
    except (TypeError, ValueError):
        order = 10**9
    return (
        order,
        str(item.get("task_id") or ""),
        str(item.get("disposition_id") or ""),
    )


def _skip_row(item: dict[str, Any], reason: str) -> dict[str, Any]:
    return {
        "queue_index": item.get("queue_index"),
        "task_id": item.get("task_id"),
        "source_row_id": item.get("source_row_id"),
        "disposition_id": item.get("disposition_id"),
        "action_type": item.get("action_type"),
        "status": item.get("status"),
        "packet_status": item.get("packet_status"),
        "reason": reason,
    }


def _evidence_sort_key(evidence: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(evidence.get("source_row_id") or ""),
        str(evidence.get("source_task_id") or ""),
        str(evidence.get("evidence_path") or ""),
    )


def _terminal_skip_row(item: dict[str, Any], evidence: list[dict[str, Any]]) -> dict[str, Any]:
    skipped = _skip_row(item, "terminal_source_disposition_present")
    skipped["terminal_evidence"] = sorted(evidence, key=_evidence_sort_key)
    return skipped


def _terminal_disposition(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    lowered = text.lower()
    if any(marker in lowered for marker in TERMINAL_DISPOSITION_MARKERS):
        return text
    return None


def _terminal_evidence_from_payload(payload: dict[str, Any], evidence_path: Path, repo: Path) -> dict[str, Any] | None:
    disposition = _terminal_disposition(payload.get("final_disposition"))
    if disposition is None:
        return None
    source_row_id = str(payload.get("source_row_id") or "").strip()
    source_task_id = str(payload.get("source_task_id") or payload.get("task_id") or "").strip()
    if not source_row_id and not source_task_id:
        return None
    commit_sha = str(payload.get("commit_sha") or "").strip()
    return {
        "evidence_path": _rel(evidence_path, repo),
        "source_row_id": source_row_id,
        "source_task_id": source_task_id,
        "commit_sha": commit_sha,
        "final_disposition": disposition,
    }


def discover_terminal_evidence_paths(repo: Path) -> list[Path]:
    paths: list[Path] = []
    seen: set[Path] = set()
    for pattern in DEFAULT_TERMINAL_EVIDENCE_GLOBS:
        for path in sorted(repo.glob(pattern)):
            if not path.is_file():
                continue
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            paths.append(path)
    return paths


def load_terminal_evidence(paths: list[Path], repo: Path) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for path in paths:
        try:
            payload = _read_json(path)
        except (OSError, json.JSONDecodeError, ValueError):
            continue
        item = _terminal_evidence_from_payload(payload, path, repo)
        if item is not None:
            evidence.append(item)
    return sorted(evidence, key=_evidence_sort_key)


def _evidence_matches_row(evidence: dict[str, Any], row: dict[str, Any]) -> bool:
    evidence_task = str(evidence.get("source_task_id") or "")
    evidence_row = str(evidence.get("source_row_id") or "")
    row_task = str(row.get("task_id") or "")
    row_id = str(row.get("source_row_id") or "")
    if evidence_task and evidence_task != row_task:
        return False
    if evidence_row and evidence_row != row_id:
        return False
    if not evidence_task and not evidence_row:
        return False
    evidence_commit = str(evidence.get("commit_sha") or "")
    row_commit = str(row.get("commit_sha") or "")
    if evidence_commit and row_commit and evidence_commit != row_commit:
        return False
    return True


def _matching_terminal_evidence(row: dict[str, Any], evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [item for item in evidence if _evidence_matches_row(item, row)]


def _normalize_bounded_review(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    selected_files = _strings(raw.get("selected_files"))
    selected_directories = _strings(raw.get("selected_directories"))
    review_focus = _strings(raw.get("review_focus"))
    if not selected_files and not selected_directories:
        return None
    if not review_focus:
        return None
    return {
        "max_files": int(raw.get("max_files") or len(selected_files) or 0),
        "max_directories": int(raw.get("max_directories") or len(selected_directories) or 0),
        "selected_files": selected_files,
        "selected_directories": selected_directories,
        "review_focus": review_focus,
    }


def _review_task(item: dict[str, Any]) -> dict[str, Any]:
    action_type = str(item.get("action_type") or "")
    if action_type not in ELIGIBLE_ACTIONS:
        raise ValueError(f"unsupported action type: {action_type}")
    bounded = _normalize_bounded_review(item.get("bounded_review"))
    if bounded is None:
        raise ValueError(f"missing bounded review for {item.get('disposition_id')}")
    row_id = str(item.get("source_row_id") or item.get("task_id") or item.get("disposition_id") or "")
    task_id = f"review-task-{_stable_slug(row_id)}"
    focus = bounded["review_focus"]
    return {
        "schema": TASK_SCHEMA,
        "task_id": task_id,
        "task_type": action_type,
        "task_label": ACTION_LABELS[action_type],
        "lane": ACTION_LANES[action_type],
        "advisory_only": True,
        "network_used": False,
        "proof_boundary": PROOF_BOUNDARY,
        "disallowed_claims": list(DISALLOWED_CLAIMS),
        "target": item.get("target"),
        "repo_identity": item.get("repo_identity"),
        "commit_sha": item.get("commit_sha"),
        "commit_short": item.get("commit_short"),
        "source_row_id": item.get("source_row_id"),
        "source_task_id": item.get("task_id"),
        "source_disposition_id": item.get("disposition_id"),
        "source_queue_index": item.get("queue_index"),
        "source_packet_status": item.get("packet_status"),
        "review_objective": _review_objective(action_type),
        "allowed_actions": _allowed_actions(action_type),
        "terminal_state_options": [
            "bounded_review_notes_recorded",
            "killed_duplicate_or_oos",
            "needs_separate_proof_followup",
        ],
        "bounded_review": bounded,
        "review_prompts": _review_prompts(action_type, focus),
        "source_review_summary": str(item.get("source_review_summary") or ""),
        "source_rationale": str(item.get("rationale") or ""),
        "next_action": str(item.get("next_action") or ""),
    }


def build_report(
    disposition: dict[str, Any],
    repo: Path,
    *,
    input_path: Path | None = None,
    input_report_label: str | None = None,
    max_tasks: int = DEFAULT_MAX_TASKS,
    terminal_evidence: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    if max_tasks < 1:
        raise ValueError("max_tasks must be at least 1")
    if disposition.get("schema") != INPUT_SCHEMA:
        raise ValueError(f"unexpected input schema: {disposition.get('schema')}")

    rows_raw = disposition.get("disposition_queue")
    if not isinstance(rows_raw, list):
        raise ValueError("input report must contain a disposition_queue list")

    rows = [row for row in rows_raw if isinstance(row, dict)]
    sorted_rows = sorted(rows, key=_task_sort_key)
    terminal_evidence = terminal_evidence or []
    selected: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    for row in sorted_rows:
        action_type = str(row.get("action_type") or "")
        if action_type not in ELIGIBLE_ACTIONS:
            skipped.append(_skip_row(row, "action_not_selected"))
            continue
        if row.get("status") != "queued":
            skipped.append(_skip_row(row, "row_not_queued"))
            continue
        if row.get("packet_status") != "source_review_packet_emitted":
            skipped.append(_skip_row(row, "source_packet_not_emitted"))
            continue
        terminal = _matching_terminal_evidence(row, terminal_evidence)
        if terminal:
            skipped.append(_terminal_skip_row(row, terminal))
            continue
        if _normalize_bounded_review(row.get("bounded_review")) is None:
            skipped.append(_skip_row(row, "bounded_review_missing_or_incomplete"))
            continue
        if len(selected) >= max_tasks:
            skipped.append(_skip_row(row, "max_tasks_reached"))
            continue
        selected.append(_review_task(row))

    action_counts = {action: 0 for action in ELIGIBLE_ACTIONS}
    for task in selected:
        action = str(task.get("task_type") or "")
        action_counts[action] = action_counts.get(action, 0) + 1
    skip_counts: dict[str, int] = {}
    for row in skipped:
        reason = str(row.get("reason") or "unknown")
        skip_counts[reason] = skip_counts.get(reason, 0) + 1

    input_report = input_report_label
    if input_report is None:
        input_report = _rel(input_path, repo) if input_path is not None else _rel(DEFAULT_IN, repo)

    return {
        "schema": SCHEMA,
        "date": str(disposition.get("date") or DEFAULT_DATE),
        "generated_at_utc": _deterministic_generated_at(disposition, input_path),
        "advisory_only": True,
        "network_used": False,
        "input_report": input_report,
        "input_schema": disposition.get("schema"),
        "proof_boundary": PROOF_BOUNDARY,
        "disallowed_claims": list(DISALLOWED_CLAIMS),
        "bounded_limits": {
            "max_tasks": max_tasks,
            "eligible_action_types": list(ELIGIBLE_ACTIONS),
        },
        "summary": {
            "source_queue_rows_seen": len(rows),
            "eligible_rows_seen": sum(1 for row in rows if row.get("action_type") in ELIGIBLE_ACTIONS),
            "emitted_task_count": len(selected),
            "skipped_row_count": len(skipped),
            "terminal_evidence_count": len(terminal_evidence),
            "selected_action_counts": action_counts,
            "skipped_reason_counts": dict(sorted(skip_counts.items())),
        },
        "tasks": selected,
        "skipped_rows": skipped,
    }


def render_markdown(report: dict[str, Any]) -> str:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    action_counts = summary.get("selected_action_counts") if isinstance(summary.get("selected_action_counts"), dict) else {}
    tasks = [task for task in _as_list(report.get("tasks")) if isinstance(task, dict)]
    skipped_rows = [row for row in _as_list(report.get("skipped_rows")) if isinstance(row, dict)]
    lines = [
        f"# Commit Mining Review Task Packet - {report.get('date') or DEFAULT_DATE}",
        "",
        "Generated by `tools/commit-mining-review-task-packet.py` from the advisory source-disposition queue.",
        "",
        "## Counts",
        "",
        f"- Source queue rows seen: {summary.get('source_queue_rows_seen', 0)}",
        f"- Eligible rows seen: {summary.get('eligible_rows_seen', 0)}",
        f"- Emitted review tasks: {summary.get('emitted_task_count', 0)}",
        f"- Skipped rows: {summary.get('skipped_row_count', 0)}",
        f"- Terminal evidence rows: {summary.get('terminal_evidence_count', 0)}",
    ]
    for action in ELIGIBLE_ACTIONS:
        lines.append(f"- {action}: {action_counts.get(action, 0)}")
    lines.extend(
        [
            "",
            "## Advisory Boundary",
            "",
            str(report.get("proof_boundary") or PROOF_BOUNDARY),
            "",
            "## Tasks",
            "",
            "| queue | task | action | commit | files | focus |",
            "|---:|---|---|---|---:|---|",
        ]
    )
    if not tasks:
        lines.append("| - | - | - | - | 0 | none |")
    for task in tasks:
        bounded = task.get("bounded_review") if isinstance(task.get("bounded_review"), dict) else {}
        focus = ", ".join(_strings(bounded.get("review_focus")))
        lines.append(
            f"| {task.get('source_queue_index')} | `{task.get('task_id')}` | `{task.get('task_type')}` | "
            f"`{task.get('commit_short') or '-'}` | {len(_as_list(bounded.get('selected_files')))} | {focus} |"
        )
    lines.extend(["", "## Task Details", ""])
    for task in tasks:
        bounded = task.get("bounded_review") if isinstance(task.get("bounded_review"), dict) else {}
        lines.append(f"### `{task.get('task_id')}`")
        lines.append("")
        lines.append(f"- Action: `{task.get('task_type')}`")
        lines.append(f"- Source disposition: `{task.get('source_disposition_id')}`")
        lines.append(f"- Review objective: {task.get('review_objective')}")
        lines.append(f"- Next action: {task.get('next_action')}")
        directories = _strings(bounded.get("selected_directories"))
        if directories:
            lines.append(f"- Bounded directories: {', '.join(directories)}")
        files = _strings(bounded.get("selected_files"))
        if files:
            lines.append(f"- Bounded files: {', '.join(files)}")
        focus = _strings(bounded.get("review_focus"))
        if focus:
            lines.append(f"- Review focus: {', '.join(focus)}")
        prompts = _strings(task.get("review_prompts"))
        if prompts:
            lines.append(f"- Review prompts: {' | '.join(prompts)}")
        lines.append("")
    lines.extend(["## Skipped Rows", ""])
    if not skipped_rows:
        lines.append("- None")
    else:
        for row in skipped_rows:
            line = (
                f"- `{row.get('disposition_id') or row.get('task_id') or '-'}`: "
                f"`{row.get('reason') or 'unknown'}`"
            )
            terminal = [item for item in _as_list(row.get("terminal_evidence")) if isinstance(item, dict)]
            if terminal:
                evidence_paths = ", ".join(str(item.get("evidence_path") or "-") for item in terminal)
                line += f" ({evidence_paths})"
            lines.append(line)
    lines.extend(["", "## Inputs", "", f"- source_disposition: `{report.get('input_report')}`"])
    return "\n".join(lines).rstrip() + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=REPO)
    parser.add_argument("--input", type=Path, default=DEFAULT_IN)
    parser.add_argument("--input-report-label", default=None)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--markdown-out", type=Path, default=DEFAULT_MD)
    parser.add_argument("--max-tasks", type=int, default=DEFAULT_MAX_TASKS)
    parser.add_argument(
        "--terminal-evidence",
        type=Path,
        action="append",
        default=[],
        help="Additional JSON report with terminal final_disposition evidence.",
    )
    parser.add_argument(
        "--no-auto-terminal-evidence",
        action="store_true",
        help="Do not scan the repo reports directory for terminal source-review evidence.",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON to stdout.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    disposition = _read_json(args.input)
    evidence_paths = list(args.terminal_evidence)
    if not args.no_auto_terminal_evidence:
        evidence_paths.extend(discover_terminal_evidence_paths(args.repo))
    terminal_evidence = load_terminal_evidence(evidence_paths, args.repo)
    report = build_report(
        disposition,
        args.repo,
        input_path=args.input,
        input_report_label=args.input_report_label,
        max_tasks=args.max_tasks,
        terminal_evidence=terminal_evidence,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.markdown_out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.markdown_out.write_text(render_markdown(report), encoding="utf-8")
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        summary = report["summary"]
        print(
            f"wrote {args.out} and {args.markdown_out} "
            f"(tasks={summary['emitted_task_count']}, skipped_rows={summary['skipped_row_count']})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
