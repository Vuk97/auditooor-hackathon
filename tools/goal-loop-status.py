#!/usr/bin/env python3
"""Emit the perpetual goal-loop status for PR #605.

The active objective is intentionally a continuing improvement loop.  This
tool makes that operational rule explicit for handoff packets and external
models without asking them to infer it from conversation history.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Iterable


DEFAULT_DATE = "2026-05-05"

REQUIRED_MEMORY_ARTIFACTS = {
    "current_state": "docs/CURRENT_STATE.md",
    "tool_status": "docs/TOOL_STATUS.md",
    "known_limitations": "reports/known_limitations_burndown_queue_2026-05-05.json",
    "scanner_truth": "reports/scanner_wiring_truth_inventory_2026-05-05.json",
    "harness_binding": "reports/harness_binding_manifest_status_2026-05-05.json",
    "commit_mining": "reports/github_commit_mining_exploit_plan_2026-05-05.json",
    "source_ref_replay": "reports/source_ref_replay_manifest_plan_2026-05-05.json",
    "no_reason_declines": "reports/no_reason_decline_memory_2026-05-05.json",
}

REPORT_ARTIFACT_STEMS = {
    "known_limitations": "known_limitations_burndown_queue",
    "scanner_truth": "scanner_wiring_truth_inventory",
    "harness_binding": "harness_binding_manifest_status",
    "commit_mining": "github_commit_mining_exploit_plan",
    "source_ref_replay": "source_ref_replay_manifest_plan",
    "no_reason_declines": "no_reason_decline_memory",
}

LOOP_PHASES = (
    "recall_memory",
    "select_next_queue_items",
    "dispatch_agents",
    "execute_safe_work",
    "verify_outputs",
    "update_memory_and_docs",
    "commit_or_handoff",
    "loop_back_to_recall_memory",
)

HANDOFF_THRESHOLDS = (
    {
        "threshold": "merge_pr_605_confidence",
        "estimate_loops_from_2026_05_05": "1-2",
        "exit_criteria": (
            "PR is clean, focused validation passes, and queued docs/reports describe "
            "the current state without claiming completion."
        ),
    },
    {
        "threshold": "controlled_new_audit_workspace",
        "estimate_loops_from_2026_05_05": "5-8",
        "exit_criteria": (
            "A bounded audit handoff packet exists, scanner/harness queues produce "
            "concrete actions, and another model can start from memory instead of "
            "rereading the repo."
        ),
    },
    {
        "threshold": "external_model_takeover",
        "estimate_loops_from_2026_05_05": "10-15",
        "exit_criteria": (
            "Claude/Kimi/Minimax can consume current state, constraints, active queues, "
            "and known blockers with low context reconstruction cost."
        ),
    },
    {
        "threshold": "memory_operational_day_to_day",
        "estimate_loops_from_2026_05_05": "15-25",
        "exit_criteria": (
            "Memory producers and dispatch queues are used every loop and stale/blocked "
            "items are visible without manual archaeology."
        ),
    },
    {
        "threshold": "commit_mining_exploit_lane",
        "estimate_loops_from_2026_05_05": "20-35",
        "exit_criteria": (
            "Prior GitHub refs and local patch commits are lifecycle-tagged, source "
            "mirrors are resolved, and review packets route to reproducible harness work."
        ),
    },
    {
        "threshold": "broad_current_roadmap_slice",
        "estimate_loops_from_2026_05_05": "40-60+",
        "exit_criteria": (
            "Known limitations, detector proof gaps, Rust coverage gaps, and harness "
            "blockers have measurable burn-down rather than only plans."
        ),
    },
    {
        "threshold": "full_memory_harness_detector_commit_program",
        "estimate_loops_from_2026_05_05": "200-250+",
        "exit_criteria": (
            "The broad program is materially burned down across memory, harness, commit "
            "mining, detector repair, Rust lift, and self-learning. The loop still remains "
            "open for new work."
        ),
    },
)


@dataclass(frozen=True)
class ArtifactStatus:
    key: str
    path: str
    exists: bool
    size_bytes: int

    def to_json(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "path": self.path,
            "exists": self.exists,
            "size_bytes": self.size_bytes,
        }


def _latest_report_rel_path(root: Path, stem: str, fallback_rel: str) -> str:
    reports_dir = root / "reports"
    if not reports_dir.is_dir():
        return fallback_rel
    matches = sorted(reports_dir.glob(f"{stem}_*.json"), key=lambda path: path.name)
    if not matches:
        return fallback_rel
    return str(matches[-1].relative_to(root))


def _resolve_required_artifact_rel_path(root: Path, key: str) -> str:
    fallback_rel = REQUIRED_MEMORY_ARTIFACTS[key]
    stem = REPORT_ARTIFACT_STEMS.get(key)
    if not stem:
        return fallback_rel
    return _latest_report_rel_path(root, stem, fallback_rel)


def artifact_statuses(root: Path) -> list[ArtifactStatus]:
    rows: list[ArtifactStatus] = []
    for key in REQUIRED_MEMORY_ARTIFACTS:
        rel = _resolve_required_artifact_rel_path(root, key)
        path = root / rel
        rows.append(
            ArtifactStatus(
                key=key,
                path=rel,
                exists=path.exists(),
                size_bytes=path.stat().st_size if path.exists() else 0,
            )
        )
    return rows


def _count_json_items(path: Path) -> int | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        for key in ("items", "rows", "actions", "candidates", "work_items"):
            value = data.get(key)
            if isinstance(value, list):
                return len(value)
    return None


def queue_signals(root: Path) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    for key in (
        "known_limitations",
        "scanner_truth",
        "harness_binding",
        "commit_mining",
        "source_ref_replay",
    ):
        rel = _resolve_required_artifact_rel_path(root, key)
        count = _count_json_items(root / rel)
        signals.append(
            {
                "queue": key,
                "source_path": rel,
                "item_count": count,
                "usable_for_dispatch": count is not None and count > 0,
            }
        )
    return signals


def build_status(root: Path, *, current_date: str = DEFAULT_DATE) -> dict[str, Any]:
    artifacts = artifact_statuses(root)
    missing = [row.path for row in artifacts if not row.exists]
    present = [row.path for row in artifacts if row.exists]
    return {
        "schema": "auditooor.goal_loop_status.v1",
        "generated_date": current_date,
        "goal_policy": {
            "status": "active_continuous_loop",
            "terminal_completion_allowed": False,
            "reason": (
                "The objective is a self-improvement and audit-capability loop. "
                "Individual PR slices can be merged, but the global goal loops back "
                "to memory recall after each verified slice."
            ),
            "loop_back_phase": "recall_memory",
        },
        "loop_phases": list(LOOP_PHASES),
        "artifact_coverage": {
            "present_count": len(present),
            "missing_count": len(missing),
            "present_paths": present,
            "missing_paths": missing,
            "artifacts": [row.to_json() for row in artifacts],
        },
        "queue_signals": queue_signals(root),
        "handoff_thresholds": list(HANDOFF_THRESHOLDS),
        "next_operational_rule": (
            "Every loop should choose bounded queue items, dispatch work, verify locally, "
            "write back memory, and then repeat. New audits may begin once the controlled "
            "handoff threshold is met; they do not require the full 200-250+ loop program."
        ),
    }


def render_markdown(status: dict[str, Any]) -> str:
    coverage = status["artifact_coverage"]
    thresholds = status["handoff_thresholds"]
    lines = [
        "# Goal Loop Status - 2026-05-05",
        "",
        "The PR #605 objective is an active loop, not a terminal task. Individual slices can be committed, pushed, merged, or handed off, but the global capability loop returns to memory recall after each verified slice.",
        "",
        "## Policy",
        "",
        f"- Goal status: `{status['goal_policy']['status']}`",
        f"- Terminal completion allowed: `{status['goal_policy']['terminal_completion_allowed']}`",
        f"- Loop-back phase: `{status['goal_policy']['loop_back_phase']}`",
        "",
        "## Loop Phases",
        "",
    ]
    lines.extend(f"{idx}. `{phase}`" for idx, phase in enumerate(status["loop_phases"], 1))
    lines.extend(
        [
            "",
            "## Memory Coverage",
            "",
            f"- Present artifacts: `{coverage['present_count']}`",
            f"- Missing artifacts: `{coverage['missing_count']}`",
            "",
            "## Handoff Thresholds",
            "",
        ]
    )
    for row in thresholds:
        lines.append(
            f"- `{row['threshold']}`: `{row['estimate_loops_from_2026_05_05']}` loops - {row['exit_criteria']}"
        )
    lines.extend(
        [
            "",
            "## Operational Rule",
            "",
            status["next_operational_rule"],
            "",
        ]
    )
    return "\n".join(lines)


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--out", type=Path, default=None, help="Write JSON status to this path")
    parser.add_argument("--md-out", type=Path, default=None, help="Write markdown status to this path")
    parser.add_argument("--date", default=DEFAULT_DATE)
    return parser.parse_args(argv)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    root = args.root.resolve()
    status = build_status(root, current_date=args.date)
    if args.out:
        write_json(args.out, status)
    if args.md_out:
        args.md_out.parent.mkdir(parents=True, exist_ok=True)
        args.md_out.write_text(render_markdown(status), encoding="utf-8")
    if not args.out and not args.md_out:
        print(json.dumps(status, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
