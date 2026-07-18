#!/usr/bin/env python3
"""Report whether local commits are ready for a batched GitHub/docs checkpoint."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tools.control import dirty


SCHEMA = "auditooor.batch_checkpoint_status.v1"
DEFAULT_UPSTREAM = "origin/continuation-plan"
DEFAULT_COMMIT_THRESHOLD = 100
DEFAULT_LOOP_THRESHOLD = 20
LIVE_STATE_SOURCES = (
    "obsidian-vault/",
    "reports/task_finalization.jsonl",
    "local commits on the active branch",
    "active agent final messages",
)
BROAD_GITHUB_SURFACES = (
    "README.md",
    "docs/CURRENT_STATE.md",
    "docs/MODEL_TAKEOVER_READINESS_*.md",
    "docs/SHARED_MEMORY_INDEX_*.md",
    "docs/MEMORY_BRIEF_*.md",
    "reports/model_takeover_readiness_*.json",
    "reports/shared_memory_index_*.json",
    "reports/memory_brief_*.json",
)
DIRTY_CHECKPOINT_RULE = (
    "Checkpoint only from a clean worktree. Dirty source, detector, generated-report, "
    "or agent-output rows mean the batch is still being assembled or needs a local commit first."
)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def git_divergence_counts(repo_root: Path, upstream: str) -> tuple[int, int]:
    res = subprocess.run(
        ["git", "rev-list", "--left-right", "--count", f"{upstream}...HEAD"],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        detail = res.stderr.strip() or res.stdout.strip() or "git rev-list failed"
        raise RuntimeError(detail)
    counts = res.stdout.strip().split()
    if len(counts) != 2:
        raise RuntimeError(f"unexpected git rev-list output: {res.stdout.strip() or '<empty>'}")
    behind_count, ahead_count = (int(value) for value in counts)
    return ahead_count, behind_count


def summarize_dirty_files(repo_root: Path) -> dict[str, Any]:
    rows = dirty.classify_git_status(repo_root)
    by_role = Counter(str(row.get("role") or "unknown") for row in rows)
    by_status = Counter(str(row.get("status") or "unknown") for row in rows)
    samples = [
        {
            "path": str(row.get("path") or ""),
            "role": str(row.get("role") or "unknown"),
            "status": str(row.get("status") or "unknown"),
        }
        for row in rows[:12]
    ]
    return {
        "total": len(rows),
        "by_role": dict(sorted(by_role.items())),
        "by_status": dict(sorted(by_status.items())),
        "samples": samples,
    }


def build_status(
    *,
    repo_root: Path,
    upstream: str = DEFAULT_UPSTREAM,
    local_commit_count: int | None = None,
    commits_behind_upstream: int | None = None,
    loops_since_checkpoint: int = 0,
    commit_threshold: int = DEFAULT_COMMIT_THRESHOLD,
    loop_threshold: int = DEFAULT_LOOP_THRESHOLD,
    force_checkpoint: bool = False,
) -> dict[str, Any]:
    blockers: list[str] = []
    if local_commit_count is None:
        try:
            local_commit_count, commits_behind_upstream = git_divergence_counts(repo_root, upstream)
        except Exception as exc:  # pragma: no cover - exercised through CLI environments
            local_commit_count = 0
            commits_behind_upstream = 0 if commits_behind_upstream is None else commits_behind_upstream
            blockers.append(f"cannot_count_local_commits: {exc}")
    elif commits_behind_upstream is None:
        commits_behind_upstream = 0

    dirty_summary: dict[str, Any]
    try:
        dirty_summary = summarize_dirty_files(repo_root)
    except Exception as exc:  # pragma: no cover - exercised through CLI environments
        dirty_summary = {"total": None, "by_role": {}, "by_status": {}, "error": str(exc)}
        blockers.append(f"cannot_classify_dirty_files: {exc}")

    commit_threshold_met = local_commit_count >= commit_threshold
    loop_threshold_met = loops_since_checkpoint >= loop_threshold
    checkpoint_due = force_checkpoint or commit_threshold_met or loop_threshold_met
    dirty_total = dirty_summary.get("total")
    dirty_blocks_checkpoint = isinstance(dirty_total, int) and dirty_total > 0
    can_checkpoint = checkpoint_due and not blockers and not dirty_blocks_checkpoint
    coordination_reason_required_for_early_push = not checkpoint_due

    reasons: list[str] = []
    if force_checkpoint:
        reasons.append("forced checkpoint requested")
    if commit_threshold_met:
        reasons.append(f"local commit threshold met: {local_commit_count} >= {commit_threshold}")
    if loop_threshold_met:
        reasons.append(f"loop threshold met: {loops_since_checkpoint} >= {loop_threshold}")
    if commits_behind_upstream:
        reasons.append(f"branch is behind upstream: {commits_behind_upstream} commit(s)")
    if isinstance(dirty_total, int) and dirty_total > 0:
        reasons.append(f"workspace has {dirty_total} dirty file(s)")
    if not reasons:
        reasons.append(
            f"batch still accumulating: {local_commit_count}/{commit_threshold} commits, "
            f"{loops_since_checkpoint}/{loop_threshold} loops"
        )

    return {
        "schema": SCHEMA,
        "generated_at": utc_now(),
        "repo_root": str(repo_root),
        "upstream": upstream,
        "policy": {
            "local_commit_threshold": commit_threshold,
            "loop_threshold": loop_threshold,
            "live_state_sources": list(LIVE_STATE_SOURCES),
            "broad_github_surfaces": list(BROAD_GITHUB_SURFACES),
            "rule": (
                "Keep Obsidian/current memory as live state during loops. "
                "Refresh broad GitHub-facing docs and push only at checkpoint, "
                "unless a real coordination blocker requires an early checkpoint."
            ),
            "dirty_checkpoint_rule": DIRTY_CHECKPOINT_RULE,
        },
        "state": {
            "local_commit_count": local_commit_count,
            "commits_behind_upstream": commits_behind_upstream,
            "loops_since_checkpoint": loops_since_checkpoint,
            "dirty_files": dirty_summary,
            "commit_threshold_met": commit_threshold_met,
            "loop_threshold_met": loop_threshold_met,
            "force_checkpoint": force_checkpoint,
            "checkpoint_due": checkpoint_due,
            "dirty_blocks_checkpoint": dirty_blocks_checkpoint,
            "can_checkpoint": can_checkpoint,
            "coordination_reason_required_for_early_push": coordination_reason_required_for_early_push,
            "blockers": blockers,
            "reasons": reasons,
        },
        "recommendation": {
            "push_now": can_checkpoint,
            "refresh_broad_github_docs_now": can_checkpoint,
            "keep_broad_github_docs_untouched": not can_checkpoint,
            "continue_local_batch": not can_checkpoint,
        },
    }


def render_markdown(report: dict[str, Any]) -> str:
    state = report["state"]
    rec = report["recommendation"]
    dirty_files = state["dirty_files"]
    role_summary = _render_count_summary(dirty_files.get("by_role", {}))
    status_summary = _render_count_summary(dirty_files.get("by_status", {}))
    dirty_samples = dirty_files.get("samples", [])
    lines = [
        "# Batch Checkpoint Status",
        "",
        f"- Branch divergence: ahead {state['local_commit_count']}, behind {state['commits_behind_upstream']}",
        f"- Dirty files: {_render_dirty_total(dirty_files)}",
        f"- Loops since checkpoint: {state['loops_since_checkpoint']}",
        f"- Checkpoint due: {'yes' if state['checkpoint_due'] else 'no'}",
        f"- Dirty files block checkpoint: {'yes' if state['dirty_blocks_checkpoint'] else 'no'}",
        f"- Push now: {'yes' if rec['push_now'] else 'no'}",
        (
            "- Coordination reason required for early push: "
            f"{'yes' if state['coordination_reason_required_for_early_push'] else 'no'}"
        ),
        f"- Broad GitHub docs refresh now: {'yes' if rec['refresh_broad_github_docs_now'] else 'no'}",
    ]
    if role_summary:
        lines.append(f"- Dirty roles: {role_summary}")
    if status_summary:
        lines.append(f"- Dirty statuses: {status_summary}")
    if dirty_samples:
        lines.append("- Dirty samples:")
        for sample in dirty_samples[:8]:
            if not isinstance(sample, dict):
                continue
            path = sample.get("path") or "-"
            role = sample.get("role") or "unknown"
            status = sample.get("status") or "unknown"
            lines.append(f"  - `{path}` ({role}, {status})")
    lines.extend(("", "## Reasons"))
    lines.extend(f"- {reason}" for reason in state["reasons"])
    if state["blockers"]:
        lines.append("")
        lines.append("## Blockers")
        lines.extend(f"- {blocker}" for blocker in state["blockers"])
    lines.append("")
    lines.append("## Live State Sources")
    lines.extend(f"- `{source}`" for source in report["policy"]["live_state_sources"])
    lines.append("")
    lines.append("## Broad GitHub Surfaces Deferred Until Checkpoint")
    lines.extend(f"- `{surface}`" for surface in report["policy"]["broad_github_surfaces"])
    lines.append("")
    lines.append("## Dirty Checkpoint Rule")
    lines.append(f"- {report['policy']['dirty_checkpoint_rule']}")
    return "\n".join(lines) + "\n"


def _render_count_summary(counts: dict[str, Any]) -> str:
    items = [f"{key}:{value}" for key, value in counts.items() if value]
    return ", ".join(items)


def _render_dirty_total(dirty_summary: dict[str, Any]) -> str:
    total = dirty_summary.get("total")
    if total is None:
        return "unknown"
    return str(total)


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be non-negative")
    return parsed


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--upstream", default=DEFAULT_UPSTREAM)
    parser.add_argument("--loops-since-checkpoint", type=positive_int, default=0)
    parser.add_argument("--commit-threshold", type=positive_int, default=DEFAULT_COMMIT_THRESHOLD)
    parser.add_argument("--loop-threshold", type=positive_int, default=DEFAULT_LOOP_THRESHOLD)
    parser.add_argument("--force-checkpoint", action="store_true")
    parser.add_argument("--markdown", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    report = build_status(
        repo_root=args.repo_root,
        upstream=args.upstream,
        loops_since_checkpoint=args.loops_since_checkpoint,
        commit_threshold=args.commit_threshold,
        loop_threshold=args.loop_threshold,
        force_checkpoint=args.force_checkpoint,
    )
    if args.markdown:
        print(render_markdown(report), end="")
    else:
        print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
