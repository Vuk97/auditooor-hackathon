#!/usr/bin/env python3
"""Read-only git worktree hygiene planner.

The planner reports registered worktrees and dry-run cleanup suggestions only.
It never invokes destructive commands such as ``git worktree remove`` or
``git worktree prune``.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable

from tools.control import dirty


SCHEMA = "auditooor.control.worktree_hygiene.v1"

CLASS_ACTIVE = "active"
CLASS_STALE = "stale"
CLASS_MISSING = "missing"


DirtyClassifier = Callable[[str | Path], list[dict[str, Any]]]


@dataclass(frozen=True)
class WorktreeHygieneRow:
    path: str
    branch: str | None
    head: str | None
    dirty_count: int | None
    classification: str
    cleanup_suggestion: str
    reason: str
    locked: bool = False
    prunable: bool = False
    dirty_classifier_error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "branch": self.branch,
            "head": self.head,
            "dirty_count": self.dirty_count,
            "classification": self.classification,
            "cleanup_suggestion": self.cleanup_suggestion,
            "reason": self.reason,
            "locked": self.locked,
            "prunable": self.prunable,
            "dirty_classifier_error": self.dirty_classifier_error,
        }


def _run_git(repo: str | Path, args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def _repo_root(repo: str | Path) -> Path | None:
    proc = _run_git(repo, ["rev-parse", "--show-toplevel"])
    if proc.returncode != 0:
        return None
    return Path(proc.stdout.strip()).resolve()


def parse_worktree_list(output: str) -> list[dict[str, str]]:
    """Parse ``git worktree list --porcelain`` output into dictionaries."""

    rows: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for raw in output.splitlines():
        if not raw.strip():
            if current:
                rows.append(current)
                current = {}
            continue
        key, has_value, value = raw.partition(" ")
        if has_value:
            current[key] = value.strip()
        else:
            current[key] = "true"
    if current:
        rows.append(current)
    return rows


def plan_worktree_hygiene(
    repo: str | Path,
    *,
    worktree_items: Iterable[dict[str, str]] | None = None,
    dirty_classifier: DirtyClassifier | None = None,
    repo_root: str | Path | None = None,
) -> dict[str, Any]:
    """Build a dry-run hygiene plan for registered git worktrees.

    ``worktree_items`` and ``dirty_classifier`` are injectable for tests and for
    callers that already captured git output.  When omitted, the function reads
    ``git worktree list --porcelain`` and uses the dirty classifier module.
    """

    if worktree_items is None:
        proc = _run_git(repo, ["worktree", "list", "--porcelain"])
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or "git worktree list --porcelain failed")
        items = parse_worktree_list(proc.stdout)
    else:
        items = list(worktree_items)

    root = Path(repo_root).expanduser().resolve() if repo_root is not None else _repo_root(repo)
    classifier = dirty_classifier or dirty.classify_git_status
    rows = [_plan_row(item, root=root, dirty_classifier=classifier).as_dict() for item in items]
    counts = {CLASS_ACTIVE: 0, CLASS_STALE: 0, CLASS_MISSING: 0}
    for row in rows:
        classification = str(row["classification"])
        counts[classification] = counts.get(classification, 0) + 1

    return {
        "schema": SCHEMA,
        "dry_run": True,
        "would_execute": False,
        "repo": str(Path(repo).expanduser()),
        "repo_root": str(root) if root is not None else None,
        "worktree_count": len(rows),
        "counts_by_classification": counts,
        "rows": rows,
    }


def plan_worktree_hygiene_from_output(
    repo: str | Path,
    worktree_list_output: str,
    *,
    dirty_classifier: DirtyClassifier | None = None,
    repo_root: str | Path | None = None,
) -> dict[str, Any]:
    """Build a plan from previously captured ``git worktree list`` output."""

    return plan_worktree_hygiene(
        repo,
        worktree_items=parse_worktree_list(worktree_list_output),
        dirty_classifier=dirty_classifier,
        repo_root=repo_root,
    )


def _plan_row(
    item: dict[str, str],
    *,
    root: Path | None,
    dirty_classifier: DirtyClassifier,
) -> WorktreeHygieneRow:
    path_text = item.get("worktree", "")
    path = Path(path_text).expanduser()
    resolved_path = path.resolve() if path.exists() else path.absolute()
    branch = _branch_name(item.get("branch"))
    head = item.get("HEAD") or None
    locked = "locked" in item
    prunable = "prunable" in item

    if not path.exists():
        return WorktreeHygieneRow(
            path=path_text,
            branch=branch,
            head=head,
            dirty_count=None,
            classification=CLASS_MISSING,
            cleanup_suggestion="dry-run only: registered path is missing; operator may review git worktree prune",
            reason="registered worktree path does not exist",
            locked=locked,
            prunable=prunable,
        )

    dirty_count, error = _dirty_count(path, dirty_classifier)
    is_current = root is not None and resolved_path == root
    if is_current:
        classification = CLASS_ACTIVE
        reason = "current active worktree"
        suggestion = "dry-run only: current worktree; never cleanup automatically"
    elif locked:
        classification = CLASS_ACTIVE
        reason = "registered worktree is locked"
        suggestion = "dry-run only: locked worktree; preserve until owner reviews lock reason"
    elif dirty_count is None:
        classification = CLASS_ACTIVE
        reason = "dirty classifier could not inspect worktree"
        suggestion = "dry-run only: inspection failed; preserve until owner resolves classifier error"
    elif dirty_count > 0:
        classification = CLASS_ACTIVE
        reason = "worktree has dirty files"
        suggestion = "dry-run only: dirty worktree; ask owner to resolve local changes"
    else:
        classification = CLASS_STALE
        reason = "linked worktree is clean"
        suggestion = "dry-run only: clean linked worktree; operator may review git worktree remove"

    return WorktreeHygieneRow(
        path=path_text,
        branch=branch,
        head=head,
        dirty_count=dirty_count,
        classification=classification,
        cleanup_suggestion=suggestion,
        reason=reason,
        locked=locked,
        prunable=prunable,
        dirty_classifier_error=error,
    )


def _dirty_count(path: Path, dirty_classifier: DirtyClassifier) -> tuple[int | None, str | None]:
    try:
        rows = dirty_classifier(path)
    except Exception as exc:  # noqa: BLE001 - planner must fail closed on classifier problems.
        return None, str(exc)
    return len(rows), None


def _branch_name(ref: str | None) -> str | None:
    if not ref:
        return None
    return ref.removeprefix("refs/heads/") or None
