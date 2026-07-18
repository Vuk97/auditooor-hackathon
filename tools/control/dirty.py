#!/usr/bin/env python3
"""Read-only dirty-file and worktree hygiene classifiers.

These helpers intentionally stop at classification and dry-run suggestions.
They never remove, prune, reset, checkout, or rewrite files.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


STATUS_TRACKED_MODIFIED = "tracked_modified"
STATUS_UNTRACKED = "untracked"
STATUS_DELETED = "deleted"
STATUS_RENAMED = "renamed"
STATUS_CONFLICTED = "conflicted"
STATUS_IGNORED_UNKNOWN = "ignored_unknown"

ROLE_CANONICAL_DOC = "canonical_doc"
ROLE_GENERATED_REPORT = "generated_report"
ROLE_WORKSPACE_EVIDENCE = "workspace_evidence"
ROLE_AGENT_OUTPUT = "agent_output"
ROLE_LOCAL_SUBMISSION_PACKET = "local_submission_packet"
ROLE_SCRATCH_TMP = "scratch_tmp"
ROLE_SOURCE_CODE = "source_code"
ROLE_UNKNOWN = "unknown"

WT_ACTIVE_CURRENT = "active_current"
WT_REGISTERED_CLEAN_UNKNOWN = "registered_clean_unknown"
WT_REGISTERED_DIRTY = "registered_dirty"
WT_MISSING_PATH = "missing_path"
WT_UNSAFE_UNKNOWN = "unsafe_unknown"


@dataclass(frozen=True)
class StatusRow:
    path: str
    status: str
    index_status: str
    worktree_status: str
    original_path: str | None = None
    raw: str = ""
    role: str = ROLE_UNKNOWN
    cleanup_suggestion: str = "dry-run only: preserve until reviewed"

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "status": self.status,
            "index_status": self.index_status,
            "worktree_status": self.worktree_status,
            "original_path": self.original_path,
            "raw": self.raw,
            "role": self.role,
            "cleanup_suggestion": self.cleanup_suggestion,
        }


@dataclass(frozen=True)
class WorktreeRow:
    path: str
    head: str | None
    branch: str | None
    safety: str
    dirty_count: int | None = None
    cleanup_suggestion: str = "dry-run only: preserve registered worktree"

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "head": self.head,
            "branch": self.branch,
            "safety": self.safety,
            "dirty_count": self.dirty_count,
            "cleanup_suggestion": self.cleanup_suggestion,
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


def classify_path_role(path: str | Path) -> str:
    """Return a conservative role label for a repo-relative or absolute path."""
    text = str(path).replace("\\", "/").strip()
    if not text:
        return ROLE_UNKNOWN
    text = text.removeprefix("./")
    lower = text.lower()
    parts = tuple(p for p in lower.split("/") if p)
    name = parts[-1] if parts else lower

    if (
        name.endswith((".tmp", ".temp", ".bak", ".swp", ".pyc", ".pyo"))
        or "__pycache__" in parts
        or ".pytest_cache" in parts
        or ".mypy_cache" in parts
        or parts[:1] in {("tmp",), ("temp",)}
        or "/tmp/" in lower
    ):
        return ROLE_SCRATCH_TMP

    if lower.startswith(("submissions/packaged/", "submissions/ready/", "submissions/staging/")):
        return ROLE_LOCAL_SUBMISSION_PACKET

    if lower.startswith(("agent_outputs/", "swarm/", "poc_task_briefs/")):
        return ROLE_AGENT_OUTPUT

    if lower.startswith(
        (
            ".audit_logs/",
            "audit/",
            "reports/",
            "scanners/",
            "logs/",
        )
    ) or name.endswith(("_summary.md", "_summary.json", "_report.md", "_report.json")):
        return ROLE_GENERATED_REPORT

    if lower.startswith(
        (
            "manual_proofs/",
            "poc_execution/",
            "deep_counterexamples/",
            "monitoring/",
        )
    ) or name in {
        "intake_baseline.json",
        "intake_baseline.md",
        "deployment_topology.json",
        "deployment_topology.md",
        "live_topology.md",
        "live_topology_checks.json",
        "scope.md",
        "severity.md",
        "severity_smart_contracts.md",
        "severity_blockchain_dlt.md",
    }:
        return ROLE_WORKSPACE_EVIDENCE

    if lower in {
        "readme.md",
        "agents.md",
        "index.md",
        "status.md",
        "final_report.md",
        "docs/readme.md",
        "docs/workflow.md",
        "docs/tool_status.md",
        "docs/known_limitations.md",
        "docs/claude_takeover_burndown.md",
        "docs/auditooor_control_plane_plan.md",
    }:
        return ROLE_CANONICAL_DOC

    if lower.startswith(("tools/", "src/", "contracts/", "lib/", "test/", "tests/")) or name.endswith(
        (
            ".py",
            ".sh",
            ".sol",
            ".rs",
            ".js",
            ".ts",
            ".tsx",
            ".jsx",
            ".go",
            ".java",
            ".c",
            ".h",
            ".cpp",
            ".hpp",
            ".toml",
            ".lock",
        )
    ):
        return ROLE_SOURCE_CODE

    return ROLE_UNKNOWN


def _split_status_path(payload: str) -> tuple[str, str | None]:
    if " -> " not in payload:
        return payload, None
    original, _, new = payload.partition(" -> ")
    return new, original


def _classify_xy(x: str, y: str) -> str:
    pair = x + y
    if pair in {"DD", "AU", "UD", "UA", "DU", "AA", "UU"} or "U" in pair:
        return STATUS_CONFLICTED
    if pair == "??":
        return STATUS_UNTRACKED
    if pair == "!!":
        return STATUS_IGNORED_UNKNOWN
    if "R" in pair or "C" in pair:
        return STATUS_RENAMED
    if "D" in pair:
        return STATUS_DELETED
    if x.strip() or y.strip():
        return STATUS_TRACKED_MODIFIED
    return STATUS_IGNORED_UNKNOWN


def parse_git_status_porcelain(output: str) -> list[StatusRow]:
    rows: list[StatusRow] = []
    for raw in output.splitlines():
        if not raw:
            continue
        if len(raw) < 3:
            rows.append(
                StatusRow(
                    path=raw,
                    status=STATUS_IGNORED_UNKNOWN,
                    index_status="",
                    worktree_status="",
                    raw=raw,
                )
            )
            continue
        x = raw[0]
        y = raw[1]
        payload = raw[3:] if len(raw) > 3 else ""
        path, original_path = _split_status_path(payload)
        status = _classify_xy(x, y)
        role = classify_path_role(path)
        rows.append(
            StatusRow(
                path=path,
                status=status,
                index_status=x,
                worktree_status=y,
                original_path=original_path,
                raw=raw,
                role=role,
                cleanup_suggestion=dry_run_cleanup_suggestion(path, status, role),
            )
        )
    return rows


def classify_git_status(repo: str | Path) -> list[dict[str, Any]]:
    """Classify `git status --porcelain=v1` rows for a repo.

    The function is read-only and raises RuntimeError if git cannot inspect the
    repository.
    """
    proc = _run_git(repo, ["status", "--porcelain=v1", "--untracked-files=all"])
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "git status --porcelain=v1 failed")
    return [row.as_dict() for row in parse_git_status_porcelain(proc.stdout)]


def dry_run_cleanup_suggestion(path: str, status: str, role: str | None = None) -> str:
    role = role or classify_path_role(path)
    if status in {STATUS_CONFLICTED, STATUS_DELETED, STATUS_RENAMED, STATUS_TRACKED_MODIFIED}:
        return "dry-run only: inspect owner intent before touching tracked change"
    if role in {ROLE_CANONICAL_DOC, ROLE_SOURCE_CODE, ROLE_WORKSPACE_EVIDENCE}:
        return "dry-run only: preserve; classify with owner before cleanup"
    if role in {ROLE_GENERATED_REPORT, ROLE_AGENT_OUTPUT, ROLE_LOCAL_SUBMISSION_PACKET, ROLE_SCRATCH_TMP}:
        return "dry-run only: cleanup candidate after owner confirms artifact is reproducible"
    return "dry-run only: unknown role; preserve"


def parse_worktree_porcelain(output: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for raw in output.splitlines():
        if not raw.strip():
            if current:
                rows.append(current)
                current = {}
            continue
        key, _, value = raw.partition(" ")
        current[key] = value.strip()
    if current:
        rows.append(current)
    return rows


def _dirty_count(path: Path) -> int | None:
    proc = _run_git(path, ["status", "--porcelain=v1"])
    if proc.returncode != 0:
        return None
    return len([line for line in proc.stdout.splitlines() if line.strip()])


def _worktree_suggestion(safety: str) -> str:
    if safety == WT_REGISTERED_DIRTY:
        return "dry-run only: preserve; ask owner to resolve dirty worktree"
    if safety == WT_REGISTERED_CLEAN_UNKNOWN:
        return "dry-run only: clean but registered; owner may review stale-worktree cleanup"
    if safety == WT_MISSING_PATH:
        return "dry-run only: missing registered path; report for owner review, do not prune"
    if safety == WT_ACTIVE_CURRENT:
        return "dry-run only: current active worktree; never cleanup automatically"
    return "dry-run only: unsafe unknown; preserve"


def list_worktrees(repo: str | Path) -> list[dict[str, Any]]:
    """Return registered worktrees with fail-closed safety classifications."""
    root = _repo_root(repo)
    proc = _run_git(repo, ["worktree", "list", "--porcelain"])
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or "git worktree list --porcelain failed")

    rows: list[WorktreeRow] = []
    for item in parse_worktree_porcelain(proc.stdout):
        path_text = item.get("worktree", "")
        path = Path(path_text).expanduser()
        head = item.get("HEAD") or None
        branch = (item.get("branch") or "").removeprefix("refs/heads/") or None

        if not path.exists():
            safety = WT_MISSING_PATH
            dirty = None
        else:
            resolved = path.resolve()
            if root is not None and resolved == root:
                safety = WT_ACTIVE_CURRENT
                dirty = _dirty_count(resolved)
            else:
                dirty = _dirty_count(resolved)
                if dirty is None:
                    safety = WT_UNSAFE_UNKNOWN
                elif dirty > 0:
                    safety = WT_REGISTERED_DIRTY
                else:
                    safety = WT_REGISTERED_CLEAN_UNKNOWN

        rows.append(
            WorktreeRow(
                path=path_text,
                head=head,
                branch=branch,
                safety=safety,
                dirty_count=dirty,
                cleanup_suggestion=_worktree_suggestion(safety),
            )
        )
    return [row.as_dict() for row in rows]
