#!/usr/bin/env python3
"""Read-only inventory for nested repo/worktree context-pollution risk.

The tool reports registered worktrees, nested git repositories, and generated
export/status directories below a repository root. It never removes files,
branches, or worktrees.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


DEFAULT_REPO = Path(__file__).resolve().parents[1]
AUDITS_ROOT = Path("/Users/wolf/audits")


@dataclass(frozen=True)
class RiskRow:
    path: str
    kind: str
    risk: str
    action: str
    dirty_count: int | None = None
    branch: str | None = None
    head: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind,
            "risk": self.risk,
            "action": self.action,
            "dirty_count": self.dirty_count,
            "branch": self.branch,
            "head": self.head,
        }


def run_git(repo: Path, args: list[str]) -> tuple[int, str, str]:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def resolve_repo(path: Path) -> Path:
    repo = path.expanduser().resolve()
    rc, out, err = run_git(repo, ["rev-parse", "--show-toplevel"])
    if rc != 0:
        raise SystemExit(err.strip() or f"not a git repository: {repo}")
    return Path(out.strip()).resolve()


def assert_not_audits_repo(repo: Path, allow_audits: bool) -> None:
    if allow_audits:
        return
    try:
        repo.relative_to(AUDITS_ROOT)
    except ValueError:
        return
    raise SystemExit(
        f"refusing to inspect /Users/wolf/audits path without --allow-audits: {repo}"
    )


def parse_worktrees(porcelain: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for raw in porcelain.splitlines():
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


def registered_worktrees(repo: Path) -> list[dict[str, str]]:
    rc, out, err = run_git(repo, ["worktree", "list", "--porcelain"])
    if rc != 0:
        raise SystemExit(err.strip() or "git worktree list failed")
    return parse_worktrees(out)


def status_count(path: Path) -> int | None:
    rc, out, _ = run_git(path, ["status", "--short"])
    if rc != 0:
        return None
    return len([line for line in out.splitlines() if line.strip()])


def is_nested(path: Path, repo: Path) -> bool:
    try:
        path.resolve().relative_to(repo)
    except ValueError:
        return False
    return path.resolve() != repo


def has_git_marker(path: Path) -> bool:
    return (path / ".git").exists()


def root_export_dirs(repo: Path, names: Iterable[str] | None = None) -> list[Path]:
    if names is None:
        candidates = repo.iterdir()
    else:
        candidates = (repo / name for name in names)
    rows: list[Path] = []
    for path in candidates:
        if not path.is_dir():
            continue
        name = path.name
        if name.startswith("."):
            continue
        if name.startswith("auditooor-") or name.endswith("-ws"):
            rows.append(path)
    return sorted(rows)


def git_path_risk(kind: str, dirty: int | None) -> tuple[str, str]:
    """Classify a nested git path; fail closed when status cannot be read."""
    if dirty is None:
        return (
            f"unknown-{kind}-status",
            "preserve; git status failed or path is unreadable",
        )
    if dirty:
        return (
            f"dirty-{kind}",
            "preserve; ask owner to save/archive/discard dirty work",
        )
    return (
        kind,
        "owner-confirm before relocation or removal",
    )


def build_inventory(repo: Path, export_names: Iterable[str] | None = None) -> dict[str, Any]:
    repo = resolve_repo(repo)
    worktrees = registered_worktrees(repo)
    registered_nested: dict[Path, dict[str, str]] = {}
    rows: list[RiskRow] = []

    for wt in worktrees:
        path_text = wt.get("worktree")
        if not path_text:
            continue
        path = Path(path_text).resolve()
        if not is_nested(path, repo):
            continue
        registered_nested[path] = wt
        dirty = status_count(path)
        risk, action = git_path_risk("nested-worktree", dirty)
        rows.append(
            RiskRow(
                path=str(path),
                kind="registered-worktree",
                risk=risk,
                action=action,
                dirty_count=dirty,
                branch=wt.get("branch", "").removeprefix("refs/heads/") or None,
                head=wt.get("HEAD"),
            )
        )

    for path in root_export_dirs(repo, export_names):
        resolved = path.resolve()
        if resolved in registered_nested:
            continue
        dirty = status_count(resolved) if has_git_marker(resolved) else None
        if has_git_marker(resolved):
            risk, action = git_path_risk("nested-git-repo", dirty)
            rows.append(
                RiskRow(
                    path=str(resolved),
                    kind="nested-git-repo",
                    risk=risk,
                    action=action,
                    dirty_count=dirty,
                )
            )
        else:
            rows.append(
                RiskRow(
                    path=str(resolved),
                    kind="export-dir",
                    risk="unclassified-root-export-dir",
                    action="preserve until owner classifies contents",
                )
            )

    return {
        "repo": str(repo),
        "risk_count": len(rows),
        "risks": [row.as_dict() for row in sorted(rows, key=lambda r: r.path)],
    }


def render_text(inv: dict[str, Any]) -> str:
    lines = [
        f"context-pollution inventory for {inv['repo']}",
        f"risk_count={inv['risk_count']}",
    ]
    if not inv["risks"]:
        lines.append("no nested worktree/repo/export-dir risks detected")
        return "\n".join(lines) + "\n"
    lines.append("")
    for row in inv["risks"]:
        dirty = row["dirty_count"]
        dirty_text = "unknown" if dirty is None else str(dirty)
        branch = f" branch={row['branch']}" if row.get("branch") else ""
        lines.append(
            f"- {row['kind']} {row['path']} risk={row['risk']} "
            f"dirty={dirty_text}{branch}"
        )
        lines.append(f"  action: {row['action']}")
    return "\n".join(lines) + "\n"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=DEFAULT_REPO)
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON.")
    parser.add_argument(
        "--allow-audits",
        action="store_true",
        help="Allow inspecting a repository under /Users/wolf/audits.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    repo = resolve_repo(args.repo)
    assert_not_audits_repo(repo, args.allow_audits)
    inv = build_inventory(repo)
    if args.json:
        print(json.dumps(inv, indent=2, sort_keys=True))
    else:
        print(render_text(inv), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
