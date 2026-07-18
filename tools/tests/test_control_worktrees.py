#!/usr/bin/env python3
"""Tests for the read-only worktree hygiene planner."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

from tools.control import worktrees


def _git(args: list[str], cwd: Path, check: bool = True) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "Test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
    }
    proc = subprocess.run(
        ["git", *args],
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(f"git {args!r} failed rc={proc.returncode}: {proc.stderr}")
    return proc


def _init_repo(repo: Path) -> None:
    _git(["init", "-b", "main"], repo)
    _git(["config", "commit.gpgsign", "false"], repo)
    (repo / "README.md").write_text("root\n", encoding="utf-8")
    _git(["add", "README.md"], repo)
    _git(["commit", "-m", "initial"], repo)


def _rows_by_path(rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(row["path"]): row for row in rows}


class TestControlWorktrees(unittest.TestCase):
    def test_parse_worktree_list_keeps_branch_head_and_flags(self) -> None:
        parsed = worktrees.parse_worktree_list(
            "worktree /repo\n"
            "HEAD abc123\n"
            "branch refs/heads/main\n"
            "\n"
            "worktree /repo-linked\n"
            "HEAD def456\n"
            "detached\n"
            "locked operator owns it\n"
            "prunable gitdir file points to non-existent location\n"
        )

        self.assertEqual(parsed[0]["worktree"], "/repo")
        self.assertEqual(parsed[0]["branch"], "refs/heads/main")
        self.assertEqual(parsed[1]["detached"], "true")
        self.assertEqual(parsed[1]["locked"], "operator owns it")
        self.assertIn("non-existent", parsed[1]["prunable"])

    def test_plan_from_captured_output_classifies_active_stale_and_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            stale = root / "stale"
            missing = root / "missing"
            repo.mkdir()
            stale.mkdir()

            output = (
                f"worktree {repo}\n"
                "HEAD aaa\n"
                "branch refs/heads/main\n"
                "\n"
                f"worktree {stale}\n"
                "HEAD bbb\n"
                "branch refs/heads/feature\n"
                "\n"
                f"worktree {missing}\n"
                "HEAD ccc\n"
                "branch refs/heads/old\n"
                "prunable gitdir file points to non-existent location\n"
            )

            def classifier(path: str | Path) -> list[dict[str, Any]]:
                if Path(path) == repo:
                    return [{"path": "tracked.py"}]
                return []

            plan = worktrees.plan_worktree_hygiene_from_output(
                repo,
                output,
                repo_root=repo,
                dirty_classifier=classifier,
            )
            rows = _rows_by_path(plan["rows"])

            self.assertTrue(plan["dry_run"])
            self.assertFalse(plan["would_execute"])
            self.assertEqual(rows[str(repo)]["classification"], worktrees.CLASS_ACTIVE)
            self.assertEqual(rows[str(repo)]["dirty_count"], 1)
            self.assertEqual(rows[str(repo)]["branch"], "main")
            self.assertEqual(rows[str(stale)]["classification"], worktrees.CLASS_STALE)
            self.assertEqual(rows[str(stale)]["dirty_count"], 0)
            self.assertEqual(rows[str(missing)]["classification"], worktrees.CLASS_MISSING)
            self.assertIsNone(rows[str(missing)]["dirty_count"])
            self.assertTrue(rows[str(missing)]["prunable"])
            self.assertEqual(
                plan["counts_by_classification"],
                {
                    worktrees.CLASS_ACTIVE: 1,
                    worktrees.CLASS_STALE: 1,
                    worktrees.CLASS_MISSING: 1,
                },
            )
            for row in rows.values():
                self.assertIn("dry-run only", row["cleanup_suggestion"])
                self.assertNotIn("would run", row["cleanup_suggestion"])

    def test_plan_fails_closed_when_dirty_classifier_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            linked = Path(tmp) / "linked"
            repo.mkdir()
            linked.mkdir()

            def classifier(_path: str | Path) -> list[dict[str, Any]]:
                raise RuntimeError("status unavailable")

            plan = worktrees.plan_worktree_hygiene(
                repo,
                repo_root=repo,
                worktree_items=[
                    {
                        "worktree": str(linked),
                        "HEAD": "abc",
                        "branch": "refs/heads/feature",
                    }
                ],
                dirty_classifier=classifier,
            )
            row = plan["rows"][0]

            self.assertEqual(row["classification"], worktrees.CLASS_ACTIVE)
            self.assertIsNone(row["dirty_count"])
            self.assertEqual(row["dirty_classifier_error"], "status unavailable")
            self.assertIn("preserve", row["cleanup_suggestion"])

    def test_real_temp_repo_plan_uses_git_worktree_list_and_dirty_classifier(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            linked_clean = root / "linked-clean"
            linked_dirty = root / "linked-dirty"
            repo.mkdir()
            _init_repo(repo)

            _git(["branch", "clean-branch"], repo)
            _git(["branch", "dirty-branch"], repo)
            _git(["worktree", "add", str(linked_clean), "clean-branch"], repo)
            _git(["worktree", "add", str(linked_dirty), "dirty-branch"], repo)
            (linked_dirty / "scratch.txt").write_text("dirty\n", encoding="utf-8")

            plan = worktrees.plan_worktree_hygiene(repo)
            rows = _rows_by_path(plan["rows"])

            self.assertEqual(rows[str(repo.resolve())]["classification"], worktrees.CLASS_ACTIVE)
            self.assertEqual(rows[str(linked_clean.resolve())]["classification"], worktrees.CLASS_STALE)
            self.assertEqual(rows[str(linked_clean.resolve())]["dirty_count"], 0)
            self.assertEqual(rows[str(linked_dirty.resolve())]["classification"], worktrees.CLASS_ACTIVE)
            self.assertEqual(rows[str(linked_dirty.resolve())]["dirty_count"], 1)
            self.assertEqual(rows[str(linked_clean.resolve())]["branch"], "clean-branch")
            self.assertIn("git worktree remove", rows[str(linked_clean.resolve())]["cleanup_suggestion"])

    def test_missing_registered_worktree_is_reported_without_pruning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            linked = root / "linked-missing"
            repo.mkdir()
            _init_repo(repo)
            _git(["branch", "missing-branch"], repo)
            _git(["worktree", "add", str(linked), "missing-branch"], repo)

            (linked / ".git").unlink()
            for path in sorted(linked.iterdir()):
                path.unlink()
            linked.rmdir()

            plan = worktrees.plan_worktree_hygiene(repo)
            rows = _rows_by_path(plan["rows"])

            self.assertEqual(rows[str(linked.resolve())]["classification"], worktrees.CLASS_MISSING)
            self.assertIsNone(rows[str(linked.resolve())]["dirty_count"])
            self.assertIn("git worktree prune", rows[str(linked.resolve())]["cleanup_suggestion"])
            self.assertFalse(linked.exists())


if __name__ == "__main__":
    unittest.main()
