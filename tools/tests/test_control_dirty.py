#!/usr/bin/env python3
"""Tests for read-only dirty/worktree classifiers."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.control import dirty


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
    (repo / "README.md").write_text("root\n")
    _git(["add", "README.md"], repo)
    _git(["commit", "-m", "initial"], repo)


def _rows_by_path(rows: list[dict[str, object]]) -> dict[str, dict[str, object]]:
    return {str(row["path"]): row for row in rows}


class TestControlDirty(unittest.TestCase):
    def test_classify_path_role_is_conservative(self) -> None:
        cases = {
            "README.md": dirty.ROLE_CANONICAL_DOC,
            "docs/TOOL_STATUS.md": dirty.ROLE_CANONICAL_DOC,
            ".audit_logs/control/run.json": dirty.ROLE_GENERATED_REPORT,
            "scanners/rust/SCAN_RUST_SUMMARY.md": dirty.ROLE_GENERATED_REPORT,
            "live_topology_checks.json": dirty.ROLE_WORKSPACE_EVIDENCE,
            "manual_proofs/proof-1.json": dirty.ROLE_WORKSPACE_EVIDENCE,
            "agent_outputs/dispatch_A.md": dirty.ROLE_AGENT_OUTPUT,
            "swarm/mining_priorities.json": dirty.ROLE_AGENT_OUTPUT,
            "submissions/packaged/finding/live-proof/manifest.json": dirty.ROLE_LOCAL_SUBMISSION_PACKET,
            "tmp/scratch.txt": dirty.ROLE_SCRATCH_TMP,
            "tools/control/dirty.py": dirty.ROLE_SOURCE_CODE,
            "contracts/Vault.sol": dirty.ROLE_SOURCE_CODE,
            "misc/notes.txt": dirty.ROLE_UNKNOWN,
        }
        for path, expected in cases.items():
            with self.subTest(path=path):
                self.assertEqual(dirty.classify_path_role(path), expected)

    def test_classify_git_status_tracks_common_porcelain_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _init_repo(repo)

            (repo / "tracked.py").write_text("one\n")
            (repo / "delete_me.sol").write_text("contract A {}\n")
            (repo / "old_name.py").write_text("old\n")
            _git(["add", "tracked.py", "delete_me.sol", "old_name.py"], repo)
            _git(["commit", "-m", "add tracked files"], repo)

            (repo / "tracked.py").write_text("two\n")
            (repo / "delete_me.sol").unlink()
            _git(["mv", "old_name.py", "new_name.py"], repo)
            (repo / "agent_outputs").mkdir()
            (repo / "agent_outputs" / "dispatch_A.md").write_text("output\n")

            rows = _rows_by_path(dirty.classify_git_status(repo))

            self.assertEqual(rows["tracked.py"]["status"], dirty.STATUS_TRACKED_MODIFIED)
            self.assertEqual(rows["tracked.py"]["role"], dirty.ROLE_SOURCE_CODE)
            self.assertEqual(rows["delete_me.sol"]["status"], dirty.STATUS_DELETED)
            self.assertEqual(rows["new_name.py"]["status"], dirty.STATUS_RENAMED)
            self.assertEqual(rows["new_name.py"]["original_path"], "old_name.py")
            self.assertEqual(rows["agent_outputs/dispatch_A.md"]["status"], dirty.STATUS_UNTRACKED)
            self.assertEqual(rows["agent_outputs/dispatch_A.md"]["role"], dirty.ROLE_AGENT_OUTPUT)
            for row in rows.values():
                self.assertIn("dry-run only", str(row["cleanup_suggestion"]))

    def test_parse_status_conflicted_and_ignored_rows(self) -> None:
        rows = _rows_by_path(
            [row.as_dict() for row in dirty.parse_git_status_porcelain("UU src/Vault.sol\n!! tmp/cache.bin\n")]
        )
        self.assertEqual(rows["src/Vault.sol"]["status"], dirty.STATUS_CONFLICTED)
        self.assertEqual(rows["tmp/cache.bin"]["status"], dirty.STATUS_IGNORED_UNKNOWN)

    def test_list_worktrees_classifies_current_clean_and_dirty_registered(self) -> None:
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
            (linked_dirty / "dirty.txt").write_text("dirty\n")

            rows = _rows_by_path(dirty.list_worktrees(repo))

            self.assertEqual(rows[str(repo.resolve())]["safety"], dirty.WT_ACTIVE_CURRENT)
            self.assertEqual(rows[str(linked_clean.resolve())]["safety"], dirty.WT_REGISTERED_CLEAN_UNKNOWN)
            self.assertEqual(rows[str(linked_dirty.resolve())]["safety"], dirty.WT_REGISTERED_DIRTY)
            self.assertEqual(rows[str(linked_dirty.resolve())]["dirty_count"], 1)
            for row in rows.values():
                self.assertIn("dry-run only", str(row["cleanup_suggestion"]))

    def test_list_worktrees_classifies_missing_path_without_pruning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            linked = root / "linked-missing"
            repo.mkdir()
            _init_repo(repo)
            _git(["branch", "missing-branch"], repo)
            _git(["worktree", "add", str(linked), "missing-branch"], repo)

            marker = linked / ".git"
            self.assertTrue(marker.exists())
            marker.unlink()
            for path in sorted(linked.iterdir()):
                path.unlink()
            linked.rmdir()

            rows = _rows_by_path(dirty.list_worktrees(repo))
            self.assertEqual(rows[str(linked.resolve())]["safety"], dirty.WT_MISSING_PATH)
            self.assertFalse(linked.exists())


if __name__ == "__main__":
    unittest.main()
