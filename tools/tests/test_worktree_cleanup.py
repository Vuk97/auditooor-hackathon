#!/usr/bin/env python3
"""Offline tests for tools/worktree-cleanup.py.

Each test spins up a real-but-throwaway git repo under
`tempfile.TemporaryDirectory()`, so we exercise the actual `git cherry`
semantics (not a mock). No network, no access to the real repo.

Test list (6):

  1. test_all_cherry_picked_branch_classified_safe_to_delete
  2. test_branch_with_unmerged_commit_preserved
  3. test_dry_run_does_not_actually_delete
  4. test_worktree_path_prefix_filters_attached_worktrees
  5. test_dirty_attached_worktree_is_preserved_even_with_really_delete
  6. test_branch_with_no_commits_ahead_is_safe_to_delete
"""

from __future__ import annotations

import importlib.util
import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"


def _load_module():
    """Load tools/worktree-cleanup.py despite the hyphen."""
    path = TOOLS / "worktree-cleanup.py"
    spec = importlib.util.spec_from_file_location("worktree_cleanup", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Register in sys.modules before exec so @dataclass on Python 3.12+
    # can resolve the module via cls.__module__ lookup.
    sys.modules["worktree_cleanup"] = module
    spec.loader.exec_module(module)
    return module


cleanup = _load_module()


def _git(args, cwd, check=True):
    """Run git with a deterministic environment."""
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "Test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "Test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
        # Avoid picking up the user's global hooks / gpg signing.
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
    }
    proc = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"git {args!r} failed (rc={proc.returncode}): {proc.stderr}"
        )
    return proc


def _init_repo(cwd: Path) -> None:
    _git(["init", "-b", "main"], cwd=cwd)
    # Disable commit signing explicitly inside the repo too.
    _git(["config", "commit.gpgsign", "false"], cwd=cwd)


def _commit_file(cwd: Path, name: str, content: str, msg: str) -> str:
    (cwd / name).write_text(content)
    _git(["add", name], cwd=cwd)
    _git(["commit", "-m", msg], cwd=cwd)
    rev = _git(["rev-parse", "HEAD"], cwd=cwd).stdout.strip()
    return rev


def _call_main(argv):
    out = io.StringIO()
    err = io.StringIO()
    try:
        with redirect_stdout(out), redirect_stderr(err):
            rc = cleanup.main(argv)
    except SystemExit as exc:
        rc = int(exc.code or 0)
    return rc, out.getvalue(), err.getvalue()


class TestWorktreeCleanup(unittest.TestCase):
    # ---------- case 1 ----------
    def test_all_cherry_picked_branch_classified_safe_to_delete(self) -> None:
        """Target has commit A; branch has A cherry-picked under a new SHA.

        `git cherry -v target branch` should return `- <sha>` for the
        lone branch commit, so the tool classifies SAFE-TO-DELETE.
        """
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _init_repo(repo)

            # Root commit so both branches share a base.
            _commit_file(repo, "base.txt", "base\n", "base")

            # Branch with commit A.
            _git(["checkout", "-b", "feature"], cwd=repo)
            a_sha = _commit_file(repo, "a.txt", "apple\n", "add apple")

            # Target branch advances independently (new file on main),
            # so the cherry-pick onto main will have a different parent
            # than A's parent on feature → guaranteed different SHA.
            _git(["checkout", "main"], cwd=repo)
            _commit_file(repo, "divergent.txt", "divergent\n", "main diverges")
            _git(["cherry-pick", a_sha], cwd=repo)

            # Sanity: cherry-pick created a different SHA.
            main_head = _git(["rev-parse", "HEAD"], cwd=repo).stdout.strip()
            self.assertNotEqual(a_sha, main_head)

            # merge-base --is-ancestor feature main → NO (different SHAs)
            proc = _git(
                ["merge-base", "--is-ancestor", "feature", "main"],
                cwd=repo, check=False,
            )
            self.assertNotEqual(
                proc.returncode, 0,
                "sanity: feature should NOT be SHA-ancestor of main",
            )

            row = cleanup.classify_branch(
                "feature", "main", cwd=str(repo),
            )
            self.assertEqual(row.classification, cleanup.CLASS_SAFE)
            self.assertEqual(row.plus_count, 0)
            self.assertGreaterEqual(row.minus_count, 1)

    # ---------- case 2 ----------
    def test_branch_with_unmerged_commit_preserved(self) -> None:
        """Branch has A cherry-picked AND a new commit B not on target.

        `git cherry` should emit a `+` line for B, so the tool
        classifies PRESERVE (fail-closed against losing B).
        """
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _init_repo(repo)

            _commit_file(repo, "base.txt", "base\n", "base")

            _git(["checkout", "-b", "feature"], cwd=repo)
            a_sha = _commit_file(repo, "a.txt", "apple\n", "add apple")
            # Commit B exists only on feature.
            _commit_file(repo, "b.txt", "banana\n", "add banana")

            _git(["checkout", "main"], cwd=repo)
            _commit_file(repo, "divergent.txt", "divergent\n", "main diverges")
            _git(["cherry-pick", a_sha], cwd=repo)

            row = cleanup.classify_branch(
                "feature", "main", cwd=str(repo),
            )
            self.assertEqual(row.classification, cleanup.CLASS_PRESERVE)
            self.assertGreaterEqual(row.plus_count, 1)
            self.assertIn("not yet on main", row.reason)

    # ---------- case 3 ----------
    def test_dry_run_does_not_actually_delete(self) -> None:
        """Even on a SAFE-classified branch, default (dry-run) does not delete."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _init_repo(repo)

            _commit_file(repo, "base.txt", "base\n", "base")

            _git(["checkout", "-b", "claudeboy-iter-test"], cwd=repo)
            a_sha = _commit_file(repo, "a.txt", "apple\n", "add apple")

            _git(["checkout", "main"], cwd=repo)
            _commit_file(repo, "divergent.txt", "divergent\n", "main diverges")
            _git(["cherry-pick", a_sha], cwd=repo)

            # Sanity: pre-run, the branch exists.
            branches_before = _git(
                ["for-each-ref", "--format=%(refname:short)", "refs/heads/"],
                cwd=repo,
            ).stdout
            self.assertIn("claudeboy-iter-test", branches_before)

            # Run the tool with default args (dry-run). Target is `main`
            # here (the fake repo's main); prefix `claudeboy-iter` matches
            # the test branch.
            rc, out, err = _call_main([
                "--target-branch", "main",
                "--prefix", "claudeboy-iter",
                "--repo", str(repo),
            ])
            self.assertEqual(rc, 0, f"stderr={err!r}")
            # Dry-run banner present, classification table shows SAFE.
            self.assertIn("dry-run", out)
            self.assertIn("SAFE-TO-DELETE", out)
            self.assertIn("claudeboy-iter-test", out)

            # Hard negative: branch still exists after the dry-run.
            branches_after = _git(
                ["for-each-ref", "--format=%(refname:short)", "refs/heads/"],
                cwd=repo,
            ).stdout
            self.assertIn(
                "claudeboy-iter-test",
                branches_after,
                "dry-run must NOT delete the branch",
            )

    def test_worktree_path_prefix_filters_attached_worktrees(self) -> None:
        """Only attached worktrees under --worktree-path-prefix remain SAFE."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            _init_repo(repo)

            _commit_file(repo, "base.txt", "base\n", "base")

            _git(["checkout", "-b", "claudeboy-iter-inside"], cwd=repo)
            inside_sha = _commit_file(repo, "inside.txt", "inside\n", "inside")

            _git(["checkout", "main"], cwd=repo)
            _git(["checkout", "-b", "claudeboy-iter-outside"], cwd=repo)
            outside_sha = _commit_file(repo, "outside.txt", "outside\n", "outside")

            _git(["checkout", "main"], cwd=repo)
            _commit_file(repo, "divergent.txt", "divergent\n", "main diverges")
            _git(["cherry-pick", inside_sha], cwd=repo)
            _git(["cherry-pick", outside_sha], cwd=repo)

            allowed_prefix = str(root / "auditooor-")
            inside_worktree = root / "auditooor-inside"
            outside_worktree = root / "other-outside"
            _git(["worktree", "add", str(inside_worktree), "claudeboy-iter-inside"], cwd=repo)
            _git(["worktree", "add", str(outside_worktree), "claudeboy-iter-outside"], cwd=repo)

            rc, out, err = _call_main([
                "--target-branch", "main",
                "--prefix", "claudeboy-iter",
                "--worktree-path-prefix", allowed_prefix,
                "--repo", str(repo),
            ])

            self.assertEqual(rc, 0, f"stderr={err!r}")
            self.assertIn("claudeboy-iter-inside", out)
            self.assertIn("SAFE-TO-DELETE", out)
            self.assertIn("claudeboy-iter-outside", out)
            self.assertIn("outside --worktree-path-prefix", out)

    def test_dirty_attached_worktree_is_preserved_even_with_really_delete(self) -> None:
        """Dirty attached worktrees are preserved before git worktree remove."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "repo"
            repo.mkdir()
            _init_repo(repo)

            _commit_file(repo, "base.txt", "base\n", "base")

            _git(["checkout", "-b", "claudeboy-iter-dirty"], cwd=repo)
            dirty_sha = _commit_file(repo, "dirty.txt", "clean\n", "dirty base")

            _git(["checkout", "main"], cwd=repo)
            _commit_file(repo, "divergent.txt", "divergent\n", "main diverges")
            _git(["cherry-pick", dirty_sha], cwd=repo)

            allowed_prefix = str(root / "auditooor-")
            dirty_worktree = root / "auditooor-dirty"
            _git(["worktree", "add", str(dirty_worktree), "claudeboy-iter-dirty"], cwd=repo)
            (dirty_worktree / "untracked.txt").write_text("preserve me\n")

            rc, out, err = _call_main([
                "--target-branch", "main",
                "--prefix", "claudeboy-iter",
                "--worktree-path-prefix", allowed_prefix,
                "--repo", str(repo),
                "--really-delete",
            ])

            self.assertEqual(rc, 0, f"stderr={err!r}")
            self.assertIn("PRESERVE", out)
            self.assertIn("dirty", out)
            self.assertTrue(dirty_worktree.exists(), "dirty worktree must not be removed")
            branches_after = _git(
                ["for-each-ref", "--format=%(refname:short)", "refs/heads/"],
                cwd=repo,
            ).stdout
            self.assertIn("claudeboy-iter-dirty", branches_after)

    def test_branch_with_no_commits_ahead_is_safe_to_delete(self) -> None:
        """Empty git-cherry output is safe when branch has no commits ahead."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            _init_repo(repo)

            _commit_file(repo, "base.txt", "base\n", "base")
            _git(["checkout", "-b", "claudeboy-iter-merged"], cwd=repo)
            _commit_file(repo, "merged.txt", "merged\n", "merged work")

            _git(["checkout", "main"], cwd=repo)
            _git(["merge", "--ff-only", "claudeboy-iter-merged"], cwd=repo)

            row = cleanup.classify_branch(
                "claudeboy-iter-merged", "main", cwd=str(repo),
            )
            self.assertEqual(row.classification, cleanup.CLASS_SAFE)
            self.assertEqual(row.plus_count, 0)
            self.assertEqual(row.minus_count, 0)
            self.assertIn("no commits ahead", row.reason)


if __name__ == "__main__":
    unittest.main()
