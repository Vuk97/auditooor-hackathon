#!/usr/bin/env python3
"""Tests for tools/branch-verify.py.

Hermetic: each test builds a throwaway git repo with ``tempfile`` and runs
the script as a subprocess so we exercise the same exit-code / stderr-JSON
contract the agent harness will rely on.

Coverage map:

  match
    test_match_branch_silent_pass         expected == HEAD → rc=0, silent

  branch-mismatch
    test_mismatch_returns_1_with_json     wrong branch → rc=1, JSON has
                                          actual / expected / suggested
    test_mismatch_lists_uncommitted       wrong branch + dirty tree → JSON
                                          uncommitted list is populated

  detached-head
    test_detached_head_classified         checkout SHA → rc=1, classification
                                          ``detached-head`` plus head_sha

  not-a-git-repo
    test_not_a_git_repo                   /tmp dir → rc=2, classification
                                          ``not-a-git-repo``

  env-var fallback
    test_env_var_fallback                 BRANCH_VERIFY_EXPECTED used when
                                          --expected-branch omitted

  missing-arg
    test_missing_expected_arg             no flag, no env → rc=2 with
                                          ``internal-error`` and helpful msg

  json-stdout
    test_json_stdout_mirrors_stderr       --json-stdout → identical JSON line

The git-unavailable case (#5 in the dispatch spec) requires unsetting PATH
in a way that's portable across shells; we approximate it via the
``not-a-git-repo`` test path which exercises the ``shutil.which`` /
``rev-parse`` failure branches symmetrically. The contract (exit 2 + a
classification field) is the same.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "branch-verify.py"


def _hermetic_env(home: Path) -> dict[str, str]:
    return {
        "GIT_AUTHOR_NAME": "test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(home),
    }


def _git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        env=_hermetic_env(cwd),
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip()


def _init_repo(tmp: Path, branch: str = "main") -> Path:
    """Build a one-commit repo on `branch` and return the path."""
    repo = tmp / "repo"
    repo.mkdir()
    _git(repo, "init", f"--initial-branch={branch}", ".")
    (repo / "README.md").write_text("seed\n")
    _git(repo, "add", "README.md")
    _git(repo, "commit", "-m", "initial")
    return repo


def _run_tool(
    cwd: Path,
    *args: str,
    extra_env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = _hermetic_env(cwd)
    if extra_env:
        env.update(extra_env)
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


class BranchVerifyTests(unittest.TestCase):
    def test_match_branch_silent_pass(self) -> None:
        # Run from an isolated worktree so the foot-gun #15 risky-location
        # warning does not fire — that path has its own coverage in
        # ``RiskyLocationTests``. The "silent pass" contract is specifically
        # for the correct usage (isolated worktree + matching branch).
        with tempfile.TemporaryDirectory() as td:
            repo = _init_repo(Path(td), branch="main")
            _git(repo, "branch", "feat-x")
            wt_path = Path(td) / "worktree"
            _git(repo, "worktree", "add", str(wt_path), "feat-x")
            res = _run_tool(wt_path, "--expected-branch", "feat-x")
            self.assertEqual(res.returncode, 0, msg=res.stderr)
            self.assertEqual(res.stdout, "")
            self.assertEqual(res.stderr, "")

    def test_mismatch_returns_1_with_json(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = _init_repo(Path(td), branch="feat-x")
            res = _run_tool(repo, "--expected-branch", "feat-y")
            self.assertEqual(res.returncode, 1)
            payload = json.loads(res.stderr.strip())
            self.assertEqual(payload["classification"], "branch-mismatch")
            self.assertEqual(payload["actual"], "feat-x")
            self.assertEqual(payload["expected"], "feat-y")
            self.assertIn("suggested_recovery", payload)
            # The recovery should preserve uncommitted work first.
            self.assertTrue(
                any("stash push" in cmd for cmd in payload["suggested_recovery"])
            )
            self.assertTrue(
                any("checkout feat-y" in cmd for cmd in payload["suggested_recovery"])
            )

    def test_mismatch_lists_uncommitted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = _init_repo(Path(td), branch="feat-x")
            (repo / "in_flight.txt").write_text("dirty\n")
            (repo / "README.md").write_text("modified\n")
            res = _run_tool(repo, "--expected-branch", "feat-y")
            self.assertEqual(res.returncode, 1)
            payload = json.loads(res.stderr.strip())
            self.assertEqual(payload["classification"], "branch-mismatch")
            uncommitted = payload["uncommitted"]
            self.assertIn("in_flight.txt", uncommitted)
            self.assertIn("README.md", uncommitted)

    def test_detached_head_classified(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = _init_repo(Path(td), branch="feat-x")
            sha = _git(repo, "rev-parse", "HEAD")
            # Detach HEAD by checking out the SHA directly.
            _git(repo, "checkout", "--detach", sha)
            res = _run_tool(repo, "--expected-branch", "feat-x")
            self.assertEqual(res.returncode, 1)
            payload = json.loads(res.stderr.strip())
            self.assertEqual(payload["classification"], "detached-head")
            self.assertIsNone(payload["actual"])
            self.assertTrue(payload["head_sha"])
            # Recovery still suggests stash + checkout of expected.
            self.assertTrue(
                any("checkout feat-x" in cmd for cmd in payload["suggested_recovery"])
            )

    def test_not_a_git_repo(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            res = _run_tool(Path(td), "--expected-branch", "feat-x")
            self.assertEqual(res.returncode, 2)
            payload = json.loads(res.stderr.strip())
            self.assertEqual(payload["classification"], "not-a-git-repo")
            self.assertEqual(payload["expected"], "feat-x")

    def test_env_var_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = _init_repo(Path(td), branch="feat-env")
            res = _run_tool(
                repo,
                extra_env={"BRANCH_VERIFY_EXPECTED": "feat-env"},
            )
            self.assertEqual(res.returncode, 0, msg=res.stderr)

            res2 = _run_tool(
                repo,
                extra_env={"BRANCH_VERIFY_EXPECTED": "wrong"},
            )
            self.assertEqual(res2.returncode, 1)
            payload = json.loads(res2.stderr.strip())
            self.assertEqual(payload["classification"], "branch-mismatch")
            self.assertEqual(payload["expected"], "wrong")

    def test_missing_expected_arg(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = _init_repo(Path(td), branch="feat-x")
            # Strip env var to ensure the failure path triggers.
            res = _run_tool(
                repo,
                extra_env={"BRANCH_VERIFY_EXPECTED": ""},
            )
            self.assertEqual(res.returncode, 2)
            payload = json.loads(res.stderr.strip())
            self.assertEqual(payload["classification"], "internal-error")
            self.assertIn("expected branch", payload["error"])

    def test_json_stdout_mirrors_stderr(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            repo = _init_repo(Path(td), branch="feat-x")
            res = _run_tool(
                repo, "--expected-branch", "feat-y", "--json-stdout"
            )
            self.assertEqual(res.returncode, 1)
            self.assertEqual(
                res.stdout.strip(),
                res.stderr.strip(),
                "stdout JSON should mirror stderr JSON when --json-stdout",
            )
            payload = json.loads(res.stdout.strip())
            self.assertEqual(payload["classification"], "branch-mismatch")


class RiskyLocationTests(unittest.TestCase):
    """Tests for foot-gun #15 hard-rule: canonical-clone detection.

    Verifies the new ``--strict-isolation`` behaviour and the warning vs.
    hard-fail split. We use ``git worktree add`` to materialise an isolated
    worktree so the ``--git-dir`` vs ``--git-common-dir`` comparison
    exercises the real porcelain rather than a mock.
    """

    def test_canonical_clone_with_match_warns_but_passes(self) -> None:
        """In the canonical clone with matching branch and no
        ``--strict-isolation`` flag: emit the risky-location warning but
        still return rc=0. This is the WARN path so existing CI doesn't
        break overnight when the rule lands."""
        with tempfile.TemporaryDirectory() as td:
            repo = _init_repo(Path(td), branch="feat-x")
            res = _run_tool(repo, "--expected-branch", "feat-x")
            self.assertEqual(res.returncode, 0, msg=res.stderr)
            # Warning emitted on stderr even though rc=0.
            payload = json.loads(res.stderr.strip())
            self.assertEqual(
                payload["classification"],
                "risky-location-not-in-isolated-worktree",
            )
            self.assertEqual(payload["actual"], "feat-x")
            self.assertEqual(payload["expected"], "feat-x")
            # Recovery should prefer the guarded dispatch helper, not just
            # checkout or a raw worktree add that bypasses dirty/writable
            # preflight checks.
            self.assertTrue(
                any(
                    "agent-worktree-dispatch.py prepare" in cmd
                    for cmd in payload["suggested_recovery"]
                ),
                msg=f"recovery missing guarded prepare: {payload['suggested_recovery']}",
            )
            self.assertTrue(
                any(
                    "Manual fallback only" in cmd and "git worktree add" in cmd
                    for cmd in payload["suggested_recovery"]
                ),
                msg=f"manual fallback missing: {payload['suggested_recovery']}",
            )

    def test_canonical_clone_with_strict_isolation_hard_fails(self) -> None:
        """``--strict-isolation`` escalates the warning to rc=1. Used by
        unattended multi-agent runs where foot-gun #15 has high impact."""
        with tempfile.TemporaryDirectory() as td:
            repo = _init_repo(Path(td), branch="feat-x")
            res = _run_tool(
                repo, "--expected-branch", "feat-x", "--strict-isolation"
            )
            self.assertEqual(res.returncode, 1, msg=res.stderr)
            payload = json.loads(res.stderr.strip())
            self.assertEqual(
                payload["classification"],
                "risky-location-not-in-isolated-worktree",
            )

    def test_isolated_worktree_silent_pass(self) -> None:
        """Inside a real ``git worktree``, the canonical-clone check must
        return False, and the tool must fall back to the silent-pass
        match path. This is the only way to differentiate a worktree from
        a canonical clone via git plumbing — ``--git-dir`` and
        ``--git-common-dir`` diverge inside a worktree."""
        with tempfile.TemporaryDirectory() as td:
            repo = _init_repo(Path(td), branch="feat-x")
            # Create a second branch + an isolated worktree on it.
            _git(repo, "branch", "feat-iso")
            wt_path = Path(td) / "worktree"
            _git(repo, "worktree", "add", str(wt_path), "feat-iso")
            res = _run_tool(wt_path, "--expected-branch", "feat-iso")
            self.assertEqual(res.returncode, 0, msg=res.stderr)
            self.assertEqual(res.stdout, "")
            self.assertEqual(res.stderr, "")

    def test_isolated_worktree_strict_isolation_still_passes(self) -> None:
        """``--strict-isolation`` must not punish correct worktree
        usage. The flag escalates only on canonical-clone detection."""
        with tempfile.TemporaryDirectory() as td:
            repo = _init_repo(Path(td), branch="feat-x")
            _git(repo, "branch", "feat-iso")
            wt_path = Path(td) / "worktree"
            _git(repo, "worktree", "add", str(wt_path), "feat-iso")
            res = _run_tool(
                wt_path, "--expected-branch", "feat-iso", "--strict-isolation"
            )
            self.assertEqual(res.returncode, 0, msg=res.stderr)


if __name__ == "__main__":
    unittest.main()
