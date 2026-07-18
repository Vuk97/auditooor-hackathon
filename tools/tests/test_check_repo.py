#!/usr/bin/env python3
"""iter13 T5 — check-repo.sh regression tests.

Covers `tools/check-repo.sh`, the wrong-worktree routing guard.

iter12 lost 2 of 5 agents to wrong-worktree routing (prompts landed in the
clob2 polymarket trading-bot repo, not auditooor). This helper is meant to
be sourced at the start of any agent script so it fails fast when pwd is
outside the expected prefix.

Exit-code contract:
    0 — pwd is inside an auditooor git repo with an auditooor-looking origin.
    2 — pwd is outside the configured prefix or outside any git repo.
    3 — pwd is inside a wrong git repo / wrong remote.

`AUDITOOOR_EXPECTED_PREFIX` can be set by persistent local agents that want a
hard path guard. CI must not rely on a Mac-specific checkout path.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "check-repo.sh"


def _run(cwd: Path, *, env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["sh", str(SCRIPT)],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        env=env,
    )


class CheckRepoTest(unittest.TestCase):
    def test_check_repo_passes_inside_auditooor(self) -> None:
        """pwd inside the primary repo tree exits 0."""
        proc = _run(ROOT)
        self.assertEqual(
            proc.returncode, 0,
            f"expected exit 0 inside {ROOT}, got {proc.returncode}\n"
            f"stderr: {proc.stderr}",
        )

    def test_check_repo_fails_outside_git_repo(self) -> None:
        """pwd outside any git repo triggers exit 2 (routing error)."""
        outside = Path(tempfile.gettempdir()).resolve()
        proc = subprocess.run(
            ["sh", str(SCRIPT)],
            cwd=str(outside),
            capture_output=True,
            text=True,
        )
        self.assertEqual(
            proc.returncode, 2,
            f"expected exit 2 outside prefix, got {proc.returncode}\n"
            f"stdout: {proc.stdout}\nstderr: {proc.stderr}",
        )
        self.assertIn("not inside a git repo", proc.stderr)

    def test_check_repo_fails_wrong_remote(self) -> None:
        """Git repo with a non-auditooor origin exits 3."""
        with tempfile.TemporaryDirectory(prefix="auditooor-check-repo-test-") as tmp:
            tmp_path = Path(tmp)
            subprocess.run(
                ["git", "init", "-q"], cwd=str(tmp_path), check=True,
            )
            subprocess.run(
                ["git", "remote", "add", "origin", "https://example.com/trading-bot.git"],
                cwd=str(tmp_path),
                check=True,
            )
            proc = _run(tmp_path)
            self.assertEqual(
                proc.returncode, 3,
                f"expected exit 3 with wrong remote, got {proc.returncode}\n"
                f"stdout: {proc.stdout}\nstderr: {proc.stderr}",
            )
            self.assertIn("origin remote", proc.stderr)

    def test_configured_prefix_is_honored(self) -> None:
        """Persistent agents can still require a specific local prefix."""
        env = os.environ.copy()
        env["AUDITOOOR_EXPECTED_PREFIX"] = str(ROOT / "definitely-not-current")
        proc = _run(ROOT, env=env)
        self.assertEqual(
            proc.returncode, 2,
            f"expected exit 2 outside configured prefix, got {proc.returncode}\n"
            f"stdout: {proc.stdout}\nstderr: {proc.stderr}",
        )
        self.assertIn("outside", proc.stderr)

    def test_check_repo_passes_in_worktree_with_non_auditooor_basename(self) -> None:
        """Regression: agents in /private/tmp/wt-<branch>/ must pass.

        Wave-2/wave-3 of PR #121 had 5+ agents fail this guard because the
        toplevel basename was `wt-pr121-A1`, `wt-pr121-A4`, etc. — none of
        which match a literal `auditooor*` substring. Repo identity must be
        established by the origin URL, not the on-disk path.
        """
        with tempfile.TemporaryDirectory(prefix="wt-pr121-fake-") as tmp:
            tmp_path = Path(tmp).resolve()
            # Sanity: the tempdir basename must NOT contain 'auditooor', or
            # this regression test trivially passes against a path-string check.
            self.assertNotIn("auditooor", tmp_path.name)
            subprocess.run(
                ["git", "init", "-q"], cwd=str(tmp_path), check=True,
            )
            subprocess.run(
                ["git", "remote", "add", "origin",
                 "https://github.com/Vuk97/auditooor.git"],
                cwd=str(tmp_path),
                check=True,
            )
            proc = _run(tmp_path)
            self.assertEqual(
                proc.returncode, 0,
                f"expected exit 0 in fake worktree {tmp_path} with auditooor "
                f"origin, got {proc.returncode}\n"
                f"stdout: {proc.stdout}\nstderr: {proc.stderr}",
            )


if __name__ == "__main__":
    unittest.main()
