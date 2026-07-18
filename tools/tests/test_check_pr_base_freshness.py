#!/usr/bin/env python3
"""Wave-5 — tools/check-pr-base-freshness.sh regression tests.

Hermetic tests: build a throwaway git repo in tmp, fabricate a `origin/main`
ref via a local "remote" working dir, then run the script with --no-fetch so
no network is touched.

Real-world driver (PR #139): a PR rooted on a stale base would have wiped
8,379 lines from 7+ merged PRs. The script's job is to fail before merge.

Cases covered:
  1. Fresh branch (0 commits behind, 0 deletions) -> exit 0
  2. Stale branch (commits-behind > threshold) -> exit 2 + actionable error
  3. High-deletion branch but fresh -> exit 1 + warning, NOT error
  4. Both stale + high-deletion -> exit 3
  5. Threshold env-vars override the defaults
  6. CLI flags --threshold-commits / --threshold-deletions override env
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "check-pr-base-freshness.sh"


def _git(cwd: Path, *args: str, env: dict[str, str] | None = None) -> str:
    """Run `git ...` in cwd; return stripped stdout. Raises on non-zero."""
    full_env = {
        # Hermetic identity so commits succeed without user .gitconfig.
        "GIT_AUTHOR_NAME": "test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(cwd),  # avoid reading ~/.gitconfig
    }
    if env:
        full_env.update(env)
    proc = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        env=full_env,
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip()


def _run_script(
    cwd: Path,
    *extra_args: str,
    env_overrides: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    """Invoke the script with --no-fetch (network-free). cwd is the repo root."""
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(cwd),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
    }
    if env_overrides:
        env.update(env_overrides)
    return subprocess.run(
        ["bash", str(SCRIPT), "--no-fetch", *extra_args],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
    )


def _make_commit(repo: Path, fname: str, content: str, msg: str) -> str:
    (repo / fname).write_text(content)
    _git(repo, "add", fname)
    _git(repo, "commit", "-m", msg)
    return _git(repo, "rev-parse", "HEAD")


def _build_repo_with_origin(
    tmp: Path,
    *,
    main_extra_commits: int,
    branch_extra_commits: int,
    branch_deletions: int,
    big_file_lines: int = 0,
) -> Path:
    """Build a hermetic clone+remote pair.

    Layout:
        tmp/origin   — bare-ish remote (we use a non-bare clone with a
                       detached HEAD so we can advance `main` on it freely)
        tmp/work     — working repo cloned from origin

    Sequence:
      1. Create initial commit on origin's main with a seed file containing
         `big_file_lines` lines (so we have lines to delete later).
      2. Clone to work/. (origin/main mirrors origin's main at this point.)
      3. Branch off work/ as `feature`.
      4. Advance origin/main by `main_extra_commits` (this is what makes the
         feature branch go "stale").
      5. On the feature branch in work/, add `branch_extra_commits` commits
         and (if branch_deletions > 0) delete that many lines from the seed.
      6. `git fetch origin` in work/ so origin/main is up to date locally.
    Returns work/ path (the script's cwd).
    """
    origin = tmp / "origin"
    work = tmp / "work"
    origin.mkdir()
    _git(origin, "init", "--initial-branch=main", ".")
    seed_lines = "\n".join(f"line {i}" for i in range(big_file_lines)) + "\n" if big_file_lines else "seed\n"
    _make_commit(origin, "seed.txt", seed_lines, "initial")

    # Clone to work/. main now tracks origin/main.
    subprocess.run(
        ["git", "clone", str(origin), str(work)],
        check=True, capture_output=True,
        env={**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null"},
    )
    # Reset identity in work/.
    _git(work, "config", "user.name", "test")
    _git(work, "config", "user.email", "test@example.com")

    # Create feature branch off the (now-stale-to-be) base.
    _git(work, "checkout", "-b", "feature")

    # Advance origin/main by N commits. We do this by checking origin out
    # detached, committing on its main, then the work clone fetches.
    if main_extra_commits > 0:
        # origin's main is the only branch — commit directly on it.
        for i in range(main_extra_commits):
            _make_commit(origin, f"main_{i}.txt", f"main_{i}\n", f"main commit {i}")

    # Branch-side commits.
    if branch_extra_commits > 0:
        for i in range(branch_extra_commits):
            _make_commit(work, f"feature_{i}.txt", f"feature_{i}\n", f"feature commit {i}")

    # Branch-side deletions (drop N lines off seed.txt).
    if branch_deletions > 0:
        path = work / "seed.txt"
        lines = path.read_text().splitlines(keepends=True)
        kept = lines[: max(0, len(lines) - branch_deletions)]
        path.write_text("".join(kept))
        _git(work, "add", "seed.txt")
        _git(work, "commit", "-m", f"drop {branch_deletions} lines from seed")

    # Fetch the advanced origin/main into the work clone so the script can
    # see it via the local refs (it will skip its own fetch via --no-fetch).
    _git(work, "fetch", "origin", "main")
    return work


class CheckPRBaseFreshnessTest(unittest.TestCase):
    def test_script_exists_and_executable(self) -> None:
        self.assertTrue(SCRIPT.exists(), f"script missing at {SCRIPT}")
        self.assertTrue(os.access(SCRIPT, os.X_OK), "script should be executable")

    def test_fresh_branch_exits_zero(self) -> None:
        """Branch with 0 commits behind origin/main and no deletions → exit 0."""
        with tempfile.TemporaryDirectory() as td:
            work = _build_repo_with_origin(
                Path(td),
                main_extra_commits=0,
                branch_extra_commits=2,
                branch_deletions=0,
            )
            proc = _run_script(work)
            self.assertEqual(
                proc.returncode, 0,
                f"expected exit 0 for fresh branch, got {proc.returncode}\n"
                f"stdout: {proc.stdout}\nstderr: {proc.stderr}",
            )
            self.assertIn("OK: branch is fresh", proc.stdout)

    def test_stale_branch_fails_exit_two(self) -> None:
        """Branch >threshold commits behind origin/main → exit 2 + actionable error."""
        with tempfile.TemporaryDirectory() as td:
            work = _build_repo_with_origin(
                Path(td),
                main_extra_commits=5,        # main has moved 5 ahead
                branch_extra_commits=1,
                branch_deletions=0,
            )
            # Set threshold to 2 so 5 > 2 trips the stale check; deletions
            # threshold high so it doesn't also trigger.
            proc = _run_script(
                work,
                env_overrides={
                    "BASE_FRESHNESS_THRESHOLD_COMMITS": "2",
                    "BASE_FRESHNESS_THRESHOLD_DELETIONS": "999999",
                },
            )
            self.assertEqual(
                proc.returncode, 2,
                f"expected exit 2 for stale branch, got {proc.returncode}\n"
                f"stdout: {proc.stdout}\nstderr: {proc.stderr}",
            )
            # Error should be actionable.
            self.assertIn("commits behind", proc.stderr)
            self.assertIn("Rebase", proc.stderr)
            self.assertIn("::error::", proc.stderr)

    def test_high_deletions_fresh_base_exits_one_with_warning(self) -> None:
        """Deletions > threshold but commits-behind = 0 → exit 1 (warning)."""
        with tempfile.TemporaryDirectory() as td:
            work = _build_repo_with_origin(
                Path(td),
                main_extra_commits=0,         # base is fresh
                branch_extra_commits=0,
                branch_deletions=50,          # delete 50 lines
                big_file_lines=200,           # seed file has 200 lines
            )
            proc = _run_script(
                work,
                env_overrides={
                    "BASE_FRESHNESS_THRESHOLD_COMMITS": "999",
                    "BASE_FRESHNESS_THRESHOLD_DELETIONS": "10",  # 50 > 10
                },
            )
            self.assertEqual(
                proc.returncode, 1,
                f"expected exit 1 for high-deletion warning, got {proc.returncode}\n"
                f"stdout: {proc.stdout}\nstderr: {proc.stderr}",
            )
            self.assertIn("::warning::", proc.stderr)
            self.assertIn("deletions", proc.stderr)
            # It is a warning, NOT an error.
            self.assertNotIn("::error::", proc.stderr)

    def test_both_stale_and_high_deletions_exits_three(self) -> None:
        """Stale base + high deletions → exit 3 (combined)."""
        with tempfile.TemporaryDirectory() as td:
            work = _build_repo_with_origin(
                Path(td),
                main_extra_commits=5,
                branch_extra_commits=0,
                branch_deletions=50,
                big_file_lines=200,
            )
            proc = _run_script(
                work,
                env_overrides={
                    "BASE_FRESHNESS_THRESHOLD_COMMITS": "2",
                    "BASE_FRESHNESS_THRESHOLD_DELETIONS": "10",
                },
            )
            self.assertEqual(
                proc.returncode, 3,
                f"expected exit 3 for stale+high-deletions, got {proc.returncode}\n"
                f"stdout: {proc.stdout}\nstderr: {proc.stderr}",
            )
            self.assertIn("::error::", proc.stderr)
            self.assertIn("commits behind", proc.stderr)

    def test_env_threshold_overrides_default(self) -> None:
        """Env var BASE_FRESHNESS_THRESHOLD_COMMITS overrides the 20 default."""
        with tempfile.TemporaryDirectory() as td:
            work = _build_repo_with_origin(
                Path(td),
                main_extra_commits=3,         # 3 commits behind
                branch_extra_commits=1,
                branch_deletions=0,
            )
            # With default threshold (20), 3-behind is fine → exit 0.
            proc_default = _run_script(work)
            self.assertEqual(
                proc_default.returncode, 0,
                f"3 < default 20 should pass, got {proc_default.returncode}\n"
                f"stderr: {proc_default.stderr}",
            )
            # With env-override threshold=1, 3-behind should fail.
            proc_strict = _run_script(
                work,
                env_overrides={"BASE_FRESHNESS_THRESHOLD_COMMITS": "1"},
            )
            self.assertEqual(
                proc_strict.returncode, 2,
                f"3 > override 1 should exit 2, got {proc_strict.returncode}\n"
                f"stderr: {proc_strict.stderr}",
            )

    def test_cli_flag_overrides_env(self) -> None:
        """--threshold-commits N on the CLI wins even if env says otherwise."""
        with tempfile.TemporaryDirectory() as td:
            work = _build_repo_with_origin(
                Path(td),
                main_extra_commits=3,
                branch_extra_commits=1,
                branch_deletions=0,
            )
            # Env says strict (1), but CLI flag says lenient (10) → 3 < 10 → pass.
            proc = _run_script(
                work,
                "--threshold-commits", "10",
                env_overrides={"BASE_FRESHNESS_THRESHOLD_COMMITS": "1"},
            )
            self.assertEqual(
                proc.returncode, 0,
                f"CLI flag --threshold-commits should override env, got {proc.returncode}\n"
                f"stdout: {proc.stdout}\nstderr: {proc.stderr}",
            )


if __name__ == "__main__":
    unittest.main()
