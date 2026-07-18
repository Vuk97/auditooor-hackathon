"""Tests for ``discover_target_pr_and_branch`` in
``tools/hackerman-pr-merge-checklist.py`` (Wave-2 generalization).

Wave-2 PR-A blocker fix. The renamed tool now auto-discovers the
target PR + branch via a priority chain:

  1. CLI flags  --pr-number / --branch
  2. Env vars   AUDITOOOR_TARGET_PR / AUDITOOOR_TARGET_BRANCH
  3. ``gh pr status --json currentBranch`` (current-branch's PR)
  4. ``git rev-parse --abbrev-ref HEAD`` (branch only)

When discovery fails entirely, ``DiscoveryError`` is raised; the CLI
catches it and exits 1 with a multi-line message naming all 3 fallback
paths.

Required cases (per PR-A spec):

- test_cli_flag_pr_number_wins
- test_env_var_pr_number_wins
- test_gh_pr_status_used_when_no_cli_no_env
- test_branch_equality_succeeds_when_discovered_correctly
- test_discovery_failure_exits_clean
- test_backwards_compatibility_pr726_alias

All ``gh`` / ``git`` calls are mocked via ``unittest.mock`` so the test
suite never makes a real network call. The Wave-1 fallback constants
(WAVE1_FALLBACK_PR_NUMBER=726, WAVE1_FALLBACK_BRANCH="wave-1-...") are
NOT used as a silent fallback; they are constants exposed for the
operator's manual override only.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-pr-merge-checklist.py"
ALIAS_PATH = REPO_ROOT / "tools" / "hackerman-pr726-merge-checklist.py"


def _load_tool() -> Any:
    name = "_hackerman_pr_merge_checklist_discovery_test_mod"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


class DiscoveryPriorityTests(unittest.TestCase):
    """Verify the priority chain CLI > env > gh > git."""

    def test_cli_flag_pr_number_wins(self) -> None:
        """CLI --pr-number overrides env AUDITOOOR_TARGET_PR AND gh."""
        env = {
            tool.ENV_PR_NUMBER: "555",
            tool.ENV_BRANCH: "env-branch",
        }
        # gh would also return something, but CLI must win.
        with mock.patch.object(
            tool, "_gh_pr_status_lookup", return_value=(444, "gh-branch")
        ):
            pr, branch, source = tool.discover_target_pr_and_branch(
                cli_pr=999,
                cli_branch=None,
                cwd=Path("/tmp"),
                env=env,
            )
        self.assertEqual(pr, 999)
        # branch falls through to env (no CLI branch).
        self.assertEqual(branch, "env-branch")
        self.assertIn("cli:pr", source)
        self.assertIn(f"env:{tool.ENV_BRANCH}", source)

    def test_env_var_pr_number_wins(self) -> None:
        """Env AUDITOOOR_TARGET_PR beats gh pr status when no CLI."""
        env = {
            tool.ENV_PR_NUMBER: "999",
            tool.ENV_BRANCH: "env-branch-name",
        }
        with mock.patch.object(
            tool, "_gh_pr_status_lookup", return_value=(123, "gh-branch")
        ):
            pr, branch, source = tool.discover_target_pr_and_branch(
                cli_pr=None,
                cli_branch=None,
                cwd=Path("/tmp"),
                env=env,
            )
        self.assertEqual(pr, 999)
        self.assertEqual(branch, "env-branch-name")
        self.assertIn(f"env:{tool.ENV_PR_NUMBER}", source)
        self.assertNotIn("gh:pr_status", source)

    def test_gh_pr_status_used_when_no_cli_no_env(self) -> None:
        """gh pr status fills both PR and branch when CLI + env empty."""
        with mock.patch.object(
            tool, "_gh_pr_status_lookup", return_value=(728, "wave-2-corpus-migration")
        ):
            pr, branch, source = tool.discover_target_pr_and_branch(
                cli_pr=None,
                cli_branch=None,
                cwd=Path("/tmp"),
                env={},  # no env vars
            )
        self.assertEqual(pr, 728)
        self.assertEqual(branch, "wave-2-corpus-migration")
        self.assertIn("gh:pr_status", source)

    def test_git_branch_used_for_branch_only_when_gh_fails(self) -> None:
        """If gh returns nothing but git knows the branch, branch is
        populated and pr is None -> DiscoveryError."""
        with mock.patch.object(
            tool, "_gh_pr_status_lookup", return_value=(None, None)
        ), mock.patch.object(
            tool, "_git_current_branch", return_value="some-branch"
        ):
            with self.assertRaises(tool.DiscoveryError) as ctx:
                tool.discover_target_pr_and_branch(
                    cli_pr=None,
                    cli_branch=None,
                    cwd=Path("/tmp"),
                    env={},
                )
            self.assertIn("CLI flags", str(ctx.exception))
            self.assertIn("Env vars", str(ctx.exception))
            self.assertIn("gh CLI", str(ctx.exception))


class BranchEqualityTests(unittest.TestCase):
    """When discovery resolves PR 728 / wave-2-corpus-migration, the
    origin-sync step's branch-equality check should accept the
    current branch instead of rejecting it as wave-1."""

    def test_branch_equality_succeeds_when_discovered_correctly(self) -> None:
        # Simulate a successful gh discovery for PR 728.
        with mock.patch.object(
            tool, "_gh_pr_status_lookup", return_value=(728, "wave-2-corpus-migration")
        ):
            pr, branch, _ = tool.discover_target_pr_and_branch(
                cli_pr=None,
                cli_branch=None,
                cwd=Path("/tmp"),
                env={},
            )
        self.assertEqual(pr, 728)
        self.assertEqual(branch, "wave-2-corpus-migration")
        # The origin-sync step compares ``current_branch`` to ``branch``.
        # Construct the same comparison the step does and confirm it
        # would NOT fail-fast on branch mismatch when we are on
        # wave-2-corpus-migration.
        current_branch = "wave-2-corpus-migration"
        expected_branch = branch
        self.assertEqual(current_branch, expected_branch)
        # Sanity: with the WAVE1 defaults the same check would FAIL.
        self.assertNotEqual(current_branch, tool.WAVE1_FALLBACK_BRANCH)


class DiscoveryFailureTests(unittest.TestCase):
    def test_discovery_failure_exits_clean(self) -> None:
        """No CLI + no env + gh fails + no git branch -> DiscoveryError
        with a clear 3-path message; the CLI surfaces it as exit 1."""
        with mock.patch.object(
            tool, "_gh_pr_status_lookup", return_value=(None, None)
        ), mock.patch.object(
            tool, "_git_current_branch", return_value=None
        ):
            with self.assertRaises(tool.DiscoveryError) as ctx:
                tool.discover_target_pr_and_branch(
                    cli_pr=None,
                    cli_branch=None,
                    cwd=Path("/tmp"),
                    env={},
                )
        msg = str(ctx.exception)
        # All 3 fallback paths must be named verbatim.
        self.assertIn("--pr-number", msg)
        self.assertIn("--branch", msg)
        self.assertIn(tool.ENV_PR_NUMBER, msg)
        self.assertIn(tool.ENV_BRANCH, msg)
        self.assertIn("gh pr status", msg)

    def test_cli_main_exits_one_on_discovery_failure(self) -> None:
        """Run the renamed tool via subprocess with no overrides + a
        shimmed-empty PATH (no gh, no git) and verify exit code 1."""
        with tempfile.TemporaryDirectory() as tmp:
            # Empty PATH so gh and git resolve to "not found".
            env = {
                "PATH": "/nonexistent",
                # Strip env-var overrides if the host has them.
                tool.ENV_PR_NUMBER: "",
                tool.ENV_BRANCH: "",
            }
            cmd = [
                sys.executable,
                str(TOOL_PATH),
                "--repo-root",
                tmp,
                "--workspace",
                tmp,
                # No --pr-number / --branch flags.
            ]
            res = subprocess.run(
                cmd, capture_output=True, text=True, check=False, env=env
            )
        self.assertEqual(res.returncode, 1, res.stderr)
        # The clear-message stderr text must be present.
        self.assertIn("auto-discover", res.stderr.lower())
        self.assertIn(tool.ENV_PR_NUMBER, res.stderr)


class BackwardsCompatibilityTests(unittest.TestCase):
    def test_backwards_compatibility_pr726_alias(self) -> None:
        """The Wave-1 path ``tools/hackerman-pr726-merge-checklist.py``
        must still resolve to the renamed tool (symlink + Makefile
        alias). Loading the module via the alias path must yield the
        same module object semantically (same discover function)."""
        self.assertTrue(
            ALIAS_PATH.exists(),
            f"back-compat alias missing: {ALIAS_PATH}",
        )
        # The alias should resolve to the renamed file (symlink).
        if ALIAS_PATH.is_symlink():
            target = os.readlink(str(ALIAS_PATH))
            self.assertIn("hackerman-pr-merge-checklist", target)
        # Loading it should expose the same constants + discover fn.
        name = "_hackerman_pr726_alias_test_mod"
        spec = importlib.util.spec_from_file_location(name, str(ALIAS_PATH))
        mod = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
        self.assertTrue(hasattr(mod, "discover_target_pr_and_branch"))
        self.assertTrue(hasattr(mod, "WAVE1_FALLBACK_PR_NUMBER"))
        self.assertEqual(mod.WAVE1_FALLBACK_PR_NUMBER, 726)
        self.assertEqual(mod.WAVE1_FALLBACK_BRANCH, "wave-1-hackerman-capability-lift")


class GhPrStatusParserTests(unittest.TestCase):
    """Verify the gh pr status JSON parser handles the documented
    envelope shape and degrades gracefully."""

    def test_gh_pr_status_parses_valid_envelope(self) -> None:
        sample = json.dumps(
            {"currentBranch": {"number": 728, "headRefName": "wave-2-corpus-migration"}}
        )
        completed = mock.MagicMock(
            returncode=0, stdout=sample, stderr=""
        )
        with mock.patch("shutil.which", return_value="/usr/bin/gh"), \
             mock.patch("subprocess.run", return_value=completed):
            pr, branch = tool._gh_pr_status_lookup(cwd=Path("/tmp"))
        self.assertEqual(pr, 728)
        self.assertEqual(branch, "wave-2-corpus-migration")

    def test_gh_pr_status_returns_none_when_gh_missing(self) -> None:
        with mock.patch("shutil.which", return_value=None):
            pr, branch = tool._gh_pr_status_lookup(cwd=Path("/tmp"))
        self.assertIsNone(pr)
        self.assertIsNone(branch)

    def test_gh_pr_status_returns_none_on_unparseable_json(self) -> None:
        completed = mock.MagicMock(
            returncode=0, stdout="not json", stderr=""
        )
        with mock.patch("shutil.which", return_value="/usr/bin/gh"), \
             mock.patch("subprocess.run", return_value=completed):
            pr, branch = tool._gh_pr_status_lookup(cwd=Path("/tmp"))
        self.assertIsNone(pr)
        self.assertIsNone(branch)


if __name__ == "__main__":
    unittest.main()
