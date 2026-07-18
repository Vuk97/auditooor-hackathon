"""Tests for the Wave-2 PR-A hackerman-pre-merge ceiling + env-forward fix.

Covers two pre-existing tooling issues identified at commit 72d3af11a2 on
the wave-2-corpus-migration branch (PR #728):

1. **Per-step subprocess ceiling**: the orchestrator's 1800s ceiling
   timed out the corpus-amplified ``make hackerman-all`` step before
   any sub-check could complete. Raised default to 3600s, env-overridable
   via ``AUDITOOOR_PRE_MERGE_STEP_TIMEOUT_S``.
2. **Env-forwarding to sub-make**: ``PR_NUMBER`` / ``BRANCH`` /
   ``AUDITOOOR_TARGET_PR`` / ``AUDITOOOR_TARGET_BRANCH`` env vars must
   flow into the ``hackerman-pr-merge-checklist`` sub-process so the
   underlying tool's 4-tier discovery sees operator context.

synthetic_fixture: true
"""
from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path
from typing import Any, Dict
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-pre-merge.py"


def _load_tool() -> Any:
    name = "_hackerman_pre_merge_ceiling_env_test_mod"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


class _FakeCompleted:
    """Minimal stand-in for ``subprocess.CompletedProcess`` so the
    fake subprocess.run callable can return a deterministic result
    without spawning a real process.
    """

    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class TimeoutDefaultRaisedTests(unittest.TestCase):
    """Case 1: default per-step ceiling is 3600s, not 1800s."""

    def test_default_constant_is_3600(self) -> None:
        self.assertEqual(tool.DEFAULT_STEP_TIMEOUT_S, 3600)

    def test_resolve_timeout_default(self) -> None:
        # No env, no arg -> default.
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop(tool.STEP_TIMEOUT_ENV_VAR, None)
            self.assertEqual(tool._resolve_step_timeout(None), 3600)

    def test_resolve_timeout_explicit_arg_wins(self) -> None:
        # Explicit positive arg takes precedence over env + default.
        with mock.patch.dict(
            os.environ, {tool.STEP_TIMEOUT_ENV_VAR: "7200"}, clear=False
        ):
            self.assertEqual(tool._resolve_step_timeout(900), 900)


class TimeoutEnvOverrideTests(unittest.TestCase):
    """Case 2: ``AUDITOOOR_PRE_MERGE_STEP_TIMEOUT_S=7200`` is honored."""

    def test_env_override_7200(self) -> None:
        with mock.patch.dict(
            os.environ, {tool.STEP_TIMEOUT_ENV_VAR: "7200"}, clear=False
        ):
            self.assertEqual(tool._resolve_step_timeout(None), 7200)

    def test_env_override_garbage_falls_back(self) -> None:
        with mock.patch.dict(
            os.environ, {tool.STEP_TIMEOUT_ENV_VAR: "not-a-number"}, clear=False
        ):
            self.assertEqual(tool._resolve_step_timeout(None), 3600)

    def test_env_override_zero_falls_back(self) -> None:
        with mock.patch.dict(
            os.environ, {tool.STEP_TIMEOUT_ENV_VAR: "0"}, clear=False
        ):
            self.assertEqual(tool._resolve_step_timeout(None), 3600)


class EnvForwardedToSubMakeTests(unittest.TestCase):
    """Case 3: PR_NUMBER / BRANCH / AUDITOOOR_TARGET_* propagate."""

    def test_pr_number_appended_as_make_var_for_checklist(self) -> None:
        checklist_step = next(
            s for s in tool.STEPS if s["step_id"] == "hackerman-pr726-merge-checklist"
        )
        env = {"PR_NUMBER": "728", "BRANCH": "wave-2-corpus-migration"}
        argv = tool._step_argv_with_env(checklist_step, env)
        # Underlying argv is `make hackerman-pr-merge-checklist`; we
        # expect the two Make-vars appended in the canonical form.
        self.assertIn("make", argv)
        self.assertIn("hackerman-pr-merge-checklist", argv)
        self.assertIn("PR_NUMBER=728", argv)
        self.assertIn("BRANCH=wave-2-corpus-migration", argv)

    def test_pr_number_not_appended_for_other_steps(self) -> None:
        # `make hackerman-all` does NOT take PR_NUMBER; the orchestrator
        # must not pollute its argv.
        all_step = next(
            s for s in tool.STEPS if s["step_id"] == "hackerman-all"
        )
        env = {"PR_NUMBER": "728", "BRANCH": "wave-2-corpus-migration"}
        argv = tool._step_argv_with_env(all_step, env)
        self.assertEqual(argv, all_step["argv"])
        self.assertNotIn("PR_NUMBER=728", argv)

    def test_subprocess_env_includes_forwarded_vars(self) -> None:
        # Verify that when _run_step is called, the subprocess sees
        # the orchestrator's forwarded env vars (so the underlying
        # tool's 4-tier discovery picks them up even when Make-var
        # forwarding doesn't apply).
        captured: Dict[str, Any] = {}

        def _fake_run(argv, **kwargs):
            captured["argv"] = argv
            captured["env"] = kwargs.get("env") or {}
            return _FakeCompleted(returncode=0)

        checklist_step = next(
            s for s in tool.STEPS if s["step_id"] == "hackerman-pr726-merge-checklist"
        )
        sentinel_env = {
            "PR_NUMBER": "728",
            "BRANCH": "wave-2-corpus-migration",
            "AUDITOOOR_TARGET_PR": "728",
            "AUDITOOOR_TARGET_BRANCH": "wave-2-corpus-migration",
            "PATH": os.environ.get("PATH", "/usr/bin"),
        }
        with mock.patch.object(tool.subprocess, "run", side_effect=_fake_run):
            result = tool._run_step(
                checklist_step,
                cwd=REPO_ROOT,
                timeout=3600,
                dry_run=False,
                env=sentinel_env,
            )
        self.assertEqual(result["verdict"], tool.PASS)
        sub_env = captured["env"]
        self.assertEqual(sub_env.get("PR_NUMBER"), "728")
        self.assertEqual(sub_env.get("BRANCH"), "wave-2-corpus-migration")
        self.assertEqual(sub_env.get("AUDITOOOR_TARGET_PR"), "728")
        self.assertEqual(
            sub_env.get("AUDITOOOR_TARGET_BRANCH"), "wave-2-corpus-migration"
        )
        # Make-var form also appended to argv for the checklist step.
        argv = captured["argv"]
        self.assertIn("PR_NUMBER=728", argv)
        self.assertIn("BRANCH=wave-2-corpus-migration", argv)


class ExistingBehaviorUnchangedTests(unittest.TestCase):
    """Case 4: behavior unchanged for steps that don't need overrides."""

    def test_dry_run_skips_subprocess(self) -> None:
        all_step = next(
            s for s in tool.STEPS if s["step_id"] == "hackerman-all"
        )
        with mock.patch.object(tool.subprocess, "run") as run_mock:
            result = tool._run_step(
                all_step, cwd=REPO_ROOT, timeout=3600, dry_run=True
            )
        self.assertEqual(result["verdict"], tool.SKIPPED)
        run_mock.assert_not_called()

    def test_run_pre_merge_dry_run_marks_all_skipped(self) -> None:
        results, overall = tool.run_pre_merge(dry_run=True)
        self.assertEqual(overall, tool.OVERALL_PASS)
        for r in results:
            self.assertEqual(r["verdict"], tool.SKIPPED)

    def test_run_pre_merge_skip_step_filters_single_step(self) -> None:
        results, overall = tool.run_pre_merge(
            dry_run=True, skip_steps=["hackerman-all"]
        )
        # All other steps are SKIPPED via dry-run; the skipped step has
        # a different reason but the same verdict bucket. Just confirm
        # we didn't crash and the structure is intact.
        self.assertEqual(overall, tool.OVERALL_PASS)
        self.assertEqual(len(results), len(tool.STEPS))

    def test_forwarded_env_vars_constant_shape(self) -> None:
        # Lock the shape of FORWARDED_ENV_VARS so future refactors
        # don't silently drop one of the four canonical vars.
        self.assertEqual(
            set(tool.FORWARDED_ENV_VARS),
            {"PR_NUMBER", "BRANCH", "AUDITOOOR_TARGET_PR", "AUDITOOOR_TARGET_BRANCH"},
        )

    def test_make_var_forward_only_for_checklist(self) -> None:
        # Lock the opt-in shape: only the merge-checklist step accepts
        # Make-var-forwarded PR_NUMBER / BRANCH on argv.
        self.assertEqual(
            tool.MAKE_VAR_FORWARD_STEP_IDS,
            frozenset({"hackerman-pr726-merge-checklist"}),
        )


if __name__ == "__main__":
    unittest.main()
