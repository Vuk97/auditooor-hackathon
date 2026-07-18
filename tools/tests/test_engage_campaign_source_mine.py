#!/usr/bin/env python3
"""Tests for the opt-in campaign-source-mine engage stage."""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
ENGAGE = ROOT / "tools" / "engage.py"


def _load_engage():
    tools_dir = str(ENGAGE.parent)
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    spec = importlib.util.spec_from_file_location("engage_campaign_source_mine_test_subject", ENGAGE)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _args():
    return SimpleNamespace(quiet=True)


class CampaignSourceMineStageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _load_engage()

    def test_stage_registered_after_post_audit_review(self) -> None:
        self.assertIn("campaign-source-mine", self.mod.STAGES)
        names = [name for name, _desc, _art in self.mod.STAGE_TABLE]
        self.assertIn("campaign-source-mine", names)
        self.assertLess(
            names.index("post-audit-review"),
            names.index("campaign-source-mine"),
        )
        self.assertIn("campaign-source-mine", self.mod.SUMMARY_ARTIFACT_PATTERNS)

    def test_env_off_skips_without_running_provider(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {}, clear=True):
            status = self.mod.stage_campaign_source_mine(Path(tmp), _args())
            self.assertTrue(status.startswith("SKIPPED"))

    def test_env_on_without_network_consent_fails_loudly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ,
            {"CAMPAIGN_SOURCE_MINE": "1"},
            clear=True,
        ):
            status = self.mod.stage_campaign_source_mine(Path(tmp), _args())
            self.assertEqual(status, "FAIL cannot-run: no-network-consent")

    def test_env_on_with_consent_invokes_source_mining_tool(self) -> None:
        calls = []

        def fake_run(cmd, timeout):
            calls.append((cmd, timeout))
            return 0, "ok", ""

        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ,
            {
                "CAMPAIGN_SOURCE_MINE": "1",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
            },
            clear=True,
        ), patch.object(self.mod, "run", side_effect=fake_run):
            ws = Path(tmp)
            status = self.mod.stage_campaign_source_mine(ws, _args())
            self.assertEqual(status, "SUCCESS")
            self.assertEqual(len(calls), 1)
            cmd, timeout = calls[0]
            self.assertIn(str(self.mod.SOURCE_MINING_CAMPAIGN), cmd)
            self.assertIn("--workspace", cmd)
            self.assertIn(str(ws), cmd)
            self.assertIn("--out", cmd)
            self.assertIn(str(ws / "source_mining" / "engage-latest"), cmd)
            # I10 fix: campaign uses CAMPAIGN_TIMEOUT (default 1h),
            # not SYNTHESIS_TIMEOUT (5m) which kills real campaigns mid-run.
            self.assertEqual(timeout, self.mod.CAMPAIGN_TIMEOUT)
            self.assertGreater(self.mod.CAMPAIGN_TIMEOUT,
                               self.mod.SYNTHESIS_TIMEOUT)


class CampaignTimeoutTests(unittest.TestCase):
    """I10: campaign-source-mine must NOT reuse SYNTHESIS_TIMEOUT (5m)
    because real-workspace campaigns dispatch one Kimi + one Minimax call
    per domain (~10-15 domains on polymarket), so a single full run is
    multi-minute by design. Reusing the synthesis-stage timeout was a
    category error that killed campaigns mid-run."""

    def setUp(self) -> None:
        self.mod = _load_engage()

    def test_campaign_timeout_default_is_an_hour(self) -> None:
        # Default 3600s leaves room for resume-skipped re-runs and wide
        # workspaces. Operator overrides via AUDITOOOR_CAMPAIGN_TIMEOUT.
        self.assertEqual(self.mod.CAMPAIGN_TIMEOUT, 3600)

    def test_campaign_timeout_strictly_greater_than_synthesis(self) -> None:
        # Regression guard: SYNTHESIS_TIMEOUT (5m) was the original I10 bug.
        # If any future change shrinks CAMPAIGN_TIMEOUT below it, that's
        # a re-introduction of the same category error.
        self.assertGreater(self.mod.CAMPAIGN_TIMEOUT,
                           self.mod.SYNTHESIS_TIMEOUT)

    def test_campaign_timeout_env_var_override(self) -> None:
        # The constant is read at module import; override needs a fresh
        # import. Verify the env-var path directly without re-loading the
        # whole engage module (expensive).
        import importlib
        with patch.dict(os.environ,
                        {"AUDITOOOR_CAMPAIGN_TIMEOUT": "7200"},
                        clear=False):
            spec = importlib.util.spec_from_file_location(
                "engage_camptimeout_envtest", ENGAGE)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            self.assertEqual(mod.CAMPAIGN_TIMEOUT, 7200)

    def test_timeout_returns_partial_status(self) -> None:
        """rc=124 (subprocess timeout) must return TIMEOUT_PARTIAL so the
        operator knows the resume cache is intact and a re-run is the
        recovery path — not generic FAIL."""
        def fake_run(cmd, timeout):
            return 124, "", "timeout after Xs"

        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ,
            {
                "CAMPAIGN_SOURCE_MINE": "1",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
            },
            clear=True,
        ), patch.object(self.mod, "run", side_effect=fake_run):
            ws = Path(tmp)
            status = self.mod.stage_campaign_source_mine(ws, _args())
            self.assertTrue(status.startswith("TIMEOUT_PARTIAL"),
                            msg=f"got: {status!r}")
            self.assertIn("re-run", status.lower())

    def test_non_timeout_failure_returns_generic_fail(self) -> None:
        """rc=1 (or any non-124 non-zero) returns FAIL rc=N, NOT
        TIMEOUT_PARTIAL — so the operator doesn't think a real failure
        is just "needs another run"."""
        def fake_run(cmd, timeout):
            return 1, "", "boom"

        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ,
            {
                "CAMPAIGN_SOURCE_MINE": "1",
                "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
            },
            clear=True,
        ), patch.object(self.mod, "run", side_effect=fake_run):
            ws = Path(tmp)
            status = self.mod.stage_campaign_source_mine(ws, _args())
            self.assertEqual(status, "FAIL rc=1")


if __name__ == "__main__":
    unittest.main()
