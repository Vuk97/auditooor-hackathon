#!/usr/bin/env python3
"""Regression tests for I8 (#319): `tools/audit-progress.py` must NOT
hardcode `--fail-fast` when an opt-in campaign is enabled.

Background: `audit-progress.py` wraps `engage.py --stage all`. The
canonical chain ends with `campaign-source-mine` (opt-in via
`CAMPAIGN_SOURCE_MINE=1`). Earlier versions hardcoded `--fail-fast`,
which meant `quality-score` (always fails on a fresh workspace because
no submissions exist to score) tripped fail-fast and the chain halted
BEFORE `campaign-source-mine` ran. The campaign was wired into the
chain (PR #316) but never reached.

The fix: drop `--fail-fast` automatically when `CAMPAIGN_SOURCE_MINE=1`,
or when the operator sets `AUDITOOOR_AUDIT_NO_FAIL_FAST=1` explicitly.

This test exercises the command-builder helper directly so we don't
have to spin up a real engage run.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "audit-progress.py"


def _load_tool():
    """Load tools/audit-progress.py as a module so we can call its
    private helpers directly. Mirrors the loader pattern used by
    test_audit_progress_guard.py."""
    spec = importlib.util.spec_from_file_location("audit_progress_test", TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class FailFastFlagTests(unittest.TestCase):
    """The default behaviour stays `--fail-fast`. Only opt-in campaign
    runs (or an explicit operator override) drop the flag so the chain
    runs to completion and reaches `campaign-source-mine`."""

    def setUp(self) -> None:
        self.mod = _load_tool()

    def test_default_chain_keeps_fail_fast(self) -> None:
        """Without any campaign opt-in, `--fail-fast` is still set so
        the chain halts on the first stage failure (existing
        behaviour; no regression)."""
        with patch.dict(os.environ, {}, clear=True):
            cmd = self.mod._build_engage_cmd(Path("/tmp/ws"), False, [])
            self.assertIn("--fail-fast", cmd)
            self.assertIn("--stage", cmd)
            self.assertIn("all", cmd)

    def test_campaign_source_mine_drops_fail_fast(self) -> None:
        """With `CAMPAIGN_SOURCE_MINE=1`, the chain runs to completion
        so the campaign (last stage) is always reached. This is the
        I8 fix."""
        with patch.dict(
            os.environ,
            {"CAMPAIGN_SOURCE_MINE": "1"},
            clear=True,
        ):
            cmd = self.mod._build_engage_cmd(Path("/tmp/ws"), False, [])
            self.assertNotIn("--fail-fast", cmd,
                             msg=f"got: {cmd!r}")
            self.assertIn("--stage", cmd)
            self.assertIn("all", cmd)

    def test_explicit_no_fail_fast_env_drops_flag(self) -> None:
        """Operator override: AUDITOOOR_AUDIT_NO_FAIL_FAST=1 drops
        `--fail-fast` regardless of campaign opt-in. Useful when an
        operator wants to see every stage failure in one run rather
        than halting on the first."""
        with patch.dict(
            os.environ,
            {"AUDITOOOR_AUDIT_NO_FAIL_FAST": "1"},
            clear=True,
        ):
            cmd = self.mod._build_engage_cmd(Path("/tmp/ws"), False, [])
            self.assertNotIn("--fail-fast", cmd)

    def test_dry_run_does_not_get_fail_fast(self) -> None:
        """Dry-run mode never gets `--fail-fast` (it doesn't execute
        anything; existing behaviour, regression guard)."""
        with patch.dict(os.environ, {}, clear=True):
            cmd = self.mod._build_engage_cmd(Path("/tmp/ws"), True, [])
            self.assertNotIn("--fail-fast", cmd)
            self.assertIn("--dry-run", cmd)

    def test_explicit_no_when_campaign_off_string_zero(self) -> None:
        """`CAMPAIGN_SOURCE_MINE=0` is treated as "off" (only literal
        "1" enables). This catches a class of operator typos where
        the campaign env var is set to anything-other-than-"1" and
        the operator expects fail-fast to drop. Should keep
        `--fail-fast`."""
        with patch.dict(
            os.environ,
            {"CAMPAIGN_SOURCE_MINE": "0"},
            clear=True,
        ):
            cmd = self.mod._build_engage_cmd(Path("/tmp/ws"), False, [])
            self.assertIn("--fail-fast", cmd)


if __name__ == "__main__":
    unittest.main()
