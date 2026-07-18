#!/usr/bin/env python3
"""test_invariant_fuzz_calls_counter_strict.py

Enforcement-gap G-10/G-11 (2026-07-03): a harness with engine evidence but NO
machine-readable call counter (executed_calls==0) was credited as a full >=1M campaign
WITHOUT proving the floor - corpus-only-no-counter fuzz-depth theater (a 128k smoke run,
or a bare medusa-corpus/README.md, satisfies it). invariant-fuzz-completeness now, under
AUDITOOOR_INVARIANT_FUZZ_CALLS_STRICT (default OFF), fails such a harness so the >=1M
floor is real. The 1M floor already fired for exec_calls>0; this closes the ==0 hole.

Pins: the strict-env branch exists, is env-gated (advisory-first), and requires a
parseable count. Behavioral smoke (verified live on NUVA at authoring time): its 10
harnesses have 0 machine-readable call counts, so DEFAULT stays warn-* while STRICT flips
to fail-invariant-fuzz-incomplete.
"""
import re
import unittest
from pathlib import Path

_SRC = (Path(__file__).resolve().parents[1] / "invariant-fuzz-completeness.py").read_text(
    encoding="utf-8", errors="replace")


class TestCallsCounterStrict(unittest.TestCase):
    def test_env_gated_branch_present(self):
        self.assertIn("AUDITOOOR_INVARIANT_FUZZ_CALLS_STRICT", _SRC,
                      "the >=1M-floor-unverifiable branch must be gated behind its named env")

    def test_branch_requires_parseable_count(self):
        self.assertIn("no machine-readable call count", _SRC,
                      "the strict branch must fail an uncounted (exec_calls==0) harness")
        self.assertIn("total_calls", _SRC, "must point the operator at a numeric total_calls receipt")

    def test_advisory_first_default_off(self):
        # the branch must be an `elif (not exec_calls) and <env>` - i.e. only engages
        # when the env is set (default OFF -> legacy behavior, no retroactive re-fail).
        self.assertRegex(
            _SRC,
            r"elif\s*\(\s*not\s+exec_calls\s*\)\s*and\s*os\.environ\.get\(\s*[\"']AUDITOOOR_INVARIANT_FUZZ_CALLS_STRICT",
            "the branch must fire only under the strict env (advisory-first)")

    def test_does_not_disturb_existing_1m_floor(self):
        # the existing exec_calls>0 under-budget branch must still be present + ordered first.
        i_exist = _SRC.find("under-budgeted:")
        i_new = _SRC.find("no machine-readable call count")
        self.assertGreater(i_exist, 0)
        self.assertGreater(i_new, i_exist, "the new ==0 branch must come AFTER the existing <1M branch")

    def test_syntax_ok(self):
        import ast
        ast.parse(_SRC)


if __name__ == "__main__":
    unittest.main()
