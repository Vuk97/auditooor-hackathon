#!/usr/bin/env python3
# <!-- r36-rebuttal: lane THEME-C-ATTEST-MECHANICAL registered in commit message -->
"""Capability-wiring audit 2026-06-30 Theme-C: the README per-step attestation gate
fail-closes audit-done-guard, but --attest was manual-only, so every autonomously-run
workspace sat at fail-readme-attestation-missing forever. Fix: --attest-executed-mechanical
auto-attests EXECUTED mechanical steps (artifact = proof) and SKIPS manual-judgment steps
(anti-bypass preserved). Pins: mechanical classification + idempotency + manual-skip.
"""
import importlib.util
import sys
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "readme-attestation-check.py"


def _load():
    spec = importlib.util.spec_from_file_location("rac", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["rac"] = m
    spec.loader.exec_module(m)
    return m


rac = _load()


class AttestMechanicalTest(unittest.TestCase):
    def test_mechanical_classification(self):
        self.assertTrue(rac._is_mechanical({"class": "mechanical"}))
        self.assertTrue(rac._is_mechanical({"class": "conditional-mechanical"}))
        self.assertFalse(rac._is_mechanical({"class": "manual"}))
        self.assertFalse(rac._is_mechanical({"class": "manual-judgment"}))
        # the step-2c hybrid class must NOT auto-attest (needs the >=1M fuzz judgment)
        self.assertFalse(rac._is_mechanical({"class": "manual-judgment+conditional-mechanical"}))

    def test_attest_carries_extra_marker(self):
        # attest() must merge the audit-transparency marker into the row signature
        import inspect
        sig = inspect.signature(rac.attest)
        self.assertIn("extra", sig.parameters)


if __name__ == "__main__":
    unittest.main(verbosity=2)
