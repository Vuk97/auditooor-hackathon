#!/usr/bin/env python3
"""test_engine_skip_misconfig_launder.py

Enforcement-gap R28 (2026-07-03): a typed deep-engine skip (stage_skips.json, any
non-empty reason) greened live-engines with NO gate distinguishing a FIXABLE misconfig
(remappings / solc / import / compile / "no single forge project root on a mixed
layout") from a GENUINE no-applicable-engine arm (no medusa/echidna equivalent for a
Go/Cosmos module) - laundering a fixable engine error into a documented skip.
audit-completeness-check now classifies the reason: the suspect flag is ALWAYS surfaced,
and under AUDITOOOR_ENGINE_SKIP_MISCONFIG_STRICT a fixable-misconfig skip is NOT credited.
"""
import importlib.util
import sys
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "audit-completeness-check.py"


def _load():
    spec = importlib.util.spec_from_file_location("acc_r28", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["acc_r28"] = m
    spec.loader.exec_module(m)
    return m


class TestEngineSkipMisconfigLaunder(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def test_fixable_misconfig_reasons_flagged(self):
        rx = self.m._ENGINE_SKIP_MISCONFIG_RE
        for r in (
            "solc version mismatch",
            "remappings.txt missing so imports fail",
            "compilation failed: ParserError",
            "no single forge project root on a mixed layout",
            "could not resolve import @openzeppelin",
            "hardhat.config not found",
        ):
            self.assertTrue(rx.search(r), f"fixable misconfig must be flagged: {r!r}")

    def test_genuine_no_engine_reasons_not_flagged(self):
        rx = self.m._ENGINE_SKIP_MISCONFIG_RE
        for r in (
            "no medusa/echidna-equivalent wired for this go arm; scanners ran",
            "Cosmos x/vault Go module has no applicable coverage-guided engine",
            "non-EVM source present, no engine produced an executed harness",
        ):
            self.assertFalse(rx.search(r), f"genuine no-engine skip must NOT be flagged: {r!r}")

    def test_advisory_first_env_gated_in_source(self):
        src = _TOOL.read_text(encoding="utf-8", errors="replace")
        self.assertIn("AUDITOOOR_ENGINE_SKIP_MISCONFIG_STRICT", src,
                      "suppression must be gated behind the named strict env (advisory-first)")
        self.assertIn("misconfig_launder_suspect", src,
                      "the suspect flag must always be surfaced on the skip record")
        # the suppression (return None) must be INSIDE the env check, not unconditional
        i_env = src.find("AUDITOOOR_ENGINE_SKIP_MISCONFIG_STRICT")
        seg = src[i_env:i_env + 200]
        self.assertIn("return None", seg, "suppression must only fire under the strict env")


if __name__ == "__main__":
    unittest.main()
