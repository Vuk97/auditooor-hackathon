#!/usr/bin/env python3
"""test_vcis_placeholder_stub_scan.py

Enforcement-gap G-2 (2026-07-03): a Go/Cosmos value-conservation-invariant-synth
(VCIS) harness that is left as an UNFILLED SCAFFOLD - residual
MODULE_ACCOUNT_PLACEHOLDER / DENOM_PLACEHOLDER, a GetTotal<Field> stub returning a
constant 0, or RegisterVCISInvariants defined-but-never-wired - credits conservation
coverage while it can NEVER fire (the #1 coverage-theater class). audit-honesty-check
now detects it via _vcis_placeholder_stubs and surfaces the count; it folds into the
hard fail-stub-harnesses tally only under AUDITOOOR_VCIS_STUB_STRICT (advisory-first).
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "audit-honesty-check.py"


def _load():
    spec = importlib.util.spec_from_file_location("audit_honesty_check_vcis", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["audit_honesty_check_vcis"] = m
    spec.loader.exec_module(m)
    return m


class TestVcisPlaceholderScan(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def _ws(self, rel, content):
        d = Path(tempfile.mkdtemp())
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return d

    def test_residual_placeholder_is_vacuous(self):
        ws = self._ws("src/vault/conservation_vcis.go",
                      'package vault\nconst MODULE_ACCOUNT_PLACEHOLDER = "MODULE_ACCOUNT_TODO"\n')
        self.assertGreaterEqual(self.m._vcis_placeholder_stubs(ws), 1)

    def test_gettotal_zero_stub_is_vacuous(self):
        ws = self._ws("src/x_vcis.go",
                      "package x\nfunc GetTotalShares() sdk.Int { return sdk.ZeroInt() }\n")
        self.assertGreaterEqual(self.m._vcis_placeholder_stubs(ws), 1)

    def test_no_vcis_harness_is_zero(self):
        ws = self._ws("main.go", "package main\nfunc main() {}\n")
        self.assertEqual(self.m._vcis_placeholder_stubs(ws), 0)

    def test_filled_vcis_is_not_flagged(self):
        # a substituted harness with real denom/module + a real assertion, no TODO stub
        ws = self._ws("src/vault/conservation_vcis.go",
                      'package vault\nconst moduleAcct = "nvyldsvault"\nconst denom = "nvylds"\n'
                      "func check(k Keeper) bool { return k.TotalShares().Equal(k.SumBalances()) }\n")
        self.assertEqual(self.m._vcis_placeholder_stubs(ws), 0)

    def test_integration_is_advisory_first(self):
        src = _TOOL.read_text(encoding="utf-8", errors="replace")
        self.assertIn("vcis_placeholder_stubs", src, "the count must be surfaced in per_function")
        self.assertIn("AUDITOOOR_VCIS_STUB_STRICT", src,
                      "folding into the hard stub tally must be gated behind the strict env")


if __name__ == "__main__":
    unittest.main()
