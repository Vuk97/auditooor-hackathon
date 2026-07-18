#!/usr/bin/env python3
"""Guard: audit-completeness-check.check_invariant_fuzz must treat EVERY
`fail-invariant-fuzz*` verdict as blocking (ok=False), not only the legacy
`fail-invariant-fuzz-incomplete`.

Root cause (nuva 2026-07-13): the invariant-fuzz gate's STRICT asset-coverage
verdict is `fail-invariant-fuzz-asset-gap`; the aggregator keyed only on the
legacy `fail-invariant-fuzz-incomplete`, so a strict asset-gap fail (15 uncovered
value-moving files) fell through to ok=True and audit-complete printed
pass-audit-complete. `warn-*`/`pass-*` stay non-blocking (advisory by design).
"""
import importlib.util
import sys
import types
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location(
        "acc_check", str(_TOOLS / "audit-completeness-check.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules["acc_check"] = m
    spec.loader.exec_module(m)
    return m


class TestInvariantFuzzAggregatorAssetGapBlocks(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def _run_with_verdict(self, verdict):
        fake = types.SimpleNamespace(
            evaluate=lambda ws: {"verdict": verdict, "reason": "x"})
        orig = self.m._load_invariant_fuzz_module
        self.m._load_invariant_fuzz_module = lambda: fake
        try:
            return self.m.check_invariant_fuzz(Path("/tmp/nonexistent-ws"))
        finally:
            self.m._load_invariant_fuzz_module = orig

    def test_asset_gap_strict_blocks(self):
        r = self._run_with_verdict("fail-invariant-fuzz-asset-gap")
        self.assertFalse(r.ok, "strict asset-gap fail must block audit-complete")

    def test_legacy_incomplete_still_blocks(self):
        r = self._run_with_verdict("fail-invariant-fuzz-incomplete")
        self.assertFalse(r.ok)

    def test_advisory_warn_does_not_block(self):
        r = self._run_with_verdict("warn-invariant-fuzz-asset-gap")
        self.assertTrue(r.ok, "advisory WARN is not a retro-red")

    def test_pass_does_not_block(self):
        r = self._run_with_verdict("pass-invariant-fuzz-complete")
        self.assertTrue(r.ok)


if __name__ == "__main__":
    unittest.main()
