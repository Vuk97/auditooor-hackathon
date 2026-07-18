#!/usr/bin/env python3
"""test_matrix_family_invariant_denominator.py

Enforcement-gap G-6 (2026-07-03): the completeness-matrix invariant axis required the
10 GENERIC canonical categories but never the PROTOCOL-FAMILY curated invariant set
(invariant_family_<family>.jsonl), so "all invariants held" could be vacuously true
over an incomplete set - the biggest false-negative surface. The matrix now detects the
family, loads its canonical categories, and surfaces the family-required categories that
NO in-scope asset enumerated (family_invariant_denominator advisory block). The gap folds
into the verdict ONLY under AUDITOOOR_MATRIX_FAMILY_INVARIANTS_STRICT (advisory-first).
"""
import importlib.util
import sys
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "completeness-matrix-build.py"


def _load():
    spec = importlib.util.spec_from_file_location("cmb_family", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["cmb_family"] = m
    spec.loader.exec_module(m)
    return m


class TestFamilyDenominator(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def test_family_detection_bridge(self):
        import tempfile
        ws = Path(tempfile.mkdtemp())
        (ws / "src").mkdir()
        (ws / "src" / "Bridge.sol").write_text(
            "contract Bridge { function lock() external {} function mint() external {} "
            "// cross-chain relayer attestation message passing wrapped }", encoding="utf-8")
        fams = self.m._detect_protocol_families(ws)
        self.assertIn("bridge_lock_mint", fams)

    def test_family_detection_needs_two_cues(self):
        import tempfile
        ws = Path(tempfile.mkdtemp())
        (ws / "src").mkdir()
        # a single incidental 'mint' must NOT tag the bridge family
        (ws / "src" / "Token.sol").write_text(
            "contract Token { function mint() external {} }", encoding="utf-8")
        self.assertNotIn("bridge_lock_mint", self.m._detect_protocol_families(ws))

    def test_family_required_categories_loaded(self):
        req = self.m._family_required_categories(["bridge_lock_mint"])
        self.assertIn("bridge_lock_mint", req)
        # every category returned must be one of the 10 canonical categories
        for c in req["bridge_lock_mint"]:
            self.assertIn(c, self.m.CANONICAL_INVARIANT_CATEGORIES)
        self.assertGreaterEqual(len(req["bridge_lock_mint"]), 1)

    def test_absent_family_lib_is_empty(self):
        self.assertEqual(self.m._family_required_categories(["nonexistent_family_xyz"]), {})


if __name__ == "__main__":
    unittest.main()
