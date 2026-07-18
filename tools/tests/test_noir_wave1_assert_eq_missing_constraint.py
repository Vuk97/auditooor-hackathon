#!/usr/bin/env python3
"""Tests for noir_assert_eq_missing_constraint detector.

Wave-6 Track K-zkBugs step K-Z.10b.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DET = ROOT / "detectors" / "noir_wave1" / "noir_assert_eq_missing_constraint.py"
FIX = ROOT / "detectors" / "noir_wave1" / "test_fixtures"


def _load():
    spec = importlib.util.spec_from_file_location("noir_assert_eq_missing_constraint", DET)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class NoirAssertEqMissingConstraintTest(unittest.TestCase):
    def test_positive_1_assert_eq_in_unconstrained(self) -> None:
        mod = _load()
        src = (FIX / "noir_assert_eq_missing_constraint_positive_1.nr").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p1.nr")
        self.assertGreaterEqual(len(hits), 1)
        self.assertEqual(hits[0]["detector_id"], "noir_assert_eq_missing_constraint")
        self.assertEqual(hits[0]["severity"], "high")
        call_kinds = [h["call_kind"] for h in hits]
        self.assertIn("assert_eq!", call_kinds)

    def test_positive_2_constrain_in_unconstrained(self) -> None:
        mod = _load()
        src = (FIX / "noir_assert_eq_missing_constraint_positive_2.nr").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p2.nr")
        self.assertGreaterEqual(len(hits), 1)
        call_kinds = [h["call_kind"] for h in hits]
        self.assertIn("constrain", call_kinds)

    def test_negative_1_assert_eq_in_constrained_fn(self) -> None:
        mod = _load()
        src = (FIX / "noir_assert_eq_missing_constraint_negative_1.nr").read_text(encoding="utf-8")
        hits = mod.run_text(src, "n1.nr")
        self.assertEqual(hits, [])

    def test_negative_2_no_assert_in_unconstrained(self) -> None:
        mod = _load()
        src = (FIX / "noir_assert_eq_missing_constraint_negative_2.nr").read_text(encoding="utf-8")
        hits = mod.run_text(src, "n2.nr")
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
