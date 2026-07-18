#!/usr/bin/env python3
"""Tests for gnark_naf_decomposition_missing_constraint detector.

Wave-7 Track K-zkBugs minor frameworks.
Corpus refs: gnark-zksecurity-09, gnark-zksecurity-0a.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DET = ROOT / "detectors" / "gnark_wave1" / "gnark_naf_decomposition_missing_constraint.py"
FIX = ROOT / "detectors" / "gnark_wave1" / "test_fixtures"


def _load():
    spec = importlib.util.spec_from_file_location("gnark_naf_missing_constraint", DET)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class GnarkNafDecompositionMissingConstraintTest(unittest.TestCase):
    def test_positive_1_tonaf_no_adjacent_constraint(self) -> None:
        mod = _load()
        src = (FIX / "gnark_naf_decomposition_missing_constraint_positive_1.go").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p1.go")
        self.assertGreaterEqual(len(hits), 1)
        self.assertEqual(hits[0]["detector_id"], "gnark_naf_decomposition_missing_constraint")
        self.assertEqual(hits[0]["severity"], "high")

    def test_positive_2_helper_fn_no_constraint(self) -> None:
        mod = _load()
        src = (FIX / "gnark_naf_decomposition_missing_constraint_positive_2.go").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p2.go")
        self.assertGreaterEqual(len(hits), 1)

    def test_negative_1_tonaf_with_adjacent_constraint(self) -> None:
        mod = _load()
        src = (FIX / "gnark_naf_decomposition_missing_constraint_negative_1.go").read_text(encoding="utf-8")
        hits = mod.run_text(src, "n1.go")
        self.assertEqual(hits, [])

    def test_negative_2_not_gnark(self) -> None:
        mod = _load()
        src = (FIX / "gnark_naf_decomposition_missing_constraint_negative_2.go").read_text(encoding="utf-8")
        hits = mod.run_text(src, "n2.go")
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
