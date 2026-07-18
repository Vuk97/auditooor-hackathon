#!/usr/bin/env python3
"""Tests for arkworks_fp_add_overflow_no_modular_reduction detector.

Wave-7 Track K-zkBugs minor frameworks.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DET = ROOT / "detectors" / "arkworks_wave1" / "arkworks_fp_add_overflow_no_modular_reduction.py"
FIX = ROOT / "detectors" / "arkworks_wave1" / "test_fixtures"


def _load():
    spec = importlib.util.spec_from_file_location("arkworks_fp_add_overflow", DET)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class ArkworksFpAddOverflowTest(unittest.TestCase):
    def test_positive_1_bigint_add_no_reduce(self) -> None:
        mod = _load()
        src = (FIX / "arkworks_fp_add_overflow_no_modular_reduction_positive_1.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p1.rs")
        self.assertGreaterEqual(len(hits), 1)
        self.assertEqual(hits[0]["detector_id"], "arkworks_fp_add_overflow_no_modular_reduction")

    def test_positive_2_accumulator_no_reduce(self) -> None:
        mod = _load()
        src = (FIX / "arkworks_fp_add_overflow_no_modular_reduction_positive_2.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p2.rs")
        self.assertGreaterEqual(len(hits), 1)

    def test_negative_1_add_with_reduce(self) -> None:
        mod = _load()
        src = (FIX / "arkworks_fp_add_overflow_no_modular_reduction_negative_1.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "n1.rs")
        self.assertEqual(hits, [])

    def test_negative_2_not_arkworks(self) -> None:
        mod = _load()
        src = (FIX / "arkworks_fp_add_overflow_no_modular_reduction_negative_2.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "n2.rs")
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
