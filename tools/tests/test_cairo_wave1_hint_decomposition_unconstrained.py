#!/usr/bin/env python3
"""Tests for cairo_hint_decomposition_unconstrained detector.

Wave-6 Track K-zkBugs step K-Z.10c.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DET = ROOT / "detectors" / "cairo_wave1" / "cairo_hint_decomposition_unconstrained.py"
FIX = ROOT / "detectors" / "cairo_wave1" / "test_fixtures"


def _load():
    spec = importlib.util.spec_from_file_location("cairo_hint_decomp_unconstrained", DET)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class CairoHintDecompositionUnconstrainedTest(unittest.TestCase):
    def test_positive_1_split_felt_no_assert(self) -> None:
        mod = _load()
        src = (FIX / "cairo_hint_decomposition_unconstrained_positive_1.cairo").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p1.cairo")
        self.assertGreaterEqual(len(hits), 1)
        self.assertEqual(hits[0]["detector_id"], "cairo_hint_decomposition_unconstrained")
        self.assertEqual(hits[0]["severity"], "high")

    def test_positive_2_lsb_extraction_no_assert(self) -> None:
        mod = _load()
        src = (FIX / "cairo_hint_decomposition_unconstrained_positive_2.cairo").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p2.cairo")
        self.assertGreaterEqual(len(hits), 1)

    def test_negative_1_decomp_with_assert(self) -> None:
        mod = _load()
        src = (FIX / "cairo_hint_decomposition_unconstrained_negative_1.cairo").read_text(encoding="utf-8")
        hits = mod.run_text(src, "n1.cairo")
        self.assertEqual(hits, [])

    def test_negative_2_not_cairo(self) -> None:
        mod = _load()
        src = (FIX / "cairo_hint_decomposition_unconstrained_negative_2.cairo").read_text(encoding="utf-8")
        hits = mod.run_text(src, "n2.cairo")
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
