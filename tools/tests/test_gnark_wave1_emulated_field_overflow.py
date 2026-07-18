#!/usr/bin/env python3
"""Tests for gnark_emulated_field_overflow detector.

Wave-7 Track K-zkBugs minor frameworks.
Corpus ref: gnark-zksecurity-0b.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DET = ROOT / "detectors" / "gnark_wave1" / "gnark_emulated_field_overflow.py"
FIX = ROOT / "detectors" / "gnark_wave1" / "test_fixtures"


def _load():
    spec = importlib.util.spec_from_file_location("gnark_emulated_field_overflow", DET)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class GnarkEmulatedFieldOverflowTest(unittest.TestCase):
    def test_positive_1_newhint_no_enforce_width(self) -> None:
        mod = _load()
        src = (FIX / "gnark_emulated_field_overflow_positive_1.go").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p1.go")
        self.assertGreaterEqual(len(hits), 1)
        self.assertEqual(hits[0]["detector_id"], "gnark_emulated_field_overflow")
        self.assertEqual(hits[0]["severity"], "high")

    def test_positive_2_element_struct_literal_no_enforce(self) -> None:
        mod = _load()
        src = (FIX / "gnark_emulated_field_overflow_positive_2.go").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p2.go")
        self.assertGreaterEqual(len(hits), 1)

    def test_negative_1_newhint_with_enforce_width(self) -> None:
        mod = _load()
        src = (FIX / "gnark_emulated_field_overflow_negative_1.go").read_text(encoding="utf-8")
        hits = mod.run_text(src, "n1.go")
        self.assertEqual(hits, [])

    def test_negative_2_not_gnark_file(self) -> None:
        mod = _load()
        src = (FIX / "gnark_emulated_field_overflow_negative_2.go").read_text(encoding="utf-8")
        hits = mod.run_text(src, "n2.go")
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
