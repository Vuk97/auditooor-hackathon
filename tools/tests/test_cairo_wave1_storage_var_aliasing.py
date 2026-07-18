#!/usr/bin/env python3
"""Tests for cairo_storage_var_aliasing detector.

Wave-6 Track K-zkBugs step K-Z.10c.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DET = ROOT / "detectors" / "cairo_wave1" / "cairo_storage_var_aliasing.py"
FIX = ROOT / "detectors" / "cairo_wave1" / "test_fixtures"


def _load():
    spec = importlib.util.spec_from_file_location("cairo_storage_var_aliasing", DET)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class CairoStorageVarAliasingTest(unittest.TestCase):
    def test_positive_1_read_write_without_fence(self) -> None:
        mod = _load()
        src = (FIX / "cairo_storage_var_aliasing_positive_1.cairo").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p1.cairo")
        self.assertGreaterEqual(len(hits), 1)
        self.assertEqual(hits[0]["detector_id"], "cairo_storage_var_aliasing")
        self.assertEqual(hits[0]["severity"], "medium")
        vars_flagged = [h["storage_var"] for h in hits]
        self.assertIn("balance", vars_flagged)

    def test_positive_2_phantom_write(self) -> None:
        mod = _load()
        src = (FIX / "cairo_storage_var_aliasing_positive_2.cairo").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p2.cairo")
        self.assertGreaterEqual(len(hits), 1)
        vars_flagged = [h["storage_var"] for h in hits]
        self.assertIn("counter", vars_flagged)

    def test_negative_1_with_serialization_fence(self) -> None:
        mod = _load()
        src = (FIX / "cairo_storage_var_aliasing_negative_1.cairo").read_text(encoding="utf-8")
        hits = mod.run_text(src, "n1.cairo")
        self.assertEqual(hits, [])

    def test_negative_2_not_cairo(self) -> None:
        mod = _load()
        src = (FIX / "cairo_storage_var_aliasing_negative_2.cairo").read_text(encoding="utf-8")
        hits = mod.run_text(src, "n2.cairo")
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
