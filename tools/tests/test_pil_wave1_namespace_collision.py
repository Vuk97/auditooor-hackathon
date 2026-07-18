#!/usr/bin/env python3
"""Tests for pil_namespace_collision detector.

Wave-7 Track K-zkBugs minor frameworks.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DET = ROOT / "detectors" / "pil_wave1" / "pil_namespace_collision.py"
FIX = ROOT / "detectors" / "pil_wave1" / "test_fixtures"


def _load():
    spec = importlib.util.spec_from_file_location("pil_namespace_collision", DET)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class PilNamespaceCollisionTest(unittest.TestCase):
    def test_positive_1_selector_collision(self) -> None:
        mod = _load()
        src = (FIX / "pil_namespace_collision_positive_1.pil").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p1.pil")
        self.assertGreaterEqual(len(hits), 1)
        self.assertEqual(hits[0]["detector_id"], "pil_namespace_collision")
        self.assertIn("selector", hits[0]["message"])

    def test_positive_2_is_last_triple_collision(self) -> None:
        mod = _load()
        src = (FIX / "pil_namespace_collision_positive_2.pil").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p2.pil")
        self.assertGreaterEqual(len(hits), 1)
        self.assertIn("is_last", hits[0]["message"])

    def test_negative_1_unique_col_names(self) -> None:
        mod = _load()
        src = (FIX / "pil_namespace_collision_negative_1.pil").read_text(encoding="utf-8")
        hits = mod.run_text(src, "n1.pil")
        self.assertEqual(hits, [])

    def test_negative_2_single_namespace(self) -> None:
        mod = _load()
        src = (FIX / "pil_namespace_collision_negative_2.pil").read_text(encoding="utf-8")
        hits = mod.run_text(src, "n2.pil")
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
