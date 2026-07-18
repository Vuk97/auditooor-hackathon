#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DET = ROOT / "detectors" / "halo2_wave1" / "halo2_layouter_region_overlap.py"
FIX = ROOT / "detectors" / "halo2_wave1" / "test_fixtures"


def _load():
    spec = importlib.util.spec_from_file_location("h2_lro", DET)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class Halo2LayouterRegionOverlapTest(unittest.TestCase):
    def test_positive_1_triple_reuse(self) -> None:
        mod = _load()
        src = (FIX / "halo2_layouter_region_overlap_positive_1.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p1.rs")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["region_name"], "process_row")
        self.assertEqual(hits[0]["reuse_count"], 3)
        self.assertEqual(hits[0]["severity"], "low")

    def test_positive_2_double_reuse(self) -> None:
        mod = _load()
        src = (FIX / "halo2_layouter_region_overlap_positive_2.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p2.rs")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["region_name"], "comparator")

    def test_negative_1_unique_names(self) -> None:
        mod = _load()
        src = (FIX / "halo2_layouter_region_overlap_negative_1.rs").read_text(encoding="utf-8")
        self.assertEqual(mod.run_text(src, "n1.rs"), [])

    def test_negative_2_not_halo2(self) -> None:
        mod = _load()
        src = (FIX / "halo2_layouter_region_overlap_negative_2.rs").read_text(encoding="utf-8")
        self.assertEqual(mod.run_text(src, "n2.rs"), [])


if __name__ == "__main__":
    unittest.main()
