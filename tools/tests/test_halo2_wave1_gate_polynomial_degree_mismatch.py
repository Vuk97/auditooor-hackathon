#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DET = ROOT / "detectors" / "halo2_wave1" / "halo2_gate_polynomial_degree_mismatch.py"
FIX = ROOT / "detectors" / "halo2_wave1" / "test_fixtures"


def _load():
    spec = importlib.util.spec_from_file_location("h2_gpdm", DET)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class Halo2GateDegreeMismatchTest(unittest.TestCase):
    def test_positive_1_high_degree(self) -> None:
        mod = _load()
        src = (FIX / "halo2_gate_polynomial_degree_mismatch_positive_1.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p1.rs")
        self.assertEqual(len(hits), 1)
        self.assertGreater(hits[0]["gate_degree"], 3)
        self.assertEqual(hits[0]["detector_id"], "halo2_gate_polynomial_degree_mismatch")

    def test_positive_2_missing_selector(self) -> None:
        mod = _load()
        src = (FIX / "halo2_gate_polynomial_degree_mismatch_positive_2.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p2.rs")
        self.assertEqual(len(hits), 1)
        self.assertFalse(hits[0]["has_selector_multiplier"])

    def test_negative_1_well_formed(self) -> None:
        mod = _load()
        src = (FIX / "halo2_gate_polynomial_degree_mismatch_negative_1.rs").read_text(encoding="utf-8")
        self.assertEqual(mod.run_text(src, "n1.rs"), [])

    def test_negative_2_not_halo2(self) -> None:
        mod = _load()
        src = (FIX / "halo2_gate_polynomial_degree_mismatch_negative_2.rs").read_text(encoding="utf-8")
        self.assertEqual(mod.run_text(src, "n2.rs"), [])


if __name__ == "__main__":
    unittest.main()
