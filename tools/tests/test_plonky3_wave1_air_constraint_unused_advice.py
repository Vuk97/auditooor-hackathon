#!/usr/bin/env python3
"""Tests for plonky3_air_constraint_unused_advice detector.

Wave-7 Track K-zkBugs minor frameworks.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DET = ROOT / "detectors" / "plonky3_wave1" / "plonky3_air_constraint_unused_advice.py"
FIX = ROOT / "detectors" / "plonky3_wave1" / "test_fixtures"


def _load():
    spec = importlib.util.spec_from_file_location("plonky3_air_unused_advice", DET)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class Plonky3AirConstraintUnusedAdviceTest(unittest.TestCase):
    def test_positive_1_timestamp_unconstrained(self) -> None:
        mod = _load()
        src = (FIX / "plonky3_air_constraint_unused_advice_positive_1.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p1.rs")
        self.assertGreaterEqual(len(hits), 1)
        self.assertEqual(hits[0]["detector_id"], "plonky3_air_constraint_unused_advice")
        self.assertEqual(hits[0]["severity"], "high")
        self.assertIn("timestamp", hits[0]["message"])

    def test_positive_2_secret_key_unconstrained(self) -> None:
        mod = _load()
        src = (FIX / "plonky3_air_constraint_unused_advice_positive_2.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p2.rs")
        self.assertGreaterEqual(len(hits), 1)
        self.assertEqual(hits[0]["detector_id"], "plonky3_air_constraint_unused_advice")

    def test_negative_1_all_columns_constrained(self) -> None:
        mod = _load()
        src = (FIX / "plonky3_air_constraint_unused_advice_negative_1.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "n1.rs")
        self.assertEqual(hits, [])

    def test_negative_2_not_plonky3(self) -> None:
        mod = _load()
        src = (FIX / "plonky3_air_constraint_unused_advice_negative_2.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "n2.rs")
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
