#!/usr/bin/env python3
"""Tests for plonky2_recursion_witness_mismatch detector.

Wave-6 Track K-zkBugs step K-Z.10a.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DET = ROOT / "detectors" / "plonky2_wave1" / "plonky2_recursion_witness_mismatch.py"
FIX = ROOT / "detectors" / "plonky2_wave1" / "test_fixtures"


def _load():
    spec = importlib.util.spec_from_file_location("plonky2_recursion_witness_mismatch", DET)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class Plonky2RecursionWitnessMismatchTest(unittest.TestCase):
    def test_positive_1_missing_witness_assignment(self) -> None:
        mod = _load()
        src = (FIX / "plonky2_recursion_witness_mismatch_positive_1.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p1.rs")
        self.assertGreaterEqual(len(hits), 1)
        self.assertEqual(hits[0]["detector_id"], "plonky2_recursion_witness_mismatch")
        self.assertEqual(hits[0]["severity"], "high")
        kinds = [h["kind"] for h in hits]
        self.assertIn("missing_witness_assignment", kinds)

    def test_positive_2_verifier_data_not_connected(self) -> None:
        mod = _load()
        src = (FIX / "plonky2_recursion_witness_mismatch_positive_2.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p2.rs")
        self.assertGreaterEqual(len(hits), 1)
        kinds = [h["kind"] for h in hits]
        self.assertIn("verifier_data_not_connected", kinds)

    def test_negative_1_properly_wired_recursion(self) -> None:
        mod = _load()
        src = (FIX / "plonky2_recursion_witness_mismatch_negative_1.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "n1.rs")
        self.assertEqual(hits, [])

    def test_negative_2_not_plonky2(self) -> None:
        mod = _load()
        src = (FIX / "plonky2_recursion_witness_mismatch_negative_2.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "n2.rs")
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
