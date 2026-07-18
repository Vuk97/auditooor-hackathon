#!/usr/bin/env python3
"""Tests for plonky3_lookup_table_argument_mismatch detector.

Wave-7 Track K-zkBugs minor frameworks.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DET = ROOT / "detectors" / "plonky3_wave1" / "plonky3_lookup_table_argument_mismatch.py"
FIX = ROOT / "detectors" / "plonky3_wave1" / "test_fixtures"


def _load():
    spec = importlib.util.spec_from_file_location("plonky3_lookup_mismatch", DET)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class Plonky3LookupTableArgumentMismatchTest(unittest.TestCase):
    def test_positive_1_arity_mismatch(self) -> None:
        mod = _load()
        src = (FIX / "plonky3_lookup_table_argument_mismatch_positive_1.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p1.rs")
        self.assertGreaterEqual(len(hits), 1)
        self.assertEqual(hits[0]["detector_id"], "plonky3_lookup_table_argument_mismatch")
        self.assertIn("arity", hits[0]["message"].lower())

    def test_positive_2_orphaned_send(self) -> None:
        mod = _load()
        src = (FIX / "plonky3_lookup_table_argument_mismatch_positive_2.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p2.rs")
        self.assertGreaterEqual(len(hits), 1)
        self.assertEqual(hits[0]["detector_id"], "plonky3_lookup_table_argument_mismatch")

    def test_negative_1_matching_arity(self) -> None:
        mod = _load()
        src = (FIX / "plonky3_lookup_table_argument_mismatch_negative_1.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "n1.rs")
        self.assertEqual(hits, [])

    def test_negative_2_not_plonky3(self) -> None:
        mod = _load()
        src = (FIX / "plonky3_lookup_table_argument_mismatch_negative_2.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "n2.rs")
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
