#!/usr/bin/env python3
"""Tests for bellperson_synthesis_unconstrained_alloc detector.

Wave-7 Track K-zkBugs minor frameworks.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DET = ROOT / "detectors" / "bellperson_wave1" / "bellperson_synthesis_unconstrained_alloc.py"
FIX = ROOT / "detectors" / "bellperson_wave1" / "test_fixtures"


def _load():
    spec = importlib.util.spec_from_file_location("bellperson_synthesis_unconstrained_alloc", DET)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class BellpersonSynthesisUnconstrainedAllocTest(unittest.TestCase):
    def test_positive_1_secret_allocated_not_enforced(self) -> None:
        mod = _load()
        src = (FIX / "bellperson_synthesis_unconstrained_alloc_positive_1.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p1.rs")
        self.assertGreaterEqual(len(hits), 1)
        self.assertEqual(hits[0]["detector_id"], "bellperson_synthesis_unconstrained_alloc")
        self.assertEqual(hits[0]["severity"], "high")

    def test_positive_2_alloc_input_not_enforced(self) -> None:
        mod = _load()
        src = (FIX / "bellperson_synthesis_unconstrained_alloc_positive_2.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p2.rs")
        self.assertGreaterEqual(len(hits), 1)
        self.assertEqual(hits[0]["detector_id"], "bellperson_synthesis_unconstrained_alloc")

    def test_negative_1_all_variables_enforced(self) -> None:
        mod = _load()
        src = (FIX / "bellperson_synthesis_unconstrained_alloc_negative_1.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "n1.rs")
        self.assertEqual(hits, [])

    def test_negative_2_not_bellperson(self) -> None:
        mod = _load()
        src = (FIX / "bellperson_synthesis_unconstrained_alloc_negative_2.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "n2.rs")
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
