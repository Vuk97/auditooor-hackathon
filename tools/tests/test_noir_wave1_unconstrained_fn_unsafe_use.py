#!/usr/bin/env python3
"""Tests for noir_unconstrained_fn_unsafe_use detector.

Wave-6 Track K-zkBugs step K-Z.10b.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DET = ROOT / "detectors" / "noir_wave1" / "noir_unconstrained_fn_unsafe_use.py"
FIX = ROOT / "detectors" / "noir_wave1" / "test_fixtures"


def _load():
    spec = importlib.util.spec_from_file_location("noir_unconstrained_fn_unsafe_use", DET)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class NoirUnconstrainedFnUnsafeUseTest(unittest.TestCase):
    def test_positive_1_inverse_without_constraint(self) -> None:
        mod = _load()
        src = (FIX / "noir_unconstrained_fn_unsafe_use_positive_1.nr").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p1.nr")
        self.assertGreaterEqual(len(hits), 1)
        self.assertEqual(hits[0]["detector_id"], "noir_unconstrained_fn_unsafe_use")
        self.assertEqual(hits[0]["severity"], "high")
        fns_called = [h["called_fn"] for h in hits]
        self.assertIn("compute_inverse", fns_called)

    def test_positive_2_bits_without_constraint(self) -> None:
        mod = _load()
        src = (FIX / "noir_unconstrained_fn_unsafe_use_positive_2.nr").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p2.nr")
        self.assertGreaterEqual(len(hits), 1)
        fns_called = [h["called_fn"] for h in hits]
        self.assertIn("get_witness_bits", fns_called)

    def test_negative_1_properly_constrained(self) -> None:
        mod = _load()
        src = (FIX / "noir_unconstrained_fn_unsafe_use_negative_1.nr").read_text(encoding="utf-8")
        hits = mod.run_text(src, "n1.nr")
        self.assertEqual(hits, [])

    def test_negative_2_no_unconstrained_fns(self) -> None:
        mod = _load()
        src = (FIX / "noir_unconstrained_fn_unsafe_use_negative_2.nr").read_text(encoding="utf-8")
        hits = mod.run_text(src, "n2.nr")
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
