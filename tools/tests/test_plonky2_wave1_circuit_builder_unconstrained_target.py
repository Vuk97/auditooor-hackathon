#!/usr/bin/env python3
"""Tests for plonky2_circuit_builder_unconstrained_target detector.

Wave-6 Track K-zkBugs step K-Z.10a.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DET = ROOT / "detectors" / "plonky2_wave1" / "plonky2_circuit_builder_unconstrained_target.py"
FIX = ROOT / "detectors" / "plonky2_wave1" / "test_fixtures"


def _load():
    spec = importlib.util.spec_from_file_location("plonky2_unconstrained_target", DET)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class Plonky2UnconstrainedTargetTest(unittest.TestCase):
    def test_positive_1_flags_secret_target(self) -> None:
        mod = _load()
        src = (FIX / "plonky2_circuit_builder_unconstrained_target_positive_1.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p1.rs")
        self.assertGreaterEqual(len(hits), 1)
        self.assertEqual(hits[0]["detector_id"], "plonky2_circuit_builder_unconstrained_target")
        self.assertEqual(hits[0]["severity"], "high")
        target_names = [h["target"] for h in hits]
        self.assertIn("secret", target_names)

    def test_positive_2_flags_nullifier_hash(self) -> None:
        mod = _load()
        src = (FIX / "plonky2_circuit_builder_unconstrained_target_positive_2.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p2.rs")
        self.assertGreaterEqual(len(hits), 1)
        target_names = [h["target"] for h in hits]
        self.assertIn("nullifier_hash", target_names)

    def test_negative_1_properly_constrained(self) -> None:
        mod = _load()
        src = (FIX / "plonky2_circuit_builder_unconstrained_target_negative_1.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "n1.rs")
        self.assertEqual(hits, [])

    def test_negative_2_not_plonky2(self) -> None:
        mod = _load()
        src = (FIX / "plonky2_circuit_builder_unconstrained_target_negative_2.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "n2.rs")
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
