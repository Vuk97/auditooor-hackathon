#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DET = ROOT / "detectors" / "halo2_wave1" / "halo2_selector_inactive_constraint_leak.py"
FIX = ROOT / "detectors" / "halo2_wave1" / "test_fixtures"


def _load():
    spec = importlib.util.spec_from_file_location("h2_sicl", DET)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class Halo2SelectorLeakTest(unittest.TestCase):
    def test_positive_1_onehot_two_leaks(self) -> None:
        mod = _load()
        src = (FIX / "halo2_selector_inactive_constraint_leak_positive_1.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p1.rs")
        self.assertEqual(len(hits), 1)
        self.assertGreaterEqual(hits[0]["leaky_constraint_count"], 2)
        self.assertEqual(hits[0]["severity"], "high")

    def test_positive_2_single_leak(self) -> None:
        mod = _load()
        src = (FIX / "halo2_selector_inactive_constraint_leak_positive_2.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p2.rs")
        self.assertEqual(len(hits), 1)
        self.assertGreaterEqual(hits[0]["leaky_constraint_count"], 1)

    def test_negative_1_all_selected(self) -> None:
        mod = _load()
        src = (FIX / "halo2_selector_inactive_constraint_leak_negative_1.rs").read_text(encoding="utf-8")
        self.assertEqual(mod.run_text(src, "n1.rs"), [])

    def test_negative_2_constraints_with_selector(self) -> None:
        mod = _load()
        src = (FIX / "halo2_selector_inactive_constraint_leak_negative_2.rs").read_text(encoding="utf-8")
        self.assertEqual(mod.run_text(src, "n2.rs"), [])


if __name__ == "__main__":
    unittest.main()
