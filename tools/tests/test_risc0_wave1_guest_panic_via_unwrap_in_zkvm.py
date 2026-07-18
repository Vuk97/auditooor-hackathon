#!/usr/bin/env python3
"""Tests for risc0_guest_panic_via_unwrap_in_zkvm detector.

Wave-7 Track K-zkBugs minor frameworks.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DET = ROOT / "detectors" / "risc0_wave1" / "risc0_guest_panic_via_unwrap_in_zkvm.py"
FIX = ROOT / "detectors" / "risc0_wave1" / "test_fixtures"


def _load():
    spec = importlib.util.spec_from_file_location("risc0_guest_panic_unwrap", DET)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class Risc0GuestPanicViaUnwrapTest(unittest.TestCase):
    def test_positive_1_unwrap_on_user_input(self) -> None:
        mod = _load()
        src = (FIX / "risc0_guest_panic_via_unwrap_in_zkvm_positive_1.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p1.rs")
        self.assertGreaterEqual(len(hits), 1)
        self.assertEqual(hits[0]["detector_id"], "risc0_guest_panic_via_unwrap_in_zkvm")
        self.assertEqual(hits[0]["severity"], "medium")

    def test_positive_2_panic_macro_in_guest(self) -> None:
        mod = _load()
        src = (FIX / "risc0_guest_panic_via_unwrap_in_zkvm_positive_2.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p2.rs")
        self.assertGreaterEqual(len(hits), 1)
        self.assertIn("panic", hits[0]["message"].lower())

    def test_negative_1_proper_error_handling(self) -> None:
        mod = _load()
        src = (FIX / "risc0_guest_panic_via_unwrap_in_zkvm_negative_1.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "n1.rs")
        self.assertEqual(hits, [])

    def test_negative_2_not_risc0_file(self) -> None:
        mod = _load()
        src = (FIX / "risc0_guest_panic_via_unwrap_in_zkvm_negative_2.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "n2.rs")
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
