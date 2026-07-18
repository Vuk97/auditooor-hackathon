#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DET = ROOT / "detectors" / "halo2_wave1" / "halo2_lookup_table_missing_complement.py"
FIX = ROOT / "detectors" / "halo2_wave1" / "test_fixtures"


def _load():
    spec = importlib.util.spec_from_file_location("h2_ltmc", DET)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class Halo2LookupMissingComplementTest(unittest.TestCase):
    def test_positive_1_word_in_byte_table(self) -> None:
        mod = _load()
        src = (FIX / "halo2_lookup_table_missing_complement_positive_1.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p1.rs")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["detector_id"], "halo2_lookup_table_missing_complement")
        self.assertEqual(hits[0]["severity"], "medium")

    def test_positive_2_address_in_byte_table(self) -> None:
        mod = _load()
        src = (FIX / "halo2_lookup_table_missing_complement_positive_2.rs").read_text(encoding="utf-8")
        hits = mod.run_text(src, "p2.rs")
        self.assertEqual(len(hits), 1)

    def test_negative_1_byte_in_byte_table(self) -> None:
        mod = _load()
        src = (FIX / "halo2_lookup_table_missing_complement_negative_1.rs").read_text(encoding="utf-8")
        self.assertEqual(mod.run_text(src, "n1.rs"), [])

    def test_negative_2_word_in_u16_table(self) -> None:
        mod = _load()
        src = (FIX / "halo2_lookup_table_missing_complement_negative_2.rs").read_text(encoding="utf-8")
        self.assertEqual(mod.run_text(src, "n2.rs"), [])


if __name__ == "__main__":
    unittest.main()
