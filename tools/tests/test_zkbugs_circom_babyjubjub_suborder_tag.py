#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DETECTOR = ROOT / "detectors" / "circom_wave1" / "zkbugs_babyjubjub_suborder_tag.py"
FIXTURES = ROOT / "detectors" / "circom_wave1" / "test_fixtures"


def _load_detector():
    spec = importlib.util.spec_from_file_location("zkbugs_babyjubjub_suborder_tag", DETECTOR)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class ZkBugsCircomBabyJubJubSuborderTagTest(unittest.TestCase):
    def test_flags_missing_suborder_enforcement(self) -> None:
        detector = _load_detector()
        source = (FIXTURES / "zkbugs_babyjubjub_suborder_tag_positive.circom").read_text(
            encoding="utf-8"
        )

        hits = detector.run_text(source, "positive.circom")

        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["severity"], "high")
        self.assertIn("LessThan(251)", hits[0]["snippet"])

    def test_accepts_constrained_suborder_and_range_check(self) -> None:
        detector = _load_detector()
        source = (FIXTURES / "zkbugs_babyjubjub_suborder_tag_negative.circom").read_text(
            encoding="utf-8"
        )

        self.assertEqual(detector.babyjubjub_suborder_tag_offsets(source), [])

    def test_ignores_unrelated_less_than_251(self) -> None:
        detector = _load_detector()
        source = """
        template GenericBound() {
            signal input amount;
            signal input limit;
            component lt = LessThan(251);
            lt.in[0] <== amount;
            lt.in[1] <== limit;
            lt.out === 1;
        }
        """

        self.assertEqual(detector.babyjubjub_suborder_tag_offsets(source), [])


if __name__ == "__main__":
    unittest.main()
