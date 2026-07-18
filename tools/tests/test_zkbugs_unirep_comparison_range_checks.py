#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DETECTOR = ROOT / "detectors" / "circom_wave1" / "zkbugs_unirep_comparison_range_checks.py"
FIXTURES = ROOT / "detectors" / "circom_wave1" / "test_fixtures"


def _load_detector():
    spec = importlib.util.spec_from_file_location(
        "zkbugs_unirep_comparison_range_checks", DETECTOR
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class ZkBugsUnirepComparisonRangeChecksTest(unittest.TestCase):
    def test_flags_unirep_less_than_without_nonce_range_check(self) -> None:
        detector = _load_detector()
        source = (FIXTURES / "zkbugs_unirep_comparison_range_checks_positive.circom").read_text(
            encoding="utf-8"
        )

        hits = detector.comparison_range_check_hits(source)

        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["template"], "EpochKeyLite")
        self.assertEqual(hits[0]["component"], "nonceLessThan")
        self.assertEqual(hits[0]["comparator"], "LessThan")
        self.assertEqual(hits[0]["bits"], 8)
        self.assertEqual(hits[0]["inputs"], ["epochKeyNonce"])
        self.assertIn("V-UNI-VUL-002", hits[0]["message"])

    def test_accepts_matching_num2bits_range_check(self) -> None:
        detector = _load_detector()
        source = (FIXTURES / "zkbugs_unirep_comparison_range_checks_negative.circom").read_text(
            encoding="utf-8"
        )

        self.assertEqual(detector.run_text(source, "EpochKeyLite.circom"), [])

    def test_rejects_wider_than_comparator_range_check(self) -> None:
        detector = _load_detector()
        source = """
        template EpochKeyLite() {
            signal input epochKeyNonce;
            component nonceBits = Num2Bits(16);
            nonceBits.in <== epochKeyNonce;
            component nonceLessThan = LessThan(8);
            nonceLessThan.in[0] <== epochKeyNonce;
            nonceLessThan.in[1] <== 3;
        }
        """

        hits = detector.comparison_range_check_hits(source)

        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["inputs"], ["epochKeyNonce"])


if __name__ == "__main__":
    unittest.main()
