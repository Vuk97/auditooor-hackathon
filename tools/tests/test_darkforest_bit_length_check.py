#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DETECTOR = ROOT / "detectors" / "circom_wave1" / "darkforest_bit_length_check.py"
FIXTURES = ROOT / "detectors" / "circom_wave1" / "test_fixtures"


def _load_detector():
    spec = importlib.util.spec_from_file_location("darkforest_bit_length_check", DETECTOR)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class DarkForestBitLengthCheckTest(unittest.TestCase):
    def test_flags_rangeproof_less_than_inputs_without_bit_length_checks(self) -> None:
        detector = _load_detector()
        source = (FIXTURES / "darkforest_bit_length_check_positive.circom").read_text(
            encoding="utf-8"
        )

        hits = detector.darkforest_bit_length_check_hits(source)

        self.assertEqual(len(hits), 2)
        self.assertEqual({hit["component"] for hit in hits}, {"lowerBound", "upperBound"})
        self.assertIn("max_abs_value+in", hits[0]["unchecked_inputs"])

    def test_accepts_rangeproof_when_comparator_inputs_are_num2bits_checked(self) -> None:
        detector = _load_detector()
        source = (FIXTURES / "darkforest_bit_length_check_negative.circom").read_text(
            encoding="utf-8"
        )

        self.assertEqual(detector.darkforest_bit_length_check_hits(source), [])

    def test_ignores_non_rangeproof_less_than(self) -> None:
        detector = _load_detector()
        source = """
        template OtherProof(bits, max_abs_value) {
            signal input in;
            component lowerBound = LessThan(bits);
            lowerBound.in[0] <== max_abs_value + in;
            lowerBound.in[1] <== 0;
        }
        """

        self.assertEqual(detector.darkforest_bit_length_check_hits(source), [])


if __name__ == "__main__":
    unittest.main()
