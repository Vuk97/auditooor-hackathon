#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DETECTOR = (
    ROOT
    / "detectors"
    / "circom_wave1"
    / "zkbugs_blake3novatreepath_checkdepth_comparator_range.py"
)
FIXTURES = ROOT / "detectors" / "circom_wave1" / "test_fixtures"


def _load_detector():
    spec = importlib.util.spec_from_file_location("zkbugs_blake3_checkdepth_range", DETECTOR)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class ZkBugsBlake3CheckDepthComparatorRangeTest(unittest.TestCase):
    def test_flags_depth_comparators_without_num2bits_range_checks(self) -> None:
        detector = _load_detector()
        source = (
            FIXTURES / "zkbugs_blake3novatreepath_checkdepth_comparator_range_positive.circom"
        ).read_text(encoding="utf-8")

        hits = detector.comparator_missing_range_check_hits(source)

        self.assertEqual(len(hits), 2)
        self.assertEqual({hit["comparator"] for hit in hits}, {"LessThan", "GreaterEqThan"})
        self.assertTrue(all(hit["inputs"] == ["depth", "leaf_depth"] for hit in hits))

    def test_ignores_fixed_depth_comparators_with_num2bits_range_checks(self) -> None:
        detector = _load_detector()
        source = (
            FIXTURES / "zkbugs_blake3novatreepath_checkdepth_comparator_range_negative.circom"
        ).read_text(encoding="utf-8")

        self.assertEqual(detector.comparator_missing_range_check_hits(source), [])

    def test_num2bits_wider_than_comparator_is_not_sufficient(self) -> None:
        detector = _load_detector()
        source = """
        template BadWideRange() {
            signal input depth;
            signal input leaf_depth;
            component depth_bits = Num2Bits(16);
            depth_bits.in <== depth;
            component leaf_bits = Num2Bits(8);
            leaf_bits.in <== leaf_depth;
            component check_parent = LessThan(8);
            check_parent.in[0] <== depth;
            check_parent.in[1] <== leaf_depth;
        }
        """

        hits = detector.comparator_missing_range_check_hits(source)

        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["inputs"], ["depth"])


if __name__ == "__main__":
    unittest.main()
