#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DETECTOR = ROOT / "detectors" / "circom_wave1" / "sha256_template_zero.py"
FIXTURES = ROOT / "detectors" / "circom_wave1" / "test_fixtures"


def _load_detector():
    spec = importlib.util.spec_from_file_location("sha256_template_zero", DETECTOR)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class Sha256TemplateZeroTest(unittest.TestCase):
    def test_flags_sha256_item_at_index_without_selector_sum_constraint(self) -> None:
        detector = _load_detector()
        source = (FIXTURES / "sha256_template_zero_positive.circom").read_text(
            encoding="utf-8"
        )

        hits = detector.sha256_template_zero_hits(source)

        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["template"], "ItemAtIndex")
        self.assertEqual(hits[0]["sha256_templates"], ["Sha256General"])
        self.assertIn("all-zero", hits[0]["message"])

    def test_accepts_item_at_index_with_exactly_one_selector_constraint(self) -> None:
        detector = _load_detector()
        source = (FIXTURES / "sha256_template_zero_negative.circom").read_text(
            encoding="utf-8"
        )

        self.assertEqual(detector.sha256_template_zero_hits(source), [])

    def test_ignores_vulnerable_helper_without_sha256_caller_shape(self) -> None:
        detector = _load_detector()
        source = """
        template ItemAtIndex(n, bitLength) {
            signal input in[n];
            signal input index;
            signal output out;
            component lt = LessThan(bitLength);
            component eqs[n];
        }
        """

        self.assertEqual(detector.sha256_template_zero_hits(source), [])


if __name__ == "__main__":
    unittest.main()
