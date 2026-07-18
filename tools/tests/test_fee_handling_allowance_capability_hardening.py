#!/usr/bin/env python3
"""Focused regression coverage for the fee-over-allowance recall lift."""

from __future__ import annotations

import importlib.util
import re
import unittest
from pathlib import Path

import yaml


REPO = Path(__file__).resolve().parents[2]
PATTERN = "fee-billed-over-approval-allowance"
PATTERN_PATH = REPO / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
REGISTRY_PATH = REPO / "detectors" / "_tier_registry.yaml"
DETECTOR_PATH = REPO / "detectors" / "wave18" / "fee_billed_over_approval_allowance.py"
BACKTEST_PATH = REPO / "tools" / "audit" / "detector-catch-rate-backtest.py"


def _load_backtest():
    spec = importlib.util.spec_from_file_location("detector_catch_rate_backtest", BACKTEST_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _match_values(spec: dict, key: str) -> list[str]:
    values: list[str] = []
    for row in spec["match"]:
        if key in row:
            values.append(row[key])
    if not values:
        raise AssertionError(f"missing predicate {key}")
    return values


class FeeHandlingAllowanceCapabilityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.spec = yaml.safe_load(PATTERN_PATH.read_text(encoding="utf-8"))
        cls.registry = yaml.safe_load(REGISTRY_PATH.read_text(encoding="utf-8"))
        cls.backtest = _load_backtest()

    def test_pattern_metadata_and_generated_detector_exist(self) -> None:
        self.assertEqual(self.spec["pattern"], PATTERN)
        self.assertEqual(self.spec["confidence"], "MEDIUM")
        self.assertIn("fee-handling", self.spec["tags"])
        self.assertTrue(DETECTOR_PATH.is_file(), f"missing generated detector {DETECTOR_PATH}")
        for fixture_path in self.spec["fixtures"].values():
            self.assertTrue((REPO / fixture_path).is_file(), f"missing fixture {fixture_path}")

    def test_fixture_pair_exercises_additive_fee_and_clean_guard(self) -> None:
        fee_amount_rx, balance_debit_rx, plain_allowance_rx = [
            re.compile(rx, re.IGNORECASE)
            for rx in _match_values(self.spec, "function.body_contains_regex")[1:4]
        ]
        full_allowance_guard = re.compile(
            _match_values(self.spec, "function.body_not_contains_regex")[0],
            re.IGNORECASE,
        )

        vuln = (REPO / self.spec["fixtures"]["vuln"]).read_text(encoding="utf-8")
        clean = (REPO / self.spec["fixtures"]["clean"]).read_text(encoding="utf-8")

        self.assertRegex(vuln, fee_amount_rx)
        self.assertRegex(vuln, balance_debit_rx)
        self.assertRegex(vuln, plain_allowance_rx)
        self.assertIsNone(full_allowance_guard.search(vuln))

        self.assertRegex(clean, fee_amount_rx)
        self.assertRegex(clean, balance_debit_rx)
        self.assertRegex(clean, full_allowance_guard)

    def test_registry_entry_points_to_wave18_fixture_pair(self) -> None:
        entry = self.registry["tiers"][PATTERN]
        self.assertEqual(entry["tier"], "E")
        self.assertEqual(entry["engine"], "slither")
        self.assertEqual(entry["argument"], PATTERN)
        self.assertEqual(entry["fixture_pair"], "patterns/fixtures/fee-billed-over-approval-allowance")
        self.assertIn("wave18", entry["waves"])
        self.assertEqual(entry["smoke_test_vuln_hits"], 1)
        self.assertEqual(entry["smoke_test_clean_hits"], 0)

    def test_backtest_derives_runtime_fee_class_for_this_slug(self) -> None:
        self.assertEqual(
            self.backtest.derive_attack_class(PATTERN, self.spec.get("tags")),
            "fee-redirect",
        )


if __name__ == "__main__":
    unittest.main()
