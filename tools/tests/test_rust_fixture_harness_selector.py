#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
HARNESS = ROOT / "detectors" / "rust_wave1" / "test_fixtures" / "test_detectors.sh"
TOOL = ROOT / "tools" / "detector-auto-detect.py"
R76_STABLECOIN_DETECTORS = (
    "broken_tri_crypto_cpmm_pools_created_without_weight_check",
    "liquidation_dosed_by_collateral_reserve_illiquidity",
    "liquidation_leaves_zombie_debt_on_borrower",
    "rapid_borrow_repay_cycle_inflates_interest_rates",
    "stableswap_disjoint_swaps_break_invariant",
)


def _load_tool_module():
    spec = importlib.util.spec_from_file_location("detector_auto_detect", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RustFixtureHarnessSelectorTest(unittest.TestCase):
    def test_single_detector_harness_rerun(self) -> None:
        proc = subprocess.run(
            ["bash", str(HARNESS), "--detector", "missing_ttl_bump_on_persistent_read"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("PASS  missing_ttl_bump_on_persistent_read positive", proc.stdout)
        self.assertIn("PASS  missing_ttl_bump_on_persistent_read negative", proc.stdout)
        self.assertIn("Rust wave1 regression:  2/2 passed", proc.stdout)
        self.assertNotIn("division_before_multiplication", proc.stdout)

    def test_nested_r76_stablecoin_detector_harness_reruns(self) -> None:
        for detector in R76_STABLECOIN_DETECTORS:
            with self.subTest(detector=detector):
                proc = subprocess.run(
                    ["bash", str(HARNESS), f"--detector={detector}"],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
                self.assertIn(f"PASS  {detector} positive", proc.stdout)
                self.assertIn(f"PASS  {detector} negative", proc.stdout)
                self.assertIn("Rust wave1 regression:  2/2 passed", proc.stdout)
                self.assertNotIn("missing_ttl_bump_on_persistent_read", proc.stdout)

    def test_unknown_detector_is_rejected(self) -> None:
        proc = subprocess.run(
            ["bash", str(HARNESS), "--detector", "does_not_exist"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("unknown detector: does_not_exist", proc.stderr)


class DetectorAutoDetectSelectorTest(unittest.TestCase):
    def test_selector_is_forwarded_to_rust_harness(self) -> None:
        module = _load_tool_module()
        with mock.patch.object(module.subprocess, "check_output", return_value="") as check_output:
            module.run_rust_fixtures(ROOT, detector="missing_ttl_bump_on_persistent_read")

        check_output.assert_called_once_with(
            [
                "bash",
                str(module.REPO / "detectors" / "rust_wave1" / "test_fixtures" / "test_detectors.sh"),
                "--detector=missing_ttl_bump_on_persistent_read",
            ],
            cwd=module.REPO,
            stderr=module.subprocess.STDOUT,
            text=True,
        )

    def test_cli_json_accepts_detector_flag(self) -> None:
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL),
                str(ROOT),
                "--wave",
                "rust_wave1",
                "--detector",
                "missing_ttl_bump_on_persistent_read",
                "--json",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn('"detector": "missing_ttl_bump_on_persistent_read"', proc.stdout)


if __name__ == "__main__":
    unittest.main()
