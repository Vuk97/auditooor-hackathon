from __future__ import annotations

import py_compile
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent.parent
RUST_DETECT = REPO_ROOT / "tools" / "rust-detect.py"
FIXTURES = REPO_ROOT / "detectors" / "rust_wave1" / "test_fixtures"
DETECTOR = REPO_ROOT / "detectors" / "rust_wave1" / "liquidation_postcheck_or_closefactor_fire16.py"
DETECTOR_ID = "liquidation_postcheck_or_closefactor_fire16"
_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture_name: str) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
        log_path = Path(tf.name)
    try:
        proc = subprocess.run(
            [
                sys.executable,
                str(RUST_DETECT),
                str(FIXTURES),
                "--only",
                DETECTOR_ID,
                "--file",
                str(FIXTURES / fixture_name),
                "--log",
                str(log_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stderr or proc.stdout)
        text = log_path.read_text(encoding="utf-8", errors="ignore")
        match = _HIT_RE.search(text)
        return (int(match.group(1)) if match else 0), text
    finally:
        log_path.unlink(missing_ok=True)


class RustLiquidationPostcheckOrClosefactorFire16Tests(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

    def test_aggregate_positive_fires_on_three_variants(self) -> None:
        hits, log_text = _run_fixture("liquidation_postcheck_or_closefactor_fire16_positive.rs")
        self.assertGreaterEqual(hits, 3, log_text)
        self.assertIn("underfunded-bonus-revert", log_text)
        self.assertIn("strict-closefactor-boundary", log_text)
        self.assertIn("missing-post-liquidation-health-check", log_text)

    def test_aggregate_clean_fixture_is_silent(self) -> None:
        hits, log_text = _run_fixture("liquidation_postcheck_or_closefactor_fire16_negative.rs")
        self.assertEqual(hits, 0, log_text)

    def test_requested_source_miss_fixtures_fire(self) -> None:
        for fixture_name in (
            "liquidation_bonus_strict_impl_reverts_when_collateral_undersubscribes_positive.rs",
            "liquidation_close_factor_off_by_one_positive.rs",
            "liquidation_no_health_factor_post_check_positive.rs",
        ):
            with self.subTest(fixture=fixture_name):
                hits, log_text = _run_fixture(fixture_name)
                self.assertGreaterEqual(hits, 1, log_text)

    def test_existing_clean_boundary_and_postcheck_fixtures_stay_silent(self) -> None:
        for fixture_name in (
            "liquidation_close_factor_off_by_one_negative.rs",
            "liquidation_no_health_factor_post_check_negative.rs",
        ):
            with self.subTest(fixture=fixture_name):
                hits, log_text = _run_fixture(fixture_name)
                self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
