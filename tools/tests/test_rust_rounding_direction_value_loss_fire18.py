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
DETECTOR = REPO_ROOT / "detectors" / "rust_wave1" / "rounding_direction_value_loss_fire18.py"
DETECTOR_ID = "rounding_direction_value_loss_fire18"
_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
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
                str(fixture),
                "--log",
                str(log_path),
            ],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=30,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stderr or proc.stdout)
        text = log_path.read_text(encoding="utf-8", errors="ignore")
        match = _HIT_RE.search(text)
        return int(match.group(1)) if match else 0, text
    finally:
        log_path.unlink(missing_ok=True)


class RustRoundingDirectionValueLossFire18Tests(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

    def test_positive_fixture_fires_on_three_value_bearing_shapes(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "rounding_direction_value_loss_fire18_positive.rs"
        )
        self.assertGreaterEqual(hits, 3, log_text)
        self.assertIn("division before multiplication", log_text)
        self.assertIn("unchecked or clamping arithmetic", log_text)
        self.assertIn("asymmetric LP min-ratio join", log_text)

    def test_negative_fixture_is_silent_on_checked_ordering_and_guards(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "rounding_direction_value_loss_fire18_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)

    def test_held_out_value_bearing_rounding_fixtures_are_recalled(self) -> None:
        held_out = [
            "rust_share_math_division_before_multiplication_value_loss_positive.rs",
            "lp_join_asymmetric_pair_sandwich_overpays_one_side_positive.rs",
        ]
        for fixture in held_out:
            with self.subTest(fixture=fixture):
                hits, log_text = _run_fixture(FIXTURES / fixture)
                self.assertGreaterEqual(hits, 1, log_text)

    def test_clean_value_bearing_controls_stay_silent(self) -> None:
        clean_controls = [
            "rust_share_math_division_before_multiplication_value_loss_negative.rs",
            "lp_join_asymmetric_pair_sandwich_overpays_one_side_negative.rs",
        ]
        for fixture in clean_controls:
            with self.subTest(fixture=fixture):
                hits, log_text = _run_fixture(FIXTURES / fixture)
                self.assertEqual(hits, 0, log_text)

    def test_generic_arithmetic_misses_fail_closed_without_value_context(self) -> None:
        generic_controls = [
            "division_before_multiplication_positive.rs",
            "integer_overflow_unchecked_block_positive.rs",
        ]
        for fixture in generic_controls:
            with self.subTest(fixture=fixture):
                hits, log_text = _run_fixture(FIXTURES / fixture)
                self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
