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
DETECTOR = (
    REPO_ROOT
    / "detectors"
    / "rust_wave1"
    / "value_math_rounding_or_minout_zero_fire20.py"
)
DETECTOR_ID = "value_math_rounding_or_minout_zero_fire20"
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


class RustValueMathRoundingOrMinoutZeroFire20Tests(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        py_compile.compile(__file__, doraise=True)

    def test_positive_fixture_fires_on_value_math_and_swap_shapes(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "value_math_rounding_or_minout_zero_fire20_positive.rs"
        )
        self.assertGreaterEqual(hits, 4, log_text)
        self.assertIn("division before multiplication", log_text)
        self.assertIn("DEX amount or quote math uses floor rounding", log_text)
        self.assertIn("minimum-output", log_text)

    def test_negative_fixture_is_silent_on_checked_rounding_and_min_out(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "value_math_rounding_or_minout_zero_fire20_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_dex_rounding_recall_fixture_is_detected(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "r94_loop_dex_rounding_direction_theft_positive.rs"
        )
        self.assertGreaterEqual(hits, 2, log_text)

    def test_confirmed_zero_min_out_recall_fixture_is_detected(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "r94_loop_dex_swap_amountoutmin_zero_no_slippage_positive.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)

    def test_raw_generic_arithmetic_without_value_context_is_silent(self) -> None:
        hits, log_text = _run_fixture(FIXTURES / "division_before_multiplication_positive.rs")
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
