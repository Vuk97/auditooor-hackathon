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
    / "rounding_direction_div_before_mul_fire24.py"
)
DETECTOR_ID = "rounding_direction_div_before_mul_fire24"
POSITIVE = FIXTURES / "rounding_direction_div_before_mul_fire24_positive.rs"
NEGATIVE = FIXTURES / "rounding_direction_div_before_mul_fire24_negative.rs"
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


class RustRoundingDirectionDivBeforeMulFire24Tests(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        py_compile.compile(__file__, doraise=True)

    def test_positive_fixture_fires_on_value_distribution_shapes(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertGreaterEqual(hits, 3, log_text)
        self.assertIn("settle_fee_rounds_user_favorable", log_text)
        self.assertIn("claim_reward_floor_first", log_text)
        self.assertIn("liquidate_with_floor_before_bonus", log_text)
        self.assertIn("user-favored direction", log_text)

    def test_negative_fixture_is_silent_on_safe_rounding(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)
        negative_text = NEGATIVE.read_text(encoding="utf-8")
        self.assertIn("mul_div_floor_checked", negative_text)
        self.assertIn("ceil_div", negative_text)
        self.assertIn("zero protocol fee rejected", negative_text)

    def test_no_unicode_dashes_in_owned_sources(self) -> None:
        for path in (DETECTOR, POSITIVE, NEGATIVE, Path(__file__)):
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIsNone(re.search("[\u2013\u2014]", text))


if __name__ == "__main__":
    unittest.main()
