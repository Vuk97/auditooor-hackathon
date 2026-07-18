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
    / "rust_division_before_multiplication_fire28.py"
)
DETECTOR_ID = "rust_division_before_multiplication_fire28"
POSITIVE = FIXTURES / "rust_division_before_multiplication_fire28_positive.rs"
NEGATIVE = FIXTURES / "rust_division_before_multiplication_fire28_negative.rs"
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


class RustDivisionBeforeMultiplicationFire28Tests(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        py_compile.compile(__file__, doraise=True)

    def test_positive_fixture_fires_on_four_precision_loss_shapes(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertGreaterEqual(hits, 4, log_text)
        self.assertIn("preview_redeem_divides_assets_before_user_shares", log_text)
        self.assertIn("claim_withdrawable_per_share_floor_first", log_text)
        self.assertIn("accrue_reward_checked_div_then_rate", log_text)
        self.assertIn("calculate_stableswap_y_scales_after_truncation", log_text)
        self.assertIn("Divide-first integer math", log_text)

    def test_negative_fixture_is_silent_on_full_precision_and_generic_math(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)
        negative_text = NEGATIVE.read_text(encoding="utf-8")
        self.assertIn("mul_div_floor", negative_text)
        self.assertIn("checked_mul", negative_text)
        self.assertIn("U256", negative_text)
        self.assertIn("normalize_pixels_generic_math", negative_text)

    def test_no_unicode_dashes_in_owned_sources(self) -> None:
        for path in (DETECTOR, POSITIVE, NEGATIVE, Path(__file__)):
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIsNone(re.search("[\u2013\u2014]", text))


if __name__ == "__main__":
    unittest.main()
