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
DETECTOR = REPO_ROOT / "detectors" / "rust_wave1" / "rounding_div_before_mul_fire34.py"
DETECTOR_ID = "rounding_div_before_mul_fire34"
POSITIVE = FIXTURES / f"{DETECTOR_ID}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR_ID}_negative.rs"
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
            timeout=60,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stderr or proc.stdout)
        text = log_path.read_text(encoding="utf-8", errors="ignore")
        match = _HIT_RE.search(text)
        return int(match.group(1)) if match else 0, text
    finally:
        log_path.unlink(missing_ok=True)


class RustRoundingDivBeforeMulFire34Tests(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

    def test_positive_fixture_fires_on_attacker_controlled_rounding(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertGreaterEqual(hits, 3, log_text)
        self.assertIn("checked_div before checked_mul", log_text)
        self.assertIn("split quotient multiplied after floor division", log_text)
        self.assertIn("floor division reaches value math sink", log_text)
        self.assertIn("class: rounding-direction-attack", log_text)

    def test_negative_fixture_is_silent_on_mul_first_or_explicit_rounding(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_fixtures_lock_precision_boundaries(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        negative = NEGATIVE.read_text(encoding="utf-8")
        detector = DETECTOR.read_text(encoding="utf-8")
        self.assertIn("checked_div(fee_denominator)?.checked_mul", positive)
        self.assertIn("let reward_units = user_weight / total_weight;", positive)
        self.assertIn("checked_div(liquidation_divisor)", positive)
        self.assertIn("checked_mul(protocol_fee_bps)?", negative)
        self.assertIn("user_weight % total_weight != 0", negative)
        self.assertIn("ceil_div(borrower_debt, liquidation_divisor)", negative)
        self.assertIn("attack_class: rounding-direction-attack", detector)


if __name__ == "__main__":
    unittest.main()
