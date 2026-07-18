from __future__ import annotations

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
DETECTOR_ID = "financial_precision_loss_div_before_mul_or_float_cast"
_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> int:
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
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stderr or proc.stdout)
        text = log_path.read_text(encoding="utf-8", errors="ignore")
        match = _HIT_RE.search(text)
        return int(match.group(1)) if match else 0
    finally:
        log_path.unlink(missing_ok=True)


class RustWave1FinancialPrecisionLossTests(unittest.TestCase):
    def test_positive_fixture_fires(self) -> None:
        hits = _run_fixture(
            FIXTURES / "financial_precision_loss_div_before_mul_or_float_cast_positive.rs"
        )
        self.assertGreaterEqual(
            hits,
            4,
            "expected one hit per bad fee/price/sqrt function in the positive fixture",
        )

    def test_negative_fixture_is_silent(self) -> None:
        hits = _run_fixture(
            FIXTURES / "financial_precision_loss_div_before_mul_or_float_cast_negative.rs"
        )
        self.assertEqual(
            hits,
            0,
            "clean financial math and non-financial float math should stay silent",
        )


if __name__ == "__main__":
    unittest.main()
