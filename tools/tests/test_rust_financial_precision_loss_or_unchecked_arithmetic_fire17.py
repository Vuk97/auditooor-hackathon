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
DETECTOR = (
    REPO_ROOT
    / "detectors"
    / "rust_wave1"
    / "financial_precision_loss_or_unchecked_arithmetic_fire17.py"
)
FIXTURES = REPO_ROOT / "detectors" / "rust_wave1" / "test_fixtures"
DETECTOR_ID = "financial_precision_loss_or_unchecked_arithmetic_fire17"
POSITIVE = FIXTURES / f"{DETECTOR_ID}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR_ID}_negative.rs"
DOUBLE_SUBTRACTION_CONFIRMED = (
    FIXTURES / "double_subtraction_accounting_fire10_positive.rs"
)
GENERIC_DIVISION_CONFIRMED = FIXTURES / "division_before_multiplication_positive.rs"
_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(prefix=".rust_fire17_fin_math_", suffix=".log") as tmp:
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
                tmp.name,
            ],
            cwd=REPO_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stdout)
        text = Path(tmp.name).read_text(encoding="utf-8", errors="ignore")
    match = _HIT_RE.search(text)
    return (int(match.group(1)) if match else 0, text)


class RustFinancialPrecisionLossOrUncheckedArithmeticFire17Test(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

    def test_positive_fixture_fires_on_three_financial_arithmetic_shapes(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 3, log_text)
        self.assertIn("division before multiplication", log_text)
        self.assertIn("unchecked or wrapping arithmetic", log_text)
        self.assertIn("repeated debit", log_text)

    def test_negative_fixture_is_silent_on_checked_financial_math(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_closes_confirmed_fund_loss_double_subtraction_miss(self) -> None:
        hits, log_text = _run_fixture(DOUBLE_SUBTRACTION_CONFIRMED)
        self.assertGreaterEqual(hits, 2, log_text)
        self.assertIn("double", log_text.lower())
        self.assertIn("repeated debit", log_text)

    def test_generic_division_fixture_stays_silent_without_financial_context(self) -> None:
        hits, log_text = _run_fixture(GENERIC_DIVISION_CONFIRMED)
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
