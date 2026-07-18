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
    REPO_ROOT / "detectors" / "rust_wave1" /
    "div_before_mul_or_unchecked_value_math_fire19.py"
)
DETECTOR_ID = "div_before_mul_or_unchecked_value_math_fire19"
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


class RustDivBeforeMulOrUncheckedValueMathFire19Tests(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        py_compile.compile(__file__, doraise=True)

    def test_positive_fixture_fires_on_three_value_math_shapes(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "div_before_mul_or_unchecked_value_math_fire19_positive.rs"
        )
        self.assertGreaterEqual(hits, 4, log_text)
        self.assertIn("division before multiplication", log_text)
        self.assertIn("unchecked arithmetic", log_text)
        self.assertIn("minimum-output protection", log_text)

    def test_negative_fixture_is_silent_on_checked_math_and_min_out(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "div_before_mul_or_unchecked_value_math_fire19_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_missing_slippage_recall_fixture_is_detected(self) -> None:
        hits, log_text = _run_fixture(FIXTURES / "missing_slippage_in_swap_call_positive.rs")
        self.assertGreaterEqual(hits, 2, log_text)

    def test_confirmed_unchecked_contract_math_recall_fixture_is_detected(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "integer_overflow_unchecked_block_positive.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)


if __name__ == "__main__":
    unittest.main()
