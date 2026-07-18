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
DETECTOR = REPO_ROOT / "detectors" / "rust_wave1" / "rounding_user_input_fire26.py"
DETECTOR_ID = "rounding_user_input_fire26"
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


class RustRoundingUserInputFire26Tests(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

    def test_positive_fixture_fires_on_three_user_input_value_math_shapes(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "rounding_user_input_fire26_positive.rs"
        )
        self.assertEqual(hits, 3, log_text)
        self.assertIn("division before multiplication", log_text)
        self.assertIn("user-controlled denominator", log_text)
        self.assertIn("intermediate overflow-prone fee math", log_text)

    def test_negative_fixture_is_silent_on_guards_and_safe_mul_div(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "rounding_user_input_fire26_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)

    def test_source_backed_r94_replay_samples_are_recalled(self) -> None:
        source_backed = [
            "r94_loop_division_by_zero_on_user_input_positive.rs",
            "r94_loop_fee_config_intermediate_overflow_vault_drain_positive.rs",
        ]
        for fixture in source_backed:
            with self.subTest(fixture=fixture):
                hits, log_text = _run_fixture(FIXTURES / fixture)
                self.assertGreaterEqual(hits, 1, log_text)

    def test_generic_division_before_multiplication_stays_silent_without_value_context(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "division_before_multiplication_positive.rs"
        )
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
