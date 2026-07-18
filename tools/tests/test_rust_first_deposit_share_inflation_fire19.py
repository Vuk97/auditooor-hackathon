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
DETECTOR = REPO_ROOT / "detectors" / "rust_wave1" / "first_deposit_share_inflation_fire19.py"
DETECTOR_ID = "first_deposit_share_inflation_fire19"
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


class RustFirstDepositShareInflationFire19Tests(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_positive_fixture_fires(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "first_deposit_share_inflation_fire19_positive.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("first-depositor-inflation candidate", log_text)

    def test_negative_fixture_is_silent(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "first_deposit_share_inflation_fire19_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)

    def test_named_fire18_misses_are_recalled(self) -> None:
        held_out = [
            "erc4626_deposit_vs_mint_asymmetric_on_first_deposit_positive.rs",
            "erc4626_inflation_attack_positive.rs",
            "erc4626_rounding_direction_inconsistent_between_convert_preview_positive.rs",
        ]
        for fixture in held_out:
            with self.subTest(fixture=fixture):
                hits, log_text = _run_fixture(FIXTURES / fixture)
                self.assertGreaterEqual(hits, 1, log_text)

    def test_clean_controls_stay_silent(self) -> None:
        clean_controls = [
            "first_deposit_share_inflation_fire19_negative.rs",
            "erc4626_deposit_vs_mint_asymmetric_on_first_deposit_negative.rs",
            "erc4626_inflation_attack_negative.rs",
            "erc4626_rounding_direction_inconsistent_between_convert_preview_negative.rs",
            "division_before_multiplication_positive.rs",
        ]
        for fixture in clean_controls:
            with self.subTest(fixture=fixture):
                hits, log_text = _run_fixture(FIXTURES / fixture)
                self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
