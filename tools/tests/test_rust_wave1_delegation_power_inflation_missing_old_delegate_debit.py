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
DETECTOR = "delegation_power_inflation_missing_old_delegate_debit"


def _run_fixture(fixture_name: str) -> tuple[int, str]:
    hit_re = re.compile(rf"^=== {DETECTOR}\s+\((\d+) hits\)", re.MULTILINE)
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
        log_path = Path(tf.name)
    try:
        proc = subprocess.run(
            [
                sys.executable,
                str(RUST_DETECT),
                str(FIXTURES),
                "--only",
                DETECTOR,
                "--file",
                str(FIXTURES / fixture_name),
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
        match = hit_re.search(text)
        return (int(match.group(1)) if match else 0), text
    finally:
        log_path.unlink(missing_ok=True)


class RustWave1DelegationPowerInflationMissingOldDelegateDebitTests(unittest.TestCase):
    def test_positive_credits_new_delegate_without_old_delegate_debit(self) -> None:
        hits, log_text = _run_fixture(
            "delegation_power_inflation_missing_old_delegate_debit_positive.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("delegation-power-inflation", log_text)

    def test_clean_debits_old_delegate_before_crediting_new_delegate(self) -> None:
        hits, log_text = _run_fixture(
            "delegation_power_inflation_missing_old_delegate_debit_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
