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
DETECTOR_ID = "rounding_direction_loss_fire13"
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


class RustRoundingDirectionLossFire13Tests(unittest.TestCase):
    def test_positive_fixture_fires_on_all_confirmed_shapes(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "rounding_direction_loss_fire13_positive.rs"
        )
        self.assertGreaterEqual(hits, 4, log_text)
        self.assertIn("unguarded 64-reserve bitmap shift", log_text)
        self.assertIn("division-before-multiplication value movement", log_text)
        self.assertIn("position swap accepts caller-controlled", log_text)
        self.assertIn("caller-dependent rounding residual payout", log_text)

    def test_negative_fixture_is_silent_on_guards_and_dust_handling(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "rounding_direction_loss_fire13_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_held_out_recall_beyond_own_fixture(self) -> None:
        held_out = [
            "bitmap_64_reserve_off_by_one_positive.rs",
            "attacker_self_sandwiches_swap_in_open_close_position_positive.rs",
            "rust_share_math_division_before_multiplication_value_loss_positive.rs",
            "incorrect_royalty_distribution_truncation_siphon_positive.rs",
        ]
        for name in held_out:
            with self.subTest(fixture=name):
                hits, log_text = _run_fixture(FIXTURES / name)
                self.assertGreaterEqual(hits, 1, log_text)

    def test_existing_clean_controls_stay_silent(self) -> None:
        clean_controls = [
            "bitmap_64_reserve_off_by_one_negative.rs",
            "attacker_self_sandwiches_swap_in_open_close_position_negative.rs",
            "rust_share_math_division_before_multiplication_value_loss_negative.rs",
            "incorrect_royalty_distribution_truncation_siphon_negative.rs",
        ]
        for name in clean_controls:
            with self.subTest(fixture=name):
                hits, log_text = _run_fixture(FIXTURES / name)
                self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
