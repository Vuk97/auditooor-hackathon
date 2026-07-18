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
DETECTOR_ID = "callback_hook_asset_release_fire13"
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
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stderr or proc.stdout)
        text = log_path.read_text(encoding="utf-8", errors="ignore")
        match = _HIT_RE.search(text)
        return (int(match.group(1)) if match else 0, text)
    finally:
        log_path.unlink(missing_ok=True)


class RustCallbackHookAssetReleaseFire13Tests(unittest.TestCase):
    def test_positive_fixture_fires(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "callback_hook_asset_release_fire13_positive.rs"
        )
        self.assertEqual(hits, 1, log_text)
        self.assertIn("hook or callback", log_text)

    def test_negative_fixture_is_silent(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "callback_hook_asset_release_fire13_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)

    def test_held_out_rental_asset_release_miss_fires(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "attacker_steals_actively_rented_nft_and_freezes_escrow_positive.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)

    def test_held_out_partial_unwrap_fee_miss_fires(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "erc721wrapper_partial_unwrap_steals_fees_positive.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)

    def test_held_out_rental_guarded_negative_is_silent(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "attacker_steals_actively_rented_nft_and_freezes_escrow_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)

    def test_held_out_partial_unwrap_negative_is_silent(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "erc721wrapper_partial_unwrap_steals_fees_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)

    def test_flashloan_no_premium_miss_fires(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "flashloan_no_premium_charged_positive.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("never accounts for a premium or fee", log_text)

    def test_flashloan_fee_charged_negative_is_silent(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "flashloan_no_premium_charged_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)

    def test_flashloan_floor_rounded_premium_miss_fires(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "flashloan_premium_rounded_down_positive.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("floor rounding", log_text)

    def test_flashloan_ceil_rounded_premium_negative_is_silent(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "flashloan_premium_rounded_down_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)

    def test_flashloan_callback_before_repayment_miss_fires(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "flashloan_callback_state_mutation_before_repay_positive.rs"
        )
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("flash callback", log_text)

    def test_flashloan_callback_repayment_negative_is_silent(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "flashloan_callback_state_mutation_before_repay_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
