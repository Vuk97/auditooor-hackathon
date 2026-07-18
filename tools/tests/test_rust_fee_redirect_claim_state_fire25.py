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
DETECTOR = REPO_ROOT / "detectors" / "rust_wave1" / "fee_redirect_claim_state_fire25.py"
DETECTOR_ID = "fee_redirect_claim_state_fire25"
POSITIVE = FIXTURES / f"{DETECTOR_ID}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR_ID}_negative.rs"

_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(prefix=".rust_fee_redirect_fire25_", suffix=".log") as tmp:
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
    return int(match.group(1)) if match else 0, text


class RustFeeRedirectClaimStateFire25Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_positive_fixture_fires_on_fee_claim_refund_and_harvest_shapes(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 4, log_text)
        self.assertIn("post-fee", log_text)
        self.assertIn("caller-supplied sink", log_text)
        self.assertIn("without consumed or claimed state", log_text)
        self.assertIn("zero minimum output", log_text)

    def test_negative_fixture_binds_recipient_marks_consumed_and_is_silent(self) -> None:
        negative_text = NEGATIVE.read_text(encoding="utf-8")
        self.assertIn("assert_eq!(fee_recipient, self.config.fee_recipient);", negative_text)
        self.assertIn("self.claimed.insert(claim_id, true);", negative_text)
        self.assertLess(
            negative_text.index("self.claimed.insert(claim_id, true);"),
            negative_text.index("token.transfer(fee_recipient, fee_amount);"),
        )
        self.assertLess(
            negative_text.index("self.claimed.insert(refund_id, true);"),
            negative_text.index("token.transfer(fee_recipient, refund_amount);"),
        )

        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_source_seed_fixtures_are_recalled(self) -> None:
        seed_fixtures = [
            "r94_loop_tax_refund_post_fee_amount_positive.rs",
            "r94_loop_withdraw_fee_no_claimed_flag_positive.rs",
            "strategypassivemanageruniswap_fee_harvest_uses_amountoutminimum_0_positive.rs",
        ]
        for fixture in seed_fixtures:
            with self.subTest(fixture=fixture):
                hits, log_text = _run_fixture(FIXTURES / fixture)
                self.assertGreaterEqual(hits, 1, log_text)

    def test_clean_source_seed_controls_stay_silent(self) -> None:
        clean_fixtures = [
            "r94_loop_tax_refund_post_fee_amount_negative.rs",
            "strategypassivemanageruniswap_fee_harvest_uses_amountoutminimum_0_negative.rs",
        ]
        for fixture in clean_fixtures:
            with self.subTest(fixture=fixture):
                hits, log_text = _run_fixture(FIXTURES / fixture)
                self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
