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
DETECTOR = REPO_ROOT / "detectors" / "rust_wave1" / "rounding_direction_fee_fire36.py"
DETECTOR_ID = "rounding_direction_fee_fire36"
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
            timeout=90,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stderr or proc.stdout)
        text = log_path.read_text(encoding="utf-8", errors="ignore")
        match = _HIT_RE.search(text)
        return int(match.group(1)) if match else 0, text
    finally:
        log_path.unlink(missing_ok=True)


class RustRoundingDirectionFeeFire36Tests(unittest.TestCase):
    def test_detector_compiles_and_declares_provenance(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        detector = DETECTOR.read_text(encoding="utf-8")
        self.assertIn('DETECTOR_ID = "rust_wave1.rounding_direction_fee_fire36"', detector)
        self.assertIn("verification_tier: tier-3-synthetic-taxonomy-anchored", detector)
        self.assertIn("attack_class: rounding-direction-attack", detector)
        self.assertIn("post_priorities_rust.md", detector)
        self.assertIn("fx-aave-liquidation-fee-rounding-direction.yaml", detector)
        self.assertIn("rounding_residual_fire35.py", detector)
        self.assertIn("go-rounding-fee-direction-fire33.py", detector)
        self.assertIn("NOT_SUBMIT_READY", detector)

    def test_positive_fixture_fires_on_wrong_direction_value_sinks(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 4, log_text)
        self.assertIn("settle_floor_fee_undercharges_protocol", log_text)
        self.assertIn("claim_ceil_reward_overpays_caller", log_text)
        self.assertIn("liquidate_floor_collateral_check", log_text)
        self.assertIn("mint_truncated_shares_to_recipient", log_text)
        self.assertIn("floor-rounded amount is pulled", log_text)
        self.assertIn("ceil-rounded amount leaves protocol custody", log_text)
        self.assertIn("health, debt, margin, or collateral decision", log_text)
        self.assertIn("inserted into `share_ledger` accounting", log_text)
        self.assertIn("rounding-direction-attack", log_text)

    def test_negative_fixture_is_silent_on_guards_and_safe_boundaries(self) -> None:
        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_false_positive_boundaries_are_locked(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        negative = NEGATIVE.read_text(encoding="utf-8")
        detector = DETECTOR.read_text(encoding="utf-8")
        for path in (DETECTOR, POSITIVE, NEGATIVE, Path(__file__)):
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("\u2014", text)
            self.assertNotIn("\u2013", text)

        self.assertIn("checked_mul(fee_bps)?.checked_div(10_000)?", positive)
        self.assertIn("accrued_rewards.div_ceil(reward_scale)", positive)
        self.assertIn("checked_div(1_000_000)?", positive)
        self.assertIn("checked_div(total_assets)? as u64", positive)

        self.assertIn("if scaled_fee % 10_000 != 0", negative)
        self.assertIn("self.rounding_carry += residual", negative)
        self.assertIn("self.refunds.insert(payer, remainder)", negative)
        self.assertIn("let protocol_fee = mul_div", negative)

        self.assertIn("state writeback or external settlement", detector)
        self.assertIn("full precision math", detector)


if __name__ == "__main__":
    unittest.main()
