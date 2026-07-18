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
    "liquidation_health_or_collateral_rounding_lag_fire20.py"
)
DETECTOR_ID = "liquidation_health_or_collateral_rounding_lag_fire20"
_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)

SEED_POSITIVES = (
    "liquidation_seaport_pair_expects_fake_clearinghouse_nft_settlementtoken_positive.rs",
    "liquidator_rounds_up_collateral_seize_rounds_down_debt_repay_positive.rs",
    "liquidator_seizes_collateral_from_solvent_borrower_due_to_ema_lag_positive.rs",
    "r94_loop_liquidation_ema_lag_seizes_solvent_borrower_positive.rs",
    "r94_loop_liquidation_rounding_up_collateral_down_debt_positive.rs",
)

SEED_NEGATIVES = (
    "liquidation_seaport_pair_expects_fake_clearinghouse_nft_settlementtoken_negative.rs",
    "liquidator_rounds_up_collateral_seize_rounds_down_debt_repay_negative.rs",
    "liquidator_seizes_collateral_from_solvent_borrower_due_to_ema_lag_negative.rs",
    "r94_loop_liquidation_ema_lag_seizes_solvent_borrower_negative.rs",
    "r94_loop_liquidation_rounding_up_collateral_down_debt_negative.rs",
)


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(prefix=".rust_liq_fire20_", suffix=".log") as tmp:
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
            timeout=60,
        )
        if proc.returncode != 0:
            raise AssertionError(proc.stdout)
        log_text = Path(tmp.name).read_text(encoding="utf-8", errors="ignore")

    match = _HIT_RE.search(log_text)
    return int(match.group(1)) if match else 0, log_text


class RustLiquidationHealthOrCollateralRoundingLagFire20Tests(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_positive_fixture_fires_on_three_liquidation_trigger_shapes(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "liquidation_health_or_collateral_rounding_lag_fire20_positive.rs"
        )
        self.assertEqual(hits, 3, log_text)
        self.assertIn("extra fake NFTs", log_text)
        self.assertIn("collateral seized rounds up", log_text)
        self.assertIn("EMA or smoothed health state", log_text)
        self.assertIn("liquidation-trigger-poison", log_text)

    def test_negative_fixture_refreshes_and_rounds_conservatively(self) -> None:
        text = (
            FIXTURES / "liquidation_health_or_collateral_rounding_lag_fire20_negative.rs"
        ).read_text(encoding="utf-8")
        self.assertIn("authorized_clearing_nfts.contains_key", text)
        self.assertIn("debt_to_repay = ceil_div", text)
        self.assertIn("refresh_health_state", text)

        hits, log_text = _run_fixture(
            FIXTURES / "liquidation_health_or_collateral_rounding_lag_fire20_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_seed_positive_misses_now_fire(self) -> None:
        for fixture_name in SEED_POSITIVES:
            with self.subTest(fixture=fixture_name):
                hits, log_text = _run_fixture(FIXTURES / fixture_name)
                self.assertGreaterEqual(hits, 1, log_text)
                self.assertIn("liquidation-trigger-poison", log_text)

    def test_confirmed_seed_clean_fixtures_stay_silent(self) -> None:
        for fixture_name in SEED_NEGATIVES:
            with self.subTest(fixture=fixture_name):
                hits, log_text = _run_fixture(FIXTURES / fixture_name)
                self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
