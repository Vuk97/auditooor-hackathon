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
DETECTOR_ID = "rust_oracle_single_source_spot_price_no_twap"
_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> int:
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
        return int(match.group(1)) if match else 0
    finally:
        log_path.unlink(missing_ok=True)


class RustOracleSingleSourceSpotPriceNoTwapTests(unittest.TestCase):
    def test_positive_fixture_fires(self) -> None:
        hits = _run_fixture(
            FIXTURES / "rust_oracle_single_source_spot_price_no_twap_positive.rs"
        )
        self.assertGreaterEqual(hits, 1)

    def test_amm_get_amounts_in_used_as_oracle_fires(self) -> None:
        hits = _run_fixture(
            FIXTURES / "r94_loop_amm_getAmountsIn_used_as_oracle_positive.rs"
        )
        self.assertGreaterEqual(hits, 1)

    def test_asymmetric_liquidity_flat_oracle_fires(self) -> None:
        hits = _run_fixture(
            FIXTURES / "r94_loop_asymmetric_liquidity_flat_oracle_positive.rs"
        )
        self.assertGreaterEqual(hits, 1)

    def test_chainlink_lookback_ignored_fires(self) -> None:
        hits = _run_fixture(
            FIXTURES / "r94_loop_chainlink_getTokenPrice_lookback_param_ignored_positive.rs"
        )
        self.assertGreaterEqual(hits, 1)

    def test_negative_fixture_is_silent(self) -> None:
        hits = _run_fixture(
            FIXTURES / "rust_oracle_single_source_spot_price_no_twap_negative.rs"
        )
        self.assertEqual(hits, 0)

    def test_amm_quote_with_trusted_oracle_negative_is_silent(self) -> None:
        hits = _run_fixture(
            FIXTURES / "r94_loop_amm_getAmountsIn_used_as_oracle_negative.rs"
        )
        self.assertEqual(hits, 0)

    def test_asymmetric_liquidity_with_spread_negative_is_silent(self) -> None:
        hits = _run_fixture(
            FIXTURES / "r94_loop_asymmetric_liquidity_flat_oracle_negative.rs"
        )
        self.assertEqual(hits, 0)

    def test_chainlink_lookback_twap_negative_is_silent(self) -> None:
        hits = _run_fixture(
            FIXTURES / "r94_loop_chainlink_getTokenPrice_lookback_param_ignored_negative.rs"
        )
        self.assertEqual(hits, 0)


if __name__ == "__main__":
    unittest.main()
