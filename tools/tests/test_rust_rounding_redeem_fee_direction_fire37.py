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
DETECTOR = REPO_ROOT / "detectors" / "rust_wave1" / "rounding_redeem_fee_direction_fire37.py"
DETECTOR_ID = "rounding_redeem_fee_direction_fire37"
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


class RustRoundingRedeemFeeDirectionFire37Tests(unittest.TestCase):
    def test_detector_compiles_and_declares_provenance(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        detector = DETECTOR.read_text(encoding="utf-8")
        self.assertIn(
            'DETECTOR_ID = "rust_wave1.rounding_redeem_fee_direction_fire37"',
            detector,
        )
        self.assertIn("verification_tier: tier-3-synthetic-taxonomy-anchored", detector)
        self.assertIn("attack_class: rounding-direction-attack", detector)
        self.assertIn("post_priorities_rust.md", detector)
        self.assertIn("erc4626-redeem-rounding-favors-caller.yaml", detector)
        self.assertIn("ec-rounding-withdraw-favors-user.yaml", detector)
        self.assertIn("rounding_direction_fee_fire36.py", detector)
        self.assertIn("rounding_residual_fire35.py", detector)
        self.assertIn("NOT_SUBMIT_READY", detector)

    def test_positive_fixture_fires_on_redeem_fee_rounding_sinks(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 4, log_text)
        self.assertIn("withdraw_floor_shares_to_burn", log_text)
        self.assertIn("redeem_fee_after_truncated_assets", log_text)
        self.assertIn("redeem_min_out_checks_gross_before_fee", log_text)
        self.assertIn("burn_ceil_assets_out_drains_reserves", log_text)
        self.assertIn("shares_to_burn is floor-rounded", log_text)
        self.assertIn("subtracted into `net_assets`", log_text)
        self.assertIn("checked against rounded gross `gross_assets`", log_text)
        self.assertIn("assets_out is ceil-rounded", log_text)
        self.assertIn("rounding-direction-attack", log_text)

    def test_negative_fixture_is_silent_on_safe_rounding_boundaries(self) -> None:
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

        self.assertIn("checked_mul(total_shares)?.checked_div(total_assets)?", positive)
        self.assertIn("gross_assets.checked_mul(fee_bps)?.checked_div(10_000)?", positive)
        self.assertIn("if gross_assets < min_assets", positive)
        self.assertIn("let assets_out = shares.div_ceil(exchange_rate);", positive)

        self.assertIn("div_ceil(total_assets)", negative)
        self.assertIn("if scaled_assets % total_shares != 0", negative)
        self.assertIn("if net_assets < min_assets", negative)
        self.assertIn("let assets_out = shares.checked_mul(total_assets)?.checked_div(total_shares)?", negative)
        self.assertIn("self.rounding_carry += remainder", negative)

        self.assertIn("check min-out against the final net amount", detector)
        self.assertIn("source-review candidates only", detector)


if __name__ == "__main__":
    unittest.main()
