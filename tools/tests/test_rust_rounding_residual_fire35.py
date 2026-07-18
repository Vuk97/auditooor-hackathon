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
DETECTOR = REPO_ROOT / "detectors" / "rust_wave1" / "rounding_residual_fire35.py"
DETECTOR_ID = "rounding_residual_fire35"
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


class RustRoundingResidualFire35Tests(unittest.TestCase):
    def test_detector_compiles_and_declares_provenance(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        detector = DETECTOR.read_text(encoding="utf-8")
        self.assertIn('DETECTOR_ID = "rust_wave1.rounding_residual_fire35"', detector)
        self.assertIn("verification_tier: tier-3-synthetic-taxonomy-anchored", detector)
        self.assertIn("attack_class: rounding-direction-attack", detector)
        self.assertIn("post_priorities_rust.md", detector)
        self.assertIn("rounding_div_before_mul_fire34.py", detector)
        self.assertIn("go-rounding-residual-fire34.py", detector)
        self.assertIn("NOT_SUBMIT_READY", detector)

    def test_positive_fixture_fires_on_residual_sinks(self) -> None:
        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 4, log_text)
        self.assertIn("distribute_fee_remainder_to_first_participant", log_text)
        self.assertIn("credit_reward_residual_to_last_receiver", log_text)
        self.assertIn("send_checked_dust_to_module_account", log_text)
        self.assertIn("pay_leftover_to_attacker_sink", log_text)
        self.assertIn("index zero or a first-participant path", log_text)
        self.assertIn("last participant path", log_text)
        self.assertIn("module, protocol, treasury, collector, or dust state", log_text)
        self.assertIn("attacker-controlled payout path", log_text)
        self.assertIn("rounding-direction-attack", log_text)

    def test_negative_fixture_is_silent_on_safe_residual_handling(self) -> None:
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

        self.assertIn("let remainder = total_fee % participants.len() as u128;", positive)
        self.assertIn("receivers.last_mut().unwrap().paid += residual;", positive)
        self.assertIn("let dust = total_fee.checked_rem(collector_count)?;", positive)
        self.assertIn("self.credit(caller, leftover);", positive)

        self.assertIn("if remainder != 0", negative)
        self.assertIn("self.rounding_carry += residual", negative)
        self.assertIn("self.refunds.insert(payer, remainder)", negative)
        self.assertIn("if dust > MAX_DUST", negative)
        self.assertIn("carry residuals forward", detector)
        self.assertIn("refund the payer", detector)


if __name__ == "__main__":
    unittest.main()
