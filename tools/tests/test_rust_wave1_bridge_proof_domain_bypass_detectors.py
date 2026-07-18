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


def _run_fixture(detector_id: str, fixture_name: str) -> int:
    hit_re = re.compile(rf"^=== {detector_id}\s+\((\d+) hits\)", re.MULTILINE)
    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
        log_path = Path(tf.name)
    try:
        proc = subprocess.run(
            [
                sys.executable,
                str(RUST_DETECT),
                str(FIXTURES),
                "--only",
                detector_id,
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
        return int(match.group(1)) if match else 0
    finally:
        log_path.unlink(missing_ok=True)


class RustWave1BridgeProofDomainBypassTests(unittest.TestCase):
    def test_signal_hash_value_not_bound_positive_fires(self) -> None:
        hits = _run_fixture(
            "r94_loop_bridge_signal_hash_value_not_bound",
            "r94_loop_bridge_signal_hash_value_not_bound_positive.rs",
        )
        self.assertGreaterEqual(hits, 1)

    def test_signal_hash_value_not_bound_clean_is_silent(self) -> None:
        hits = _run_fixture(
            "r94_loop_bridge_signal_hash_value_not_bound",
            "r94_loop_bridge_signal_hash_value_not_bound_negative.rs",
        )
        self.assertEqual(hits, 0)

    def test_token_mint_not_verified_positive_fires(self) -> None:
        hits = _run_fixture(
            "r94_loop_bridge_token_mint_not_verified",
            "r94_loop_bridge_token_mint_not_verified_positive.rs",
        )
        self.assertGreaterEqual(hits, 1)

    def test_token_mint_not_verified_clean_is_silent(self) -> None:
        hits = _run_fixture(
            "r94_loop_bridge_token_mint_not_verified",
            "r94_loop_bridge_token_mint_not_verified_negative.rs",
        )
        self.assertEqual(hits, 0)

    def test_recipient_non_20_byte_positive_fires(self) -> None:
        hits = _run_fixture(
            "r94_loop_bridge_recipient_non_20_byte_silent_burn",
            "r94_loop_bridge_recipient_non_20_byte_silent_burn_positive.rs",
        )
        self.assertGreaterEqual(hits, 1)

    def test_recipient_non_20_byte_clean_is_silent(self) -> None:
        hits = _run_fixture(
            "r94_loop_bridge_recipient_non_20_byte_silent_burn",
            "r94_loop_bridge_recipient_non_20_byte_silent_burn_negative.rs",
        )
        self.assertEqual(hits, 0)


if __name__ == "__main__":
    unittest.main()
