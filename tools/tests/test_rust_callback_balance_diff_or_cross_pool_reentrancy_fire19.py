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
DETECTOR = REPO_ROOT / "detectors" / "rust_wave1" / "callback_balance_diff_or_cross_pool_reentrancy_fire19.py"
TEST_FILE = Path(__file__).resolve()
DETECTOR_ID = "callback_balance_diff_or_cross_pool_reentrancy_fire19"
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


class RustCallbackBalanceDiffOrCrossPoolReentrancyFire19Tests(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        py_compile.compile(str(TEST_FILE), doraise=True)

    def test_positive_fixture_fires_on_three_reentrancy_shapes(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "callback_balance_diff_or_cross_pool_reentrancy_fire19_positive.rs"
        )
        self.assertGreaterEqual(hits, 3, log_text)
        self.assertIn("balance-diff amount inference", log_text)
        self.assertIn("pool-scoped reentrancy guard", log_text)
        self.assertIn("liquidation or debt takeover", log_text)

    def test_negative_fixture_is_silent_on_guarded_or_finalized_paths(self) -> None:
        hits, log_text = _run_fixture(
            FIXTURES / "callback_balance_diff_or_cross_pool_reentrancy_fire19_negative.rs"
        )
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_r94_reentrancy_misses_are_recalled(self) -> None:
        held_out = [
            "r94_loop_erc777_balance_diff_reentrancy_spoof_amount_positive.rs",
            "r94_loop_hook_bypasses_reentrancy_guard_cross_pool_positive.rs",
            "r94_loop_liquidation_reentrancy_takeover_positive.rs",
        ]
        for fixture in held_out:
            with self.subTest(fixture=fixture):
                hits, log_text = _run_fixture(FIXTURES / fixture)
                self.assertGreaterEqual(hits, 1, log_text)

    def test_existing_clean_controls_stay_silent(self) -> None:
        controls = [
            "r94_loop_erc777_balance_diff_reentrancy_spoof_amount_negative.rs",
            "r94_loop_hook_bypasses_reentrancy_guard_cross_pool_negative.rs",
            "r94_loop_liquidation_reentrancy_takeover_negative.rs",
        ]
        for fixture in controls:
            with self.subTest(fixture=fixture):
                hits, log_text = _run_fixture(FIXTURES / fixture)
                self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
