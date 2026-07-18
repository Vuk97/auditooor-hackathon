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

BOOST_DETECTOR = "r94_loop_boost_mutation_without_settling_rewards"
CACHED_INDEX_DETECTOR = "r94_loop_reward_cached_vs_current_index_drift"


def _run_fixture(detector_id: str, fixture_name: str) -> int:
    hit_re = re.compile(rf"^=== {re.escape(detector_id)}\s+\((\d+) hits\)", re.MULTILINE)
    fixture = FIXTURES / fixture_name
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
        match = hit_re.search(text)
        return int(match.group(1)) if match else 0
    finally:
        log_path.unlink(missing_ok=True)


class RustWave1RewardsDistributionSkewTests(unittest.TestCase):
    def test_boost_mutation_positive_fires(self) -> None:
        hits = _run_fixture(
            BOOST_DETECTOR,
            "r94_loop_boost_mutation_without_settling_rewards_positive.rs",
        )
        self.assertEqual(hits, 1)

    def test_boost_mutation_negative_is_silent(self) -> None:
        hits = _run_fixture(
            BOOST_DETECTOR,
            "r94_loop_boost_mutation_without_settling_rewards_negative.rs",
        )
        self.assertEqual(hits, 0)

    def test_cached_index_positive_fires(self) -> None:
        hits = _run_fixture(
            CACHED_INDEX_DETECTOR,
            "r94_loop_reward_cached_vs_current_index_drift_positive.rs",
        )
        self.assertEqual(hits, 1)

    def test_cached_index_negative_is_silent(self) -> None:
        hits = _run_fixture(
            CACHED_INDEX_DETECTOR,
            "r94_loop_reward_cached_vs_current_index_drift_negative.rs",
        )
        self.assertEqual(hits, 0)


if __name__ == "__main__":
    unittest.main()
