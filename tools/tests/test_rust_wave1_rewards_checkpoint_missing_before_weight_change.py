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
DETECTOR = "rust_rewards_checkpoint_missing_before_weight_change"
DETECTOR_PATH = REPO_ROOT / "detectors" / "rust_wave1" / f"{DETECTOR}.py"
POSITIVE = FIXTURES / f"{DETECTOR}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR}_negative.rs"
RECURSIVE_POSITIVE = (
    FIXTURES / "incentivizederc20_recursive_liquidity_reward_steal_positive.rs"
)
RECURSIVE_NEGATIVE = (
    FIXTURES / "incentivizederc20_recursive_liquidity_reward_steal_negative.rs"
)
BOOST_POSITIVE = (
    FIXTURES / "r94_loop_boost_mutation_without_settling_rewards_positive.rs"
)
BOOST_POST_SETTLE_POSITIVE = (
    FIXTURES
    / "r94_loop_boost_mutation_without_settling_rewards_positive_post_settle.rs"
)
BOOST_NEGATIVE = (
    FIXTURES / "r94_loop_boost_mutation_without_settling_rewards_negative.rs"
)
BOOST_POST_SETTLE_NEGATIVE = (
    FIXTURES
    / "r94_loop_boost_mutation_without_settling_rewards_negative_post_settle.rs"
)
_HIT_RE = re.compile(rf"^=== {DETECTOR}\s+\((\d+) hits\)", re.MULTILINE)


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
                DETECTOR,
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
        return (int(match.group(1)) if match else 0), text
    finally:
        log_path.unlink(missing_ok=True)


class RustRewardsCheckpointMissingBeforeWeightChangeTests(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)

    def test_positive_mutates_distribution_weight_before_checkpoint(self) -> None:
        text = POSITIVE.read_text(encoding="utf-8")
        self.assertIn("self.delegations.insert", text)
        self.assertIn("self.total_weight += stake", text)
        self.assertLess(
            text.index("self.delegations.insert"),
            text.index("self.sync_reward_accumulator"),
        )

        hits, log_text = _run_fixture(POSITIVE)
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("changes reward distribution weight before", log_text)
        self.assertIn("rewards-distribution-skew", log_text)

    def test_negative_checkpoints_before_distribution_weight_mutation(self) -> None:
        text = NEGATIVE.read_text(encoding="utf-8")
        self.assertIn("self.sync_reward_accumulator", text)
        self.assertIn("self.delegations.insert", text)
        self.assertLess(
            text.index("self.sync_reward_accumulator"),
            text.index("self.delegations.insert"),
        )

        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_recursive_liquidity_reward_miss_now_fires(self) -> None:
        text = RECURSIVE_POSITIVE.read_text(encoding="utf-8")
        self.assertIn("fn deposit_collateral", text)
        self.assertIn("position.balance * pool.reward_per_token_stored", text)

        hits, log_text = _run_fixture(RECURSIVE_POSITIVE)
        self.assertGreaterEqual(hits, 1, log_text)
        self.assertIn("source-principal", log_text)
        self.assertIn("rewards-distribution-skew", log_text)

    def test_recursive_liquidity_guarded_fixture_is_silent(self) -> None:
        text = RECURSIVE_NEGATIVE.read_text(encoding="utf-8")
        self.assertIn("source_position", text)
        self.assertIn("is_yield_bearing", text)

        hits, log_text = _run_fixture(RECURSIVE_NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_boost_mutation_misses_now_fire(self) -> None:
        for fixture in (BOOST_POSITIVE, BOOST_POST_SETTLE_POSITIVE):
            with self.subTest(fixture=fixture.name):
                hits, log_text = _run_fixture(fixture)
                self.assertGreaterEqual(hits, 1, log_text)
                self.assertIn("changes reward distribution weight before", log_text)
                self.assertIn("rewards-distribution-skew", log_text)

    def test_boost_mutation_with_pre_settlement_is_silent(self) -> None:
        for fixture in (BOOST_NEGATIVE, BOOST_POST_SETTLE_NEGATIVE):
            with self.subTest(fixture=fixture.name):
                hits, log_text = _run_fixture(fixture)
                self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
