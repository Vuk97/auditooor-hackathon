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
DETECTOR = "rewards_checkpoint_or_denominator_fire16"
DETECTOR_PATH = REPO_ROOT / "detectors" / "rust_wave1" / f"{DETECTOR}.py"
POSITIVE = FIXTURES / f"{DETECTOR}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR}_negative.rs"

SEED_POSITIVES = (
    "r94_loop_checkpoint_same_block_ambiguity_positive.rs",
    "r94_loop_draw_reward_wrong_denominator_positive.rs",
    "r94_loop_gauge_reward_stake_withdraw_burst_game_positive.rs",
)
SEED_NEGATIVES = (
    "r94_loop_checkpoint_same_block_ambiguity_negative.rs",
    "r94_loop_draw_reward_wrong_denominator_negative.rs",
    "r94_loop_gauge_reward_stake_withdraw_burst_game_negative.rs",
)

_HIT_RE = re.compile(rf"^=== {DETECTOR}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(prefix=".rust_rewards_fire16_", suffix=".log") as tmp:
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


class RustRewardsCheckpointOrDenominatorFire16Tests(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)

    def test_positive_fixture_covers_three_same_class_shapes(self) -> None:
        text = POSITIVE.read_text(encoding="utf-8")
        self.assertIn("checkpoints.get_at_block(block)", text)
        self.assertIn("reward_amount * user_balance / total_supply()", text)
        self.assertIn("accrue_for_user(balance_of(user))", text)

        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 3, log_text)
        self.assertIn("checkpoint-or-denominator", log_text)
        self.assertIn("rewards-distribution-skew", log_text)
        self.assertIn("eligible reward denominator", log_text)
        self.assertIn("instantaneous balance", log_text)

    def test_negative_fixture_guards_all_three_shapes(self) -> None:
        text = NEGATIVE.read_text(encoding="utf-8")
        self.assertIn("checkpoint_index", text)
        self.assertIn("eligible_supply()", text)
        self.assertIn("time_weighted_balance(user)", text)

        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_seed_misses_now_fire(self) -> None:
        for fixture_name in SEED_POSITIVES:
            with self.subTest(fixture=fixture_name):
                hits, log_text = _run_fixture(FIXTURES / fixture_name)
                self.assertGreaterEqual(hits, 1, log_text)
                self.assertIn("rewards-distribution-skew", log_text)

    def test_confirmed_seed_clean_fixtures_stay_silent(self) -> None:
        for fixture_name in SEED_NEGATIVES:
            with self.subTest(fixture=fixture_name):
                hits, log_text = _run_fixture(FIXTURES / fixture_name)
                self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
