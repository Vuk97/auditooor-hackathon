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
DETECTOR_ID = "rewards_checkpoint_round_fire36"
DETECTOR = REPO_ROOT / "detectors" / "rust_wave1" / f"{DETECTOR_ID}.py"
POSITIVE = FIXTURES / f"{DETECTOR_ID}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR_ID}_negative.rs"

_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(prefix=".rust_rewards_fire36_", suffix=".log") as tmp:
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


class RustRewardsCheckpointRoundFire36Tests(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_positive_fixture_flags_live_round_reads_before_finalize(self) -> None:
        text = POSITIVE.read_text(encoding="utf-8")
        self.assertLess(
            text.index("self.start_reward_round(round, reward_amount);"),
            text.index("let live_supply = self.total_stake;"),
        )
        self.assertLess(
            text.index("let live_supply = self.total_stake;"),
            text.index("self.finalize_round_settlement(round);"),
        )
        self.assertLess(
            text.index("self.active_epoch = epoch;"),
            text.index("let delegate_count = self.delegates.len();"),
        )
        self.assertLess(
            text.index("let delegate_count = self.delegates.len();"),
            text.index("self.complete_epoch_settlement(epoch, reward_amount);"),
        )
        self.assertLess(
            text.index("self.open_reward_round(self.current_round, reward_amount);"),
            text.index("let pending = self.pending_rewards.get(&user).copied().unwrap_or(0);"),
        )
        self.assertLess(
            text.index("let pending = self.pending_rewards.get(&user).copied().unwrap_or(0);"),
            text.index("self.credit_pending_rewards(user, pending);"),
        )

        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 3, log_text)
        self.assertIn("starts a reward accrual round", log_text)
        self.assertIn("before settlement finalizes", log_text)
        self.assertIn("mutable supply, delegate, round, or pending state", log_text)
        self.assertIn("rewards-distribution-skew", log_text)

    def test_negative_fixture_snapshots_before_start_or_reads_after_finalize(self) -> None:
        text = NEGATIVE.read_text(encoding="utf-8")
        self.assertLess(
            text.index("let supply_snapshot = self.total_stake;"),
            text.index("self.start_reward_round(round, reward_amount);"),
        )
        self.assertLess(
            text.index("let delegate_count_snapshot = self.delegates.len();"),
            text.index("self.active_epoch = epoch;"),
        )
        self.assertLess(
            text.index("self.credit_pending_rewards(user, pending_snapshot);"),
            text.index("let _report_only = self.current_round;"),
        )
        self.assertIn("string_bait", text)

        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
