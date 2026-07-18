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
DETECTOR_ID = "rewards_delegate_weight_checkpoint_fire37"
DETECTOR = REPO_ROOT / "detectors" / "rust_wave1" / f"{DETECTOR_ID}.py"
POSITIVE = FIXTURES / f"{DETECTOR_ID}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR_ID}_negative.rs"

_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(prefix=".rust_rewards_fire37_", suffix=".log") as tmp:
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


class RustRewardsDelegateWeightCheckpointFire37Tests(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_positive_fixture_flags_live_delegate_validator_and_recipient_denoms(self) -> None:
        text = POSITIVE.read_text(encoding="utf-8")
        self.assertLess(
            text.index("self.delegate_weights.get(&validator)"),
            text.index("let payout = epoch_reward * delegate_weight / self.total_stake;"),
        )
        self.assertLess(
            text.index("self.active_epoch = epoch;"),
            text.index("let active_validator_count = self.active_validators.len();"),
        )
        self.assertLess(
            text.index("let recipient_count = self.current_recipients.len();"),
            text.index("for recipient in self.current_recipients.iter().copied()"),
        )

        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 3, log_text)
        self.assertIn("live delegate or validator weight", log_text)
        self.assertIn("live active validator count", log_text)
        self.assertIn("current reward recipient set", log_text)
        self.assertIn("committed epoch checkpoint", log_text)
        self.assertIn("rewards-distribution-skew", log_text)

    def test_negative_fixture_uses_checkpointed_epoch_denominators(self) -> None:
        text = NEGATIVE.read_text(encoding="utf-8")
        self.assertIn("delegate_weight_snapshot", text)
        self.assertIn("checkpoint.total_stake_snapshot", text)
        self.assertIn("checkpoint.active_validator_count_snapshot", text)
        self.assertIn("checkpoint.recipient_set_snapshot", text)
        self.assertIn("string_bait", text)

        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
