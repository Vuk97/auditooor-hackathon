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
DETECTOR_ID = "rust_rewards_accumulator_checkpoint_fire32"
DETECTOR = REPO_ROOT / "detectors" / "rust_wave1" / f"{DETECTOR_ID}.py"
POSITIVE = FIXTURES / f"{DETECTOR_ID}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR_ID}_negative.rs"

_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(prefix=".rust_rewards_fire32_", suffix=".log") as tmp:
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


class RustRewardsAccumulatorCheckpointFire32Tests(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_positive_fixture_flags_pre_checkpoint_mutations(self) -> None:
        text = POSITIVE.read_text(encoding="utf-8")
        self.assertLess(
            text.index("self.users[user].stake += amount"),
            text.index("self.update_global_accumulator();"),
        )
        self.assertLess(
            text.index("self.users[user].reward_debt = self.pool.acc_reward_per_share"),
            text.index("self.settle_user_index(user);"),
        )
        self.assertLess(
            text.index("vault.pool.total_shares = supply"),
            text.index("vault.update_global_accumulator();"),
        )

        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 3, log_text)
        self.assertIn("checkpointing pending rewards", log_text)
        self.assertIn("updating the reward accumulator", log_text)
        self.assertIn("settling the user reward index", log_text)
        self.assertIn("rewards-distribution-skew", log_text)

    def test_negative_fixture_settles_before_mutation_and_string_bait_is_silent(self) -> None:
        text = NEGATIVE.read_text(encoding="utf-8")
        self.assertLess(
            text.index("self.update_global_accumulator();"),
            text.index("self.users[user].stake += amount"),
        )
        self.assertLess(
            text.index("self.settle_user_index(user);"),
            text.index("self.users[user].shares += amount"),
        )
        self.assertLess(
            text.index("self.update_global_accumulator();\n        self.pool.total_shares = supply"),
            text.index("let _new_rate = rate;"),
        )
        self.assertIn("string_bait", text)

        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
