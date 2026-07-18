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
DETECTOR = "rewards_distribution_skew_checkpoint_fire24"
DETECTOR_PATH = REPO_ROOT / "detectors" / "rust_wave1" / f"{DETECTOR}.py"
POSITIVE = FIXTURES / f"{DETECTOR}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR}_negative.rs"

_HIT_RE = re.compile(rf"^=== {DETECTOR}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(prefix=".rust_rewards_fire24_", suffix=".log") as tmp:
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


class RustRewardsDistributionSkewCheckpointFire24Tests(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_positive_fixture_flags_user_only_reward_branch(self) -> None:
        text = POSITIVE.read_text(encoding="utf-8")
        self.assertIn("if emergency", text)
        self.assertIn("self.users[user].reward_debt", text)
        self.assertIn("self.users[user].multiplier = 1", text)
        self.assertIn("self.update_global_accumulator();", text)
        self.assertLess(
            text.index("self.users[user].reward_debt"),
            text.index("} else {"),
        )
        self.assertGreater(
            text.index("self.update_global_accumulator();"),
            text.index("} else {"),
        )

        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 1, log_text)
        self.assertIn("advances user reward debt", log_text)
        self.assertIn("total reward debt update", log_text)
        self.assertIn("rewards-distribution-skew", log_text)

    def test_negative_fixture_global_checkpoint_before_claim_is_silent(self) -> None:
        text = NEGATIVE.read_text(encoding="utf-8")
        self.assertLess(
            text.index("self.update_global_accumulator();"),
            text.index("if emergency"),
        )
        self.assertIn("self.total_reward_debt += owed", text)
        self.assertIn("self.users[user].reward_debt", text)

        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
