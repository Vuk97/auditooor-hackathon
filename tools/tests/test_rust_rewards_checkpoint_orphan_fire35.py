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
DETECTOR_ID = "rewards_checkpoint_orphan_fire35"
DETECTOR = REPO_ROOT / "detectors" / "rust_wave1" / f"{DETECTOR_ID}.py"
POSITIVE = FIXTURES / f"{DETECTOR_ID}_positive.rs"
NEGATIVE = FIXTURES / f"{DETECTOR_ID}_negative.rs"

_HIT_RE = re.compile(rf"^=== {DETECTOR_ID}\s+\((\d+) hits\)", re.MULTILINE)


def _run_fixture(fixture: Path) -> tuple[int, str]:
    with tempfile.NamedTemporaryFile(prefix=".rust_rewards_fire35_", suffix=".log") as tmp:
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


class RustRewardsCheckpointOrphanFire35Tests(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_positive_fixture_fires_on_old_account_orphan_paths(self) -> None:
        text = POSITIVE.read_text(encoding="utf-8")
        self.assertLess(
            text.index("self.position_owner.insert(position_id, to);"),
            text.index("self.checkpoint_account(from);"),
        )
        self.assertLess(
            text.index("self.delegations.insert(delegator, new_validator);"),
            text.index("self.checkpoint_delegation_rewards(delegator, old_validator);"),
        )
        self.assertLess(
            text.index("self.stakes.insert(account, previous - amount);"),
            text.index("self.settle_account_rewards(account);"),
        )

        hits, log_text = _run_fixture(POSITIVE)
        self.assertEqual(hits, 3, log_text)
        self.assertIn("old reward account", log_text)
        self.assertIn("orphaned or assigned to the wrong user", log_text)
        self.assertIn("rewards-distribution-skew", log_text)

    def test_negative_fixture_settles_old_side_first_and_string_bait_is_silent(self) -> None:
        text = NEGATIVE.read_text(encoding="utf-8")
        self.assertLess(
            text.index("self.checkpoint_account(from);"),
            text.index("self.position_owner.insert(position_id, to);"),
        )
        self.assertLess(
            text.index("self.checkpoint_delegation_rewards(delegator, old_validator);"),
            text.index("self.delegations.insert(delegator, new_validator);"),
        )
        self.assertLess(
            text.index("self.settle_account_rewards(account);"),
            text.index("self.stakes.insert(account, previous - amount);"),
        )
        self.assertIn("string_bait", text)

        hits, log_text = _run_fixture(NEGATIVE)
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
