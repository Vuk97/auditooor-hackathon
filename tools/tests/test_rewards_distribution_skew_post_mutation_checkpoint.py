from __future__ import annotations

import os
import py_compile
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
PATTERN = "rewards-distribution-skew-post-mutation-checkpoint"
DETECTOR = ROOT / "detectors" / "wave70" / "rewards_distribution_skew_post_mutation_checkpoint.py"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "rewards_distribution_skew_post_mutation_checkpoint"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"


def _python_with_slither() -> str | None:
    candidates = [
        os.environ.get("SLITHER_PYTHON"),
        sys.executable,
        "/opt/homebrew/opt/python@3.13/bin/python3.13",
        "/opt/homebrew/bin/python3.13",
    ]
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        try:
            proc = subprocess.run(
                [candidate, "-c", "import slither; import slither.detectors.abstract_detector"],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode == 0:
            return candidate
    return None


class RewardsDistributionSkewPostMutationCheckpointTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> int:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [slither_python, str(RUNNER), "--tier=ALL", str(fixture), PATTERN],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn(PATTERN, proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_detector_and_fixtures_capture_post_mutation_checkpoint_order(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("_BALANCE_MUTATION_RE", detector_text)
        self.assertIn("_REWARD_CHECKPOINT_RE", detector_text)
        self.assertIn("post-mutation checkpoint order", detector_text)

        self.assertIn("shares[msg.sender] += amount;", positive_text)
        self.assertIn("rewardDebt[msg.sender] = (shares[msg.sender] * accRewardPerShare) / PRECISION;", positive_text)
        self.assertRegex(
            positive_text,
            r"shares\[msg\.sender\]\s*\+=\s*amount;[\s\S]*rewardDebt\[msg\.sender\]\s*=",
        )

        self.assertRegex(
            clean_text,
            r"rewardDebt\[msg\.sender\]\s*=[\s\S]*shares\[msg\.sender\]\s*\+=\s*amount;",
        )
        self.assertRegex(
            clean_text,
            r"rewardDebt\[msg\.sender\]\s*=[\s\S]*shares\[msg\.sender\]\s*-=\s*amount;",
        )

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertGreaterEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
