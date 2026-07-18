from __future__ import annotations

import json
import os
import py_compile
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
PATTERN = "reward-terminal-branch-without-period-advance"
DETECTOR = ROOT / "detectors" / "wave17" / "reward_terminal_branch_without_period_advance.py"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "reward_terminal_branch_without_period_advance"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
SMOKE = FIXTURE_DIR / "smoke.json"
AUCTION_STALL_POSITIVE = ROOT / "patterns" / "fixtures" / "auction-failure-stalls-period_vuln.sol"
AUCTION_STALL_CLEAN = ROOT / "patterns" / "fixtures" / "auction-failure-stalls-period_clean.sol"
AUCTION_ADVANCE_POSITIVE = ROOT / "patterns" / "fixtures" / "auction-failure-stalls-period-advance_vuln.sol"
AUCTION_ADVANCE_CLEAN = ROOT / "patterns" / "fixtures" / "auction-failure-stalls-period-advance_clean.sol"
BLOCK_NUMBER_POSITIVE = ROOT / "patterns" / "fixtures" / "block-number-time-assumption_vuln.sol"


def _python_with_slither() -> str | None:
    candidates = [
        os.environ.get("SLITHER_PYTHON"),
        sys.executable,
        "/opt/homebrew/opt/python@3.13/bin/python3.13",
        "/opt/homebrew/bin/python3.13",
        "python3",
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


class RewardTerminalBranchWithoutPeriodAdvanceTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> tuple[int, str]:
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
        self.assertNotIn("No custom detectors found", proc.stdout)
        self.assertNotIn("UNKNOWN function predicate key", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1)), proc.stdout

    def test_detector_fixture_and_smoke_metadata(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        detector_text = DETECTOR.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("failed terminal branch exits before period advance", detector_text)
        self.assertIn("function finalizeAuction() external", positive_text)
        self.assertIn("return;", positive_text)
        self.assertIn("currentPeriod += 1;", clean_text)
        self.assertEqual(payload["schema"], "auditooor.canonical_detector_fixture_smoke.v1")
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["attack_class"], "rewards-distribution-skew")
        self.assertEqual(payload["positive_hits"], 2)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertEqual(payload["coverage_claim"], "detector_fixture_smoke_only")
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        hits, log_text = self._hits(POSITIVE)
        self.assertEqual(hits, 2, log_text)
        hits, log_text = self._hits(CLEAN)
        self.assertEqual(hits, 0, log_text)

    def test_confirmed_auction_misses_are_covered(self) -> None:
        hits, log_text = self._hits(AUCTION_STALL_POSITIVE)
        self.assertEqual(hits, 1, log_text)
        hits, log_text = self._hits(AUCTION_STALL_CLEAN)
        self.assertEqual(hits, 0, log_text)

        hits, log_text = self._hits(AUCTION_ADVANCE_POSITIVE)
        self.assertEqual(hits, 1, log_text)
        hits, log_text = self._hits(AUCTION_ADVANCE_CLEAN)
        self.assertEqual(hits, 0, log_text)

    def test_block_number_time_miss_is_out_of_scope_for_this_subshape(self) -> None:
        hits, log_text = self._hits(BLOCK_NUMBER_POSITIVE)
        self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
