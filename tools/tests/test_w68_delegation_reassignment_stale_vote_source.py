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
DETECTOR = ROOT / "detectors" / "wave68" / "w68_delegation_reassignment_stale_vote_source.py"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "w68_delegation_reassignment_stale_vote_source"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
W68_ZERO_COVERAGE_DIR = ROOT / "detectors" / "fixtures" / "w68_zero_coverage"
NO_DEBIT_POSITIVE = W68_ZERO_COVERAGE_DIR / "delegation_power_inflation_positive.sol"
NO_DEBIT_CLEAN = W68_ZERO_COVERAGE_DIR / "delegation_power_inflation_clean.sol"
PATTERN = "w68-delegation-reassignment-stale-vote-source"


def _python_with_slither() -> str | None:
    candidates = [
        os.environ.get("SLITHER_PYTHON"),
        sys.executable,
        "/opt/homebrew/opt/python@3.14/bin/python3.14",
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


class W68DelegationReassignmentStaleVoteSourceTest(unittest.TestCase):
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
        self.assertNotIn("UNKNOWN predicate key", proc.stdout)
        self.assertNotIn("UNKNOWN function predicate key", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_positive_fixtures_and_no_debit_regression(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        no_debit_positive_text = NO_DEBIT_POSITIVE.read_text(encoding="utf-8")
        no_debit_clean_text = NO_DEBIT_CLEAN.read_text(encoding="utf-8")

        self.assertIn('ARGUMENT = "w68-delegation-reassignment-stale-vote-source"', detector_text)
        self.assertIn("delegatedTokenIds", detector_text)
        self.assertIn("removeDelegation", detector_text)
        self.assertIn("delegationPower", detector_text)
        self.assertIn("delegatedTokenIds[newDelegate].push(tokenId)", positive_text)
        self.assertIn("_removeDelegation(oldDelegate, tokenId)", clean_text)
        self.assertIn("delegationPower[to] += balanceOf[msg.sender]", no_debit_positive_text)
        self.assertIn("delegationPower[prev] -= balanceOf[msg.sender]", no_debit_clean_text)

        self.assertEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)
        self.assertEqual(self._hits(NO_DEBIT_POSITIVE), 1)
        self.assertEqual(self._hits(NO_DEBIT_CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
