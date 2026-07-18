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
PATTERN = "vote-power-self-delegation-double-count"
W68_DIRECT = "w68-vote-double-count-delegation"
W68_NO_DEBIT = "w68-delegation-power-inflation-no-debit"
DETECTOR = ROOT / "detectors" / "wave17" / "vote_power_self_delegation_double_count.py"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "vote_power_self_delegation_double_count"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
SMOKE = FIXTURE_DIR / "smoke.json"


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


class VotePowerSelfDelegationDoubleCountTest(unittest.TestCase):
    def _hits(self, fixture: Path, pattern: str = PATTERN) -> int:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [slither_python, str(RUNNER), "--tier=ALL", str(fixture), pattern],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn(pattern, proc.stdout)
        self.assertNotIn("No custom detectors found", proc.stdout)
        self.assertNotIn("UNKNOWN function predicate key", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_detector_fixture_and_smoke_metadata_stay_aligned(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)
        self.assertIn("solodit_8730", detector_text)
        self.assertIn("solodit 33575", detector_text.lower())
        self.assertIn("body_not_contains_regex", detector_text)
        self.assertIn("oldDelegate", detector_text)

        self.assertIn("function selfDelegate() external", positive_text)
        self.assertIn("address oldDelegate = delegateOf[msg.sender];", positive_text)
        self.assertIn("delegatedVotes[newDelegate] += balanceOf[msg.sender];", positive_text)
        self.assertNotIn("delegatedVotes[oldDelegate] -=", positive_text)
        self.assertIn("forVotes[proposalId] += delegatedVotes[msg.sender];", positive_text)

        self.assertIn("delegatedVotes[oldDelegate] -= units;", clean_text)
        self.assertIn("if (oldDelegate == newDelegate)", clean_text)
        self.assertIn("forVotes[proposalId] += delegatedVotes[msg.sender];", clean_text)

        self.assertEqual(payload["schema"], "auditooor.canonical_detector_fixture_smoke.v1")
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertEqual(payload["w68_vote_double_count_delegation_hits_on_positive"], 0)
        self.assertEqual(payload["w68_delegation_power_inflation_no_debit_hits_on_positive"], 0)
        self.assertEqual(payload["coverage_claim"], "detector_fixture_smoke_only")
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertIn("stale self-delegate source shape", payload["limitation_note"])

    def test_positive_fires_clean_is_quiet_and_w68_rejects_positive(self) -> None:
        self.assertEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)
        self.assertEqual(self._hits(POSITIVE, W68_DIRECT), 0)
        self.assertEqual(self._hits(POSITIVE, W68_NO_DEBIT), 0)


if __name__ == "__main__":
    unittest.main()
