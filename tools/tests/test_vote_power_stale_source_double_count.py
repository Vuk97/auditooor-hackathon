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
PATTERN = "vote-power-stale-source-double-count"
DETECTOR = ROOT / "detectors" / "wave17" / "vote_power_stale_source_double_count.py"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "vote_power_stale_source_double_count"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
SMOKE = FIXTURE_DIR / "smoke.json"

LEGACY_REASSIGN_POSITIVE = (
    ROOT / "detectors" / "fixtures" / "delegation_reassignment_stale_vote_source" / "positive.sol"
)
LEGACY_REASSIGN_CLEAN = (
    ROOT / "detectors" / "fixtures" / "delegation_reassignment_stale_vote_source" / "clean.sol"
)
SELF_DELEGATION_POSITIVE = (
    ROOT / "detectors" / "fixtures" / "vote_power_self_delegation_double_count" / "positive.sol"
)
SELF_DELEGATION_CLEAN = (
    ROOT / "detectors" / "fixtures" / "vote_power_self_delegation_double_count" / "clean.sol"
)
STALE_SOURCE_POSITIVE = (
    ROOT / "detectors" / "fixtures" / "vote_double_count_stale_source_retention" / "positive.sol"
)
STALE_SOURCE_CLEAN = (
    ROOT / "detectors" / "fixtures" / "vote_double_count_stale_source_retention" / "clean.sol"
)


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


class VotePowerStaleSourceDoubleCountTest(unittest.TestCase):
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
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1)), proc.stdout

    def test_detector_fixture_and_smoke_metadata_stay_aligned(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)
        self.assertIn("_has_debit_before_credit", detector_text)
        self.assertIn("delegateSources[newDelegate].push(sourceId);", positive_text)
        self.assertIn("delegateVotePower[to] += balanceOf[msg.sender];", positive_text)
        self.assertIn("_removeDelegation(currentDelegate, sourceId);", clean_text)
        self.assertIn("delegateVotePower[previousDelegate] -= units;", clean_text)
        self.assertEqual(payload["schema"], "auditooor.canonical_detector_fixture_smoke.v1")
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["positive_hits"], 2)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")

    def test_positive_fixture_fires_and_clean_fixture_is_quiet(self) -> None:
        hits, log_text = self._hits(POSITIVE)
        self.assertEqual(hits, 2, log_text)
        hits, log_text = self._hits(CLEAN)
        self.assertEqual(hits, 0, log_text)

    def test_known_vote_double_count_samples_are_replayed(self) -> None:
        for fixture in [
            LEGACY_REASSIGN_POSITIVE,
            SELF_DELEGATION_POSITIVE,
            STALE_SOURCE_POSITIVE,
        ]:
            with self.subTest(fixture=fixture.name):
                hits, log_text = self._hits(fixture)
                self.assertGreaterEqual(hits, 1, log_text)

        for fixture in [
            LEGACY_REASSIGN_CLEAN,
            SELF_DELEGATION_CLEAN,
            STALE_SOURCE_CLEAN,
        ]:
            with self.subTest(fixture=fixture.name):
                hits, log_text = self._hits(fixture)
                self.assertEqual(hits, 0, log_text)


if __name__ == "__main__":
    unittest.main()
