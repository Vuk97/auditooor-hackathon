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
PATTERN = "delegation-power-stale-source-retention"
DETECTOR = ROOT / "detectors" / "wave17" / "delegation_power_stale_source_retention.py"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "delegation_power_stale_source_retention"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
SMOKE = FIXTURE_DIR / "smoke.json"
W68_POSITIVE = ROOT / "detectors" / "fixtures" / "w68_zero_coverage" / "delegation_power_inflation_positive.sol"
W68_CLEAN = ROOT / "detectors" / "fixtures" / "w68_zero_coverage" / "delegation_power_inflation_clean.sol"
DF_POSITIVE = ROOT / "detectors" / "fixtures" / "vote_power_self_delegation_double_count" / "positive.sol"


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


class DelegationPowerStaleSourceRetentionTest(unittest.TestCase):
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
        self.assertNotIn("No custom detectors found", proc.stdout)
        self.assertNotIn("UNKNOWN predicate key", proc.stdout)
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
        self.assertIn("selfDelegated|selfDelegate", detector_text)
        self.assertIn("function.body_not_contains_regex", detector_text)
        self.assertIn("delegationPower[oldDelegate] -= units;", clean_text)

        self.assertIn("function delegate(address newDelegate) external", positive_text)
        self.assertIn("address oldDelegate = delegateOf[msg.sender];", positive_text)
        self.assertIn("delegationPower[newDelegate] += balanceOf[msg.sender];", positive_text)
        self.assertNotIn("delegationPower[oldDelegate] -=", positive_text)

        self.assertEqual(payload["schema"], "auditooor.canonical_detector_fixture_smoke.v1")
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertEqual(payload["w68_positive_hits"], 1)
        self.assertEqual(payload["w68_clean_hits"], 0)
        self.assertEqual(payload["worker_df_self_delegation_positive_hits"], 0)
        self.assertEqual(payload["coverage_claim"], "fixture_smoke_and_named_miss_backtest")
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")

    def test_positive_fires_clean_is_quiet_and_named_miss_is_closed(self) -> None:
        self.assertEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)
        self.assertEqual(self._hits(W68_POSITIVE), 1)
        self.assertEqual(self._hits(W68_CLEAN), 0)
        self.assertEqual(self._hits(DF_POSITIVE), 0)


if __name__ == "__main__":
    unittest.main()
