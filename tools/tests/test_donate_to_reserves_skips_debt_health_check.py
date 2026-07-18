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
PATTERN = "donate-to-reserves-skips-debt-health-check"
DETECTOR = ROOT / "detectors" / "wave17" / "donate_to_reserves_skips_debt_health_check.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "donate_to_reserves_skips_debt_health_check"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
CLEAN_NON_LENDING = FIXTURE_DIR / "clean_non_lending.sol"
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
            probe = subprocess.run(
                [candidate, "-c", "import slither; import slither.detectors.abstract_detector"],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode == 0:
            return candidate
    return None


class DonateToReservesSkipsDebtHealthCheckTest(unittest.TestCase):
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
        self.assertNotIn("No custom detectors found", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_detector_reference_and_fixture_metadata(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        reference_text = REFERENCE.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        clean_non_lending_text = CLEAN_NON_LENDING.read_text(encoding="utf-8")
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("contract.source_matches_regex", detector_text)
        self.assertIn("^donateToReserves$", detector_text)

        self.assertIn(f"pattern: {PATTERN}", reference_text)
        self.assertIn("contract.source_matches_regex", reference_text)
        self.assertIn("fixtures:", reference_text)

        self.assertIn("function donateToReserves(uint256 amount) external", positive_text)
        self.assertNotIn("checkLiquidity(msg.sender)", positive_text)
        self.assertIn("checkLiquidity(msg.sender);", clean_text)
        self.assertIn("requireAccountStatusCheck(msg.sender);", clean_text)
        self.assertIn("_isHealthy(msg.sender)", clean_text)
        self.assertIn("contract CommunityTreasury", clean_non_lending_text)
        self.assertNotIn("collateral", clean_non_lending_text.lower())
        self.assertIn("function donateToReserves(uint256 amount) external", clean_non_lending_text)

        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["status"], "smoke_pass")
        self.assertEqual(payload["coverage_claim"], "detector_fixture_smoke_only")
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertEqual(len(payload["additional_clean_fixtures"]), 1)
        self.assertEqual(
            payload["additional_clean_fixtures"][0]["path"],
            "detectors/fixtures/donate_to_reserves_skips_debt_health_check/clean_non_lending.sol",
        )
        self.assertEqual(payload["additional_clean_fixtures"][0]["clean_hits"], 0)
        commands = [
            payload["positive_command"],
            payload["clean_command"],
            payload["additional_clean_fixtures"][0]["command"],
        ]
        self.assertTrue(all("python3 detectors/run_custom.py" in command for command in commands))
        self.assertFalse(any("/opt/homebrew" in command for command in commands))

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertGreaterEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)
        self.assertEqual(self._hits(CLEAN_NON_LENDING), 0)


if __name__ == "__main__":
    unittest.main()
