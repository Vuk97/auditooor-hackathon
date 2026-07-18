from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
PATTERN = "interest-accrual-during-pause"
DETECTOR = (
    ROOT
    / "detectors"
    / "wave_graveyard"
    / "wave13_broken"
    / "interest_accrual_during_pause.py"
)
REFERENCE = ROOT / "reference" / "patterns.dsl" / "glider-interest-accrual-during-pause.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "interest_accrual_during_pause"
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


class InterestAccrualDuringPauseTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> int:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [
                slither_python,
                str(RUNNER),
                "--include-graveyard",
                "--tier=ALL",
                str(fixture),
                PATTERN,
            ],
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

    def test_detector_and_reference_stay_honest_about_scope(self) -> None:
        detector_text = DETECTOR.read_text(encoding="utf-8")
        reference_text = REFERENCE.read_text(encoding="utf-8")

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)
        self.assertIn("fixture-smoke", detector_text)
        self.assertIn("interest-accruals-when-contract-is-paused", reference_text)
        self.assertIn("accrueInterest", reference_text)

    def test_fixture_pair_models_unguarded_and_guarded_accrual(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        clean = CLEAN.read_text(encoding="utf-8")

        self.assertIn("function repay(uint256 amount) external whenNotPaused", positive)
        self.assertIn("function accrueInterest() external {", positive)
        self.assertIn("function accrueInterest() external whenNotPaused", clean)

    def test_smoke_record_captures_positive_and_clean_counts(self) -> None:
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "passed_vulnerable_clean_smoke")
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertGreaterEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertGreaterEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
