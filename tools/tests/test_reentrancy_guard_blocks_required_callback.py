from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

import py_compile


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
PATTERN = "reentrancy-guard-blocks-required-callback"
DETECTOR = ROOT / "detectors" / "wave17" / "reentrancy_guard_blocks_required_callback.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "reentrancy_guard_blocks_required_callback"
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


class ReentrancyGuardBlocksRequiredCallbackTest(unittest.TestCase):
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

    def test_detector_reference_and_fixture_wiring(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        reference_text = REFERENCE.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("nonReentrant", detector_text)
        self.assertIn("completeQueuedWithdrawal", detector_text)

        self.assertIn(f"pattern: {PATTERN}", reference_text)
        self.assertIn("fixtures:", reference_text)
        self.assertIn(
            "vuln: detectors/fixtures/reentrancy_guard_blocks_required_callback/positive.sol",
            reference_text,
        )
        self.assertIn(
            "clean: detectors/fixtures/reentrancy_guard_blocks_required_callback/clean.sol",
            reference_text,
        )

        self.assertIn("function completeQueuedWithdrawal() external nonReentrant", positive_text)
        self.assertIn("receive() external payable nonReentrant", positive_text)
        self.assertIn("function completeQueuedWithdrawal() external", clean_text)
        self.assertIn("receive() external payable {}", clean_text)
        self.assertNotIn("function completeQueuedWithdrawal() external nonReentrant", clean_text)
        self.assertNotIn("receive() external payable nonReentrant", clean_text)

        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["status"], "passed_vulnerable_clean_smoke")
        self.assertEqual(payload["coverage_claim"], "detector_fixture_smoke_only")
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
