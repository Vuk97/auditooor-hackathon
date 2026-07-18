from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ARGUMENT = "missing-two-step-ownership-transfer-hunter"
RUNNER = ROOT / "detectors" / "run_custom.py"
DETECTOR = (
    ROOT
    / "detectors"
    / "wave17"
    / "missing_two_step_ownership_transfer_hunter.py"
)
REFERENCE = ROOT / "reference" / "patterns.dsl" / "missing-two-step-ownership-transfer-hunter.yaml"
UNDERSCORE_FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "missing_two_step_ownership_transfer_hunter"
HYPHEN_FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "missing-two-step-ownership-transfer-hunter"
POSITIVE = UNDERSCORE_FIXTURE_DIR / "positive.sol"
CLEAN = UNDERSCORE_FIXTURE_DIR / "clean.sol"
SMOKE = UNDERSCORE_FIXTURE_DIR / "smoke.json"


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


class MissingTwoStepOwnershipTransferHunterTest(unittest.TestCase):
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
                "--tier=ALL",
                str(fixture),
                ARGUMENT,
            ],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertNotIn("UNKNOWN function predicate key", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_reference_yaml_is_honest_fixture_smoke_only(self) -> None:
        text = REFERENCE.read_text(encoding="utf-8")
        self.assertIn("status: not-submit-ready", text)
        self.assertIn("submission_posture: NOT_SUBMIT_READY", text)
        self.assertIn(
            "vuln: detectors/fixtures/missing_two_step_ownership_transfer_hunter/positive.sol",
            text,
        )
        self.assertIn(
            "clean: detectors/fixtures/missing_two_step_ownership_transfer_hunter/clean.sol",
            text,
        )

    def test_dual_fixture_directories_stay_in_sync(self) -> None:
        for filename in ("positive.sol", "clean.sol"):
            self.assertEqual(
                (UNDERSCORE_FIXTURE_DIR / filename).read_text(encoding="utf-8"),
                (HYPHEN_FIXTURE_DIR / filename).read_text(encoding="utf-8"),
            )

        underscore_smoke = json.loads((UNDERSCORE_FIXTURE_DIR / "smoke.json").read_text(encoding="utf-8"))
        hyphen_smoke = json.loads((HYPHEN_FIXTURE_DIR / "smoke.json").read_text(encoding="utf-8"))
        self.assertEqual(underscore_smoke["status"], hyphen_smoke["status"])
        self.assertEqual(
            underscore_smoke["submission_posture"], hyphen_smoke["submission_posture"]
        )
        self.assertEqual(underscore_smoke["vulnerable_hits"], hyphen_smoke["vulnerable_hits"])
        self.assertEqual(underscore_smoke["clean_hits"], hyphen_smoke["clean_hits"])

    def test_detector_source_looks_for_pending_accept_markers(self) -> None:
        text = DETECTOR.read_text(encoding="utf-8")
        self.assertIn("_TWO_STEP_MARKER_REGEX", text)
        self.assertIn("acceptOwnership", text)
        self.assertIn("pendingOwner", text)

    def test_smoke_record_captures_positive_and_clean_counts(self) -> None:
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "smoke_pass")
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(
            payload["vulnerable_fixture"],
            "detectors/fixtures/missing_two_step_ownership_transfer_hunter/positive.sol",
        )
        self.assertEqual(
            payload["clean_fixture"],
            "detectors/fixtures/missing_two_step_ownership_transfer_hunter/clean.sol",
        )
        self.assertGreaterEqual(payload["vulnerable_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertGreaterEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
