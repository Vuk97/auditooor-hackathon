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
PATTERN = "redundant-self-assignment-indicates-potential-typo-or-logic-error"
DETECTOR = (
    ROOT
    / "detectors"
    / "wave_graveyard"
    / "wave13_broken"
    / "redundant_self_assignment_indicates_potential_typo_or_logic_error.py"
)
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "redundant_self_assignment_indicates_potential_typo_or_logic_error"
FIXTURE_DIR_HYPHEN = ROOT / "detectors" / "fixtures" / PATTERN
POSITIVE = FIXTURE_DIR / "redundant_self_assignment_indicates_potential_typo_or_logic_error_vulnerable.sol"
CLEAN = FIXTURE_DIR / "redundant_self_assignment_indicates_potential_typo_or_logic_error_clean.sol"
SMOKE = FIXTURE_DIR / "smoke.json"
POSITIVE_HYPHEN = FIXTURE_DIR_HYPHEN / "redundant_self_assignment_indicates_potential_typo_or_logic_error_vulnerable.sol"
CLEAN_HYPHEN = FIXTURE_DIR_HYPHEN / "redundant_self_assignment_indicates_potential_typo_or_logic_error_clean.sol"
SMOKE_HYPHEN = FIXTURE_DIR_HYPHEN / "smoke.json"


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


class RedundantSelfAssignmentIndicatesPotentialTypoOrLogicErrorTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> int:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [slither_python, str(RUNNER), "--include-graveyard", "--tier=ALL", str(fixture), PATTERN],
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

    def test_detector_compiles_and_reference_points_at_owned_fixture_pair(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        reference_text = REFERENCE.read_text(encoding="utf-8")

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("_SELF_ASSIGNMENT_REGEX", detector_text)
        self.assertIn(r"\s*=\s*\1\s*;", detector_text)
        self.assertIn(str(POSITIVE.relative_to(ROOT)), reference_text)
        self.assertIn(str(CLEAN.relative_to(ROOT)), reference_text)
        self.assertIn("same-identifier self-assignment", reference_text)
        self.assertIn("Fixture-smoke/source-shape proof only", reference_text)

    def test_fixture_pair_and_hyphen_alias_stay_in_sync(self) -> None:
        self.assertEqual(POSITIVE.read_text(encoding="utf-8"), POSITIVE_HYPHEN.read_text(encoding="utf-8"))
        self.assertEqual(CLEAN.read_text(encoding="utf-8"), CLEAN_HYPHEN.read_text(encoding="utf-8"))

    def test_smoke_metadata_marks_advisory_only_posture(self) -> None:
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        payload_hyphen = json.loads(SMOKE_HYPHEN.read_text(encoding="utf-8"))

        self.assertEqual(payload["schema"], "auditooor.canonical_detector_fixture_smoke.v1")
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["detector_slug"], "redundant_self_assignment_indicates_potential_typo_or_logic_error")
        self.assertEqual(payload["detector_path"], str(DETECTOR.relative_to(ROOT)))
        self.assertEqual(payload["status"], "passed_vulnerable_clean_smoke")
        self.assertEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(payload["coverage_claim"], "detector_fixture_smoke_only")
        self.assertIn("--include-graveyard", payload["positive_command"])
        self.assertIn("--include-graveyard", payload["clean_command"])
        self.assertEqual(payload["limitation_note"], payload_hyphen["limitation_note"])

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
