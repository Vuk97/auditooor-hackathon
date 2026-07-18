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
PATTERN = "front-running-createpair-may-cause-permenant-dos-for-function-logic"
DETECTOR = (
    ROOT
    / "detectors"
    / "wave_graveyard"
    / "wave13_broken"
    / "front_running_createpair_may_cause_permenant_dos_for_function_logic.py"
)
DSL = (
    ROOT
    / "detectors"
    / "_specs"
    / "drafts_glider"
    / "front-running-createpair-may-cause-permenant-dos-for-function-logic.yaml"
)
FIXTURE_DIR = (
    ROOT
    / "detectors"
    / "fixtures"
    / "front_running_createpair_may_cause_permenant_dos_for_function_logic"
)
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


class FrontRunningCreatepairMayCausePermenantDosForFunctionLogicTest(unittest.TestCase):
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

    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

    def test_detector_and_dsl_still_describe_name_match_missing_call_shape(self) -> None:
        detector_text = DETECTOR.read_text(encoding="utf-8")
        dsl_text = DSL.read_text(encoding="utf-8")

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn('_REQUIRED_CALL_REGEX = re.compile(r".*(accrue|update|sync|validate|check).*"', detector_text)
        self.assertIn('skeleton: "name_match_missing_call"', dsl_text)
        self.assertIn('required_call_regex: ".*(accrue|update|sync|validate|check).*"', dsl_text)

    def test_smoke_metadata_keeps_not_submit_ready_posture(self) -> None:
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["coverage_claim"], "detector_fixture_smoke_only")
        self.assertEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertIn("--include-graveyard", payload["positive_command"])
        self.assertIn("source-shape proof only", payload["limitation_note"])

    def test_fixture_pair_models_missing_vs_present_preflight_check(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        clean = CLEAN.read_text(encoding="utf-8")

        self.assertIn("function createPairForListing()", positive)
        self.assertIn("createpairRequested = true;", positive)
        self.assertNotIn("checkPairCreationState();", positive)

        self.assertIn("function checkPairCreationState() internal view", clean)
        self.assertIn("checkPairCreationState();", clean)
        self.assertIn('require(!createpairRequested, "pair already requested");', clean)

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
