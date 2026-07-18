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
PATTERN = "eoa-restricted-modifiers-that-checks-the-bytecode-size-of-the-caller-a"
DETECTOR = (
    ROOT
    / "detectors"
    / "wave_graveyard"
    / "wave13_broken"
    / "eoa_restricted_modifiers_that_checks_the_bytecode_size_of_the_caller_a.py"
)
SPEC_DRAFT = (
    ROOT
    / "detectors"
    / "_specs"
    / "drafts_glider"
    / f"{PATTERN}.yaml"
)
FIXTURE_DIR = (
    ROOT
    / "detectors"
    / "fixtures"
    / "eoa_restricted_modifiers_that_checks_the_bytecode_size_of_the_caller_a"
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


class EoaRestrictedModifiersThatChecksTheBytecodeSizeOfTheCallerATest(unittest.TestCase):
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

    def test_row_sources_align_on_codesize_guard_shape(self) -> None:
        detector_text = DETECTOR.read_text(encoding="utf-8")
        spec_text = SPEC_DRAFT.read_text(encoding="utf-8")

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("EOA-only modifier/function uses caller bytecode size", detector_text)
        self.assertIn('skeleton: "semantic_eoa_codesize_guard"', spec_text)
        self.assertIn("function.body_contains_regex", spec_text)
        self.assertIn("code\\\\.length", spec_text)
        self.assertIn(
            "eoa_restricted_modifiers_that_checks_the_bytecode_size_of_the_caller_a/positive.sol",
            spec_text,
        )
        self.assertIn(
            "eoa_restricted_modifiers_that_checks_the_bytecode_size_of_the_caller_a/clean.sol",
            spec_text,
        )
        self.assertTrue(POSITIVE.is_file())
        self.assertTrue(CLEAN.is_file())

    def test_fixture_shape_models_bypassable_modifier_and_clean_rewrite(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        clean = CLEAN.read_text(encoding="utf-8")

        self.assertIn("modifier onlyEOA()", positive)
        self.assertIn("require(msg.sender.code.length == 0, \"only EOA\");", positive)
        self.assertNotIn("tx.origin == msg.sender", positive)

        self.assertIn("modifier onlyEOA()", clean)
        self.assertIn("require(tx.origin == msg.sender, \"only EOA\");", clean)
        self.assertNotIn("msg.sender.code.length == 0", clean)

    def test_smoke_record_captures_positive_and_clean_counts(self) -> None:
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        self.assertEqual(payload["status"], "smoke_pass")
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertGreaterEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertGreaterEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
