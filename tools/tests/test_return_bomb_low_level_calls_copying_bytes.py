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
PATTERN = "return-bomb-low-level-calls-copying-bytes"
DETECTOR = (
    ROOT
    / "detectors"
    / "wave_graveyard"
    / "wave13_broken"
    / "return_bomb_low_level_calls_copying_bytes.py"
)
SNIPPET = (
    ROOT
    / "detectors"
    / "wave_graveyard"
    / "wave13_broken"
    / "return_bomb_low_level_calls_copying_bytes.test.snippet"
)
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "return-bomb-low-level-calls-copying-bytes"
UNDERSCORE_FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "return_bomb_low_level_calls_copying_bytes"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
BAIT = FIXTURE_DIR / "comment_string_bait.sol"
SMOKE = FIXTURE_DIR / "smoke.json"
UNDERSCORE_SMOKE = UNDERSCORE_FIXTURE_DIR / "smoke.json"


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


class ReturnBombLowLevelCallsCopyingBytesTest(unittest.TestCase):
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
        self.assertNotIn("No custom detectors found", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_detector_reference_and_smoke_row_evidence(self) -> None:
        detector_text = DETECTOR.read_text(encoding="utf-8")
        snippet_text = SNIPPET.read_text(encoding="utf-8")

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)
        self.assertIn("return-bomb-low-level-calls-copying-bytes", snippet_text)

        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        self.assertEqual(payload["schema"], "auditooor.canonical_detector_fixture_smoke.v1")
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["detector_slug"], "return_bomb_low_level_calls_copying_bytes")
        self.assertEqual(payload["status"], "passed_vulnerable_clean_adversarial_smoke")
        self.assertEqual(
            payload["positive_fixture_path"],
            "detectors/fixtures/return-bomb-low-level-calls-copying-bytes/positive.sol",
        )
        self.assertEqual(
            payload["clean_fixture_path"],
            "detectors/fixtures/return-bomb-low-level-calls-copying-bytes/clean.sol",
        )
        self.assertEqual(
            payload["adversarial_negative_fixture_path"],
            "detectors/fixtures/return-bomb-low-level-calls-copying-bytes/comment_string_bait.sol",
        )
        self.assertEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertEqual(payload["adversarial_negative_hits"], 0)
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(payload["coverage_claim"], "detector_fixture_smoke_only")

        underscore_payload = json.loads(UNDERSCORE_SMOKE.read_text(encoding="utf-8"))
        self.assertEqual(underscore_payload["pattern"], PATTERN)
        self.assertEqual(underscore_payload["detector_slug"], "return_bomb_low_level_calls_copying_bytes")
        self.assertEqual(underscore_payload["adversarial_negative_hits"], 0)

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertGreaterEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)
        self.assertEqual(self._hits(BAIT), 0)


if __name__ == "__main__":
    unittest.main()
