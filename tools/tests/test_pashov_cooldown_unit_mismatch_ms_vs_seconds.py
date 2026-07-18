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
PATTERN = "pashov-cooldown-unit-mismatch-ms-vs-seconds"
DETECTOR = ROOT / "detectors" / "wave17" / "pashov_cooldown_unit_mismatch_ms_vs_seconds.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "pashov_cooldown_unit_mismatch_ms_vs_seconds"
ALT_FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "pashov-cooldown-unit-mismatch-ms-vs-seconds"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
SMOKE = FIXTURE_DIR / "smoke.json"
ALT_POSITIVE = ALT_FIXTURE_DIR / "positive.sol"
ALT_CLEAN = ALT_FIXTURE_DIR / "clean.sol"
ALT_SMOKE = ALT_FIXTURE_DIR / "smoke.json"


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


class PashovCooldownUnitMismatchMsVsSecondsTest(unittest.TestCase):
    def _run(self, fixture: Path) -> tuple[int, int]:
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

        hits_match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        loaded_match = re.search(r"loaded\s+(\d+)\s+custom detector", proc.stdout)
        self.assertIsNotNone(hits_match, proc.stdout)
        self.assertIsNotNone(loaded_match, proc.stdout)
        return int(hits_match.group(1)), int(loaded_match.group(1))

    def test_detector_reference_and_fixture_scope_stay_aligned(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        reference_text = REFERENCE.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("NOT_SUBMIT_READY fixture-smoke/source-shape proof only", detector_text)
        self.assertIn("block.timestamp * 1000", detector_text)
        self.assertIn("cooldownEnd = block.timestamp + cooldownDuration", detector_text)

        self.assertIn(str(POSITIVE.relative_to(ROOT)), reference_text)
        self.assertIn(str(CLEAN.relative_to(ROOT)), reference_text)
        self.assertIn(str(ALT_POSITIVE.relative_to(ROOT)), reference_text)
        self.assertIn(str(ALT_CLEAN.relative_to(ROOT)), reference_text)
        self.assertIn("submission_posture: NOT_SUBMIT_READY", reference_text)
        self.assertIn("Fixture-smoke/source-shape proof only", reference_text)

        self.assertIn("function unstake() external view returns (bool)", positive_text)
        self.assertIn("uint256 currentTime = block.timestamp * 1000;", positive_text)
        self.assertIn("require(currentTime >= cooldownEnd", positive_text)

        self.assertIn("function unstake() external view returns (bool)", clean_text)
        self.assertIn("uint256 currentTime = block.timestamp;", clean_text)
        self.assertNotIn("block.timestamp * 1000", clean_text)

        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["status"], "passed_vulnerable_clean_smoke")
        self.assertEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["vulnerable_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertEqual(payload["loaded_detector_count"], 1)
        self.assertEqual(payload["coverage_claim"], "detector_fixture_smoke_only")
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertIn("block.timestamp * 1000", payload["limitation_note"])

    def test_hyphenated_fixture_mirror_stays_in_sync(self) -> None:
        alt_payload = json.loads(ALT_SMOKE.read_text(encoding="utf-8"))

        self.assertEqual(POSITIVE.read_text(encoding="utf-8"), ALT_POSITIVE.read_text(encoding="utf-8"))
        self.assertEqual(CLEAN.read_text(encoding="utf-8"), ALT_CLEAN.read_text(encoding="utf-8"))
        self.assertEqual(alt_payload["pattern"], PATTERN)
        self.assertEqual(alt_payload["positive_fixture_path"], str(ALT_POSITIVE.relative_to(ROOT)))
        self.assertEqual(alt_payload["clean_fixture_path"], str(ALT_CLEAN.relative_to(ROOT)))
        self.assertEqual(alt_payload["positive_hits"], 1)
        self.assertEqual(alt_payload["clean_hits"], 0)
        self.assertIn("Compatibility mirror", alt_payload["limitation_note"])

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        positive_hits, positive_loaded = self._run(POSITIVE)
        clean_hits, clean_loaded = self._run(CLEAN)
        self.assertEqual(positive_hits, 1)
        self.assertEqual(clean_hits, 0)
        self.assertEqual(positive_loaded, 1)
        self.assertEqual(clean_loaded, 1)


if __name__ == "__main__":
    unittest.main()
