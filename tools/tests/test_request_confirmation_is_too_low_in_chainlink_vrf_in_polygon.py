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
PATTERN = "request-confirmation-is-too-low-in-chainlink-vrf-in-polygon"
DETECTOR = ROOT / "detectors" / "wave17" / "request_confirmation_is_too_low_in_chainlink_vrf_in_polygon.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "request_confirmation_is_too_low_in_chainlink_vrf_in_polygon"
MIRROR_DIR = ROOT / "detectors" / "fixtures" / PATTERN
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
SMOKE = FIXTURE_DIR / "smoke.json"
MANIFEST = FIXTURE_DIR / "manifest.json"
ALT_POSITIVE = MIRROR_DIR / "positive.sol"
ALT_CLEAN = MIRROR_DIR / "clean.sol"
ALT_SMOKE = MIRROR_DIR / "smoke.json"


def _python_with_slither() -> str | None:
    candidates = [
        os.environ.get("SLITHER_PYTHON"),
        sys.executable,
        "/opt/homebrew/opt/python@3.13/bin/python3.13",
        "/opt/homebrew/bin/python3.13",
        "python3",
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


class RequestConfirmationIsTooLowInChainlinkVrfInPolygonTest(unittest.TestCase):
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
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_detector_reference_fixture_and_smoke_metadata(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        reference_text = REFERENCE.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        smoke = json.loads(SMOKE.read_text(encoding="utf-8"))
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("glider-chainlink-vrf-request-confirmations-too-low", detector_text)
        self.assertIn("requestRandomWords", detector_text)
        self.assertIn("requestConfirmations", detector_text)
        self.assertIn("DetectorClassification.MEDIUM", detector_text)
        self.assertIn("DetectorClassification.LOW", detector_text)

        self.assertIn(f"pattern: {PATTERN}", reference_text)
        self.assertIn("status: not-submit-ready", reference_text)
        self.assertIn("coverage_claim: detector_fixture_smoke_only", reference_text)
        self.assertIn("backend_scope: solidity_alias_for_promoted_glider_detector", reference_text)
        self.assertIn("duplicate_of_pattern: glider-chainlink-vrf-request-confirmations-too-low", reference_text)
        self.assertIn("requestRandomWords\\s*\\(", reference_text)
        self.assertIn("vuln: detectors/fixtures/request_confirmation_is_too_low_in_chainlink_vrf_in_polygon/positive.sol", reference_text)
        self.assertIn("clean: detectors/fixtures/request_confirmation_is_too_low_in_chainlink_vrf_in_polygon/clean.sol", reference_text)

        self.assertIn("return coordinator.requestRandomWords(keyHash, subscriptionId, 1, 200000, 1);", positive_text)
        self.assertIn("return coordinator.requestRandomWords(keyHash, subscriptionId, 3, 200000, 1);", clean_text)

        self.assertEqual(smoke["schema"], "auditooor.canonical_detector_fixture_smoke.v1")
        self.assertEqual(smoke["pattern"], PATTERN)
        self.assertEqual(smoke["status"], "passed_vulnerable_clean_smoke")
        self.assertEqual(smoke["positive_hits"], 1)
        self.assertEqual(smoke["vulnerable_hits"], 1)
        self.assertEqual(smoke["clean_hits"], 0)
        self.assertEqual(smoke["detector_path"], str(DETECTOR.relative_to(ROOT)))
        self.assertEqual(smoke["coverage_claim"], "detector_fixture_smoke_only")
        self.assertEqual(smoke["backend_scope"], "solidity_alias_for_promoted_glider_detector")
        self.assertFalse(smoke["promotion_allowed"])
        self.assertEqual(smoke["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(smoke["duplicate_of_detector"], "glider-chainlink-vrf-request-confirmations-too-low")
        self.assertEqual(manifest["smoke_record_path"], str(SMOKE.relative_to(ROOT)))
        self.assertEqual(manifest["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(manifest["duplicate_of_detector"], "glider-chainlink-vrf-request-confirmations-too-low")

    def test_hyphenated_fixture_mirror_stays_in_sync(self) -> None:
        self.assertEqual(POSITIVE.read_text(encoding="utf-8"), ALT_POSITIVE.read_text(encoding="utf-8"))
        self.assertEqual(CLEAN.read_text(encoding="utf-8"), ALT_CLEAN.read_text(encoding="utf-8"))

        canonical = json.loads(SMOKE.read_text(encoding="utf-8"))
        mirror = json.loads(ALT_SMOKE.read_text(encoding="utf-8"))
        self.assertEqual(canonical["pattern"], mirror["pattern"])
        self.assertEqual(canonical["positive_hits"], mirror["positive_hits"])
        self.assertEqual(canonical["clean_hits"], mirror["clean_hits"])
        self.assertEqual(mirror["submission_posture"], "NOT_SUBMIT_READY")
        self.assertIn("Compatibility mirror", mirror["limitation_note"])

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertGreaterEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
