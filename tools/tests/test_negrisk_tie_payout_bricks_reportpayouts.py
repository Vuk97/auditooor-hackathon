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
PATTERN = "negrisk-tie-payout-bricks-reportpayouts"
DETECTOR = ROOT / "detectors" / "wave17" / "negrisk_tie_payout_bricks_reportpayouts.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "negrisk_tie_payout_bricks_reportpayouts"
ALT_FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "negrisk-tie-payout-bricks-reportpayouts"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
MANIFEST = FIXTURE_DIR / "manifest.json"
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


class NegRiskTiePayoutBricksReportpayoutsTest(unittest.TestCase):
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

    def test_detector_reference_and_fixture_metadata_stay_scoped(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        reference_text = REFERENCE.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        smoke = json.loads(SMOKE.read_text(encoding="utf-8"))

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("_INCLUDE_LEAF_HELPERS = True", detector_text)
        self.assertIn("0.5 ether", detector_text)
        self.assertIn("allowTies|isNegRisk", detector_text)

        self.assertIn("status: not-submit-ready", reference_text)
        self.assertIn("coverage_claim: detector_fixture_smoke_only", reference_text)
        self.assertIn("submission_posture: NOT_SUBMIT_READY", reference_text)
        self.assertIn(str(POSITIVE.relative_to(ROOT)), reference_text)
        self.assertIn(str(CLEAN.relative_to(ROOT)), reference_text)
        self.assertIn("literal UMA tie sentinel branch", reference_text)

        self.assertIn("function _constructPayouts(int256 price)", positive_text)
        self.assertIn("price == 0.5 ether", positive_text)
        self.assertIn("payouts[0] = 1;", positive_text)
        self.assertIn("payouts[1] = 1;", positive_text)

        self.assertIn("function _constructPayouts(int256 price)", clean_text)
        self.assertIn("bool public immutable isNegRisk;", clean_text)
        self.assertIn("if (isNegRisk) revert TieUnsupported();", clean_text)

        self.assertEqual(manifest["pattern"], PATTERN)
        self.assertEqual(manifest["coverage_claim"], "detector_fixture_smoke_only")
        self.assertFalse(manifest["promotion_allowed"])
        self.assertEqual(manifest["submission_posture"], "NOT_SUBMIT_READY")

        self.assertEqual(smoke["pattern"], PATTERN)
        self.assertEqual(smoke["status"], "passed_vulnerable_clean_smoke")
        self.assertEqual(smoke["positive_hits"], 1)
        self.assertEqual(smoke["vulnerable_hits"], 1)
        self.assertEqual(smoke["clean_hits"], 0)
        self.assertEqual(smoke["coverage_claim"], "detector_fixture_smoke_only")
        self.assertFalse(smoke["promotion_allowed"])
        self.assertEqual(smoke["submission_posture"], "NOT_SUBMIT_READY")
        self.assertIn("literal 0.5 ether tie branch", smoke["limitation_note"])

    def test_hyphenated_fixture_mirror_stays_in_sync(self) -> None:
        self.assertEqual(POSITIVE.read_text(encoding="utf-8"), ALT_POSITIVE.read_text(encoding="utf-8"))
        self.assertEqual(CLEAN.read_text(encoding="utf-8"), ALT_CLEAN.read_text(encoding="utf-8"))

        canonical = json.loads(SMOKE.read_text(encoding="utf-8"))
        mirror = json.loads(ALT_SMOKE.read_text(encoding="utf-8"))
        self.assertEqual(canonical["pattern"], mirror["pattern"])
        self.assertEqual(canonical["positive_hits"], mirror["positive_hits"])
        self.assertEqual(canonical["vulnerable_hits"], mirror["vulnerable_hits"])
        self.assertEqual(canonical["clean_hits"], mirror["clean_hits"])
        self.assertEqual(mirror["submission_posture"], "NOT_SUBMIT_READY")

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
