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
PATTERN = "r94-reverse-rewards-distribution-end-raw-subtraction"
DETECTOR = ROOT / "detectors" / "wave17" / "r94_reverse_rewards_distribution_end_raw_subtraction.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "r94_reverse_rewards_distribution_end_raw_subtraction"
MIRROR_DIR = ROOT / "detectors" / "fixtures" / PATTERN
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
SMOKE = FIXTURE_DIR / "smoke.json"
MIRROR_POSITIVE = MIRROR_DIR / "positive.sol"
MIRROR_CLEAN = MIRROR_DIR / "clean.sol"
MIRROR_SMOKE = MIRROR_DIR / "smoke.json"


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


class R94ReverseRewardsDistributionEndRawSubtractionTest(unittest.TestCase):
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

    def test_detector_reference_and_fixture_scope_stay_aligned(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        reference_text = REFERENCE.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        mirror_positive_text = MIRROR_POSITIVE.read_text(encoding="utf-8")
        mirror_clean_text = MIRROR_CLEAN.read_text(encoding="utf-8")
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        mirror_payload = json.loads(MIRROR_SMOKE.read_text(encoding="utf-8"))

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)
        self.assertIn("distributionEnd - block.timestamp without underflow clamp", detector_text)
        self.assertIn("lastTimeRewardApplicable", detector_text)

        self.assertIn(f"pattern: {PATTERN}", reference_text)
        self.assertIn("status: not-submit-ready", reference_text)
        self.assertIn("coverage_claim: detector_fixture_smoke_only", reference_text)
        self.assertIn("submission_posture: NOT_SUBMIT_READY", reference_text)
        self.assertIn(str(POSITIVE.relative_to(ROOT)), reference_text)
        self.assertIn(str(CLEAN.relative_to(ROOT)), reference_text)
        self.assertIn(str(MIRROR_POSITIVE.relative_to(ROOT)), reference_text)
        self.assertIn(str(MIRROR_CLEAN.relative_to(ROOT)), reference_text)

        self.assertIn("contract ReverseRewardsDistributionEndRawSubtractionPositive", positive_text)
        self.assertIn("function rewardPerToken() public view returns (uint256)", positive_text)
        self.assertIn("uint256 currentTime = block.timestamp;", positive_text)
        self.assertIn("distributionEnd - currentTime", positive_text)
        self.assertNotIn("lastTimeRewardApplicable()", positive_text)
        self.assertEqual(positive_text, mirror_positive_text)

        self.assertIn("contract ReverseRewardsDistributionEndRawSubtractionClean", clean_text)
        self.assertIn("function lastTimeRewardApplicable() public view returns (uint256)", clean_text)
        self.assertIn("return Math.min(block.timestamp, distributionEnd);", clean_text)
        self.assertIn("uint256 currentTime = lastTimeRewardApplicable();", clean_text)
        self.assertIn("currentTime - lastUpdateTime", clean_text)
        self.assertEqual(clean_text, mirror_clean_text)

        self.assertEqual(payload["schema"], "auditooor.canonical_detector_fixture_smoke.v1")
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["status"], "passed_vulnerable_clean_smoke")
        self.assertEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["vulnerable_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertEqual(payload["coverage_claim"], "detector_fixture_smoke_only")
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(mirror_payload["pattern"], PATTERN)
        self.assertEqual(mirror_payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(mirror_payload["positive_hits"], payload["positive_hits"])
        self.assertEqual(mirror_payload["clean_hits"], payload["clean_hits"])

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(MIRROR_POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)
        self.assertEqual(self._hits(MIRROR_CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
