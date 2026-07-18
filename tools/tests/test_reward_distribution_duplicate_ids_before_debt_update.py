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
PATTERN = "reward-distribution-duplicate-ids-before-debt-update"
DETECTOR = ROOT / "detectors" / "wave17" / "reward_distribution_duplicate_ids_before_debt_update.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
COMPILER = ROOT / "tools" / "pattern-compile.py"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "reward_distribution_duplicate_ids_before_debt_update"
MIRROR_DIR = ROOT / "detectors" / "fixtures" / "reward-distribution-duplicate-ids-before-debt-update"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
DEDUPE_CLEAN = FIXTURE_DIR / "dedupe_clean.sol"
BAIT = FIXTURE_DIR / "comment_string_bait.sol"
SMOKE = FIXTURE_DIR / "smoke.json"
MIRROR_POSITIVE = MIRROR_DIR / "positive.sol"
MIRROR_CLEAN = MIRROR_DIR / "clean.sol"
MIRROR_DEDUPE_CLEAN = MIRROR_DIR / "dedupe_clean.sol"
MIRROR_BAIT = MIRROR_DIR / "comment_string_bait.sol"
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


class RewardDistributionDuplicateIdsBeforeDebtUpdateTest(unittest.TestCase):
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
        self.assertNotIn("UNKNOWN function predicate key", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_detector_reference_and_fixture_smoke_metadata_stay_advisory(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        reference_text = REFERENCE.read_text(encoding="utf-8")
        compiler_text = COMPILER.read_text(encoding="utf-8")
        dsl_text = (ROOT / "reference" / "PATTERN_DSL.md").read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        dedupe_text = DEDUPE_CLEAN.read_text(encoding="utf-8")
        bait_text = BAIT.read_text(encoding="utf-8")
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        mirror_payload = json.loads(MIRROR_SMOKE.read_text(encoding="utf-8"))

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)
        self.assertIn("function.body_ordered_regex", detector_text)
        self.assertIn("'ignore_comments_and_strings': True", detector_text)
        self.assertIn("_INCLUDE_LEAF_HELPERS = True", detector_text)

        self.assertIn('"function.body_ordered_regex"', compiler_text)
        self.assertIn("function.body_ordered_regex", dsl_text)
        self.assertIn("status: not-submit-ready", reference_text)
        self.assertIn("coverage_claim: detector_fixture_smoke_only", reference_text)
        self.assertIn("submission_posture: NOT_SUBMIT_READY", reference_text)
        self.assertIn("include_leaf_helpers: true", reference_text)
        self.assertIn("ignore_comments_and_strings: true", reference_text)
        self.assertIn(str(POSITIVE.relative_to(ROOT)), reference_text)
        self.assertIn(str(CLEAN.relative_to(ROOT)), reference_text)
        self.assertIn(str(DEDUPE_CLEAN.relative_to(ROOT)), reference_text)
        self.assertIn(str(BAIT.relative_to(ROOT)), reference_text)
        self.assertIn("Fixture-smoke/source-shape proof only", reference_text)

        self.assertIn("function getAvailableReward", positive_text)
        self.assertIn("external view", positive_text)
        self.assertIn("rewards[i] = rewardPerIP - rewardDebt[ipIds[i]];", positive_text)

        self.assertIn("rewardDebt[ipIds[i]] += reward;", clean_text)
        self.assertIn("require(ipIds[i] != ipIds[i - 1]", dedupe_text)
        self.assertIn("Bait only", bait_text)

        self.assertEqual(payload["schema"], "auditooor.canonical_detector_fixture_smoke.v1")
        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["status"], "passed_vulnerable_clean_adversarial_smoke")
        self.assertEqual(payload["positive_hits"], 1)
        self.assertEqual(payload["vulnerable_hits"], 1)
        self.assertEqual(payload["clean_hits"], 0)
        self.assertEqual(payload["adversarial_negative_hits"], 0)
        self.assertEqual(payload["coverage_claim"], "detector_fixture_smoke_only")
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertIn("duplicate-ID reward computation shape", payload["limitation_note"])
        self.assertEqual(payload["additional_clean_fixtures"][0]["name"], "dedupe_clean")
        self.assertEqual(payload["additional_clean_fixtures"][0]["clean_hits"], 0)

        self.assertEqual(mirror_payload["pattern"], PATTERN)
        self.assertEqual(mirror_payload["positive_hits"], payload["positive_hits"])
        self.assertEqual(mirror_payload["clean_hits"], payload["clean_hits"])
        self.assertEqual(
            mirror_payload["adversarial_negative_hits"],
            payload["adversarial_negative_hits"],
        )
        self.assertEqual(
            mirror_payload["additional_clean_fixtures"][0]["name"],
            payload["additional_clean_fixtures"][0]["name"],
        )
        self.assertEqual(
            mirror_payload["additional_clean_fixtures"][0]["clean_hits"],
            payload["additional_clean_fixtures"][0]["clean_hits"],
        )
        self.assertEqual(mirror_payload["submission_posture"], "NOT_SUBMIT_READY")

    def test_hyphenated_fixture_mirror_stays_in_sync(self) -> None:
        self.assertEqual(POSITIVE.read_text(encoding="utf-8"), MIRROR_POSITIVE.read_text(encoding="utf-8"))
        self.assertEqual(CLEAN.read_text(encoding="utf-8"), MIRROR_CLEAN.read_text(encoding="utf-8"))
        self.assertEqual(
            DEDUPE_CLEAN.read_text(encoding="utf-8"),
            MIRROR_DEDUPE_CLEAN.read_text(encoding="utf-8"),
        )
        self.assertEqual(BAIT.read_text(encoding="utf-8"), MIRROR_BAIT.read_text(encoding="utf-8"))

    def test_positive_fixture_fires_and_clean_fixtures_stay_quiet(self) -> None:
        self.assertEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)
        self.assertEqual(self._hits(DEDUPE_CLEAN), 0)
        self.assertEqual(self._hits(BAIT), 0)


if __name__ == "__main__":
    unittest.main()
