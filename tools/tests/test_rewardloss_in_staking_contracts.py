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
PATTERN = "rewardloss-in-staking-contracts"
DETECTOR = ROOT / "detectors" / "wave_graveyard" / "wave13_broken" / "rewardloss_in_staking_contracts.py"
SPEC = ROOT / "detectors" / "_specs" / "drafts_glider" / f"{PATTERN}.yaml"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "rewardloss_in_staking_contracts"
MIRROR_DIR = ROOT / "detectors" / "fixtures" / "rewardloss-in-staking-contracts"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
BAIT = FIXTURE_DIR / "comment_string_bait.sol"
SMOKE = FIXTURE_DIR / "smoke.json"
MIRROR_POSITIVE = MIRROR_DIR / "positive.sol"
MIRROR_CLEAN = MIRROR_DIR / "clean.sol"
MIRROR_BAIT = MIRROR_DIR / "comment_string_bait.sol"
MIRROR_SMOKE = MIRROR_DIR / "smoke.json"
LEGACY_CLEAN = ROOT / "detectors" / "wave13_broken" / "rewardloss_in_staking_contracts_clean.sol"


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


class RewardlossInStakingContractsTest(unittest.TestCase):
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
        self.assertNotIn("No custom detectors found", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_detector_reference_and_fixture_metadata_stay_graveyard_only(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        spec_text = SPEC.read_text(encoding="utf-8")
        reference_text = REFERENCE.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        bait_text = BAIT.read_text(encoding="utf-8")
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))
        mirror_payload = json.loads(MIRROR_SMOKE.read_text(encoding="utf-8"))

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("_REQUIRED_CALL_REGEX", detector_text)
        self.assertIn("wave_graveyard", str(DETECTOR))

        self.assertIn('skeleton: "name_match_missing_call"', spec_text)
        self.assertIn('fn_name_regex: ".*(rewardPerToken).*"', spec_text)
        self.assertIn('read_var_regex: ".*(rewardpert).*"', spec_text)

        self.assertIn("backend: solidity", reference_text)
        self.assertIn("function.reads_state_var_matching", reference_text)
        self.assertIn("wiring_status: graveyard-fixture-smoke-only", reference_text)
        self.assertIn("coverage_claim: detector_fixture_smoke_only", reference_text)
        self.assertIn("promotion_allowed: false", reference_text)
        self.assertIn("submission_posture: NOT_SUBMIT_READY", reference_text)
        self.assertIn("canonical_detector_path: detectors/wave_graveyard/wave13_broken/rewardloss_in_staking_contracts.py", reference_text)
        self.assertIn(str(POSITIVE.relative_to(ROOT)), reference_text)
        self.assertIn(str(CLEAN.relative_to(ROOT)), reference_text)
        self.assertIn(str(BAIT.relative_to(ROOT)), reference_text)
        self.assertIn("does not prove semantic staking reward loss", reference_text)
        self.assertIn("--include-graveyard", reference_text)

        self.assertIn("return rewardpert > 0;", positive_text)
        self.assertIn("_updateReward();", clean_text)
        self.assertIn("Bait only", bait_text)
        self.assertIn("without updateReward", bait_text)
        self.assertIn("_guard();", LEGACY_CLEAN.read_text(encoding="utf-8"))

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
        self.assertIn("Graveyard detector fixture-smoke only", payload["limitation_note"])
        self.assertIn("--include-graveyard", payload["commands"]["positive"])
        self.assertEqual(payload["legacy_detector_path"], payload["detector_path"])

        self.assertEqual(mirror_payload["pattern"], PATTERN)
        self.assertEqual(mirror_payload["positive_hits"], payload["positive_hits"])
        self.assertEqual(mirror_payload["clean_hits"], payload["clean_hits"])
        self.assertEqual(mirror_payload["adversarial_negative_hits"], payload["adversarial_negative_hits"])
        self.assertEqual(mirror_payload["submission_posture"], "NOT_SUBMIT_READY")

    def test_hyphenated_fixture_mirror_stays_in_sync(self) -> None:
        self.assertEqual(POSITIVE.read_text(encoding="utf-8"), MIRROR_POSITIVE.read_text(encoding="utf-8"))
        self.assertEqual(CLEAN.read_text(encoding="utf-8"), MIRROR_CLEAN.read_text(encoding="utf-8"))
        self.assertEqual(BAIT.read_text(encoding="utf-8"), MIRROR_BAIT.read_text(encoding="utf-8"))

    def test_positive_fixture_fires_and_clean_fixtures_stay_quiet(self) -> None:
        self.assertEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)
        self.assertEqual(self._hits(BAIT), 0)


if __name__ == "__main__":
    unittest.main()
