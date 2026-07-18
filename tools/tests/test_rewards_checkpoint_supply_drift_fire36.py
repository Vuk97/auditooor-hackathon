from __future__ import annotations

import importlib.util
import json
import os
import py_compile
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DETECTOR_PATH = ROOT / "detectors" / "wave17" / "rewards_checkpoint_supply_drift_fire36.py"
RUNNER = ROOT / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "rewards-checkpoint-supply-drift-fire36"
POSITIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "rewards_checkpoint_supply_drift_fire36.sol"
)
NEGATIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "rewards_checkpoint_supply_drift_fire36.sol"
)


def _load_detector():
    module_name = "rewards_checkpoint_supply_drift_fire36"
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, DETECTOR_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class RewardsCheckpointSupplyDriftFire36Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector = _load_detector()
        self.assertEqual(detector.DETECTOR_NAME, DETECTOR_NAME)
        self.assertEqual(detector.DETECTOR_SEVERITY_DEFAULT, "Medium")
        self.assertEqual(detector.SUBMISSION_POSTURE, "NOT_SUBMIT_READY")
        self.assertEqual(detector.COVERAGE_CLAIM, "detector_fixture_smoke_only")
        self.assertFalse(detector.PROMOTION_ALLOWED)
        self.assertEqual(detector.VERIFICATION_TIER, "tier-3-synthetic-taxonomy-anchored")

    def test_positive_fixture_fires_on_epoch_live_supply_votes_and_delegate_set(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(POSITIVE), str(POSITIVE))

        self.assertEqual(len(findings), 4)
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in findings}, {"Medium"})
        self.assertEqual(
            {finding.function for finding in findings},
            {
                "rewardPerTokenForEpoch",
                "checkpointAccount",
                "delegateRewardShare",
                "checkpointVotes",
            },
        )

        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("live supply denominator `totalSupply()`", messages)
        self.assertIn("live supply denominator `totalStaked`", messages)
        self.assertIn("mutable delegate-set denominator `rewardDelegates[operator].length`", messages)
        self.assertIn("live supply denominator `votes.getVotes(address(this))`", messages)
        self.assertIn("committed, checkpointed, or epoch-bound denominator", messages)

    def test_negative_fixture_uses_committed_epoch_denominators(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(findings, [])
        negative = _read(NEGATIVE)
        self.assertIn("uint256 committedSupply = rewardEpochSupply[epoch];", negative)
        self.assertIn("uint256 epochSupply = rewardEpochSupply[epoch];", negative)
        self.assertIn("uint256 committedDelegateCount = epochDelegateCount[epoch];", negative)
        self.assertIn("votes.getPastVotes(address(this), snapshotBlock)", negative)
        self.assertIn('string memory bait = "return epochRewards[epoch] / totalStaked;";', negative)

    def test_regex_runner_records_positive_hits_and_negative_silence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fire36_rewards_checkpoint_supply_") as tmp:
            env = os.environ.copy()
            env["PYTHONDONTWRITEBYTECODE"] = "1"

            for fixture, expected_hits in ((POSITIVE, 4), (NEGATIVE, 0)):
                with self.subTest(fixture=fixture.name):
                    manifest = Path(tmp) / f"{fixture.stem}.json"
                    proc = subprocess.run(
                        [
                            sys.executable,
                            str(RUNNER),
                            str(fixture),
                            "--workspace",
                            tmp,
                            "--output",
                            str(manifest),
                            "--detector",
                            DETECTOR_NAME,
                            "--json-only",
                        ],
                        cwd=ROOT,
                        env=env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                        timeout=30,
                    )
                    self.assertEqual(proc.returncode, 0, proc.stdout)
                    data = json.loads(manifest.read_text(encoding="utf-8"))
                    self.assertEqual(data["per_detector_counts"][DETECTOR_NAME], expected_hits)

    def test_source_refs_and_no_unicode_dashes_in_owned_sources(self) -> None:
        detector_text = _read(DETECTOR_PATH)
        self.assertIn("reports/detector_lift_fire35_20260605/post_priorities_all.md", detector_text)
        self.assertIn(
            "reference/patterns.dsl/rewards-distribution-skew-live-denominator.yaml",
            detector_text,
        )
        self.assertIn(
            "reference/patterns.dsl/can-reward-dist-precomputed-totalsupply.yaml",
            detector_text,
        )
        self.assertIn("detectors/wave17/rewards_delegate_drift_fire35.py", detector_text)
        self.assertIn("detectors/wave17/rewards_live_supply_drift_fire34.py", detector_text)
        self.assertIn(
            "detectors/rust_wave1/reward_index_or_supply_checkpoint_drift_fire20.py",
            detector_text,
        )

        for path in (DETECTOR_PATH, POSITIVE, NEGATIVE, Path(__file__)):
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIsNone(re.search("[\u2013\u2014]", text))


if __name__ == "__main__":
    unittest.main()
