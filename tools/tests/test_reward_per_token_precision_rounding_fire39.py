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
DETECTOR_PATH = ROOT / "detectors" / "wave17" / "reward_per_token_precision_rounding_fire39.py"
RUNNER = ROOT / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "reward-per-token-precision-rounding-fire39"
POSITIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "reward_per_token_precision_rounding_fire39.sol"
)
NEGATIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "reward_per_token_precision_rounding_fire39.sol"
)


def _load_detector():
    module_name = "reward_per_token_precision_rounding_fire39"
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


class RewardPerTokenPrecisionRoundingFire39Test(unittest.TestCase):
    def test_detector_compiles_and_declares_required_provenance(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(__file__, doraise=True)
        detector = _load_detector()
        detector_text = _read(DETECTOR_PATH)

        self.assertEqual(detector.DETECTOR_NAME, DETECTOR_NAME)
        self.assertEqual(detector.DETECTOR_SEVERITY_DEFAULT, "Medium")
        self.assertEqual(detector.SUBMISSION_POSTURE, "NOT_SUBMIT_READY")
        self.assertEqual(detector.VERIFICATION_TIER, "tier-3-synthetic-taxonomy-anchored")
        self.assertEqual(detector.ATTACK_CLASS, "rounding-direction-attack")
        self.assertIn("context_pack_id: auditooor.vault_context_pack.v1:resume:cbdd9eeb5255863c", detector_text)
        self.assertIn("context_pack_hash: cbdd9eeb5255863c4870d83e88642e9c4a3eef8e7cdfb8b5fb9a8ee7ac5a25d8", detector_text)
        self.assertIn("MCP receipt: .auditooor/memory_context_receipt.json", detector_text)
        self.assertIn("R40/R76/R80 caveat", detector_text)
        self.assertIn("ec-reward-per-token-precision-loss", detector_text)
        self.assertIn("fx-aave-liquidation-fee-rounding-direction", detector_text)
        self.assertIn("flashloan-no-fee-charged", detector_text)

    def test_fixture_pair_pins_semantic_boundary(self) -> None:
        positive_text = _read(POSITIVE)
        negative_text = _read(NEGATIVE)

        self.assertIn("rewardPerTokenStored += rewardAmount / totalStaked", positive_text)
        self.assertIn("rewardDelta / totalStaked * 1e18", positive_text)
        self.assertIn("rayDivFloor(liquidityIndex)", positive_text)
        self.assertIn("transferOnLiquidation(borrower, treasury, scaledProtocolFee)", positive_text)

        self.assertIn("rewardAmount * ACC_PRECISION / totalStaked", negative_text)
        self.assertIn("MathFire39Negative.mulDiv(rewardDelta, ACC_PRECISION, totalStaked)", negative_text)
        self.assertIn("rewardRemainder += rewardAmount", negative_text)
        self.assertIn("rayDivCeil(liquidationProtocolFeeAmount, liquidityIndex)", negative_text)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()
        positive_findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive_findings), 3)
        self.assertEqual(negative_findings, [])
        self.assertEqual({finding.detector for finding in positive_findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in positive_findings}, {"Medium"})
        self.assertEqual(
            {finding.function for finding in positive_findings},
            {
                "distributeUnscaledReward",
                "notifyRewardAfterDivisionScale",
                "liquidationCall",
            },
        )
        self.assertEqual(
            {finding.branch for finding in positive_findings},
            {
                "unscaled reward index",
                "temporary scale-after-division reward increment",
                "liquidation protocol fee floor conversion",
            },
        )

        messages = "\n".join(finding.message for finding in positive_findings)
        self.assertIn("reward-per-token accounting", messages)
        self.assertIn("Scale before dividing", messages)
        self.assertIn("floor-style rounding", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_inline_boundaries_for_safe_syntax_variants(self) -> None:
        detector = _load_detector()
        vulnerable_reward = """
        contract C {
            uint256 public totalStaked;
            uint256 public rewardPerTokenStored;
            function syncRewards(uint256 rewardAmount) external {
                rewardPerTokenStored += rewardAmount / totalStaked;
            }
        }
        """
        safe_scaled_reward = """
        contract C {
            uint256 constant ACC_PRECISION = 1e18;
            uint256 public totalStaked;
            uint256 public rewardPerTokenStored;
            function syncRewards(uint256 rewardAmount) external {
                rewardPerTokenStored += rewardAmount * ACC_PRECISION / totalStaked;
            }
        }
        """
        vulnerable_liquidation = """
        contract C {
            address treasury;
            IAToken aToken;
            uint256 liquidityIndex;
            function liquidationCall(address borrower, uint256 liquidationProtocolFeeAmount) external {
                uint256 protocolFeeShares = liquidationProtocolFeeAmount.rayDivFloor(liquidityIndex);
                aToken.transferOnLiquidation(borrower, treasury, protocolFeeShares);
            }
        }
        """
        safe_liquidation = """
        contract C {
            address treasury;
            IAToken aToken;
            function liquidationCall(address borrower, uint256 liquidationProtocolFeeAmount) external {
                uint256 liquidityIndex = _currentLiquidityIndex();
                uint256 protocolFeeShares = rayDivCeil(liquidationProtocolFeeAmount, liquidityIndex);
                aToken.transferOnLiquidation(borrower, treasury, protocolFeeShares);
            }
        }
        """

        self.assertEqual(len(detector.scan(vulnerable_reward, "vuln_reward.sol")), 1)
        self.assertEqual(detector.scan(safe_scaled_reward, "safe_reward.sol"), [])
        self.assertEqual(len(detector.scan(vulnerable_liquidation, "vuln_liq.sol")), 1)
        self.assertEqual(detector.scan(safe_liquidation, "safe_liq.sol"), [])

    def _run_regex_runner(self, target: Path, manifest: Path) -> dict:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        proc = subprocess.run(
            [
                sys.executable,
                str(RUNNER),
                str(target),
                "--workspace",
                str(manifest.parent),
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
        return json.loads(manifest.read_text(encoding="utf-8"))

    def test_regex_runner_records_positive_hits_and_negative_silence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="fire39_reward_precision_") as tmp:
            positive_data = self._run_regex_runner(POSITIVE, Path(tmp) / "positive.json")
            negative_data = self._run_regex_runner(NEGATIVE, Path(tmp) / "negative.json")

            self.assertEqual(positive_data["per_detector_counts"][DETECTOR_NAME], 3)
            self.assertEqual(negative_data["per_detector_counts"][DETECTOR_NAME], 0)
            self.assertEqual(positive_data["files_scanned"], 1)
            self.assertEqual(negative_data["files_scanned"], 1)
            self.assertEqual(
                {Path(row["file"]).name for row in positive_data["findings"]},
                {POSITIVE.name},
            )

    def test_no_unicode_dashes_in_owned_sources(self) -> None:
        for path in (DETECTOR_PATH, POSITIVE, NEGATIVE, Path(__file__)):
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIsNone(re.search("[\u2013\u2014]", text))


if __name__ == "__main__":
    unittest.main()
