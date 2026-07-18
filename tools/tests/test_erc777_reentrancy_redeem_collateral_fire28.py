from __future__ import annotations

import importlib.util
import os
import py_compile
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DETECTOR_PATH = ROOT / "detectors" / "wave17" / "erc777_reentrancy_redeem_collateral_fire28.py"
POSITIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "erc777_reentrancy_redeem_collateral_fire28.sol"
)
NEGATIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "erc777_reentrancy_redeem_collateral_fire28.sol"
)
RUNNER = ROOT / "detectors" / "run_regex_detectors.py"
SOURCE_REF_REDEEM = (
    ROOT
    / "reference"
    / "patterns.dsl.r94_solodit_reentrancy"
    / "erc777-reentrancy-during-redeem-charges-more-collateral.yaml"
)
SOURCE_REF_REWARDS = (
    ROOT
    / "reference"
    / "patterns.dsl.r94_solodit_reentrancy"
    / "updateaccountrewards-after-external-call-reentrancy-reward-steal.yaml"
)
DETECTOR_NAME = "erc777-reentrancy-redeem-collateral-fire28"


def _load_detector():
    module_name = "erc777_reentrancy_redeem_collateral_fire28"
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


class ERC777ReentrancyRedeemCollateralFire28Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_source_refs_and_fixture_contracts_exist(self) -> None:
        detector_text = _read(DETECTOR_PATH)
        redeem_ref = _read(SOURCE_REF_REDEEM)
        rewards_ref = _read(SOURCE_REF_REWARDS)
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("erc777-reentrancy-during-redeem-charges-more-collateral", redeem_ref)
        self.assertIn("Vault redeem-shares performs external transfer", rewards_ref)
        self.assertIn(str(SOURCE_REF_REDEEM.relative_to(ROOT)), detector_text)
        self.assertIn(str(SOURCE_REF_REWARDS.relative_to(ROOT)), detector_text)
        self.assertIn("collateralToken.safeTransfer(msg.sender, collateralOut);", positive)
        self.assertIn("shares[msg.sender] -= shareAmount;", positive)
        self.assertIn("rewardToken.safeTransfer(msg.sender, amount);", positive)
        self.assertIn("_updateAccountRewards(msg.sender);", positive)
        self.assertIn("external nonReentrant", negative)
        self.assertIn("assetToken.safeTransferFrom(msg.sender, address(this), amount);", negative)

    def test_positive_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        clean_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(findings), 5)
        self.assertEqual(clean_findings, [])
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual(
            {finding.function for finding in findings},
            {"redeem", "withdrawCollateral", "claimRewards", "liquidate", "exitEth"},
        )
        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("callback-capable value transfer before", messages)
        self.assertIn("ERC777 or receiver-hook reentrancy", messages)

    def test_regex_runner_discovers_detector_for_fixture_pair(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        for fixture, expected_hits in ((POSITIVE, 5), (NEGATIVE, 0)):
            with self.subTest(fixture=fixture.name):
                proc = subprocess.run(
                    [
                        sys.executable,
                        str(RUNNER),
                        str(fixture),
                        "--detector",
                        DETECTOR_NAME,
                        "--no-manifest",
                    ],
                    cwd=ROOT,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(proc.returncode, 0, proc.stdout)
                match = re.search(r"total hits:\s*(\d+)", proc.stdout)
                self.assertIsNotNone(match, proc.stdout)
                self.assertEqual(int(match.group(1)), expected_hits, proc.stdout)


if __name__ == "__main__":
    unittest.main()
