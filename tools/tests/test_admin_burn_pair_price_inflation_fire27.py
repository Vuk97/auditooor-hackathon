from __future__ import annotations

import importlib.util
import json
import os
import py_compile
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
DETECTOR_PATH = REPO / "detectors" / "wave17" / "admin_burn_pair_price_inflation_fire27.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "admin_burn_pair_price_inflation_fire27.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "admin_burn_pair_price_inflation_fire27.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "admin-burn-pair-price-inflation-fire27"


def _load_detector():
    module_name = "admin_burn_pair_price_inflation_fire27"
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


class AdminBurnPairPriceInflationFire27Test(unittest.TestCase):
    def test_detector_and_fixture_sources_are_aligned(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        positive_text = _read(POSITIVE)
        negative_text = _read(NEGATIVE)

        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn("burn-on-transfer-to-pair-inflates-price", detector_text)
        self.assertIn("abi-encode-packed-hash-collision", detector_text)
        self.assertIn("ccip-receiver-and-chain-unvalidated", detector_text)
        self.assertIn("admin-bypass", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)

        self.assertIn("function emergencyAdminBurnPairReserve", positive_text)
        self.assertIn("external onlyOwner", positive_text)
        self.assertIn("balanceOf[ammPair] -= amount;", positive_text)
        self.assertIn("totalSupply -= amount;", positive_text)
        self.assertIn("IUniswapV2PairLike(ammPair).sync();", positive_text)

        self.assertIn("require(msg.sender == router", negative_text)
        self.assertIn("approvedPools[pool]", negative_text)
        self.assertIn("token0() == address(this)", negative_text)
        self.assertIn("token1() == address(this)", negative_text)
        self.assertIn("balanceOf[msg.sender] -= amount;", negative_text)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        positive_findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive_findings), 1)
        self.assertEqual(negative_findings, [])
        self.assertEqual({finding.detector for finding in positive_findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in positive_findings}, {"High"})
        self.assertEqual(
            {finding.function for finding in positive_findings},
            {"emergencyAdminBurnPairReserve"},
        )

        message = positive_findings[0].message
        self.assertIn("admin-controlled", message)
        self.assertIn("AMM reserve", message)
        self.assertIn("inflate spot price", message)
        self.assertIn("pool-domain authorization", message)
        self.assertIn("NOT_SUBMIT_READY", message)

    def test_guarded_pool_domain_inline_source_is_silent(self) -> None:
        detector = _load_detector()
        source = """
        pragma solidity ^0.8.20;
        interface IPair {
            function token0() external view returns (address);
            function token1() external view returns (address);
            function sync() external;
        }
        contract GuardedPoolBurn {
            address public router;
            mapping(address => uint256) public balanceOf;
            uint256 public totalSupply;
            function routerBurn(address pool, uint256 amount) external {
                require(msg.sender == router, "router");
                require(IPair(pool).token0() == address(this) || IPair(pool).token1() == address(this), "domain");
                balanceOf[pool] -= amount;
                totalSupply -= amount;
                IPair(pool).sync();
            }
        }
        """
        self.assertEqual(detector.scan(source, "GuardedPoolBurn.sol"), [])

    def test_regex_runner_reports_positive_only(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        with tempfile.TemporaryDirectory(prefix="fire27_admin_burn_pair_") as tmp:
            positive_manifest = Path(tmp) / "positive.json"
            negative_manifest = Path(tmp) / "negative.json"

            positive_proc = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    str(POSITIVE),
                    "--workspace",
                    tmp,
                    "--output",
                    str(positive_manifest),
                    "--detector",
                    DETECTOR_NAME,
                    "--json-only",
                ],
                cwd=REPO,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30,
            )
            self.assertEqual(positive_proc.returncode, 0, positive_proc.stdout)

            negative_proc = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    str(NEGATIVE),
                    "--workspace",
                    tmp,
                    "--output",
                    str(negative_manifest),
                    "--detector",
                    DETECTOR_NAME,
                    "--json-only",
                ],
                cwd=REPO,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=30,
            )
            self.assertEqual(negative_proc.returncode, 0, negative_proc.stdout)

            positive_data = json.loads(positive_manifest.read_text(encoding="utf-8"))
            negative_data = json.loads(negative_manifest.read_text(encoding="utf-8"))

            self.assertEqual(positive_data["per_detector_counts"][DETECTOR_NAME], 1)
            self.assertEqual(negative_data["per_detector_counts"][DETECTOR_NAME], 0)
            self.assertEqual(
                {Path(row["file"]).name for row in positive_data["findings"]},
                {POSITIVE.name},
            )
            self.assertEqual(negative_data["findings"], [])


if __name__ == "__main__":
    unittest.main()
