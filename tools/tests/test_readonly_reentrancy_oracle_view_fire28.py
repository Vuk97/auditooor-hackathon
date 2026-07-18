from __future__ import annotations

import importlib.util
import os
import py_compile
import re
import subprocess
import sys
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
DETECTOR_PATH = REPO / "detectors" / "wave17" / "readonly_reentrancy_oracle_view_fire28.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "readonly_reentrancy_oracle_view_fire28.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "readonly_reentrancy_oracle_view_fire28.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "readonly-reentrancy-oracle-view-fire28"
SOURCE_REFS = [
    REPO
    / "reference"
    / "patterns.dsl.r94_solodit_reentrancy"
    / "balancerpairoracle-read-only-reentrancy-no-vault-guard.yaml",
    REPO
    / "reference"
    / "patterns.dsl.r94_solodit_reentrancy"
    / "wsteth-eth-curve-lp-price-manipulable-via-readonly-reentrancy.yaml",
]


def _load_detector():
    module_name = "readonly_reentrancy_oracle_view_fire28"
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


class ReadonlyReentrancyOracleViewFire28Test(unittest.TestCase):
    def test_detector_compiles_and_cites_source_refs(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)

        detector_text = _read(DETECTOR_PATH)
        self.assertIn(f'DETECTOR_NAME = "{DETECTOR_NAME}"', detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)
        self.assertIn("attack_class: reentrancy-cross-contract", detector_text)
        self.assertIn("balancerpairoracle-read-only-reentrancy-no-vault-guard.yaml", detector_text)
        self.assertIn("wsteth-eth-curve-lp-price-manipulable-via-readonly-reentrancy.yaml", detector_text)
        for source_ref in SOURCE_REFS:
            self.assertTrue(source_ref.is_file(), str(source_ref))

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()
        positive = detector.scan(_read(POSITIVE), POSITIVE.name)
        negative = detector.scan(_read(NEGATIVE), NEGATIVE.name)

        self.assertEqual(len(positive), 3)
        self.assertEqual({finding.function for finding in positive}, {"getPrice", "virtualPrice", "getRate"})
        self.assertTrue(all(finding.detector == DETECTOR_NAME for finding in positive))
        self.assertTrue(all(finding.severity == "High" for finding in positive))
        self.assertTrue(all("read-only reentrancy mitigation" in finding.message for finding in positive))
        self.assertEqual(negative, [])

    def test_fixture_pair_documents_mitigation_boundaries(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("balancerVault.getPoolTokens(poolId)", positive)
        self.assertIn("curvePool.get_virtual_price()", positive)
        self.assertIn("poolRateProvider.getRate()", positive)

        self.assertIn("_ensureNotInVaultContext();", negative)
        self.assertIn("curvePool.remove_liquidity(0, zeroAmounts);", negative)
        self.assertIn("lastRateBlock == block.number", negative)
        self.assertIn("twapOracle.consult(pool, 30 minutes)", negative)

    def test_source_refs_support_readonly_reentrancy_class(self) -> None:
        joined = "\n".join(_read(source_ref) for source_ref in SOURCE_REFS)
        self.assertIn("ReadOnlyReentrancy", joined)
        self.assertIn("getPoolTokens", joined)
        self.assertIn("virtual_price", joined)
        self.assertIn("no reentrancy guard", joined)

    def test_regex_runner_discovers_detector_for_fixture_pair(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        for fixture, expected_hits in ((POSITIVE, 3), (NEGATIVE, 0)):
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
                    cwd=REPO,
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
