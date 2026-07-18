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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "deprecated_market_liquidation_block_fire28.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "deprecated_market_liquidation_block_fire28.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "deprecated_market_liquidation_block_fire28.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "deprecated-market-liquidation-block-fire28"
SOURCE_REFS = [
    REPO
    / "reference"
    / "patterns.dsl.r74_mined_spearbit"
    / "borrow-token-caps-may-prevent-repayment-and-liquidations.yaml",
    REPO
    / "reference"
    / "patterns.dsl.r74_mined_cs.PROMOTED"
    / "liquidation-revert-due-to-unrelated-paused.yaml",
    REPO
    / "reference"
    / "patterns.dsl.zellic_k2_mined"
    / "reserve-cap-bypass-freezes-liquidation.yaml",
]


def _load_detector():
    module_name = "deprecated_market_liquidation_block_fire28"
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


class DeprecatedMarketLiquidationBlockFire28Test(unittest.TestCase):
    def test_detector_compiles(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)

    def test_source_refs_support_detector_family(self) -> None:
        refs = "\n".join(_read(path) for path in SOURCE_REFS)
        self.assertIn("Borrow token caps may prevent repayment and liquidations", refs)
        self.assertIn("Liquidation Revert Due to Unrelated Paused", refs)
        self.assertIn("Reserve cap bypass freezes liquidation", refs)
        self.assertIn("ignore caps during debt reduction", refs)

    def test_positive_fixture_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        positive_findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(negative_findings, [])
        self.assertEqual(len(positive_findings), 2)
        self.assertEqual(
            {finding.function for finding in positive_findings},
            {"liquidateBorrow", "repayBorrow"},
        )
        self.assertEqual({finding.detector for finding in positive_findings}, {DETECTOR_NAME})

        messages = "\n".join(finding.message for finding in positive_findings)
        self.assertIn("pause/deprecated/frozen/cap state", messages)
        self.assertIn("liquidation-only bypass or debt-reduction exception", messages)
        self.assertIn("supply cap", messages)
        self.assertIn("frozen", messages)

    def test_fixture_pair_locks_fp_boundaries(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertIn("function liquidateBorrow(address borrower, address market", positive)
        self.assertIn("require(!m.deprecated", positive)
        self.assertIn("require(m.totalSupply + repayAmount <= m.supplyCap", positive)
        self.assertNotIn("liquidationKeeper", positive)
        self.assertNotIn("debtReductionMode", positive)

        self.assertIn("msg.sender == liquidationKeeper", negative)
        self.assertIn("if (!debtReductionMode)", negative)
        self.assertIn("function setMarketPaused", negative)
        self.assertIn("function supply", negative)

    def test_regex_runner_discovers_detector_for_owned_fixture_pair(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        for fixture, expected_hits in ((POSITIVE, 2), (NEGATIVE, 0)):
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
