from __future__ import annotations

import importlib.util
import py_compile
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DETECTOR = ROOT / "detectors" / "wave17" / "fund_loss_safecast_int128_fire26.py"
REGEX_RUNNER = ROOT / "detectors" / "run_regex_detectors.py"
PATTERN = "fund-loss-safecast-int128-fire26"
POSITIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "fund_loss_safecast_int128_fire26.sol"
)
NEGATIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "fund_loss_safecast_int128_fire26.sol"
)
SOURCE_BACKED_POSITIVE = ROOT / "patterns" / "fixtures" / "fx-v4core-safecast-int128-missing_vuln.sol"
SOURCE_BACKED_CLEAN = ROOT / "patterns" / "fixtures" / "fx-v4core-safecast-int128-missing_clean.sol"


def _load_detector():
    module_name = "fund_loss_safecast_int128_fire26"
    if module_name in sys.modules:
        return sys.modules[module_name]
    spec = importlib.util.spec_from_file_location(module_name, DETECTOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


class FundLossSafecastInt128Fire26Test(unittest.TestCase):
    def test_detector_and_fixture_sources_are_aligned(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector_text = _read(DETECTOR)
        positive_text = _read(POSITIVE)
        negative_text = _read(NEGATIVE)

        self.assertIn(f'DETECTOR_NAME = "{PATTERN}"', detector_text)
        self.assertIn("signed-delta-to-uint128", detector_text)
        self.assertIn("wide-value-to-uint128", detector_text)
        self.assertIn("value-to-int128", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)
        self.assertIn("PROMOTION_ALLOWED = False", detector_text)

        self.assertIn("uint128 credit = uint128(delta);", positive_text)
        self.assertIn("int128 liquidityDelta = -int128(liquidityAmount);", positive_text)
        self.assertIn("uint128 bookedAmount = uint128(amount);", positive_text)

        self.assertIn("SafeCastFire26.toUint128FromInt(delta)", negative_text)
        self.assertIn("liquidityAmount.toInt128()", negative_text)
        self.assertIn("amount.toUint128()", negative_text)
        self.assertIn("require(amount <= type(uint128).max", negative_text)

    def test_owned_positive_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        positive_findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        negative_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(positive_findings), 3)
        self.assertEqual(negative_findings, [])
        self.assertEqual(
            {finding.function for finding in positive_findings},
            {"applyDelta", "burnLiquidity", "settleBalance"},
        )
        self.assertEqual(
            {re.search(r"branch ([^:]+):", finding.message).group(1) for finding in positive_findings},
            {"signed-delta-to-uint128", "value-to-int128", "wide-value-to-uint128"},
        )

    def test_source_backed_uniswap_v4_fixture_pair(self) -> None:
        detector = _load_detector()

        vuln_findings = detector.scan(_read(SOURCE_BACKED_POSITIVE), str(SOURCE_BACKED_POSITIVE))
        clean_findings = detector.scan(_read(SOURCE_BACKED_CLEAN), str(SOURCE_BACKED_CLEAN))

        self.assertEqual(len(vuln_findings), 1)
        self.assertEqual(vuln_findings[0].function, "applyDelta")
        self.assertIn("signed-delta-to-uint128", vuln_findings[0].message)
        self.assertEqual(clean_findings, [])

    def test_regex_runner_entrypoint_fires_and_stays_silent(self) -> None:
        positive = subprocess.run(
            [
                sys.executable,
                str(REGEX_RUNNER),
                str(POSITIVE),
                "--detector",
                PATTERN,
                "--no-manifest",
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        self.assertEqual(positive.returncode, 0, positive.stdout)
        self.assertIn("total hits: 3", positive.stdout)

        negative = subprocess.run(
            [
                sys.executable,
                str(REGEX_RUNNER),
                str(NEGATIVE),
                "--detector",
                PATTERN,
                "--no-manifest",
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        self.assertEqual(negative.returncode, 0, negative.stdout)
        self.assertIn("total hits: 0", negative.stdout)


if __name__ == "__main__":
    unittest.main()
