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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "readonly_reentrancy_accounting_fire35.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "readonly_reentrancy_accounting_fire35.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "readonly_reentrancy_accounting_fire35.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "readonly-reentrancy-accounting-fire35"


def _load_detector():
    module_name = "readonly_reentrancy_accounting_fire35"
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


class ReadonlyReentrancyAccountingFire35Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector = _load_detector()
        self.assertEqual(detector.DETECTOR_NAME, DETECTOR_NAME)
        self.assertEqual(detector.DETECTOR_SEVERITY_DEFAULT, "Medium")
        self.assertEqual(detector.SUBMISSION_POSTURE, "NOT_SUBMIT_READY")
        self.assertFalse(detector.PROMOTION_ALLOWED)

    def test_positive_fixture_fires_on_stale_accounting_after_view_or_hook(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(POSITIVE), str(POSITIVE))

        self.assertEqual(len(findings), 4)
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in findings}, {"Medium"})
        self.assertEqual(
            {finding.function for finding in findings},
            {
                "mintAfterHookWithStaleRate",
                "redeemAfterOracleWithStaleTotal",
                "borrowAfterRateProviderWithStaleIndex",
                "settleAfterHookWithStaleReserve",
            },
        )

        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("exchange rate `rateBefore`", messages)
        self.assertIn("cached total `assetsBefore`", messages)
        self.assertIn("accounting index `indexBefore`", messages)
        self.assertIn("reserve `reserveBefore`", messages)
        self.assertIn("external view or hook boundary", messages)
        self.assertIn("without a fresh refresh", messages)
        self.assertIn("NOT_SUBMIT_READY", messages)

    def test_negative_fixture_refresh_guard_and_local_paths_are_silent(self) -> None:
        detector = _load_detector()
        findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(findings, [])
        negative = _read(NEGATIVE)
        self.assertIn("uint256 rateAfter = exchangeRateStored;", negative)
        self.assertIn("uint256 assetsAfter = totalAssetsCached;", negative)
        self.assertIn("accrueInterest();", negative)
        self.assertIn("uint256 reserveAfter = reserve0;", negative)
        self.assertIn("external nonReentrant", negative)
        self.assertIn("function localAccountingOnly(uint256 amount) external", negative)

    def test_regex_runner_records_positive_hits_and_negative_silence(self) -> None:
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"

        for fixture, expected_hits in ((POSITIVE, 4), (NEGATIVE, 0)):
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

    def test_source_refs_and_no_unicode_dashes_in_owned_sources(self) -> None:
        detector_text = _read(DETECTOR_PATH)
        self.assertIn("reports/detector_lift_fire34_20260605/post_priorities_all.md", detector_text)
        self.assertIn(
            "reference/patterns.dsl/reentrancy-cross-contract-stale-state-callback.yaml",
            detector_text,
        )
        self.assertIn(
            "reference/patterns.dsl/fx-euler-erc4626-view-readonly-reentrancy-unguarded.yaml",
            detector_text,
        )
        self.assertIn("detectors/wave17/callback_ledger_settlement_fire33.py", detector_text)
        self.assertIn("detectors/wave17/read_only_reentrancy_view.py", detector_text)
        self.assertIn("R37", detector_text)
        self.assertIn("R40", detector_text)
        self.assertIn("R76", detector_text)
        self.assertIn("R80", detector_text)

        for path in (DETECTOR_PATH, POSITIVE, NEGATIVE, Path(__file__)):
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIsNone(re.search("[\u2013\u2014]", text))


if __name__ == "__main__":
    unittest.main()
