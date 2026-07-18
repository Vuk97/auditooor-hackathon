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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "state_delta_before_use_fire34.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "state_delta_before_use_fire34.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "state_delta_before_use_fire34.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "state-delta-before-use-fire34"


def _load_detector():
    module_name = "state_delta_before_use_fire34"
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


class StateDeltaBeforeUseFire34Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector = _load_detector()
        self.assertEqual(detector.DETECTOR_NAME, DETECTOR_NAME)
        self.assertEqual(detector.DETECTOR_SEVERITY_DEFAULT, "Medium")
        self.assertEqual(detector.SUBMISSION_POSTURE, "NOT_SUBMIT_READY")
        self.assertFalse(detector.PROMOTION_ALLOWED)

    def test_positive_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        clean_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(findings), 5)
        self.assertEqual(clean_findings, [])
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in findings}, {"Medium"})
        self.assertEqual(
            {finding.function for finding in findings},
            {
                "settleForCachedSender",
                "withdrawWithCachedBalance",
                "chargeWithCachedFee",
                "buyWithCachedPrice",
                "accountWithCachedTokenDelta",
            },
        )

        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("pre-boundary sender snapshot `senderSnapshot`", messages)
        self.assertIn("pre-boundary balance snapshot `balanceBefore`", messages)
        self.assertIn("pre-boundary fee snapshot `feeBefore`", messages)
        self.assertIn("pre-boundary price snapshot `priceBefore`", messages)
        self.assertIn("pre-boundary token delta snapshot `receivedDelta`", messages)
        self.assertIn("fresh post-boundary revalidation", messages)

    def test_fixture_pair_contains_revalidation_contrast(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertRegex(
            positive,
            r"address senderSnapshot = currentSender\[orderId\];"
            r"[\s\S]*hook\.beforeSettle\(orderId\);"
            r"[\s\S]*settlementCredit\[senderSnapshot\] \+= amount;",
        )
        self.assertRegex(
            positive,
            r"uint256 balanceBefore = asset\.balanceOf\(address\(this\)\);"
            r"[\s\S]*hook\.beforeSettle\(amount\);"
            r"[\s\S]*uint256 payout = balanceBefore - amount;",
        )
        self.assertRegex(
            positive,
            r"uint256 feeBefore = feeBps;"
            r"[\s\S]*hook\.beforeFee\(amount\);"
            r"[\s\S]*uint256 fee = amount \* feeBefore / 10_000;",
        )
        self.assertRegex(
            positive,
            r"uint256 priceBefore = oracle\.latestPrice\(\);"
            r"[\s\S]*oracle\.refreshPrice\(\);"
            r"[\s\S]*uint256 cost = amount \* priceBefore / 1e18;",
        )
        self.assertRegex(
            positive,
            r"uint256 receivedDelta = asset\.balanceOf\(address\(this\)\) - balanceBefore;"
            r"[\s\S]*hook\.beforeSettle\(amount\);"
            r"[\s\S]*accountedAssets \+= receivedDelta;",
        )

        for fresh_name in (
            "senderAfter",
            "balanceAfter",
            "feeAfter",
            "priceAfter",
            "freshReceivedDelta",
        ):
            with self.subTest(fresh_name=fresh_name):
                self.assertIn(f"uint256 {fresh_name}", negative) if fresh_name != "senderAfter" else self.assertIn(
                    "address senderAfter", negative
                )

        self.assertNotIn("settlementCredit[senderSnapshot] += amount;", negative)
        self.assertNotIn("uint256 payout = balanceBefore - amount;", negative)
        self.assertNotIn("uint256 cost = amount * priceBefore / 1e18;", negative)

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
        self.assertIn("reports/detector_lift_fire33_20260605/post_priorities_all.md", detector_text)
        self.assertIn("reference/patterns.dsl/state-change-between-check-and-use.yaml", detector_text)
        self.assertIn("detectors/wave17/state_check_token_delta_fire31.py", detector_text)
        self.assertIn("detectors/wave17/state_tocou_external_balance_fire32.py", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)

        for path in (DETECTOR_PATH, POSITIVE, NEGATIVE, Path(__file__)):
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIsNone(re.search("[\u2013\u2014]", text))


if __name__ == "__main__":
    unittest.main()
