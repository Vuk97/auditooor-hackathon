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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "state_tocou_external_balance_fire32.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "state_tocou_external_balance_fire32.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "state_tocou_external_balance_fire32.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "state-tocou-external-balance-fire32"


def _load_detector():
    module_name = "state_tocou_external_balance_fire32"
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


class StateTocouExternalBalanceFire32Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

        detector = _load_detector()
        self.assertEqual(detector.DETECTOR_NAME, DETECTOR_NAME)
        self.assertEqual(detector.DETECTOR_SEVERITY_DEFAULT, "Medium")
        self.assertEqual(detector.SUBMISSION_POSTURE, "NOT_SUBMIT_READY")

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
                "mintSharesWithStaleSupply",
                "payoutUsingPreDepositBalance",
                "burnReceiptUsingStaleDebt",
                "borrowWithStaleReserveSolvency",
                "withdrawUsingStaleShareBalance",
            },
        )

        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("pre-boundary supply snapshot `supplyBefore`", messages)
        self.assertIn("pre-boundary balance snapshot `balanceBefore`", messages)
        self.assertIn("pre-boundary debt snapshot `debtBefore`", messages)
        self.assertIn("pre-boundary reserve snapshot `reserveBefore`", messages)
        self.assertIn("pre-boundary share snapshot `sharesBefore`", messages)
        self.assertIn("fresh post-boundary read or delta", messages)

    def test_fixture_pair_contains_fresh_read_contrast(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertRegex(
            positive,
            r"uint256 supplyBefore = shareToken\.totalSupply\(\);"
            r"[\s\S]*asset\.transferFrom\(msg\.sender, address\(this\), assets\);"
            r"[\s\S]*uint256 sharesToMint = assets \* supplyBefore / asset\.balanceOf",
        )
        self.assertRegex(
            positive,
            r"uint256 balanceBefore = asset\.balanceOf\(address\(this\)\);"
            r"[\s\S]*strategy\.deposit\(amount\);"
            r"[\s\S]*uint256 payout = balanceBefore - amount;",
        )
        self.assertRegex(
            positive,
            r"uint256 debtBefore = market\.totalDebt\(msg\.sender\);"
            r"[\s\S]*market\.repay\(msg\.sender, repayAmount\);"
            r"[\s\S]*uint256 remainingDebt = debtBefore - repayAmount;",
        )
        self.assertRegex(
            positive,
            r"uint256 reserveBefore = reserveAssets;"
            r"[\s\S]*pool\.rebalance\(\);"
            r"[\s\S]*require\(reserveBefore \* collateralFactor >=",
        )
        self.assertRegex(
            positive,
            r"uint256 sharesBefore = shareBalance\[msg\.sender\];"
            r"[\s\S]*strategy\.withdraw\(amount\);"
            r"[\s\S]*shareToken\.burn\(msg\.sender, sharesBefore\);",
        )

        for fresh_name in (
            "supplyAfter",
            "balanceAfter",
            "debtAfter",
            "reserveAfter",
            "sharesAfter",
        ):
            with self.subTest(fresh_name=fresh_name):
                self.assertIn(f"uint256 {fresh_name}", negative)

        self.assertNotIn("uint256 payout = balanceBefore - amount;", negative)
        self.assertNotIn("shareToken.burn(msg.sender, sharesBefore);", negative)

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
        self.assertIn("reports/detector_lift_fire31_20260605/post_priorities_all.md", detector_text)
        self.assertIn("detectors/wave17/state_check_token_delta_fire31.py", detector_text)
        self.assertIn(
            "reference/patterns.dsl/state-change-between-check-and-use-token-delta-boundary.yaml",
            detector_text,
        )
        self.assertIn("reference/patterns.dsl/state-check-before-token-or-sender-mutation.yaml", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)

        for path in (DETECTOR_PATH, POSITIVE, NEGATIVE, Path(__file__)):
            with self.subTest(path=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIsNone(re.search("[\u2013\u2014]", text))


if __name__ == "__main__":
    unittest.main()
