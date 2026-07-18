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
DETECTOR_PATH = REPO / "detectors" / "wave17" / "state_check_token_delta_fire31.py"
POSITIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "state_check_token_delta_fire31.sol"
)
NEGATIVE = (
    REPO
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "state_check_token_delta_fire31.sol"
)
RUNNER = REPO / "detectors" / "run_regex_detectors.py"
DETECTOR_NAME = "state-check-token-delta-fire31"


def _load_detector():
    module_name = "state_check_token_delta_fire31"
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


class StateCheckTokenDeltaFire31Test(unittest.TestCase):
    def test_detector_and_test_compile(self) -> None:
        py_compile.compile(str(DETECTOR_PATH), doraise=True)
        py_compile.compile(str(Path(__file__)), doraise=True)

    def test_positive_fires_and_negative_fixture_is_silent(self) -> None:
        detector = _load_detector()

        findings = detector.scan(_read(POSITIVE), str(POSITIVE))
        clean_findings = detector.scan(_read(NEGATIVE), str(NEGATIVE))

        self.assertEqual(len(findings), 3)
        self.assertEqual(clean_findings, [])
        self.assertEqual({finding.detector for finding in findings}, {DETECTOR_NAME})
        self.assertEqual({finding.severity for finding in findings}, {"Medium"})
        self.assertEqual(
            {finding.function for finding in findings},
            {
                "withdrawUsingPreTransferBalance",
                "spendWithStaleAllowance",
                "callbackUsesCachedAccounting",
            },
        )

        messages = "\n".join(finding.message for finding in findings)
        self.assertIn("pre-boundary balance `balanceBefore`", messages)
        self.assertIn("pre-boundary allowance `allowanceBefore`", messages)
        self.assertIn("pre-boundary cached accounting `accountedBefore`", messages)
        self.assertIn("fresh post-boundary delta or revalidation", messages)

    def test_fixture_pair_contains_revalidation_contrast(self) -> None:
        positive = _read(POSITIVE)
        negative = _read(NEGATIVE)

        self.assertRegex(
            positive,
            r"uint256 balanceBefore = asset\.balanceOf\(address\(this\)\);"
            r"[\s\S]*asset\.transferFrom\(msg\.sender, address\(this\), amount\);"
            r"[\s\S]*uint256 payout = balanceBefore - amount;",
        )
        self.assertRegex(
            positive,
            r"uint256 allowanceBefore = asset\.allowance"
            r"[\s\S]*IReceiverFire31\(receiver\)\.onDeposit"
            r"[\s\S]*accounted\[msg\.sender\] = allowanceBefore - amount;",
        )
        self.assertRegex(
            positive,
            r"uint256 accountedBefore = accounted\[msg\.sender\];"
            r"[\s\S]*IReceiverFire31\(receiver\)\.onDeposit"
            r"[\s\S]*cachedAssets = accountedBefore - amount;",
        )

        self.assertIn("uint256 actualReceived = balanceAfter - balanceBefore;", negative)
        self.assertIn("uint256 allowanceAfter = asset.allowance", negative)
        self.assertIn("uint256 accountedAfter = accounted[msg.sender];", negative)
        self.assertNotIn("uint256 payout = balanceBefore - amount;", negative)
        self.assertNotIn("accounted[msg.sender] = allowanceBefore - amount;", negative)

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
