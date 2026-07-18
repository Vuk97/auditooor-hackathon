from __future__ import annotations

import os
import py_compile
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
PATTERN = "reentrancy-nonce-or-callback-accounting-fire18"
DETECTOR = ROOT / "detectors" / "wave17" / "reentrancy_nonce_or_callback_accounting_fire18.py"
POSITIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "positive"
    / "reentrancy_nonce_or_callback_accounting_fire18.sol"
)
NEGATIVE = (
    ROOT
    / "detectors"
    / "test_fixtures"
    / "negative"
    / "reentrancy_nonce_or_callback_accounting_fire18.sol"
)


def _python_with_slither() -> str | None:
    candidates = [
        os.environ.get("SLITHER_PYTHON"),
        sys.executable,
        "/opt/homebrew/opt/python@3.13/bin/python3.13",
        "/opt/homebrew/bin/python3.13",
    ]
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        try:
            probe = subprocess.run(
                [candidate, "-c", "import slither; import slither.detectors.abstract_detector"],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode == 0:
            return candidate
    return None


class ReentrancyNonceOrCallbackAccountingFire18Test(unittest.TestCase):
    def _run_detector(self, fixture: Path) -> tuple[int, str]:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [slither_python, str(RUNNER), "--tier=ALL", str(fixture), PATTERN],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn(PATTERN, proc.stdout)
        self.assertNotIn("UNKNOWN function predicate key", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1)), proc.stdout

    def test_detector_compiles_and_documents_scope(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)
        self.assertIn("_post_control_finalization_writes", detector_text)
        self.assertIn("_has_balance_based_multi_call_gap", detector_text)
        self.assertIn("state_variables_written", detector_text)

    def test_fixture_pair_contains_bug_and_clean_contrast(self) -> None:
        positive = POSITIVE.read_text(encoding="utf-8")
        negative = NEGATIVE.read_text(encoding="utf-8")

        self.assertIn("IRefundHookFire18(hook).beforeConsume", positive)
        self.assertIn("delete pendingCommitment[commitment];", positive)
        self.assertIn("_safeMint(to, nextTokenId);", positive)
        self.assertIn("nextTokenId += 1;", positive)
        self.assertIn("address(this).balance", positive)
        self.assertIn("operator.call{value:", positive)

        self.assertIn("delete pendingCommitment[commitment];", negative)
        self.assertIn("IRefundHookFire18Clean(hook).beforeConsume", negative)
        self.assertIn("uint256 tokenId = nextTokenId;", negative)
        self.assertIn("function dispatch(bytes32) external payable nonReentrant", negative)
        self.assertIn("function notifyOnly(address target) external", negative)

    def test_positive_fixture_fires_three_times_and_clean_fixture_is_silent(self) -> None:
        positive_hits, positive_output = self._run_detector(POSITIVE)
        clean_hits, clean_output = self._run_detector(NEGATIVE)

        self.assertEqual(positive_hits, 3, positive_output)
        self.assertEqual(clean_hits, 0, clean_output)
        self.assertIn("consumeWithRefund", positive_output)
        self.assertIn("mint", positive_output)
        self.assertIn("dispatch", positive_output)


if __name__ == "__main__":
    unittest.main()
