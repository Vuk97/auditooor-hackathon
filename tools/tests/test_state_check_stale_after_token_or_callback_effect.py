from __future__ import annotations

import json
import os
import py_compile
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "detectors" / "run_custom.py"
PATTERN = "state-check-stale-after-token-or-callback-effect"
DETECTOR = ROOT / "detectors" / "wave17" / "state_check_stale_after_token_or_callback_effect.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "state_check_stale_after_token_or_callback_effect"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
SMOKE = FIXTURE_DIR / "smoke.json"
EC_FOT_VULN = ROOT / "patterns" / "fixtures" / "ec-fot-token-in-non-fot-pool_vuln.sol"
PAYMASTER_VULN = ROOT / "patterns" / "fixtures" / "erc4337-paymaster-no-sender-validation_vuln.sol"
FIRE6_POSITIVE = (
    ROOT
    / "detectors"
    / "fixtures"
    / "reentrancy_external_callback_before_accounting_finalized"
    / "positive.sol"
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


class StateCheckStaleAfterTokenOrCallbackEffectTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> int:
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
        return int(match.group(1))

    def test_detector_reference_and_fixture_scope_stay_aligned(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        reference_text = REFERENCE.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        payload = json.loads(SMOKE.read_text(encoding="utf-8"))

        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)
        self.assertIn("_token_effect_stales_checked_amount", detector_text)
        self.assertIn("_callback_effect_stales_policy_check", detector_text)

        self.assertIn("state-check-before-token-or-sender-mutation.yaml", reference_text)
        self.assertIn("callback_before_accounting_finalized_cross_contract.py", reference_text)
        self.assertIn("submission_posture: NOT_SUBMIT_READY", reference_text)

        self.assertIn("function swap(uint256 amount0In, address to)", positive_text)
        self.assertIn("token0.transferFrom(msg.sender, address(this), amount0In);", positive_text)
        self.assertIn("amount0In * uint256(reserve1)", positive_text)
        self.assertIn("policy.beforeSponsor(userOp.sender, maxCost);", positive_text)
        self.assertIn("spent[userOp.sender] += maxCost;", positive_text)

        self.assertIn("uint256 actualReceived = balanceAfter - balanceBefore;", clean_text)
        self.assertIn("uint256 quotaAfter = quota[userOp.sender];", clean_text)
        self.assertIn("not sponsored after policy", clean_text)

        self.assertEqual(payload["pattern"], PATTERN)
        self.assertEqual(payload["status"], "smoke_pass")
        self.assertEqual(payload["coverage_claim"], "detector_fixture_smoke_only")
        self.assertFalse(payload["promotion_allowed"])
        self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(payload["positive_hits"], 2)
        self.assertEqual(payload["clean_hits"], 0)

    def test_positive_fixture_fires_twice_and_clean_fixture_stays_quiet(self) -> None:
        self.assertEqual(self._hits(POSITIVE), 2)
        self.assertEqual(self._hits(CLEAN), 0)

    def test_source_backed_boundary_and_adjacent_splits(self) -> None:
        self.assertEqual(self._hits(EC_FOT_VULN), 1)
        self.assertEqual(self._hits(PAYMASTER_VULN), 0)
        self.assertEqual(self._hits(FIRE6_POSITIVE), 0)


if __name__ == "__main__":
    unittest.main()
