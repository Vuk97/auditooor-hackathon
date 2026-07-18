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
PATTERN = "rebasing-lst-payout-locked-in-nominal-units"
DETECTOR = ROOT / "detectors" / "wave17" / "rebasing_lst_payout_locked_in_nominal_units.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "rebasing_lst_payout_locked_in_nominal_units"
POSITIVE = FIXTURE_DIR / "positive.sol"
CLEAN = FIXTURE_DIR / "clean.sol"
SMOKE = FIXTURE_DIR / "smoke.json"


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
            proc = subprocess.run(
                [candidate, "-c", "import slither; import slither.detectors.abstract_detector"],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode == 0:
            return candidate
    return None


class RebasingLstPayoutLockedInNominalUnitsTest(unittest.TestCase):
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
        self.assertNotIn("UNKNOWN predicate key", proc.stdout)
        self.assertNotIn("UNKNOWN function predicate key", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_reference_yaml_and_smoke_metadata(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        reference_text = REFERENCE.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        smoke = json.loads(SMOKE.read_text(encoding="utf-8"))

        self.assertIn("status: not-submit-ready", reference_text)
        self.assertIn("coverage_claim: detector_fixture_smoke_only", reference_text)
        self.assertIn("promotion_allowed: false", reference_text)
        self.assertIn("submission_posture: NOT_SUBMIT_READY", reference_text)
        self.assertNotIn("contract.name_matches", reference_text)
        self.assertIn(
            "vuln: detectors/fixtures/rebasing_lst_payout_locked_in_nominal_units/positive.sol",
            reference_text,
        )
        self.assertIn(
            "clean: detectors/fixtures/rebasing_lst_payout_locked_in_nominal_units/clean.sol",
            reference_text,
        )

        self.assertIn("contract RebasingLstWithdrawQueuePositive", positive_text)
        self.assertIn("amountToRedeem", positive_text)
        self.assertIn("stETH.safeTransfer(msg.sender, request.amountToRedeem);", positive_text)

        self.assertIn("contract RebasingLstWithdrawQueueClean", clean_text)
        self.assertIn("getSharesByPooledEth", clean_text)
        self.assertIn("getPooledEthByShares", clean_text)

        self.assertEqual(smoke["schema"], "auditooor.canonical_detector_fixture_smoke.v1")
        self.assertEqual(smoke["pattern"], PATTERN)
        self.assertEqual(smoke["positive_hits"], 1)
        self.assertEqual(smoke["clean_hits"], 0)
        self.assertEqual(smoke["coverage_claim"], "detector_fixture_smoke_only")
        self.assertFalse(smoke["promotion_allowed"])
        self.assertEqual(smoke["submission_posture"], "NOT_SUBMIT_READY")

    def test_positive_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertGreaterEqual(self._hits(POSITIVE), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
