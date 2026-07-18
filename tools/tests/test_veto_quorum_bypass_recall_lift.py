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
PATTERN = "r74-abi-quorum-lost-after-manual-value-set"
DETECTOR = ROOT / "detectors" / "wave17" / "r74_abi_quorum_lost_after_manual_value_set.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
FIXTURE_DIR = ROOT / "detectors" / "fixtures" / "veto_quorum_bypass_recall_lift"
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


class VetoQuorumBypassRecallLiftTest(unittest.TestCase):
    def _hits(self, fixture: Path) -> int:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [
                slither_python,
                str(RUNNER),
                "--tier=ALL",
                str(fixture),
                PATTERN,
            ],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn(PATTERN, proc.stdout)
        self.assertNotIn("No custom detectors found", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_recall_lift_fixture_hits_veto_threshold_and_voting_power_setters(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        detector_text = DETECTOR.read_text(encoding="utf-8")
        reference_text = REFERENCE.read_text(encoding="utf-8")
        positive_text = POSITIVE.read_text(encoding="utf-8")
        clean_text = CLEAN.read_text(encoding="utf-8")
        smoke_payload = json.loads(SMOKE.read_text(encoding="utf-8"))

        self.assertIn("veto/quorum setter", detector_text)
        self.assertIn("writes quorum-like storage", detector_text)
        self.assertIn("setVetoThreshold", detector_text)
        self.assertIn("VotingPower", detector_text)
        self.assertIn("setGovernanceConfig", detector_text)
        self.assertIn("config path", detector_text)
        self.assertIn("live denominator", detector_text)
        self.assertIn("NOT_SUBMIT_READY", detector_text)

        self.assertIn("cross-domain-optimistic-veto-denominator-mismatch", reference_text)
        self.assertIn("batch02-governance-quorum-denominator-cast-votes", reference_text)
        self.assertIn("veto-selector-check-wrapper-bypass", reference_text)
        self.assertIn("quorum-denominator-static-stale-total-power", reference_text)

        self.assertIn("function setVetoThreshold(uint256 newThreshold) external", positive_text)
        self.assertIn("function setVotingPower(uint256 newVotingPower) external", positive_text)
        self.assertIn("function setGovernanceConfig(GovernanceConfig calldata newConfig) external", positive_text)
        self.assertNotIn("_validateVetoBounds", positive_text)
        self.assertNotIn("_validateVotingPower", positive_text)

        self.assertIn("function setVetoThreshold(uint256 newThreshold) external", clean_text)
        self.assertIn("_validateVetoBounds(newThreshold);", clean_text)
        self.assertIn("_validateVotingPower(newVotingPower);", clean_text)
        self.assertIn("function setGovernanceConfig(GovernanceConfig calldata newConfig) external", clean_text)
        self.assertIn("_validateDenominator(newConfig.vetoDenominator);", clean_text)
        self.assertIn("require(newDenominator == 10_000", clean_text)

        self.assertEqual(smoke_payload["pattern"], PATTERN)
        self.assertEqual(smoke_payload["status"], "passed_vulnerable_clean_smoke")
        self.assertEqual(smoke_payload["positive_hits"], 3)
        self.assertEqual(smoke_payload["clean_hits"], 0)
        self.assertIn("setter or config path", smoke_payload["limitation_note"])

        self.assertGreaterEqual(self._hits(POSITIVE), 3)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
