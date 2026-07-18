#!/usr/bin/env python3
"""Focused regression for the W6-8 access-control recall lift."""

from __future__ import annotations

import os
import py_compile
import re
import subprocess
import sys
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
PATTERN = "access-control-third-party-debt-mutation-missing-delegation"
RUNNER = ROOT / "detectors" / "run_custom.py"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
DETECTOR = ROOT / "detectors" / "wave18" / "access_control_third_party_debt_mutation_missing_delegation.py"
FIXTURE_DIR = ROOT / "tools" / "tests" / "fixtures" / "access_control_third_party_debt_mutation"
VULN = FIXTURE_DIR / "vulnerable.sol"
CLEAN = FIXTURE_DIR / "clean.sol"


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


class AccessControlThirdPartyDebtMutationCapabilityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.spec = yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))

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
        self.assertNotIn("No custom detectors found", proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_pattern_metadata_and_fixture_scope(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)

        self.assertEqual(self.spec["pattern"], PATTERN)
        self.assertEqual(self.spec["severity"], "HIGH")
        self.assertEqual(self.spec["confidence"], "MEDIUM")
        self.assertIn("access-control", self.spec["tags"])
        self.assertEqual(self.spec["fixtures"]["vuln"], str(VULN.relative_to(ROOT)))
        self.assertEqual(self.spec["fixtures"]["clean"], str(CLEAN.relative_to(ROOT)))

        detector_text = DETECTOR.read_text(encoding="utf-8")
        self.assertIn(f'ARGUMENT = "{PATTERN}"', detector_text)
        self.assertIn("borrowAllowance", detector_text)
        self.assertIn("debtOf[borrower] += amount", VULN.read_text(encoding="utf-8"))
        self.assertIn("asset.transfer(msg.sender, amount)", VULN.read_text(encoding="utf-8"))
        self.assertIn("borrowAllowance[borrower][msg.sender] >= amount", CLEAN.read_text(encoding="utf-8"))

    def test_vulnerable_fixture_fires_and_clean_fixture_stays_quiet(self) -> None:
        self.assertEqual(self._hits(VULN), 1)
        self.assertEqual(self._hits(CLEAN), 0)


if __name__ == "__main__":
    unittest.main()
