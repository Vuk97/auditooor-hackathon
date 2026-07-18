#!/usr/bin/env python3
"""Focused tests for Worker FR's fee-accounting guard DSL lift."""

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
RUNNER = ROOT / "detectors" / "run_custom.py"
PATTERN = "worker-fr-fee-accounting-guard-missing"
REFERENCE = ROOT / "reference" / "patterns.dsl" / f"{PATTERN}.yaml"
DETECTOR = ROOT / "detectors" / "wavefire4_fr" / f"{PATTERN.replace('-', '_')}.py"
VULN = ROOT / "patterns" / "fixtures" / f"{PATTERN}_vuln.sol"
CLEAN = ROOT / "patterns" / "fixtures" / f"{PATTERN}_clean.sol"

EXISTING_FIXTURES = [
    ("amm-reserves-fee-conflation", ROOT / "patterns" / "fixtures" / "amm-reserves-fee-conflation_vuln.sol", 2),
    ("fee-calculation-accrual-missing", ROOT / "patterns" / "fixtures" / "fee-calculation-accrual-missing_vuln.sol", 2),
    ("fx-euler-protocol-fee-share-unbounded", ROOT / "patterns" / "fixtures" / "fx-euler-protocol-fee-share-unbounded_vuln.sol", 1),
]

EXISTING_CLEAN_FIXTURES = [
    ROOT / "patterns" / "fixtures" / "amm-reserves-fee-conflation_clean.sol",
    ROOT / "patterns" / "fixtures" / "fee-calculation-accrual-missing_clean.sol",
    ROOT / "patterns" / "fixtures" / "fx-euler-protocol-fee-share-unbounded_clean.sol",
]


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


class WorkerFrFeeAccountingGuardMissingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.slither_python = _python_with_slither()

    def _hits(self, fixture: Path) -> int:
        if self.slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [self.slither_python, str(RUNNER), "--tier=ALL", str(fixture), PATTERN],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn(PATTERN, proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_dsl_metadata_is_bounded_to_fee_redirect_fixtures(self) -> None:
        spec = yaml.safe_load(REFERENCE.read_text(encoding="utf-8"))

        self.assertEqual(spec["pattern"], PATTERN)
        self.assertIn("fee-redirect", spec["tags"])
        self.assertEqual(spec["confidence"], "LOW")
        self.assertEqual(spec["fixtures"]["vuln"], f"patterns/fixtures/{PATTERN}_vuln.sol")
        self.assertEqual(spec["fixtures"]["clean"], f"patterns/fixtures/{PATTERN}_clean.sol")
        for slug in (
            "amm-reserves-fee-conflation",
            "fee-calculation-accrual-missing",
            "fx-euler-protocol-fee-share-unbounded",
        ):
            self.assertIn(slug, spec["cross_refs"])

    def test_fixture_pair_models_three_guard_families(self) -> None:
        vuln = VULN.read_text(encoding="utf-8")
        clean = CLEAN.read_text(encoding="utf-8")

        self.assertIn("amount0 = (liquidity * reserve0) / totalSupply;", vuln)
        self.assertIn("feePerSecond = newRate;", vuln)
        self.assertIn("return protocolShare;", vuln)
        self.assertNotIn("uint256 realReserve0 = reserve0 - accruedFee;", vuln)
        self.assertNotIn("accrueFee();", vuln)
        self.assertNotIn("feeReceiver == address(0)", vuln)

        self.assertIn("uint256 realReserve0 = reserve0 - accruedFee;", clean)
        self.assertIn("accrueFee();", clean)
        self.assertIn("feeReceiver == address(0)", clean)
        self.assertIn("protocolShare > MAX_PROTOCOL_FEE_SHARE", clean)

    def test_compiled_detector_smoke_counts(self) -> None:
        py_compile.compile(str(DETECTOR), doraise=True)
        self.assertEqual(self._hits(VULN), 5)
        self.assertEqual(self._hits(CLEAN), 0)

    def test_existing_requested_fixtures_are_recalled_and_clean_controls_silent(self) -> None:
        for slug, fixture, expected_hits in EXISTING_FIXTURES:
            with self.subTest(slug=slug):
                self.assertEqual(self._hits(fixture), expected_hits)

        for fixture in EXISTING_CLEAN_FIXTURES:
            with self.subTest(fixture=fixture.name):
                self.assertEqual(self._hits(fixture), 0)


if __name__ == "__main__":
    unittest.main()
