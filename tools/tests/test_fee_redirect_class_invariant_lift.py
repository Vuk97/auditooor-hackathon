#!/usr/bin/env python3
"""Focused regression coverage for the shared fee-redirect class invariant lift."""

from __future__ import annotations

import importlib.util
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
BACKTEST_PATH = ROOT / "tools" / "audit" / "detector-catch-rate-backtest.py"
REGISTRY_PATH = ROOT / "detectors" / "_tier_registry.yaml"

SEED_PATTERNS = {
    "amm-reserves-fee-conflation": ROOT / "reference" / "patterns.dsl" / "amm-reserves-fee-conflation.yaml",
    "fee-billed-over-approval-allowance": ROOT / "reference" / "patterns.dsl" / "fee-billed-over-approval-allowance.yaml",
}
SHARED_PATTERN = "fee-ledger-sink-mismatch"
SHARED_PATTERN_PATH = ROOT / "reference" / "patterns.dsl" / f"{SHARED_PATTERN}.yaml"
SHARED_DETECTOR = ROOT / "detectors" / "wave18" / "fee_ledger_sink_mismatch.py"
SHARED_VULN = ROOT / "patterns" / "fixtures" / "fee-ledger-sink-mismatch_vuln.sol"
SHARED_CLEAN = ROOT / "patterns" / "fixtures" / "fee-ledger-sink-mismatch_clean.sol"
AMM_VULN = ROOT / "patterns" / "fixtures" / "amm-reserves-fee-conflation_vuln.sol"
AMM_CLEAN = ROOT / "patterns" / "fixtures" / "amm-reserves-fee-conflation_clean.sol"


def _load_backtest():
    spec = importlib.util.spec_from_file_location("detector_catch_rate_backtest", BACKTEST_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


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


class FeeRedirectClassInvariantLiftTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.seed_specs = {
            name: yaml.safe_load(path.read_text(encoding="utf-8"))
            for name, path in SEED_PATTERNS.items()
        }
        cls.shared_spec = yaml.safe_load(SHARED_PATTERN_PATH.read_text(encoding="utf-8"))
        cls.registry = yaml.safe_load(REGISTRY_PATH.read_text(encoding="utf-8"))
        cls.backtest = _load_backtest()

    def _hits(self, fixture: Path, pattern: str) -> int:
        slither_python = _python_with_slither()
        if slither_python is None:
            self.skipTest("slither-analyzer is not importable by the tested Python interpreters")

        env = os.environ.copy()
        env["AUDITOOOR_FIXTURE_SMOKE_MODE"] = "1"
        env["AUDITOOOR_SLITHER_NOCACHE"] = "1"
        proc = subprocess.run(
            [slither_python, str(RUNNER), "--tier=ALL", str(fixture), pattern],
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn(pattern, proc.stdout)
        match = re.search(r"total hits:\s*(\d+)", proc.stdout)
        self.assertIsNotNone(match, proc.stdout)
        return int(match.group(1))

    def test_seed_patterns_are_cross_linked_into_shared_invariant(self) -> None:
        for seed_name, spec in self.seed_specs.items():
            self.assertIn("fee-redirect", spec["tags"])
            self.assertIn(SHARED_PATTERN, spec["cross_refs"])
            self.assertIn("actor-ledger-mismatch", spec["tags"])

        self.assertEqual(self.shared_spec["pattern"], SHARED_PATTERN)
        self.assertIn("fee-redirect", self.shared_spec["tags"])
        self.assertIn("actor-ledger-mismatch", self.shared_spec["tags"])
        self.assertIn("amm-reserves-fee-conflation", self.shared_spec["cross_refs"])
        self.assertIn("fee-billed-over-approval-allowance", self.shared_spec["cross_refs"])

    def test_shared_fixture_pair_models_both_fee_sink_variants(self) -> None:
        vuln = SHARED_VULN.read_text(encoding="utf-8")
        clean = SHARED_CLEAN.read_text(encoding="utf-8")

        self.assertIn("allowance[from][msg.sender] -= amount;", vuln)
        self.assertIn("uint256 feeFloat = accruedFee;", vuln)
        self.assertIn("a0 = (liquidity * reserve0) / totalSupply + feeFloat - feeFloat;", vuln)
        self.assertNotIn("allowance[from][msg.sender] -= totalDebit;", vuln)
        self.assertNotIn("realReserve0 = reserve0 - accruedFee;", vuln)

        self.assertIn("allowance[from][msg.sender] -= totalDebit;", clean)
        self.assertIn("uint256 realReserve0 = reserve0 - accruedFee;", clean)

    def test_registry_and_backtest_classification_stay_fee_redirect(self) -> None:
        amm_entry = self.registry["tiers"]["amm-reserves-fee-conflation"]
        shared_entry = self.registry["tiers"][SHARED_PATTERN]

        self.assertEqual(amm_entry["fixture_pair"], "patterns/fixtures/amm-reserves-fee-conflation")
        self.assertEqual(amm_entry["smoke_test_vuln_hits"], 1)
        self.assertEqual(amm_entry["smoke_test_clean_hits"], 0)

        self.assertEqual(shared_entry["fixture_pair"], "patterns/fixtures/fee-ledger-sink-mismatch")
        self.assertEqual(shared_entry["smoke_test_vuln_hits"], 2)
        self.assertEqual(shared_entry["smoke_test_clean_hits"], 0)

        self.assertEqual(
            self.backtest.derive_attack_class("amm-reserves-fee-conflation", self.seed_specs["amm-reserves-fee-conflation"].get("tags")),
            "fee-redirect",
        )
        self.assertEqual(
            self.backtest.derive_attack_class("fee-billed-over-approval-allowance", self.seed_specs["fee-billed-over-approval-allowance"].get("tags")),
            "fee-redirect",
        )
        self.assertEqual(
            self.backtest.derive_attack_class(SHARED_PATTERN, self.shared_spec.get("tags")),
            "fee-redirect",
        )

    def test_compiled_shared_detector_and_smoke_counts_match_expectation(self) -> None:
        py_compile.compile(str(SHARED_DETECTOR), doraise=True)
        detector_text = SHARED_DETECTOR.read_text(encoding="utf-8")
        self.assertIn(f'ARGUMENT = "{SHARED_PATTERN}"', detector_text)
        self.assertIn("Fee ledger sink mismatch across actor and accounting boundaries", detector_text)

        self.assertEqual(self._hits(SHARED_VULN, SHARED_PATTERN), 2)
        self.assertEqual(self._hits(SHARED_CLEAN, SHARED_PATTERN), 0)

    def test_existing_amm_fixture_pair_stays_live_after_registry_add(self) -> None:
        self.assertEqual(self._hits(AMM_VULN, "amm-reserves-fee-conflation"), 1)
        self.assertEqual(self._hits(AMM_CLEAN, "amm-reserves-fee-conflation"), 0)


if __name__ == "__main__":
    unittest.main()
