#!/usr/bin/env python3
"""Guard test: scope_exclusion classifies Cosmos-SDK test-harness dirs (/simulation/,
/simapp/, /testutils/) as test/OOS - the single source of truth used by the coverage
gates. NUVA 2026-06-30: the cross-function / core / function coverage gates enumerated
deposit|withdraw@vault/simulation as a mutation-verify requirement on OOS sim code."""
import importlib.util
import unittest
from pathlib import Path

_SE_PATH = Path(__file__).resolve().parents[1] / "lib" / "scope_exclusion.py"
_spec = importlib.util.spec_from_file_location("scope_exclusion", _SE_PATH)
SE = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(SE)


class CosmosSimExclusionTest(unittest.TestCase):
    def test_simulation_dir_is_test_and_oos(self):
        for p in ("src/vault/simulation/vault.go", "x/vault/simulation/operations.go"):
            self.assertTrue(SE.is_test(p), f"{p} must be test")
            self.assertTrue(SE.is_oos(p), f"{p} must be OOS")

    def test_simapp_dir_is_test_and_oos(self):
        for p in ("src/vault/simapp/app.go", "simapp/export.go"):
            self.assertTrue(SE.is_test(p), f"{p} must be test")
            self.assertTrue(SE.is_oos(p), f"{p} must be OOS")

    def test_testutils_dir_is_test(self):
        self.assertTrue(SE.is_test("src/vault/testutils/helpers.go"))

    def test_production_keeper_and_types_still_in_scope(self):
        # the economic core + types must NOT be excluded by this change
        for p in ("src/vault/keeper/valuation_engine.go", "src/vault/types/msgs.go",
                  "src/nuva-evm-contracts/contracts/prime/NuvaVault.sol"):
            self.assertFalse(SE.is_test(p), f"{p} must stay in-scope")


if __name__ == "__main__":
    unittest.main()
