"""Loop-fix 2026-06-23 (etherfi step-5/core-coverage): core-coverage-completeness
read the durable `.auditooor/mvc_sidecar/*.json` files (it is documented to) but its
record parser only understood FLAT per-function rows (a list under results/verdicts/...
or a dict with verdict+source_file). The durable mvc_sidecar CLUSTER schema - one dict
per harness campaign with `harness_path` + `invariants[]` + `mutation_detail[]` +
`mutants_killed` + `cut_contracts[]` - matched none of those, so `_records_from_payload`
returned [] and genuine >=1M-call mutation-verified CORE harnesses (etherfi LiquidRestaking
real LiquidityPool/WeETH, CashSolvency real DebtManagerCore) got ZERO core-coverage credit
-> fail-core-coverage-periphery-only despite real core CUTs. Delivery bug (strong supply,
weak serving join), not a missing harness.

The fix teaches the three parser helpers the cluster schema: recognize it as one record,
treat mutants_killed>=1 / a FAIL mutation_detail row as a genuine kill, and extract CUT
keys from cut_contracts[] AND from the leading CamelCase contract name in each mutant
description. False-green-safe: a vacuous (0-kill) cluster still credits nothing, and CUT
keys join to the core set by basename only (cannot credit a non-core contract).
"""
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location("ccc_cluster", str(_TOOLS / "core-coverage-completeness.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ccc_cluster"] = mod
    spec.loader.exec_module(mod)
    return mod


def _write_vmf(ws: Path, core_file: str):
    d = ws / ".auditooor"
    d.mkdir(parents=True, exist_ok=True)
    (d / "value_moving_functions.json").write_text(json.dumps({
        "workspace": str(ws), "function_count": 1,
        "functions": [{"file": core_file, "function": "withdraw", "language": "sol",
                       "transfer_hit": True, "ledger_write_hit": True}],
    }), encoding="utf-8")


def _write_src(ws: Path, rel: str):
    p = ws / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("// SPDX-License-Identifier: MIT\ncontract C { function withdraw() public {} }\n")


def _write_cluster(ws: Path, name: str, payload: dict):
    d = ws / ".auditooor" / "mvc_sidecar"
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(json.dumps(payload), encoding="utf-8")


class TestCoreCoverageMvcClusterSidecar(unittest.TestCase):
    def test_cluster_with_explicit_cut_contracts_credits_core(self):
        ws = Path(tempfile.mkdtemp())
        _write_src(ws, "src/cash-v3/src/debt-manager/DebtManagerCore.sol")
        _write_vmf(ws, "src/cash-v3/src/debt-manager/DebtManagerCore.sol")
        _write_cluster(ws, "cash_solvency.json", {
            "cluster": "CashSolvency",
            "harness_path": "chimera_harnesses/CashSolvency/src/CashSolvencyHarness.sol",
            "mutation_verified": True, "mutants_killed": 4,
            "cut_contracts": ["src/cash-v3/src/debt-manager/DebtManagerCore.sol"],
            "mutation_detail": [{"mutant": "DebtManagerCore.repay 2x credit",
                                 "baseline": "PASS", "mutant_result": "FAIL"}],
            "result": "honest-negative",
        })
        r = _load().evaluate(ws)
        self.assertEqual(r["verdict"], "pass-core-covered")
        self.assertIn("src/cash-v3/src/debt-manager/DebtManagerCore.sol", r["covered_core"])

    def test_cluster_credits_via_mutant_name_when_no_cut_contracts(self):
        # liquid_restaking.json in the wild has NO cut_contracts; the mutated
        # contract name in mutation_detail[].mutant must still credit the core.
        ws = Path(tempfile.mkdtemp())
        _write_src(ws, "src/smart-contracts/src/LiquidityPool.sol")
        _write_vmf(ws, "src/smart-contracts/src/LiquidityPool.sol")
        _write_cluster(ws, "liquid_restaking.json", {
            "cluster": "LiquidRestaking",
            "harness_path": "chimera_harnesses/LiquidRestaking/harness/LiquidRestakingHarness.sol",
            "mutation_verified": True, "mutants_killed": 3,
            "mutation_detail": [{"mutant": "LiquidityPool._sharesForDepositAmount +5% over-credit",
                                 "baseline": "PASS", "mutant_result": "FAIL"}],
            "result": "honest-negative",
        })
        r = _load().evaluate(ws)
        self.assertEqual(r["verdict"], "pass-core-covered")
        self.assertIn("src/smart-contracts/src/LiquidityPool.sol", r["covered_core"])

    def test_vacuous_cluster_credits_nothing(self):
        # mutants_killed=0 and no FAIL mutation_detail -> not a genuine kill.
        ws = Path(tempfile.mkdtemp())
        _write_src(ws, "src/cash-v3/src/debt-manager/DebtManagerCore.sol")
        _write_vmf(ws, "src/cash-v3/src/debt-manager/DebtManagerCore.sol")
        _write_cluster(ws, "vacuous.json", {
            "cluster": "Vacuous",
            "harness_path": "h.sol",
            "mutation_verified": True, "mutants_killed": 0,
            "cut_contracts": ["src/cash-v3/src/debt-manager/DebtManagerCore.sol"],
            "mutation_detail": [{"mutant": "DebtManagerCore noop", "baseline": "PASS", "mutant_result": "PASS"}],
            "result": "honest-negative",
        })
        r = _load().evaluate(ws)
        self.assertEqual(r["verdict"], "fail-core-coverage-periphery-only")
        self.assertEqual(r["covered_core_count"], 0)

    def test_cluster_cannot_false_green_non_core_contract(self):
        # A kill cluster whose CUT is a PERIPHERY contract must not credit the
        # core (basename join only credits contracts already in the core set).
        ws = Path(tempfile.mkdtemp())
        _write_src(ws, "src/CoreVault.sol")
        _write_src(ws, "src/Logger.sol")
        _write_vmf(ws, "src/CoreVault.sol")
        _write_cluster(ws, "periphery.json", {
            "cluster": "Periphery", "harness_path": "h.sol",
            "mutation_verified": True, "mutants_killed": 2,
            "cut_contracts": ["src/Logger.sol"],
            "mutation_detail": [{"mutant": "Logger.log drop", "baseline": "PASS", "mutant_result": "FAIL"}],
        })
        r = _load().evaluate(ws)
        self.assertEqual(r["verdict"], "fail-core-coverage-periphery-only")


if __name__ == "__main__":
    unittest.main(verbosity=2)
