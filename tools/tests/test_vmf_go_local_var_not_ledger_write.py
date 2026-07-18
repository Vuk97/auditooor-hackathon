#!/usr/bin/env python3
"""Regression (generic capability fix, nuva 2026-07-12): the Go value-moving
extractor must NOT flag a function as a ledger write when the only write-shaped
match is an UNQUALIFIED LOCAL variable assignment (`vaults = append(vaults, v)` /
`vaults[a] = true`) with no store/keeper receiver. Those live in read-only
queries, pure constructors, and validators - they move no value, yet the value-
named local (`vaults`/`metadataDenomUnits`) inflated the per-language value-moving
floor as false "uncovered" units.

Assertion 1: a read-only query whose only write-shaped token is a local
`vaults := []T{}` + `vaults = append(...)` is NOT value-moving.
Assertion 2: a genuine cosmos collections keeper store write
`k.vaults.Set(ctx, addr, v)` IS still flagged value-moving (conservative - the fix
must not over-exclude a real store write)."""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("vmf_lv", _T / "value-moving-functions.py")
_m = importlib.util.module_from_spec(_spec)
sys.modules["vmf_lv"] = _m
_spec.loader.exec_module(_m)


def _analyze_go(src: str) -> list[dict]:
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "x.go"
        p.write_text(src, encoding="utf-8")
        return _m._analyze_file(p, "x.go", "go")


class TestGoLocalVarNotLedgerWrite(unittest.TestCase):
    def test_local_slice_build_is_not_value_moving(self):
        # read-only query: build + return a local slice; no store/keeper write.
        src = (
            "func (k Keeper) Vaults(ctx context.Context) []types.VaultAccount {\n"
            "    vaults := []types.VaultAccount{}\n"
            "    for _, v := range all {\n"
            "        vaults = append(vaults, v)\n"
            "    }\n"
            "    return vaults\n"
            "}\n"
        )
        recs = _analyze_go(src)
        vm = [r for r in recs if r["function"] == "Vaults"]
        self.assertEqual(vm, [], f"local-slice query must not be value-moving; got {vm}")

    def test_local_dedup_map_is_not_value_moving(self):
        # pure validator: local dedup map keyed on a value-named local.
        src = (
            "func (gs GenesisState) Validate() error {\n"
            "    vaults := make(map[string]bool)\n"
            "    for _, v := range gs.Vaults {\n"
            "        vaults[v.Address] = true\n"
            "    }\n"
            "    return nil\n"
            "}\n"
        )
        recs = _analyze_go(src)
        vm = [r for r in recs if r["function"] == "Validate"]
        self.assertEqual(vm, [], f"local dedup-map validator must not be value-moving; got {vm}")

    def test_keeper_collections_store_write_is_flagged(self):
        # genuine store write: collections `.Set(...)` on a value-named store.
        src = (
            "func (k Keeper) SetVault(ctx context.Context, addr string, v types.VaultAccount) {\n"
            "    k.vaults.Set(ctx, addr, v)\n"
            "}\n"
        )
        recs = _analyze_go(src)
        vm = [r for r in recs if r["function"] == "SetVault"]
        self.assertEqual(len(vm), 1, f"genuine keeper store write must be flagged; got {recs}")
        self.assertTrue(vm[0]["ledger_write_hit"],
                        "collections store write must set ledger_write_hit")

    def test_qualified_keeper_bare_assign_still_counts(self):
        # a QUALIFIED bare assignment (`k.balances[addr] = x`) is a real ledger
        # write and must still count - the guard only drops UNQUALIFIED locals.
        src = (
            "func (k Keeper) credit(ctx context.Context, addr string, amt Int) {\n"
            "    k.balances[addr] = amt\n"
            "}\n"
        )
        recs = _analyze_go(src)
        vm = [r for r in recs if r["function"] == "credit"]
        self.assertEqual(len(vm), 1, f"qualified keeper write must be flagged; got {recs}")
        self.assertIn("balances", vm[0]["ledger_write_evidence"])


if __name__ == "__main__":
    unittest.main()
