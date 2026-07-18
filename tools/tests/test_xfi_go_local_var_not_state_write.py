#!/usr/bin/env python3
"""Regression (generic capability fix, nuva 2026-07-12): cross-function-invariant
coverage must NOT treat a Go function as a state-write member of a cross-function
pair when the only write-shaped match is an UNQUALIFIED LOCAL variable assignment
(`vaults := []T{}` + `vaults = append(vaults, v)` / `vaults[a] = true`) with no
store/keeper receiver. Those live in read-only queries, pure constructors, and
validators - they move no value and must not form a phantom `state:<local>`
cross-fn requirement.

This mirrors the guard added to value-moving-functions.py (commit 9250f04f6b);
the two sibling `_WRITE_RES["go"]` tables are KEEP-IN-SYNC and now consistent.

Assertion 1: a fn whose only Go write is a local slice build is NOT value-moving
(`writes` set empty).
Assertion 2: a genuine cosmos collections keeper store write `k.vaults.Set(ctx,
addr, v)` IS flagged (`writes` non-empty)."""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "cross-function-invariant-coverage.py"


def _load():
    spec = importlib.util.spec_from_file_location("xfi_cov_lv", _TOOL)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["xfi_cov_lv"] = mod
    spec.loader.exec_module(mod)
    return mod


xfi = _load()


def _defs(src: str) -> list:
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "x.go"
        p.write_text(src, encoding="utf-8")
        return xfi._extract_fn_defs(p, "go", "x.go")


class TestGoLocalVarNotStateWrite(unittest.TestCase):
    def test_local_slice_build_is_not_state_write(self):
        # read-only query: build + return a local slice; no store/keeper write.
        # NOTE: named plainly (not a Get*/get* accessor) so the _is_go_readonly_fn
        # getter shortcut does NOT pre-empt the write-scan - this exercises the
        # bare-assign local guard itself.
        src = (
            "func (k Keeper) enumerate(ctx context.Context) []types.VaultAccount {\n"
            "    vaults := []types.VaultAccount{}\n"
            "    for _, v := range all {\n"
            "        vaults = append(vaults, v)\n"
            "    }\n"
            "    return vaults\n"
            "}\n"
        )
        defs = [d for d in _defs(src) if d.name == "enumerate"]
        self.assertEqual(len(defs), 1)
        self.assertEqual(
            defs[0].writes, set(),
            f"local-slice build must not be a state write; got {defs[0].writes}",
        )

    def test_local_dedup_map_is_not_state_write(self):
        # pure validator: local dedup map keyed on a value-named local.
        src = (
            "func (gs GenesisState) check() error {\n"
            "    vaults := make(map[string]bool)\n"
            "    for _, v := range gs.Vaults {\n"
            "        vaults[v.Address] = true\n"
            "    }\n"
            "    return nil\n"
            "}\n"
        )
        defs = [d for d in _defs(src) if d.name == "check"]
        self.assertEqual(len(defs), 1)
        self.assertEqual(
            defs[0].writes, set(),
            f"local dedup-map validator must not be a state write; got {defs[0].writes}",
        )

    def test_keeper_collections_store_write_is_flagged(self):
        # genuine store write: collections `.Set(...)` on a value-named store.
        src = (
            "func (k Keeper) persist(ctx context.Context, addr string, v types.VaultAccount) {\n"
            "    k.vaults.Set(ctx, addr, v)\n"
            "}\n"
        )
        defs = [d for d in _defs(src) if d.name == "persist"]
        self.assertEqual(len(defs), 1)
        self.assertIn(
            "vaults", defs[0].writes,
            f"collections store write must be a state write; got {defs[0].writes}",
        )

    def test_qualified_keeper_bare_assign_still_counts(self):
        # a QUALIFIED bare assignment (`k.balances[addr] = x`) is a real state
        # write and must still count - the guard only drops UNQUALIFIED locals.
        src = (
            "func (k Keeper) credit(ctx context.Context, addr string, amt Int) {\n"
            "    k.balances[addr] = amt\n"
            "}\n"
        )
        defs = [d for d in _defs(src) if d.name == "credit"]
        self.assertEqual(len(defs), 1)
        self.assertIn(
            "balances", defs[0].writes,
            f"qualified keeper write must be a state write; got {defs[0].writes}",
        )


if __name__ == "__main__":
    unittest.main()
