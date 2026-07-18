#!/usr/bin/env python3
"""Guard: value-moving-functions must NOT count a Go `package main` build tool
(a //go:generate codegen generator, or the node/cmd entrypoint) as a value-moving
protocol function.

Root cause (axelar-dlt 2026-07-12): parseContracts@x/evm/types/contractsgen/
generate.go - a `package main` go:generate binary that emits Go source - was
shape-flagged ledger_write_hit and inflated the per-language Go value-moving
floor (audit-honesty-check corroborated_genuine[go] >= 45). The Cosmos
value-moving surface lives in library packages (keeper/msg_server/module); a
`package main` file is never a fund/share-conservation obligation.

NEVER-OVER-EXCLUDE: a library-package (`package keeper`) value-mover is still
counted.
"""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location(
        "vmf_pm", str(_TOOLS / "value-moving-functions.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules["vmf_pm"] = m
    spec.loader.exec_module(m)
    return m


class TestGoPackageMainExcluded(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def test_package_main_generator_yields_no_value_movers(self):
        with tempfile.TemporaryDirectory() as t:
            f = Path(t) / "generate.go"
            f.write_text(
                "package main\n\n"
                "import \"os\"\n\n"
                "func parseContracts(path string) error {\n"
                "\treturn os.WriteFile(path, nil, 0644)\n}\n",
                encoding="utf-8")
            recs = self.m._analyze_file(f, "x/evm/types/contractsgen/generate.go", "go")
            self.assertEqual(recs, [], f"package main build tool must yield 0 value-movers: {recs}")

    def test_library_keeper_value_mover_still_counted(self):
        with tempfile.TemporaryDirectory() as t:
            f = Path(t) / "keeper.go"
            # a genuine custody mover in a library package must survive
            f.write_text(
                "package keeper\n\n"
                "func (k Keeper) SendCoins(ctx Ctx, from, to Addr, amt Coins) error {\n"
                "\treturn k.bank.SendCoins(ctx, from, to, amt)\n}\n",
                encoding="utf-8")
            recs = self.m._analyze_file(f, "x/bank/keeper/keeper.go", "go")
            names = {r.get("function") or r.get("name") for r in recs}
            self.assertIn("SendCoins", names,
                          f"library-package value-mover must still be counted: {recs}")


if __name__ == "__main__":
    unittest.main()
