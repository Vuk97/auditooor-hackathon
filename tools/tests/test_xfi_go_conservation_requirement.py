#!/usr/bin/env python3
"""test_xfi_go_conservation_requirement.py

Enforcement-gap G-1 (2026-07-03): a Go/Cosmos ws with a real bank/module-account
fund-movement surface (SendCoins* / MintCoins / BurnCoins via a bankKeeper) but no
sibling-pair / state-machine requirement WARN-passed (pass-no-requirements) with ZERO
conservation coverage. cross-function-invariant-coverage now derives a value-
conservation requirement over the fund-moving functions. ADVISORY-FIRST: surfaced as
go_conservation_surface always; added to the enforced requirement set ONLY under
AUDITOOOR_XFI_GO_CONSERVATION_STRICT (default OFF).
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "cross-function-invariant-coverage.py"


def _load():
    spec = importlib.util.spec_from_file_location("xfi_gc", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["xfi_gc"] = m
    spec.loader.exec_module(m)
    return m


_GO_MOVER = """package vault
type Keeper struct { bankKeeper BankKeeper }
func (k Keeper) PayInterest(ctx Ctx) error {
    return k.bankKeeper.SendCoinsFromModuleToAccount(ctx, "vault", addr, coins)
}
func (k Keeper) CollectFee(ctx Ctx) error {
    return k.bankKeeper.SendCoins(ctx, from, to, coins)
}
func (k Keeper) Mint(ctx Ctx) error {
    return k.bankKeeper.MintCoins(ctx, "vault", coins)
}
"""


class TestGoConservationRequirement(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def _ws(self, rel, content):
        d = Path(tempfile.mkdtemp())
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return d

    def test_fund_movement_surface_derives_requirement(self):
        ws = self._ws("src/vault/keeper.go", _GO_MOVER)
        req = self.m._go_conservation_requirement(ws)
        self.assertIsNotNone(req)
        self.assertEqual(req.kind, "go-conservation")
        self.assertGreaterEqual(len(req.function_names), 2)
        self.assertIn("PayInterest", req.function_names)

    def test_single_mover_is_not_a_requirement(self):
        ws = self._ws("src/x.go",
                      'package x\nfunc F(k Keeper){ k.bankKeeper.SendCoins(ctx, a, b, c) }\n')
        self.assertIsNone(self.m._go_conservation_requirement(ws), "needs >=2 fund-moving fns")

    def test_no_go_source_is_none(self):
        ws = self._ws("src/A.sol", "contract A {}")
        self.assertIsNone(self.m._go_conservation_requirement(ws))

    def test_no_bank_keeper_is_none(self):
        # SendCoins-looking token but no bankKeeper -> not a real module conservation surface
        ws = self._ws("src/x.go", 'package x\nfunc F(){ foo.SendCoins() }\nfunc G(){ foo.MintCoins() }\n')
        self.assertIsNone(self.m._go_conservation_requirement(ws))

    def test_advisory_first_default_does_not_add(self):
        os.environ.pop("AUDITOOOR_XFI_GO_CONSERVATION_STRICT", None)
        ws = self._ws("src/vault/keeper.go", _GO_MOVER)
        r = self.m.evaluate(ws)
        # default: the derived requirement is NOT enforced; surfaced as advisory only.
        self.assertEqual(r.get("verdict"), "pass-no-requirements")
        self.assertIsNotNone(r.get("go_conservation_surface"))

    def test_strict_enforces_the_requirement(self):
        os.environ["AUDITOOOR_XFI_GO_CONSERVATION_STRICT"] = "1"
        try:
            ws = self._ws("src/vault/keeper.go", _GO_MOVER)
            r = self.m.evaluate(ws)
            # strict: the conservation requirement is enforced; with no mutation-verified
            # test it is UNCOVERED -> fail (the gate the gap exists to close).
            self.assertEqual(r.get("verdict"), "fail-cross-function-uncovered")
            self.assertGreaterEqual(r.get("requirement_count"), 1)
        finally:
            os.environ.pop("AUDITOOOR_XFI_GO_CONSERVATION_STRICT", None)


if __name__ == "__main__":
    unittest.main()
