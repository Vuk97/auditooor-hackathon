#!/usr/bin/env python3
"""Regression tests for tools/stale-accrual-before-value-gate-dominance.py.

Proves the accrual-dominance set-difference query READERS\\DOMINATED is:
  - a SET relation whose predicate DISCRIMINATES: an entrypoint that reads a
    lazily-accrued Q to authorize a fund move but whose closure has NO accrual is
    a SURVIVOR; the SAME entrypoint once an accrual call is added to its closure
    is KEPT (the NON-VACUITY MUTATION case - the guard is load-bearing, not the
    trivial "all readers" answer);
  - TRANSITIVE: an accrual reached N hops deep in a helper KEEPS the entrypoint
    (impossible for a body-scoped regex);
  - NOT a shape: a fund-mover with no Q-read is not a reader; a Q-reader with no
    fund move is not a reader;
  - HONEST on class-absence: a repo with no accrual primitive reports class_present
    False + an honest cited-empty (distinct from a vacuous 0-fn substrate).
"""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_TOOL = _HERE.parent / "stale-accrual-before-value-gate-dominance.py"
_spec = importlib.util.spec_from_file_location("stale_accrual", _TOOL)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


# A synthetic Cosmos-style vault. SwapOut reads Q (ConvertSharesToRedeemCoin) and
# moves value (SendCoins) but NEVER reconciles -> stale-accrual survivor.
# Withdraw reads Q AND calls reconcileVault first -> DOMINATED (kept).
_VAULT_STALE = """
package keeper

func (k Keeper) reconcileVault(ctx Ctx, v *Vault) error {
    return nil
}

func (k Keeper) ConvertSharesToRedeemCoin(ctx Ctx, v Vault, shares Int) (Coin, error) {
    return Coin{}, nil
}

func (k Keeper) SwapOut(ctx Ctx, v *Vault, shares Int) error {
    assets, _ := k.ConvertSharesToRedeemCoin(ctx, *v, shares)
    return k.BankKeeper.SendCoins(ctx, owner, v.Addr, assets)
}

func (k Keeper) Withdraw(ctx Ctx, v *Vault, shares Int) error {
    k.reconcileVault(ctx, v)
    assets, _ := k.ConvertSharesToRedeemCoin(ctx, *v, shares)
    return k.BankKeeper.SendCoins(ctx, owner, v.Addr, assets)
}

func (k Keeper) SetSwapEnabled(ctx Ctx, v *Vault, on bool) error {
    v.Enabled = on
    return nil
}
"""

# The SAME repo but SwapOut now transitively reconciles through a helper
# `settleAndPay` (accrual N hops deep) - proving the KEEP is TRANSITIVE.
_VAULT_TRANSITIVE_FIX = """
package keeper

func (k Keeper) reconcileVault(ctx Ctx, v *Vault) error { return nil }

func (k Keeper) settleAndPay(ctx Ctx, v *Vault) error {
    return k.reconcileVault(ctx, v)
}

func (k Keeper) ConvertSharesToRedeemCoin(ctx Ctx, v Vault, shares Int) (Coin, error) {
    return Coin{}, nil
}

func (k Keeper) SwapOut(ctx Ctx, v *Vault, shares Int) error {
    k.settleAndPay(ctx, v)
    assets, _ := k.ConvertSharesToRedeemCoin(ctx, *v, shares)
    return k.BankKeeper.SendCoins(ctx, owner, v.Addr, assets)
}
"""

# A repo with NO accrual primitive at all (axelar-style) - the class does not
# apply -> honest cited-empty.
_NO_ACCRUAL = """
package keeper

func (k Keeper) LinkAddress(ctx Ctx, a Addr) error {
    return k.BankKeeper.SendCoins(ctx, a, mod, coins)
}

func (k Keeper) totalAssets(ctx Ctx) Int { return Int{} }
"""


def _write(tmp: Path, name: str, body: str) -> Path:
    p = tmp / "src"
    p.mkdir(parents=True, exist_ok=True)
    f = p / name
    f.write_text(body)
    return tmp


def _run(tmp: Path) -> dict:
    emit = tmp / "out.jsonl"
    return mod.run(["--workspace", str(tmp), "--emit", str(emit), "--json"])


class NodePredicateTest(unittest.TestCase):
    def test_accrual_predicate(self):
        for n in ("reconcileVault", "accrueInterest", "_updateInterestIndex",
                  "checkpoint", "poke", "atomicallyReconcileInterest",
                  "CalculateAccruedInterest", "settleInterest"):
            self.assertTrue(mod._ACCRUAL.match(n), n)

    def test_accrual_negatives(self):
        # a getter / setter / unrelated fn is NOT an accrual primitive.
        for n in ("SwapOut", "SetSwapEnabled", "totalAssets", "LinkAddress",
                  "GetVault"):
            self.assertFalse(mod._ACCRUAL.match(n), n)

    def test_q_read_and_value_predicates(self):
        self.assertTrue(mod._Q_READ.match("ConvertSharesToRedeemCoin"))
        self.assertTrue(mod._Q_READ.match("healthFactor"))
        self.assertTrue(mod._VALUE_CALL.match("SendCoins"))
        self.assertTrue(mod._VALUE_CALL.match("Enqueue"))
        self.assertFalse(mod._Q_READ.match("SetSwapEnabled"))


class SetDifferenceDiscriminatesTest(unittest.TestCase):
    def test_survivor_and_kept_split(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            _write(tmp, "vault.go", _VAULT_STALE)
            s = _run(tmp)
            self.assertTrue(s["class_present"])
            survivors = {x["fn"] for x in s["survivors"]}
            # SwapOut reads Q + moves value, NO reconcile -> survivor
            self.assertIn("SwapOut", survivors)
            # Withdraw reconciles first -> KEPT (dominated), NOT a survivor
            self.assertNotIn("Withdraw", survivors)
            self.assertIn("Withdraw", s["kept_readers_with_accrual"])
            # SetSwapEnabled neither reads Q nor moves value -> not a reader
            self.assertNotIn("SetSwapEnabled", survivors)
            # non-vacuous: there IS a kept reader, so it is not "all readers"
            self.assertGreaterEqual(s["size_DOMINATED"], 1)

    def test_nonvacuity_mutation_kills_the_survivor(self):
        # THE non-vacuity mutation: give SwapOut a (transitive) accrual call. The
        # SAME fn must flip survivor -> kept, proving the accrual-closure guard is
        # load-bearing (not a trivial predicate that keeps everything a survivor).
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            _write(tmp, "vault.go", _VAULT_TRANSITIVE_FIX)
            s = _run(tmp)
            survivors = {x["fn"] for x in s["survivors"]}
            self.assertNotIn("SwapOut", survivors,
                             "accrual N hops deep must KEEP SwapOut (transitive)")
            self.assertIn("SwapOut", s["kept_readers_with_accrual"])
            self.assertEqual(s["size_DIFF_survivors"], 0)

    def test_obligation_written_for_survivor(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            _write(tmp, "vault.go", _VAULT_STALE)
            s = _run(tmp)
            rows = [json.loads(l) for l in
                    Path(s["obligations_path"]).read_text().splitlines() if l.strip()]
            self.assertTrue(any(r["function"] == "SwapOut" for r in rows))
            r = next(r for r in rows if r["function"] == "SwapOut")
            self.assertEqual(r["schema"], "auditooor.stale_accrual_value_gate.v1")
            self.assertEqual(r["attack_class"],
                             "stale-lazy-accrual-quantity-gates-value-action")
            self.assertTrue(r["source_refs"])


class HonestEmptyTest(unittest.TestCase):
    def test_no_accrual_primitive_is_honest_empty_not_survivors(self):
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d)
            _write(tmp, "nexus.go", _NO_ACCRUAL)
            s = _run(tmp)
            self.assertFalse(s["class_present"])
            self.assertEqual(s["size_DIFF_survivors"], 0)
            self.assertTrue(s["honest_empty_class_not_present"])
            # substrate DID materialize (fns indexed) - not a vacuous empty
            self.assertGreater(s["n_functions_indexed"], 0)
            self.assertFalse(s["substrate_vacuous"])


if __name__ == "__main__":
    unittest.main()
