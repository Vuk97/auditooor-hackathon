#!/usr/bin/env python3
"""End-to-end PLANT-A-BUG regression for the FLUSH-GROUP coupling shape (SCC loop tick-33,
2026-07-08). The tick-32 flush-group detector must catch a REAL non-atomic partial-flush bug
from source, not just a hand-built fixture - and must NOT fire on the atomic (CacheContext+
write) idiom (NUVA's real reconcile is atomic -> cited-NEGATIVE, so a blanket flagger would
be a false-positive machine). Plants a Go keeper fn that persists TWO coupled ledgers
(vaultShares -> Vaults, then stakingShares -> Balances) with an error-return BETWEEN the two
Set calls and NO CacheContext (partial-flush: if validate() errors after the first Set
commits, Vaults persists but Balances does not -> the paired ledgers desync). Asserts the
whole wired chain fires from SOURCE, mirroring the real NUVA idiom (lowercase value fields
like the real _doDeposit / triggerRedeem conserved sets):
  source -> value-moving-functions (VMF captures the 2 lowercase value fields)
         -> state-coupling-graph (SCG emits a promotable flush-group edge)
         -> exploit-queue._gather_from_state_coupling (lead reaches the queue)
         -> audit-completeness-check.check_state_coupling (FAILS-CLOSED under STRICT)
and the ATOMIC counter-case emits ZERO flush-group edges (no FP).

This locks the wiring so the flush-group detector cannot silently become an orphan (never
reaches the queue) or a blanket flagger (fires on the atomic both-or-neither idiom)."""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent

# Non-atomic: two paired persists with an error-return between them, no CacheContext.
# Lowercase value fields (vaultShares/stakingShares) mirror NUVA's real conserved sets -
# PascalCase struct fields are dropped as Go store/type names by _is_nonvalue_field.
_PLANT_NONATOMIC = """package keeper

import sdk "cosmossdk.io/types"

type Keeper struct{ BankKeeper BankKeeper; Vaults Map; Balances Map }

func (k Keeper) reconcilePair(ctx sdk.Context, owner sdk.AccAddress, amt sdk.Coin) error {
\tif err := k.BankKeeper.SendCoins(ctx, owner, k.addr(), sdk.NewCoins(amt)); err != nil {
\t\treturn err
\t}
\tvaultShares := sdk.ZeroInt()
\tvaultShares = vaultShares.Add(amt.Amount)
\tif err := k.Vaults.Set(ctx, owner, vaultShares); err != nil {
\t\treturn err
\t}
\tif err := k.validate(ctx, owner); err != nil {
\t\treturn err
\t}
\tstakingShares := sdk.ZeroInt()
\tstakingShares = stakingShares.Add(amt.Amount)
\tif err := k.Balances.Set(ctx, owner, stakingShares); err != nil {
\t\treturn err
\t}
\treturn nil
}
"""

# Atomic: identical body but wrapped in CacheContext + write() (both-or-neither).
_PLANT_ATOMIC = """package keeper

import sdk "cosmossdk.io/types"

type Keeper struct{ BankKeeper BankKeeper; Vaults Map; Balances Map }

func (k Keeper) reconcilePairAtomic(ctx sdk.Context, owner sdk.AccAddress, amt sdk.Coin) error {
\tcacheCtx, write := ctx.CacheContext()
\tif err := k.BankKeeper.SendCoins(cacheCtx, owner, k.addr(), sdk.NewCoins(amt)); err != nil {
\t\treturn err
\t}
\tvaultShares := sdk.ZeroInt()
\tvaultShares = vaultShares.Add(amt.Amount)
\tif err := k.Vaults.Set(cacheCtx, owner, vaultShares); err != nil {
\t\treturn err
\t}
\tstakingShares := sdk.ZeroInt()
\tstakingShares = stakingShares.Add(amt.Amount)
\tif err := k.Balances.Set(cacheCtx, owner, stakingShares); err != nil {
\t\treturn err
\t}
\twrite()
\treturn nil
}
"""


def _load(name, fname):
    s = importlib.util.spec_from_file_location(name, _T / fname)
    m = importlib.util.module_from_spec(s)
    sys.modules[name] = m
    s.loader.exec_module(m)
    return m


def _build_ws(source: str):
    ws = Path(tempfile.mkdtemp())
    (ws / "keeper").mkdir()
    (ws / "keeper" / "vault.go").write_text(source)
    (ws / ".auditooor").mkdir()
    (ws / ".auditooor" / "inscope_units.jsonl").write_text("")
    subprocess.run([sys.executable, str(_T / "value-moving-functions.py"), str(ws),
                    "--out", str(ws / ".auditooor" / "value_moving_functions.json")],
                   check=True, capture_output=True)
    scg = _load("_fg_scg_" + ws.name, "state-coupling-graph.py")
    scg.main(["--workspace", str(ws), "--emit"])
    return ws


def _edges(ws):
    p = ws / ".auditooor" / "state_coupling_edges.jsonl"
    return [json.loads(l) for l in p.read_text().splitlines()] if p.exists() else []


class TestFlushGroupEndToEndPlant(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ws = _build_ws(_PLANT_NONATOMIC)
        cls.ws_atomic = _build_ws(_PLANT_ATOMIC)

    def test_1_vmf_captured_the_two_paired_value_fields(self):
        fns = json.loads((self.ws / ".auditooor" / "value_moving_functions.json").read_text())["functions"]
        rp = next((r for r in fns if r["function"] == "reconcilePair"), None)
        self.assertIsNotNone(rp, "VMF must capture reconcilePair from source")
        self.assertIn("vaultShares", rp.get("ledger_write_evidence", []))
        self.assertIn("stakingShares", rp.get("ledger_write_evidence", []))

    def test_2_scg_fired_a_promotable_flush_group_edge(self):
        fg = [e for e in _edges(self.ws) if e["kind"] == "flush-group"]
        self.assertTrue(fg, "the SCG must fire a flush-group edge on the non-atomic partial flush")
        self.assertTrue(any(v["fn"] == "reconcilePair" for e in fg for v in e["violators"]))
        self.assertTrue(fg[0]["evidence"]["promotable"], "flush-group edge must be promotable")
        self.assertEqual(fg[0]["evidence"].get("tier"), "partial-flush")

    def test_3_atomic_variant_does_not_fire_no_false_positive(self):
        fg = [e for e in _edges(self.ws_atomic) if e["kind"] == "flush-group"]
        self.assertEqual(fg, [],
                         "CacheContext+write is both-or-neither - must NOT fire flush-group "
                         "(else NUVA's real atomic reconcile would be a false positive)")

    def test_4_lead_reaches_the_exploit_queue(self):
        eq = _load("_fg_eq", "exploit-queue.py")
        rows = [r for r in eq._gather_from_state_coupling(self.ws) if "SCG" in r.get("lead_id", "")]
        fg = [r for r in rows if "flush" in json.dumps(r).lower()]
        self.assertTrue(fg, "the planted flush-group lead must reach the exploit-queue (not an orphan)")

    def test_5_audit_complete_gate_fails_closed_under_strict(self):
        acc = _load("_fg_acc", "audit-completeness-check.py")
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        try:
            r = acc.check_state_coupling(self.ws)
        finally:
            os.environ.pop("AUDITOOOR_L37_STRICT", None)
        self.assertFalse(r.ok,
                         "audit-complete must FAIL-CLOSED on the unprobed planted flush-group under STRICT")

    def test_6_gate_names_the_uncovered_surface_not_just_a_count(self):
        # Operator ask 2026-07-08: the failing gate must NAME what to audit (which coupled
        # cells + which violator file:line), not just report an open-edge count. The
        # completeness check emits open_edge_details; the gate reason cites the top rows.
        scc = _load("_fg_scc_wl", "state-coupling-completeness-check.py")
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        try:
            scc.main(["--workspace", str(self.ws)])
            res = json.loads((self.ws / ".auditooor" / "state_coupling_completeness.json").read_text())
            acc = _load("_fg_acc_wl", "audit-completeness-check.py")
            r = acc.check_state_coupling(self.ws)
        finally:
            os.environ.pop("AUDITOOOR_L37_STRICT", None)
        # (a) the artifact carries an actionable worklist (cells + probe question + file:line)
        details = res.get("open_edge_details") or []
        self.assertTrue(details, "open_edge_details worklist must be emitted for open edges")
        d = details[0]
        self.assertEqual(d["kind"], "flush-group")
        self.assertEqual({d["cell_a"], d["cell_b"]}, {"vaultShares", "stakingShares"})
        self.assertTrue(d.get("probe_question"), "each row must carry a human probe question")
        self.assertTrue(d["violators"], "each row must name the violator site(s)")
        self.assertIn(":", d["violators"][0]["site"], "violator site must be file:line")
        self.assertEqual(d["violators"][0]["fn"], "reconcilePair")
        # (b) the gate reason names the surface, not just a count
        self.assertIn("flush-group", r.reason)
        self.assertIn("reconcilePair", r.reason)
        self.assertIn("vaultShares", r.reason)


# WRAPPER-PERSIST partial-flush (mutation-proven 2026-07-09 on NUVA's real code shape): NUVA
# persists value state via keeper SETTER WRAPPERS (SetVaultShares / SetStakingShares), not bare
# collection .Set(. The flush-group detector must recognize `.Set<Cell>(` wrappers whose suffix
# matches a conserved cell - else it is BLIND to a partial-flush in NUVA's actual code.
_WRAPPER_NONATOMIC = """package keeper

import sdk "cosmossdk.io/types"

type Keeper struct{ BankKeeper BankKeeper }

func (k Keeper) reconcileWrapper(ctx sdk.Context, owner sdk.AccAddress, amt sdk.Coin) error {
\tif err := k.BankKeeper.SendCoins(ctx, owner, k.addr(), sdk.NewCoins(amt)); err != nil {
\t\treturn err
\t}
\tvaultShares := sdk.ZeroInt()
\tvaultShares = vaultShares.Add(amt.Amount)
\tif err := k.SetVaultShares(ctx, owner, vaultShares); err != nil {
\t\treturn err
\t}
\tif err := k.validate(ctx, owner); err != nil {
\t\treturn err
\t}
\tstakingShares := sdk.ZeroInt()
\tstakingShares = stakingShares.Add(amt.Amount)
\tif err := k.SetStakingShares(ctx, owner, stakingShares); err != nil {
\t\treturn err
\t}
\treturn nil
}
"""

# same, wrapped in the atomic CacheContext+write idiom -> mutation-kill boundary (no fire).
_WRAPPER_ATOMIC = _WRAPPER_NONATOMIC.replace(
    "reconcileWrapper(ctx sdk.Context, owner sdk.AccAddress, amt sdk.Coin) error {",
    "reconcileWrapper(ctx sdk.Context, owner sdk.AccAddress, amt sdk.Coin) error {\n"
    "\tcacheCtx, write := ctx.CacheContext()").replace(
    "SendCoins(ctx,", "SendCoins(cacheCtx,").replace(
    "SetVaultShares(ctx,", "SetVaultShares(cacheCtx,").replace(
    "SetStakingShares(ctx,", "SetStakingShares(cacheCtx,").replace(
    "\treturn nil\n}", "\twrite()\n\treturn nil\n}")


class TestFlushGroupWrapperPersist(unittest.TestCase):
    """NUVA-real-pattern: persists via keeper setter wrappers, not bare collection .Set(.
    Mutation verification - the de-atomicized wrapper mutant FIRES; the atomic variant is the
    mutation-kill (proves the interest/reconcile cited-NEGATIVE is non-vacuous)."""

    def test_wrapper_persist_nonatomic_fires(self):
        fg = [e for e in _edges(_build_ws(_WRAPPER_NONATOMIC))
              if e["kind"] == "flush-group" and e["evidence"].get("promotable")]
        self.assertTrue(fg, "a de-atomicized wrapper-persist (SetVaultShares/SetStakingShares) "
                            "partial-flush must FIRE - NUVA's real persist pattern")
        self.assertEqual({fg[0]["cell_a"], fg[0]["cell_b"]}, {"vaultShares", "stakingShares"})

    def test_wrapper_persist_atomic_is_mutation_kill(self):
        fg = [e for e in _edges(_build_ws(_WRAPPER_ATOMIC)) if e["kind"] == "flush-group"]
        self.assertEqual(fg, [], "CacheContext+write wrapper-persist must NOT fire (mutation-kill "
                                 "boundary: the atomicity is the load-bearing guard)")


if __name__ == "__main__":
    unittest.main()
