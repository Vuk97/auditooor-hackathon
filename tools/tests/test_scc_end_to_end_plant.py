#!/usr/bin/env python3
"""End-to-end PLANT-A-BUG regression (operator-demanded, 2026-07-08): prove the wired SCC
chain catches a REAL coupled-state bug from source, not just a fixture. Plants a Go vault
with a share-inflation bug (BuggyMint increments TotalShares WITHOUT receiving the paired
asset) and asserts the whole chain fires:
  source -> value-moving-functions (VMF) -> state-coupling-graph (SCG emit)
         -> exploit-queue._gather_from_state_coupling (lead reaches the queue)
         -> audit-completeness-check.check_state_coupling (FAILS-CLOSED under STRICT)

This locks the wiring fixed in 8b55ab8254 - if any link silently breaks (the SCG becomes an
orphan again, or the gate stops failing-closed), this test goes red."""
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent

_PLANT = """package keeper

import sdk "cosmossdk.io/types"

type VaultAccount struct{ TotalShares sdk.Coin }
type Keeper struct{ BankKeeper BankKeeper; VaultAccounts Map }

// Deposit: receives the asset (bank.Send) AND mints shares - BALANCED (correct).
func (k Keeper) Deposit(ctx sdk.Context, owner sdk.AccAddress, vault VaultAccount, assets, shares sdk.Coin) error {
\tif err := k.BankKeeper.SendCoins(ctx, owner, vault.address(), sdk.NewCoins(assets)); err != nil {
\t\treturn err
\t}
\tvault.TotalShares = vault.TotalShares.Add(shares)
\treturn k.VaultAccounts.Set(ctx, vault.address(), vault)
}

// BuggyMint: mints shares (increments TotalShares) but NEVER receives the paired asset -
// PLANTED SHARE-INFLATION BUG (shares minted without backing assets = insolvency).
func (k Keeper) BuggyMint(ctx sdk.Context, vault VaultAccount, shares sdk.Coin) error {
\tvault.TotalShares = vault.TotalShares.Add(shares)
\treturn k.VaultAccounts.Set(ctx, vault.address(), vault)
}
"""


def _load(name, fname):
    s = importlib.util.spec_from_file_location(name, _T / fname)
    m = importlib.util.module_from_spec(s)
    sys.modules[name] = m
    s.loader.exec_module(m)
    return m


class TestSCCEndToEndPlant(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ws = Path(tempfile.mkdtemp())
        (cls.ws / "keeper").mkdir()
        (cls.ws / "keeper" / "vault.go").write_text(_PLANT)
        (cls.ws / ".auditooor").mkdir()
        (cls.ws / ".auditooor" / "inscope_units.jsonl").write_text("")
        # VMF via its real CLI (argparse is under __main__, no importable main()).
        subprocess.run([sys.executable, str(_T / "value-moving-functions.py"), str(cls.ws),
                        "--out", str(cls.ws / ".auditooor" / "value_moving_functions.json")],
                       check=True, capture_output=True)
        scg = _load("_e2e_scg", "state-coupling-graph.py")
        scg.main(["--workspace", str(cls.ws), "--emit"])

    def test_1_vmf_captured_the_unbalanced_writer_from_source(self):
        import json
        fns = json.loads((self.ws / ".auditooor" / "value_moving_functions.json").read_text())["functions"]
        buggy = next((r for r in fns if r["function"] == "BuggyMint"), None)
        self.assertIsNotNone(buggy, "VMF must capture BuggyMint from source")
        self.assertIn("TotalShares", buggy.get("ledger_write_evidence", []))
        self.assertFalse(buggy.get("transfer_hit"), "BuggyMint moves no asset (the bug)")

    def test_2_scg_fired_the_planted_edge_with_correct_violator(self):
        import json
        edges = [json.loads(l) for l in
                 (self.ws / ".auditooor" / "state_coupling_edges.jsonl").read_text().splitlines()]
        xd = [e for e in edges if e["kind"] == "cross-domain-conservation"]
        self.assertTrue(xd, "the SCG must fire a cross-domain edge on the planted inflation")
        self.assertTrue(any(v["fn"] == "BuggyMint" for e in xd for v in e["violators"]))
        self.assertTrue(xd[0]["evidence"]["promotable"])

    def test_3_lead_reaches_the_exploit_queue(self):
        eq = _load("_e2e_eq", "exploit-queue.py")
        rows = [r for r in eq._gather_from_state_coupling(self.ws)
                if "SCG" in r.get("lead_id", "")]
        self.assertTrue(rows, "the planted coupled-state lead must reach the exploit-queue")

    def test_4_audit_complete_gate_fails_closed_under_strict(self):
        acc = _load("_e2e_acc", "audit-completeness-check.py")
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        try:
            r = acc.check_state_coupling(self.ws)
        finally:
            os.environ.pop("AUDITOOOR_L37_STRICT", None)
        self.assertFalse(r.ok,
                         "audit-complete must FAIL-CLOSED on the unprobed planted coupling under STRICT")


if __name__ == "__main__":
    unittest.main()
