#!/usr/bin/env python3
"""Guard test: invariant-auto-synth.py must synthesize invariants for the Go (Cosmos SDK)
keeper ECONOMIC CORE, not only the gRPC (ctx,msg) message handlers.

Pinned gap (NUVA 2026-06-30): synth_invariants_go only emitted candidates when params
matched (ctx + msg) - i.e. only msg_server.go. Internal keeper methods (valuation_engine.go
NAV math, abci.go BeginBlocker interest accrual, payout.go, reconcile.go) have no msg param,
so they produced 0 candidates -> 0 invariants -> 0 per-fn hunt questions -> the entire
economic core (where BOTH filed NUVA findings live) was silently unhunted. The fix adds
value/accounting/math name-keyword coverage + a generic ctx-state-mutator catch-all
(getters excluded).
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "invariant-auto-synth.py"

VALUATION_GO = """package keeper

import sdk "github.com/cosmos/cosmos-sdk/types"

// economic core - NO msg param, previously produced 0 invariants
func (k Keeper) CalculateNAV(ctx sdk.Context, vault Vault) sdk.Int { return sdk.ZeroInt() }
func (ve *ValuationEngine) Value(ctx sdk.Context) sdk.Int { return sdk.ZeroInt() }
func (k Keeper) accrueInterest(ctx sdk.Context) error { return nil }
func (k Keeper) BeginBlocker(ctx sdk.Context) {}
func (k Keeper) reconcile(ctx sdk.Context) error { return nil }
func (k Keeper) GetVault(ctx sdk.Context, addr string) (Vault, bool) { return Vault{}, false }
"""


class GoEconomicCoreInvariantTest(unittest.TestCase):
    def setUp(self):
        self.ws = Path(tempfile.mkdtemp(prefix="inv_go_econ_"))
        (self.ws / "src" / "vault" / "keeper").mkdir(parents=True)
        (self.ws / "src" / "vault" / "keeper" / "valuation_engine.go").write_text(VALUATION_GO)
        self.out = self.ws / "inv.jsonl"

    def _run(self):
        rc = subprocess.run(
            [sys.executable, str(_TOOL), "--workspace", str(self.ws),
             "--output", str(self.out), "--json"],
            capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(rc.returncode, 0, rc.stderr)
        rows = [json.loads(l) for l in self.out.read_text().splitlines() if l.strip()]
        return {r.get("function"): r for r in rows if r.get("language") == "go"}

    def test_economic_core_functions_get_invariants(self):
        fns = self._run()
        # the value/accounting/math + BeginBlocker functions must now appear
        for need in ("CalculateNAV", "Value", "accrueInterest", "BeginBlocker", "reconcile"):
            self.assertIn(need, fns, f"{need} must produce invariants (was silently unhunted)")
        # NAV/accounting fns carry the conservation + overflow invariants
        nav_cands = " ".join(fns["CalculateNAV"].get("invariant_candidates", []))
        self.assertIn("accounting-conservation", nav_cands)
        self.assertIn("no-overflow-precision", nav_cands)

    def test_getter_excluded(self):
        fns = self._run()
        # pure getters must NOT be emitted (would flood the hunt with view functions)
        self.assertNotIn("GetVault", fns, "getters must stay out of the state-mutator catch-all")


if __name__ == "__main__":
    unittest.main()
