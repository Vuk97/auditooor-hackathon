#!/usr/bin/env python3
"""Regression tests for go_ast_consensus_hook_unbounded_iteration - the chain-halt
(consensus-hook unbounded iteration) detector. Grounded in the NUVA/Provenance miss:
BeginBlocker -> WalkDue over an uncapped timeout queue while a sibling hook IS capped."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "detectors" / "go_ast_consensus_hook_unbounded_iteration.py"
_spec = importlib.util.spec_from_file_location("chui", _TOOL)
chui = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(chui)


def _pkg(files: dict[str, str]) -> str:
    d = Path(tempfile.mkdtemp(prefix="chui_"))
    for rel, body in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return str(d)


# Positive: the NUVA shape - BeginBlocker -> uncapped WalkDue over a growable queue,
# with a SIBLING EndBlocker call that IS capped (MaxSwapOutBatchSize) -> CRITICAL.
NUVA_ABCI = """package keeper
const MaxSwapOutBatchSize = 100
func (k *Keeper) BeginBlocker(ctx Context) error {
    return k.handleVaultInterestTimeouts(ctx)
}
func (k *Keeper) EndBlocker(ctx Context) error {
    return k.processPendingSwapOuts(ctx, MaxSwapOutBatchSize)
}
"""
NUVA_RECONCILE = """package keeper
func (k Keeper) handleVaultInterestTimeouts(ctx Context) error {
    return k.PayoutTimeoutQueue.WalkDue(ctx, now, func(t uint64, a Addr) (bool, error) {
        return false, nil
    })
}
func (k Keeper) processPendingSwapOuts(ctx Context, batch int) error {
    count := 0
    return k.SwapOutQueue.Walk(ctx, nil, func(a Addr) (bool, error) {
        count++
        if count >= batch { return true, nil }
        return false, nil
    })
}
func (k *Keeper) Enqueue(ctx Context) { k.PayoutTimeoutQueue.Enqueue(ctx, x) }
"""


class ConsensusHookUnboundedTest(unittest.TestCase):
    def test_fires_on_uncapped_hook_walk_critical(self):
        root = _pkg({"keeper/abci.go": NUVA_ABCI, "keeper/reconcile.go": NUVA_RECONCILE})
        rep = chui.scan_root(root)
        fns = {f["function"] for f in rep["findings"]}
        self.assertIn("handleVaultInterestTimeouts", fns, "must flag the uncapped BeginBlocker walk")
        crit = [f for f in rep["findings"] if f["function"] == "handleVaultInterestTimeouts"]
        self.assertEqual(crit[0]["severity_hint"], "critical", "sibling-cap asymmetry -> CRITICAL")
        self.assertEqual(crit[0]["reached_from_hook"], "BeginBlocker")
        self.assertEqual(crit[0]["walk"], "WalkDue")

    def test_does_not_flag_capped_sibling(self):
        root = _pkg({"keeper/abci.go": NUVA_ABCI, "keeper/reconcile.go": NUVA_RECONCILE})
        rep = chui.scan_root(root)
        fns = {f["function"] for f in rep["findings"]}
        self.assertNotIn("processPendingSwapOuts", fns,
                         "the in-scope batch cap (count >= batch break) must suppress the finding")

    def test_non_hook_walk_not_flagged(self):
        # a Walk in a plain query handler NOT reachable from any consensus hook
        pkg = """package keeper
func (k Keeper) QueryAll(ctx Context) error {
    return k.SomeQueue.Walk(ctx, nil, func(a Addr) (bool, error) { return false, nil })
}
"""
        root = _pkg({"keeper/query.go": pkg})
        rep = chui.scan_root(root)
        self.assertEqual(rep["finding_count"], 0, "walk not reachable from a block hook is not a halt vector")

    def test_capped_hook_walk_clean(self):
        # a BeginBlocker whose walk IS bounded in-scope -> no finding
        pkg = """package keeper
func (k *Keeper) BeginBlocker(ctx Context) error {
    n := 0
    return k.Q.Walk(ctx, nil, func(a Addr) (bool, error) {
        n++
        if n >= 100 { return true, nil }
        return false, nil
    })
}
"""
        root = _pkg({"keeper/abci.go": pkg})
        rep = chui.scan_root(root)
        self.assertEqual(rep["finding_count"], 0, "in-scope cap (n >= 100 break) makes the hook bounded")


if __name__ == "__main__":
    unittest.main(verbosity=2)
