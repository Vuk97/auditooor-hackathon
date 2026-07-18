#!/usr/bin/env python3
"""Test the mechanism-scan-run driver: runs applicable detectors, writes the common
mechanism_scan sidecars, language-gates, and closes the completeness-matrix loop."""
import importlib.util, json, tempfile, unittest
from pathlib import Path

_MOD = Path(__file__).resolve().parents[1] / "mechanism-scan-run.py"
_spec = importlib.util.spec_from_file_location("msr", _MOD)
msr = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(msr)

_GO_HALT = """package keeper
const MaxBatch = 100
func (k *Keeper) BeginBlocker(ctx Context) error { return k.handleTimeouts(ctx) }
func (k *Keeper) EndBlocker(ctx Context) error { return k.processPending(ctx, MaxBatch) }
func (k Keeper) handleTimeouts(ctx Context) error {
    return k.PayoutQueue.WalkDue(ctx, now, func(t uint64, a Addr)(bool,error){return false,nil})
}
func (k Keeper) processPending(ctx Context, b int) error {
    c:=0
    return k.SwapQueue.Walk(ctx,nil,func(a Addr)(bool,error){c++;if c>=b{return true,nil};return false,nil})
}
func (k *Keeper) Enqueue(ctx Context){ k.PayoutQueue.Enqueue(ctx,x) }
"""


def _ws(files):
    d = Path(tempfile.mkdtemp(prefix="msr_"))
    (d / ".auditooor").mkdir()
    inscope = []
    for rel, body in files.items():
        p = d / "src" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
        inscope.append({"file": "src/" + rel, "function": "x"})
    (d / ".auditooor" / "inscope_units.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in inscope), encoding="utf-8")
    return d


class MechScanRunTest(unittest.TestCase):
    def test_driver_writes_sidecar_with_finding(self):
        ws = _ws({"vault/keeper/abci.go": _GO_HALT})
        rep = msr.run(ws)
        self.assertIn("go", rep["ws_languages"])
        sc = ws / ".auditooor" / "mechanism_scan" / "consensus-hook-unbounded-iteration.json"
        self.assertTrue(sc.is_file(), "driver must write the mechanism_scan sidecar")
        data = json.loads(sc.read_text())
        self.assertGreaterEqual(data["finding_count"], 1, "the uncapped BeginBlocker walk must be captured")
        self.assertEqual(data["mechanism"], "consensus-hook-unbounded-iteration")

    def test_language_gating_skips_inapplicable(self):
        ws = _ws({"vault/keeper/abci.go": _GO_HALT})  # go only
        rep = msr.run(ws)
        skipped = {s["detector"] for s in rep["skipped"]}
        self.assertIn("sol_ast_unbounded_attacker_growable_iteration", skipped)
        self.assertIn("rust_substrate_hook_unbounded_iteration", skipped)

    def test_clean_scan_writes_empty_sidecar(self):
        # a go ws with a BOUNDED hook -> detector runs clean -> sidecar with 0 findings
        clean = """package keeper
func (k *Keeper) BeginBlocker(ctx Context) error {
    n:=0
    return k.Q.Walk(ctx,nil,func(a Addr)(bool,error){n++;if n>=100{return true,nil};return false,nil})
}
"""
        ws = _ws({"vault/keeper/abci.go": clean})
        msr.run(ws)
        sc = ws / ".auditooor" / "mechanism_scan" / "consensus-hook-unbounded-iteration.json"
        self.assertTrue(sc.is_file())
        self.assertEqual(json.loads(sc.read_text())["finding_count"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
