#!/usr/bin/env python3
"""G3 - hook-panic-no-recover arm of go_ast_consensus_hook_unbounded_iteration.

Predicate: a panic-source op (nil-map/index write, type-assert w/o comma-ok,
unchecked / or %) inside a Begin/End/PreBlock-hook-reachable body with NO
recover() on the path. mechanism=hook-panic-no-recover impact=chain-halt,
verdict='needs-fuzz' (NO-AUTO-CREDIT). Non-vacuous: each test would FLIP if the
predicate or a specific FP-guard were removed."""
import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "detectors" / "go_ast_consensus_hook_unbounded_iteration.py"
_FIX = Path(__file__).resolve().parent / "fixtures" / "G3"
_spec = importlib.util.spec_from_file_location("chui_g3", _TOOL)
chui = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(chui)


def _pkg(files: dict) -> str:
    d = Path(tempfile.mkdtemp(prefix="g3_"))
    for rel, body in files.items():
        p = d / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return str(d)


class HookPanicNoRecoverTest(unittest.TestCase):
    def test_fixture_positive_and_negative(self):
        rep = chui.scan_panic_no_recover(str(_FIX))
        fns = {h["function"] for h in rep["hypotheses"]}
        # nil-map write in a 1-hop hook callee -> POSITIVE.
        self.assertIn("handleTimeouts", fns, "must flag the nil-map write on the hook path")
        # 2-hop type-assert without comma-ok -> POSITIVE (extends past 1-hop).
        self.assertIn("unsafeAssert", fns, "hops>=2 must reach the type-assert callee")
        # fully guarded (recover + comma-ok + zero-check) -> NEGATIVE.
        self.assertNotIn("processJobs", fns, "recover()+comma-ok+zero-check must suppress")
        for h in rep["hypotheses"]:
            self.assertEqual(h["verdict"], "needs-fuzz", "NO-AUTO-CREDIT")
            self.assertEqual(h["mechanism"], "hook-panic-no-recover")
            self.assertEqual(h["impact"], "chain-halt")

    def test_recover_guard_is_load_bearing(self):
        # Same nil-map write, but WITH a deferred recover() -> suppressed.
        # Removing the recover() branch from the predicate would FLIP this.
        guarded = """package keeper
func (k *Keeper) BeginBlocker(ctx Context) error { return k.step(ctx) }
func (k Keeper) step(ctx Context) error {
    defer func() { if r := recover(); r != nil { _ = r } }()
    var m map[uint64]bool
    m[1] = true
    return nil
}
"""
        root = _pkg({"abci.go": guarded})
        rep = chui.scan_panic_no_recover(root)
        self.assertEqual(rep["hypothesis_count"], 0, "recover() on the path must suppress the panic op")

    def test_comma_ok_guard_is_load_bearing(self):
        ok = """package keeper
func (k *Keeper) BeginBlocker(ctx Context) error { return k.step(ctx) }
func (k Keeper) step(ctx Context) error {
    v, ok := any(ctx).(*Vault)
    _ = v; _ = ok
    return nil
}
"""
        root = _pkg({"abci.go": ok})
        rep = chui.scan_panic_no_recover(root)
        self.assertEqual(rep["hypothesis_count"], 0, "comma-ok assert must not be flagged")

    def test_not_hook_reachable_not_flagged(self):
        # A nil-map write in a plain query handler NOT reachable from any hook.
        pkg = """package keeper
func (k Keeper) QueryFoo(ctx Context) error {
    var m map[uint64]bool
    m[1] = true
    return nil
}
"""
        root = _pkg({"query.go": pkg})
        rep = chui.scan_panic_no_recover(root)
        self.assertEqual(rep["hypothesis_count"], 0, "reachability guard: no hook -> no halt vector")

    def test_zero_check_suppresses_division(self):
        pkg = """package keeper
func (k *Keeper) EndBlocker(ctx Context) error { return k.calc(ctx, 5) }
func (k Keeper) calc(ctx Context, n int) error {
    if n == 0 { return nil }
    _ = 100 / n
    return nil
}
"""
        root = _pkg({"abci.go": pkg})
        rep = chui.scan_panic_no_recover(root)
        self.assertEqual(rep["hypothesis_count"], 0, "in-body zero-check must suppress div-by-zero")

    def test_unchecked_division_flagged(self):
        pkg = """package keeper
func (k *Keeper) EndBlocker(ctx Context) error { return k.calc(ctx, 5) }
func (k Keeper) calc(ctx Context, n int) error {
    _ = 100 / n
    return nil
}
"""
        root = _pkg({"abci.go": pkg})
        rep = chui.scan_panic_no_recover(root)
        self.assertEqual(rep["hypothesis_count"], 1, "unchecked variable divisor on a hook path -> flag")
        self.assertEqual(rep["hypotheses"][0]["panic_kind"], "unchecked-div")

    def test_make_init_suppresses_map_write(self):
        pkg = """package keeper
func (k *Keeper) BeginBlocker(ctx Context) error { return k.step(ctx) }
func (k Keeper) step(ctx Context) error {
    m := make(map[uint64]bool)
    m[1] = true
    return nil
}
"""
        root = _pkg({"abci.go": pkg})
        rep = chui.scan_panic_no_recover(root)
        self.assertEqual(rep["hypothesis_count"], 0, "make()-init'd map write is not a nil-map panic")

    def test_dedup_marks_covered_by_sibling_arm(self):
        # A hook that BOTH walks an uncapped queue (unbounded-iteration arm) AND has
        # a nil-map write in the SAME function -> the panic hit is deduped (covered_by).
        pkg = """package keeper
func (k *Keeper) BeginBlocker(ctx Context) error {
    var m map[uint64]bool
    m[1] = true
    return k.Q.Walk(ctx, nil, func(a Addr) (bool, error) { return false, nil })
}
"""
        root = _pkg({"abci.go": pkg})
        sib = chui.scan_root(root).get("findings", [])
        rep = chui.scan_panic_no_recover(root, dedup_against=sib)
        # the sibling arm owns (abci.go, BeginBlocker); the panic hit is deduped out.
        self.assertEqual(rep["hypothesis_count"], 0, "covered_by sibling arm -> not emitted")
        self.assertGreaterEqual(rep["covered_dedup_count"], 1, "dedup must record the covered hit")

    def test_emit_gated_off_by_default(self):
        pkg = {"abci.go": (_FIX / "abci.go").read_text(),
               "work.go": (_FIX / "work.go").read_text()}
        root = _pkg(pkg)
        out = str(Path(root) / "hyp.jsonl")
        os.environ.pop(chui.PANIC_ENV, None)
        res = chui._emit_panic_hypotheses(root, out)
        self.assertFalse(res["emitted"], "advisory-first: emission OFF unless env is set")
        self.assertFalse(Path(out).exists(), "no file written when gated off")
        os.environ[chui.PANIC_ENV] = "1"
        try:
            res = chui._emit_panic_hypotheses(root, out)
        finally:
            os.environ.pop(chui.PANIC_ENV, None)
        self.assertTrue(res["emitted"] and Path(out).exists(), "env-on writes the jsonl")
        self.assertGreater(res["count"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
