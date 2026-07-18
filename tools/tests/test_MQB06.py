#!/usr/bin/env python3
"""test_MQB06.py - recover()-catchable-set completeness screen (MQ-B06).

Exercises tools/recover-completeness-screen.py, an advisory-first, NO-AUTO-CREDIT
(verdict=needs-fuzz, auto_credit=false) GENERAL enforcement screen for the
private invariant "every fault reachable on a recover-guarded body is a
recover-catchable panic". A reachable runtime.throw / fatalthrow fault
(concurrent-map, unbounded-recursion stack overflow, all-goroutines deadlock)
makes the guard a FALSE SHIELD.

Non-vacuity is proven several ways:
  * each arm's planted positive FIRES and each guarded negative stays SILENT;
  * MUTATION-VERIFY on REAL fleet source (sei evmrpc/filter.go NewFilter): the
    mutex-guarded map write is SILENT and FIRES only once the lock is removed on
    a temp copy - and the same relation is proven inline so the test is
    non-vacuous even off the fleet;
  * each CORE PREDICATE (recover-guard, sync-guard, depth-bound, self-recursion
    receiver-discrimination) is shown load-bearing: neutralising it flips the
    verdict;
  * FP guards: a fn-local map, a no-recover body, and same-named DELEGATION
    (`x.other.Foo()`) all stay silent.
"""
import importlib.util
import json
import os
import pathlib
import re
import sys
import tempfile
import unittest

_TOOL = pathlib.Path(__file__).resolve().parents[1] / "recover-completeness-screen.py"
_FLEET_FILTER = pathlib.Path(
    "/Users/wolf/audits/sei/src/sei-chain/evmrpc/filter.go")


def _load():
    spec = importlib.util.spec_from_file_location("recover_completeness", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["recover_completeness"] = m
    spec.loader.exec_module(m)
    return m


# --------------------------------------------------------------------------- #
# Inline Go fixtures (kept minimal + gofmt-shaped: decl col-0, close `}` col-0).#
# --------------------------------------------------------------------------- #
CMAP_POS = """package p

type API struct {
\tfilters map[string]int
}

func (a *API) NewFilter(id string) (err error) {
\tdefer func() { recover() }()
\ta.filters[id] = 1
\treturn nil
}
"""

CMAP_GUARDED = """package p

type API struct {
\tfilters map[string]int
}

func (a *API) NewFilter(id string) (err error) {
\tdefer func() { recover() }()
\ta.mu.Lock()
\tdefer a.mu.Unlock()
\ta.filters[id] = 1
\treturn nil
}
"""

CMAP_LOCAL_FP = """package p

func Compute(req string) (err error) {
\tdefer func() { recover() }()
\tm := make(map[string]int)
\tm[req] = 1
\treturn nil
}
"""

CMAP_NO_RECOVER_FP = """package p

type API struct {
\tfilters map[string]int
}

func (a *API) NewFilter(id string) error {
\ta.filters[id] = 1
\treturn nil
}
"""

REC_POS = """package p

func Decode(b []byte) (err error) {
\tdefer func() { recover() }()
\tif len(b) > 0 {
\t\treturn Decode(b[1:])
\t}
\treturn nil
}
"""

REC_BOUNDED = """package p

func Decode(b []byte, depth int) (err error) {
\tdefer func() { recover() }()
\tif depth > 100 {
\t\treturn nil
\t}
\tif len(b) > 0 {
\t\treturn Decode(b[1:], depth+1)
\t}
\treturn nil
}
"""

REC_DELEGATION_FP = """package p

type S struct{}

func (s *S) Decode(h string) (err error) {
\tdefer func() { recover() }()
\treturn s.other.Decode(h)
}
"""

REC_GO_RESTART_FP = """package p

func (wsc *W) readRoutine(ctx context.Context) {
\tdefer func() {
\t\tif r := recover(); r != nil {
\t\t\tgo wsc.readRoutine(ctx)
\t\t}
\t}()
\tfor {
\t\tprocess(ctx)
\t}
}
"""

REC_DEFER_RESTART_FP = """package p

func (wsc *W) readRoutine(ctx context.Context) {
\tdefer func() { recover() }()
\tdefer wsc.readRoutine(ctx)
\tprocess(ctx)
}
"""

DEADLOCK_POS = """package p

func (w *W) readLoop() (err error) {
\tdefer func() { recover() }()
\t<-w.ch
\treturn nil
}
"""

DEADLOCK_ESCAPED = """package p

func (w *W) readLoop() (err error) {
\tdefer func() { recover() }()
\tselect {
\tcase <-w.ch:
\tcase <-w.done:
\t}
\treturn nil
}
"""


class TestRecoverCompleteness(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def _rows(self, src, fname="pkg/p.go", arms=None, all_scopes=False):
        return self.m.analyze_source(src, fname, all_scopes=all_scopes, arms=arms)

    # ---- ARM A: concurrent_map_fatal ------------------------------------
    def test_concurrent_map_positive_fires(self):
        rows = self._rows(CMAP_POS, arms=["concurrent_map_fatal"])
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual(r["arm"], "concurrent_map_fatal")
        self.assertEqual(r["function"], "NewFilter")
        self.assertEqual(r["verdict"], "needs-fuzz")
        self.assertFalse(r["auto_credit"])
        self.assertTrue(r["no_auto_credit"])
        self.assertTrue(r["recover_guarded"])
        self.assertIn("concurrent map", r["recover_proof_fatal"])
        self.assertEqual(r["capability"], "MQ-B06-recover-completeness")
        for k in ("file", "line", "function", "capability"):
            self.assertIn(k, r)

    def test_concurrent_map_guarded_is_silent(self):
        self.assertEqual(
            self._rows(CMAP_GUARDED, arms=["concurrent_map_fatal"]), [])

    def test_concurrent_map_fn_local_map_is_silent(self):
        # A fn-local `m := make(map[..])` is single-goroutine-owned, not a race.
        self.assertEqual(
            self._rows(CMAP_LOCAL_FP, arms=["concurrent_map_fatal"]), [])

    def test_concurrent_map_no_recover_is_silent(self):
        # No recover guard => not a fault-containment enforcement point => the
        # dual (missing-recover) census owns it, not this completeness lens.
        self.assertEqual(
            self._rows(CMAP_NO_RECOVER_FP, arms=["concurrent_map_fatal"]), [])

    # ---- MUTATION-VERIFY (inline): weaken the sync guard -> FIRES --------
    def test_concurrent_map_mutation_inline(self):
        # guarded (silent) -> remove the lock -> fires, proving the sync guard
        # is the load-bearing suppressor.
        self.assertEqual(
            self._rows(CMAP_GUARDED, arms=["concurrent_map_fatal"]), [])
        weakened = CMAP_GUARDED.replace(
            "\ta.mu.Lock()\n\tdefer a.mu.Unlock()\n", "")
        self.assertNotEqual(weakened, CMAP_GUARDED)
        rows = self._rows(weakened, arms=["concurrent_map_fatal"])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["function"], "NewFilter")

    # ---- MUTATION-VERIFY (REAL fleet source) ----------------------------
    @unittest.skipUnless(_FLEET_FILTER.is_file(),
                         "fleet source (sei evmrpc/filter.go) not present")
    def test_concurrent_map_mutation_real_fleet(self):
        src = _FLEET_FILTER.read_text(errors="replace")
        # NewFilter's map write is mutex-guarded -> the whole file is SILENT for
        # this arm.
        base = self.m.analyze_source(src, str(_FLEET_FILTER),
                                     arms=["concurrent_map_fatal"])
        self.assertEqual(base, [], "guarded real source must be silent")
        anchor = ("\ta.filtersMu.Lock()\n\tdefer a.filtersMu.Unlock()\n\n"
                  "\tcurFilterID := ethrpc.NewID()\n"
                  "\ta.filters[curFilterID] = filter{\n"
                  "\t\ttyp:          LogsSubscription,")
        self.assertIn(anchor, src, "NewFilter lock+write anchor present")
        weakened = src.replace(
            anchor,
            ("\tcurFilterID := ethrpc.NewID()\n"
             "\ta.filters[curFilterID] = filter{\n"
             "\t\ttyp:          LogsSubscription,"), 1)
        self.assertNotEqual(weakened, src)
        rows = self.m.analyze_source(weakened, str(_FLEET_FILTER),
                                     arms=["concurrent_map_fatal"])
        fired = [r for r in rows if r["function"] == "NewFilter"]
        self.assertEqual(len(fired), 1,
                         "removing NewFilter's lock must expose the fatal")
        self.assertIn("concurrent map", fired[0]["recover_proof_fatal"])

    # ---- ARM B: unbounded_recursion_fatal -------------------------------
    def test_recursion_positive_fires(self):
        rows = self._rows(REC_POS, fname="pkg/decode.go",
                          arms=["unbounded_recursion_fatal"])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["function"], "Decode")
        self.assertIn("stack overflow", rows[0]["recover_proof_fatal"])
        self.assertTrue(rows[0]["recover_guarded"])

    def test_recursion_bounded_is_silent(self):
        self.assertEqual(
            self._rows(REC_BOUNDED, fname="pkg/decode.go",
                       arms=["unbounded_recursion_fatal"]), [])

    def test_recursion_delegation_is_silent(self):
        # `s.other.Decode(h)` is delegation to a DIFFERENT object, not recursion.
        self.assertEqual(
            self._rows(REC_DELEGATION_FP, fname="pkg/decode.go",
                       arms=["unbounded_recursion_fatal"]), [])

    def test_recursion_go_restart_is_silent(self):
        # `go wsc.readRoutine(ctx)` inside a deferred recover runs on a FRESH
        # goroutine stack = a restart, not synchronous stack-consuming recursion,
        # so it must NOT be flagged as an unbounded-recursion fatal.
        # (fleet FP: sei sei-tendermint/rpc/jsonrpc/server/ws_handler.go readRoutine)
        self.assertEqual(
            self._rows(REC_GO_RESTART_FP, fname="rpc/server/ws.go",
                       arms=["unbounded_recursion_fatal"], all_scopes=True), [])

    def test_recursion_defer_restart_is_silent(self):
        # `defer wsc.readRoutine(ctx)` runs after the frame unwinds = a restart,
        # not synchronous recursion; must stay silent.
        self.assertEqual(
            self._rows(REC_DEFER_RESTART_FP, fname="rpc/server/ws.go",
                       arms=["unbounded_recursion_fatal"], all_scopes=True), [])

    def test_recursion_go_restart_mutation_is_load_bearing(self):
        # Non-vacuity of the go/defer exclusion: the SAME body with the leading
        # `go ` removed is a synchronous self-call and DOES fire - proving the
        # exclusion (not some unrelated silencer) is what suppresses the FP.
        synchronous = REC_GO_RESTART_FP.replace(
            "go wsc.readRoutine(ctx)", "wsc.readRoutine(ctx)")
        self.assertNotEqual(synchronous, REC_GO_RESTART_FP)
        rows = self._rows(synchronous, fname="rpc/server/ws.go",
                          arms=["unbounded_recursion_fatal"], all_scopes=True)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["function"], "readRoutine")

    def test_recursion_bounded_mutation_inline(self):
        # bounded (silent) -> neutralise the depth-bound lexicon -> fires.
        saved = self.m._DEPTH_GUARD
        try:
            self.m._DEPTH_GUARD = re.compile(r"ZZZ_NEVER_MATCHES")
            rows = self._rows(REC_BOUNDED, fname="pkg/decode.go",
                              arms=["unbounded_recursion_fatal"])
            self.assertEqual(len(rows), 1,
                             "with no depth-bound recognised the recursion fires")
        finally:
            self.m._DEPTH_GUARD = saved
        self.assertEqual(
            self._rows(REC_BOUNDED, fname="pkg/decode.go",
                       arms=["unbounded_recursion_fatal"]), [],
            "restored depth-bound predicate suppresses again")

    # ---- ARM C: blocking_deadlock_fatal ---------------------------------
    def test_deadlock_positive_fires(self):
        rows = self._rows(DEADLOCK_POS, arms=["blocking_deadlock_fatal"])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["function"], "readLoop")
        self.assertIn("deadlock", rows[0]["recover_proof_fatal"])

    def test_deadlock_escaped_is_silent(self):
        self.assertEqual(
            self._rows(DEADLOCK_ESCAPED, arms=["blocking_deadlock_fatal"]), [])

    # ---- CORE PREDICATE load-bearing: recover-guard ---------------------
    def test_recover_guard_predicate_is_load_bearing(self):
        saved = self.m.recover_guarded
        try:
            self.m.recover_guarded = lambda ftext: False
            self.assertEqual(
                self._rows(CMAP_POS, arms=["concurrent_map_fatal"]), [],
                "no recover-guarded enforcement point => nothing to complete")
        finally:
            self.m.recover_guarded = saved
        self.assertEqual(
            len(self._rows(CMAP_POS, arms=["concurrent_map_fatal"])), 1)

    # ---- CORE PREDICATE load-bearing: sync-guard ------------------------
    def test_sync_guard_predicate_is_load_bearing(self):
        saved = self.m._SYNC_GUARD
        try:
            self.m._SYNC_GUARD = re.compile(r"ZZZ_NEVER_MATCHES")
            self.assertEqual(
                len(self._rows(CMAP_GUARDED, arms=["concurrent_map_fatal"])), 1,
                "neutralising the sync lexicon exposes the guarded map write")
        finally:
            self.m._SYNC_GUARD = saved

    # ---- advisory-first contract ----------------------------------------
    def test_advisory_off_by_default(self):
        os.environ.pop(self.m._ADVISORY_ENV, None)
        with tempfile.TemporaryDirectory() as d:
            res = self.m.evaluate(d)
            self.assertIsNone(res["recover_completeness_screen"],
                              "advisory must be OFF (None) by default")

    def test_run_emits_needs_fuzz_sidecar(self):
        with tempfile.TemporaryDirectory() as d:
            ws = pathlib.Path(d)
            (ws / "pkg").mkdir()
            (ws / "pkg" / "p.go").write_text(CMAP_POS)
            out = self.m.run(ws)
            self.assertTrue(out.exists())
            self.assertEqual(out.name, "recover_completeness_hypotheses.jsonl")
            rows = [json.loads(x) for x in out.read_text().splitlines() if x.strip()]
            self.assertGreaterEqual(len(rows), 1)
            self.assertTrue(all(r["verdict"] == "needs-fuzz" for r in rows))
            self.assertTrue(all(r["auto_credit"] is False for r in rows))

    def test_run_zero_rows_emits_empty_sidecar_never_failcloses(self):
        with tempfile.TemporaryDirectory() as d:
            ws = pathlib.Path(d)
            (ws / "pkg").mkdir()
            (ws / "pkg" / "p.go").write_text(CMAP_GUARDED)  # silent
            out = self.m.run(ws)
            self.assertTrue(out.exists())
            self.assertEqual(out.read_text().strip(), "")

    # ---- generality: no target-specific string in emitted rows ----------
    def test_rows_are_general_not_shape_specific(self):
        rows = self._rows(CMAP_POS, arms=["concurrent_map_fatal"])
        blob = json.dumps(rows).lower()
        for banned in ("polymarket", "sei", "cosmos", "tendermint", "morpho"):
            self.assertNotIn(banned, blob,
                             "row must not encode a specific target/protocol")
        self.assertEqual(rows[0]["attack_class"],
                         "runtime-fault-containment-completeness")


if __name__ == "__main__":
    unittest.main()
