#!/usr/bin/env python3
"""test_R12.py - go-goroutine-lifecycle-census (R12) non-vacuous test suite.

Proves, per the capability contract:
  * a PLANTED POSITIVE fires for each of the 3 enforcement-point arms
    (spawn_no_recover, select_no_escape, shared_cell_unsync);
  * a GUARDED NEGATIVE stays silent for each arm (guard present -> no row);
  * NEUTRALISING the core predicate makes the positive test FAIL (the guard
    detector is load-bearing, not decorative);
  * the ingress-adjacency gate suppresses non-ingress scopes by default and
    --all lifts it;
  * every emitted row is advisory-first (verdict=needs-fuzz, no_auto_credit).

Plus an OPTIONAL real-fleet mutation-verify (skipUnless the optimism p2p file is
present): the guarded discovery.go select arm is SILENT; removing one
`case <-ctx.Done()` escape on a TEMP COPY makes it FIRE. The original ws file is
never mutated.
"""
import importlib.util
import os
import shutil
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "go-goroutine-lifecycle-census.py"
_FLEET = Path("/Users/wolf/audits/optimism/src/op-node/p2p/discovery.go")
# op-service/rpc/stream.go: three `case <-quit:` cancellation idioms that were a
# select_no_escape fleet FP (lines 55, 111, 122) before the quit-channel fix.
_FLEET_STREAM = Path("/Users/wolf/audits/optimism/src/op-service/rpc/stream.go")


def _load():
    spec = importlib.util.spec_from_file_location("r12census", _TOOL)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


M = _load()

# --- fixtures (gofmt-style: top-level func at col0, `}` closes at col0) ------ #

SPAWN_POS = """package x

func (s *Server) CheckTx(req []byte) {
\tgo func() {
\t\tprocess(req)
\t}()
}
"""

SPAWN_GUARDED = """package x

func (s *Server) CheckTx(req []byte) {
\tgo func() {
\t\tdefer func() {
\t\t\tif r := recover(); r != nil {
\t\t\t}
\t\t}()
\t\tprocess(req)
\t}()
}
"""

SELECT_POS = """package x

func HandleMsg(ctx context.Context, in chan int, out chan int) {
\tselect {
\tcase v := <-in:
\t\tout <- v
\t}
}
"""

SELECT_GUARDED_DONE = """package x

func HandleMsg(ctx context.Context, in chan int, out chan int) {
\tselect {
\tcase v := <-in:
\t\tout <- v
\tcase <-ctx.Done():
\t\treturn
\t}
}
"""

SELECT_GUARDED_DEFAULT = """package x

func HandleMsg(ctx context.Context, in chan int, out chan int) {
\tselect {
\tcase v := <-in:
\t\tout <- v
\tdefault:
\t\treturn
\t}
}
"""

# quit-channel idiom (op-service/rpc/stream.go): a receive on a cancellation-
# named channel is a bounded escape -> must stay SILENT (was a fleet FP).
SELECT_GUARDED_QUIT = """package x

func HandleMsg(quit <-chan struct{}, dest chan int, item int) {
\tselect {
\tcase dest <- item:
\tcase <-quit:
\t\treturn
\t}
}
"""

# `*Ch` suffix name heuristic: a receive on `stopCh` is a bounded escape.
SELECT_GUARDED_CHSUFFIX = """package x

func HandleMsg(stopCh <-chan struct{}, in chan int, out chan int) {
\tselect {
\tcase v := <-in:
\t\tout <- v
\tcase <-stopCh:
\t\treturn
\t}
}
"""

# bare `case <-c:` whose body returns/breaks -> drain-then-exit escape.
SELECT_GUARDED_BARE_RETURN = """package x

func HandleMsg(c chan struct{}, in chan int, out chan int) {
\tselect {
\tcase v := <-in:
\t\tout <- v
\tcase <-c:
\t\treturn
\t}
}
"""

# a SEND to a cancel-named channel is NOT a bounded escape -> must still FIRE
# (guards against the receive/send confusion in the name heuristic).
SELECT_SEND_TO_QUIT_FIRES = """package x

func HandleMsg(quit chan struct{}, in chan int) {
\tselect {
\tcase v := <-in:
\t\t_ = v
\tcase quit <- struct{}{}:
\t}
}
"""

SHARED_POS = """package x

func (r *Reactor) Receive(msg int) {
\tm := map[int]int{}
\tgo func() {
\t\tm[msg] = 1
\t}()
}
"""

SHARED_GUARDED = """package x

func (r *Reactor) Receive(msg int) {
\tm := map[int]int{}
\tvar mu sync.Mutex
\tgo func() {
\t\tmu.Lock()
\t\tm[msg] = 1
\t\tmu.Unlock()
\t}()
}
"""

NON_INGRESS = """package x

func helper() {
\tgo func() {
\t\tx()
\t}()
}
"""


def _arms(rows):
    return sorted({r["arm"] for r in rows})


class SpawnArm(unittest.TestCase):
    def test_positive_fires(self):
        rows = M.analyze_source(SPAWN_POS, "abci/x.go", arms=["spawn_no_recover"])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["arm"], "spawn_no_recover")

    def test_guarded_silent(self):
        rows = M.analyze_source(SPAWN_GUARDED, "abci/x.go",
                                arms=["spawn_no_recover"])
        self.assertEqual(rows, [])

    def test_neutralised_predicate_kills_positive(self):
        # If the recover-detector always reports "recover present", the positive
        # can no longer fire -> proves the predicate is load-bearing.
        orig = M.closure_has_toplevel_recover
        try:
            M.closure_has_toplevel_recover = lambda body: True
            rows = M.analyze_source(SPAWN_POS, "abci/x.go",
                                    arms=["spawn_no_recover"])
            self.assertEqual(rows, [], "positive must vanish when guard-detector "
                             "is neutralised (non-vacuity)")
        finally:
            M.closure_has_toplevel_recover = orig


class SelectArm(unittest.TestCase):
    def test_positive_fires(self):
        rows = M.analyze_source(SELECT_POS, "rpc/x.go",
                                arms=["select_no_escape"])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["arm"], "select_no_escape")

    def test_guarded_done_silent(self):
        rows = M.analyze_source(SELECT_GUARDED_DONE, "rpc/x.go",
                                arms=["select_no_escape"])
        self.assertEqual(rows, [])

    def test_guarded_default_silent(self):
        rows = M.analyze_source(SELECT_GUARDED_DEFAULT, "rpc/x.go",
                                arms=["select_no_escape"])
        self.assertEqual(rows, [])

    def test_guarded_quit_silent(self):
        rows = M.analyze_source(SELECT_GUARDED_QUIT, "rpc/x.go",
                                arms=["select_no_escape"])
        self.assertEqual(rows, [], "receive on a cancellation-named channel "
                         "(quit) is a bounded escape")

    def test_guarded_chsuffix_silent(self):
        rows = M.analyze_source(SELECT_GUARDED_CHSUFFIX, "rpc/x.go",
                                arms=["select_no_escape"])
        self.assertEqual(rows, [], "receive on a `*Ch`-suffixed channel is a "
                         "bounded escape")

    def test_guarded_bare_return_silent(self):
        rows = M.analyze_source(SELECT_GUARDED_BARE_RETURN, "rpc/x.go",
                                arms=["select_no_escape"])
        self.assertEqual(rows, [], "bare `case <-c:` with a returning body is a "
                         "drain-then-exit escape")

    def test_send_to_quit_still_fires(self):
        # A SEND to a cancel-named channel is not a bounded escape; the name
        # heuristic must not silence it.
        rows = M.analyze_source(SELECT_SEND_TO_QUIT_FIRES, "rpc/x.go",
                                arms=["select_no_escape"])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["arm"], "select_no_escape")

    def test_neutralised_predicate_kills_positive(self):
        orig = M.select_is_escaped
        try:
            M.select_is_escaped = lambda body: True
            rows = M.analyze_source(SELECT_POS, "rpc/x.go",
                                    arms=["select_no_escape"])
            self.assertEqual(rows, [], "positive must vanish when escape-detector "
                             "is neutralised (non-vacuity)")
        finally:
            M.select_is_escaped = orig


class SharedCellArm(unittest.TestCase):
    def test_positive_fires(self):
        rows = M.analyze_source(SHARED_POS, "p2p/x.go",
                                arms=["shared_cell_unsync"])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["arm"], "shared_cell_unsync")

    def test_guarded_silent(self):
        rows = M.analyze_source(SHARED_GUARDED, "p2p/x.go",
                                arms=["shared_cell_unsync"])
        self.assertEqual(rows, [])

    def test_neutralised_predicate_kills_positive(self):
        orig = M.has_sync_guard
        try:
            M.has_sync_guard = lambda text: True
            rows = M.analyze_source(SHARED_POS, "p2p/x.go",
                                    arms=["shared_cell_unsync"])
            self.assertEqual(rows, [], "positive must vanish when sync-guard "
                             "detector is neutralised (non-vacuity)")
        finally:
            M.has_sync_guard = orig


class IngressGate(unittest.TestCase):
    def test_non_ingress_silent_by_default(self):
        rows = M.analyze_source(NON_INGRESS, "util/helpers.go",
                                arms=["spawn_no_recover"])
        self.assertEqual(rows, [], "non-ingress scope must be gated out by "
                         "default")

    def test_all_scopes_lifts_gate(self):
        rows = M.analyze_source(NON_INGRESS, "util/helpers.go",
                                all_scopes=True, arms=["spawn_no_recover"])
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0]["ingress_adjacent"])


class AdvisoryContract(unittest.TestCase):
    def test_every_row_advisory(self):
        rows = []
        for src, fn in ((SPAWN_POS, "abci/x.go"), (SELECT_POS, "rpc/x.go"),
                        (SHARED_POS, "p2p/x.go")):
            rows += M.analyze_source(src, fn)
        self.assertTrue(rows)
        for r in rows:
            self.assertEqual(r["verdict"], "needs-fuzz")
            self.assertIs(r["no_auto_credit"], True)
            self.assertIn("private_invariant", r)


@unittest.skipUnless(_FLEET.is_file(), "optimism p2p fleet fixture absent")
class RealFleetMutation(unittest.TestCase):
    """Guarded real file is silent; weakening one guard on a TEMP COPY fires.
    The workspace file is never mutated (temp copy under a /p2p/ path so the
    ingress-path gate stays realistic)."""

    def test_silent_then_fires(self):
        base = Path(tempfile.mkdtemp())
        try:
            d = base / "p2p"
            d.mkdir()
            tmp = d / "discovery.go"
            shutil.copy(_FLEET, tmp)

            clean = M.analyze_file(tmp, arms=["select_no_escape"])
            self.assertEqual(clean, [], "guarded fleet selects must be silent")

            # weaken: delete the first `case <-ctx.Done():` + its `return` body.
            lines = tmp.read_text().split("\n")
            out, i, done = [], 0, False
            while i < len(lines):
                if not done and lines[i].strip() == "case <-ctx.Done():":
                    i += 1
                    if i < len(lines) and lines[i].strip() == "return":
                        i += 1
                    done = True
                    continue
                out.append(lines[i])
                i += 1
            self.assertTrue(done, "expected a ctx.Done() escape to remove")
            tmp.write_text("\n".join(out))

            fired = M.analyze_file(tmp, arms=["select_no_escape"])
            self.assertEqual(len(fired), 1,
                             "weakened select must fire exactly once")
            self.assertEqual(fired[0]["arm"], "select_no_escape")
        finally:
            shutil.rmtree(base, ignore_errors=True)
        # original fleet file untouched (we only ever wrote to the temp copy).
        self.assertTrue(_FLEET.is_file())


@unittest.skipUnless(_FLEET_STREAM.is_file(), "optimism rpc/stream.go absent")
class RealFleetStreamNoFP(unittest.TestCase):
    """The op-service/rpc/stream.go quit-channel idiom must yield ZERO
    select_no_escape rows (regression for the named fleet FP)."""

    def test_select_arm_no_false_positive(self):
        rows = M.analyze_file(_FLEET_STREAM, arms=["select_no_escape"])
        self.assertEqual(rows, [], "quit-channel selects must not fire "
                         f"select_no_escape (got {[r['line'] for r in rows]})")

    def test_spawn_arm_true_detection_preserved(self):
        # the unrecovered `go func(){ <-rpcSub.Err() ... }` in Subscribe() is a
        # legitimate spawn-arm detection that must keep firing.
        rows = M.analyze_file(_FLEET_STREAM, arms=["spawn_no_recover"])
        self.assertGreaterEqual(len(rows), 1,
                                "spawn-arm true detection must be preserved")


if __name__ == "__main__":
    unittest.main(verbosity=2)
