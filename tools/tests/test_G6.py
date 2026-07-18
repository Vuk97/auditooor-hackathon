#!/usr/bin/env python3
"""test_G6.py - goroutine-fanout unsynchronized-shared-write advisory (G6).

Extends tools/go-detector-runner.py with an advisory-first, NO-AUTO-CREDIT
(verdict=needs-fuzz) detector ``_detect_goroutine_fanout_unsync_shared``: a
``go func(...){...}()`` fan-out whose closure writes a captured non-receiver
shared cell (map/slice index, ptr-deref, or sdk.Context mutating method)
with NO mutex/channel/atomic guard in the closure + enclosing scope.

Non-vacuity: the write predicate and the guard predicate are BOTH load-
bearing - neutralising ``_G6_INDEX_WRITE`` silences the UNGUARDED fixture,
and neutralising ``_G6_GUARD`` makes the GUARDED fixture fire. A bare
WaitGroup is NOT counted as a guard (test_waitgroup_is_not_a_guard). Distinct
from Pattern 39 (receiver self-field writes) - the receiver-write fixture is
silent, and the emitter de-dups (file,line) against Pattern 39's hits.
"""
import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "go-detector-runner.py"
_FIX = Path(__file__).resolve().parent / "fixtures" / "G6"


def _load():
    spec = importlib.util.spec_from_file_location("gdr_g6", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["gdr_g6"] = m  # dataclass string annotations need this
    spec.loader.exec_module(m)
    return m


def _fs(name):
    return {Path(name): (_FIX / name).read_text(encoding="utf-8")}


class TestGoroutineFanoutUnsync(unittest.TestCase):
    def setUp(self):
        self.m = _load()

    def _hits(self, name):
        return self.m._detect_goroutine_fanout_unsync_shared(_fs(name))

    # ---- mutation-kill (unguarded fires / guarded silent) ----------------
    def test_unguarded_fires(self):
        hits = self._hits("unguarded.go")
        self.assertEqual(len(hits), 1, "unguarded fan-out must fire exactly once")
        h = hits[0]
        self.assertEqual(h.extra["write_kind"], "index")
        self.assertEqual(h.extra["shared_base"], "n")
        self.assertIn("n.Children[index]", h.snippet)

    def test_guarded_silent(self):
        # A mutex Lock/Unlock CALL in the closure scope defends the write.
        self.assertEqual(self._hits("guarded.go"), [], "mutex-guarded must not fire")

    # ---- FP-guards -------------------------------------------------------
    def test_receiver_write_silent(self):
        # Writing the receiver's own field is Pattern 39 territory, not G6.
        self.assertEqual(self._hits("receiver_write.go"), [],
                         "receiver self-field write must not fire (keeps lanes distinct)")

    def test_local_var_silent(self):
        # A slice declared inside the closure is not shared state.
        self.assertEqual(self._hits("local_var.go"), [],
                         "closure-local declared var must not fire")

    def test_waitgroup_is_not_a_guard(self):
        # The unguarded fixture HAS a WaitGroup (wg.Add/Done/Wait) yet fires:
        # a completion barrier does not serialize concurrent writes.
        src = (_FIX / "unguarded.go").read_text()
        self.assertIn("wg.Wait()", src)
        self.assertEqual(len(self._hits("unguarded.go")), 1)

    # ---- non-vacuity: both predicates are load-bearing -------------------
    def test_write_predicate_is_load_bearing(self):
        saved = self.m._G6_INDEX_WRITE
        try:
            self.m._G6_INDEX_WRITE = re.compile(r"ZZZ_NEVER_MATCHES")
            self.assertEqual(self._hits("unguarded.go"), [],
                             "neutralising the write predicate must silence the fixture")
        finally:
            self.m._G6_INDEX_WRITE = saved
        self.assertEqual(len(self._hits("unguarded.go")), 1)

    def test_guard_predicate_is_load_bearing(self):
        saved = self.m._G6_GUARD
        try:
            self.m._G6_GUARD = re.compile(r"ZZZ_NEVER_MATCHES")
            # With the guard neutralised, the GUARDED fixture now fires,
            # proving the mutex-suppression is what kept it silent.
            self.assertEqual(len(self._hits("guarded.go")), 1,
                             "neutralising the guard predicate must expose the guarded fixture")
        finally:
            self.m._G6_GUARD = saved
        self.assertEqual(self._hits("guarded.go"), [])

    # ---- dedup vs Pattern 39 (A1 boundary) -------------------------------
    def test_emit_dedups_against_pattern39(self):
        ws = Path(tempfile.mkdtemp())
        fs = _fs("unguarded.go")
        hits = self.m._detect_goroutine_fanout_unsync_shared(fs)
        self.assertEqual(len(hits), 1)
        h = hits[0]
        # Fabricate a Pattern-39 hit at the SAME (file,line) -> must be dropped.
        collide = [self.m.Hit(file=h.file, line=h.line, snippet="x")]
        recs, _ = self.m._emit_goroutine_fanout_unsync_shared_hypotheses(
            ws, fs, collide)
        self.assertEqual(recs, [], "overlap with Pattern 39 must be de-duped out")
        # With NO Pattern-39 overlap the hit is net-new.
        recs2, _ = self.m._emit_goroutine_fanout_unsync_shared_hypotheses(
            ws, fs, [])
        self.assertEqual(len(recs2), 1)
        self.assertEqual(recs2[0]["verdict"], "needs-fuzz")
        self.assertEqual(recs2[0]["lane"], "G6")

    # ---- advisory-first gating + NO-AUTO-CREDIT --------------------------
    def _ws_with_fixture(self, name):
        d = Path(tempfile.mkdtemp())
        (d / "trie").mkdir()
        (d / "trie" / name).write_text((_FIX / name).read_text(), encoding="utf-8")
        return d

    def test_advisory_off_by_default(self):
        os.environ.pop(self.m.G6_FANOUT_ENV, None)
        ws = self._ws_with_fixture("unguarded.go")
        self.m.scan_workspace(ws, tuple(self.m._DEFAULT_GUARDS))
        jl = ws / ".auditooor" / self.m.G6_FANOUT_OUT
        self.assertFalse(jl.exists(), "no jsonl emitted when the env flag is unset")

    def test_enabled_emits_needs_fuzz_jsonl(self):
        os.environ[self.m.G6_FANOUT_ENV] = "1"
        try:
            ws = self._ws_with_fixture("unguarded.go")
            summ = self.m.scan_workspace(ws, tuple(self.m._DEFAULT_GUARDS))
            jl = ws / ".auditooor" / self.m.G6_FANOUT_OUT
            self.assertTrue(jl.exists(), "jsonl emitted when enabled")
            rows = [json.loads(x) for x in jl.read_text().splitlines() if x.strip()]
            self.assertGreaterEqual(len(rows), 1)
            self.assertTrue(all(r["verdict"] == "needs-fuzz" for r in rows),
                            "every emitted row is NO-AUTO-CREDIT needs-fuzz")
            # G6 must NOT appear in the main patterns output (kept advisory).
            self.assertNotIn(self.m.G6_FANOUT_PID, summ["patterns"])
        finally:
            os.environ.pop(self.m.G6_FANOUT_ENV, None)


if __name__ == "__main__":
    unittest.main()
