#!/usr/bin/env python3
"""test_G12.py - go.go.panic.goroutine_no_toplevel_recover (G12).

Extends tools/go-detector-runner.py with an advisory-first, NO-AUTO-CREDIT
(verdict=needs-fuzz) detector that fires when a ``go func(...){...}()`` spawn
has a brace-balanced closure body with ZERO ``recover(`` call. A panic inside a
bare goroutine cannot be recovered by the caller, so a panicking callee
reachable from the closure crashes the whole process (M14-trap reachable-panic
axis; a CONFIRMED needs a runtime panicking-callee path).

Non-vacuity: the recover-in-body predicate is load-bearing. Mutating it (e.g.
treating ANY recover token including a comment as a guard, or dropping the
recover check entirely) breaks a case: the comment-recover fixture must still
fire, and the recover-bearing sibling must stay clean.

Dedup boundary (A1): the emitter diffs emitted hits vs G6
(goroutine_fanout_unsync_shared) by (file,line) - it does NOT re-derive a
covered_by signal.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "go-detector-runner.py"
_FIX = Path(__file__).resolve().parent / "fixtures" / "G12"


def _load():
    spec = importlib.util.spec_from_file_location("gdr_g12", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["gdr_g12"] = m
    spec.loader.exec_module(m)
    return m


class TestGoroutineNoToplevelRecover(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        self.path = _FIX / "goroutines.go"
        self.src = self.path.read_text()

    def _hits(self, src=None, rel="src/goroutines.go"):
        fs = {rel: src if src is not None else self.src}
        return self.m._detect_goroutine_no_toplevel_recover(fs)

    def _snips(self, hits):
        return " || ".join(h.snippet for h in hits)

    # ---- core predicate matrix ------------------------------------------
    def test_fires_on_bare_goroutine(self):
        snips = self._snips(self._hits())
        self.assertIn("go func()", snips,
                      "a bare goroutine with no recover must fire")

    def test_recover_bearing_sibling_clean(self):
        # spawnGuarded's goroutine has recover() in-body; its go-func line must
        # NOT be among the fired lines. Count: 3 bare goroutines fire, 1 is
        # clean (spawnGuarded).
        self.assertEqual(len(self._hits()), 3,
                         "exactly the 3 bare goroutines fire; guarded is clean")

    def test_caller_scope_recover_still_fires(self):
        # callerRecoverUseless has recover in the CALLER, not the goroutine.
        src = ("package p\nfunc f(work func()) {\n"
               "\tdefer func() { _ = recover() }()\n"
               "\tgo func() { work() }()\n}\n")
        self.assertEqual(len(self._hits(src)), 1,
                         "caller-scope recover does not suppress the goroutine")

    def test_comment_recover_still_fires(self):
        src = ("package p\nfunc f(work func()) {\n"
               "\tgo func() {\n\t\t// recover() here but not really\n"
               "\t\twork()\n\t}()\n}\n")
        self.assertEqual(len(self._hits(src)), 1,
                         "a // recover() comment is not a guard")

    def test_test_file_skipped(self):
        skip = _FIX / "goroutines_skip_test.go"
        hits = self._hits(skip.read_text(), rel="src/goroutines_skip_test.go")
        self.assertEqual(hits, [], "*_test.go goroutine must be skipped")

    def test_testdata_skipped(self):
        hits = self._hits(self.src, rel="src/testdata/goroutines.go")
        self.assertEqual(hits, [], "/testdata/ goroutine must be skipped")

    # ---- non-vacuity: predicate is load-bearing -------------------------
    def test_recover_predicate_load_bearing(self):
        # The recover-bearing sibling is clean by design. If we scan a variant
        # where the recover is removed, it starts firing (predicate matters).
        with_recover = self.src
        without = with_recover.replace(
            "if r := recover(); r != nil {\n\t\t\t\t_ = r\n\t\t\t}", "_ = 1")
        self.assertEqual(len(self._hits(with_recover)), 3)
        self.assertEqual(len(self._hits(without)), 4,
                         "removing the recover flips the guarded sibling to fire")

    # ---- dedup boundary (A1): diff vs G6, not re-derived ----------------
    def test_dedup_drops_g6_overlap(self):
        ws = Path(tempfile.mkdtemp())
        (ws / "src").mkdir()
        p = ws / "src" / "goroutines.go"
        p.write_text(self.src)
        fs = {"src/goroutines.go": self.src}
        one = self.m._detect_goroutine_no_toplevel_recover(fs)[0]
        collide = self.m.Hit(file=one.file, line=one.line, snippet="x")
        recs, _ = self.m._emit_goroutine_no_toplevel_recover_hypotheses(
            ws, fs, [collide])
        kept = {(r["file"], r["line"]) for r in recs}
        self.assertNotIn((one.file, one.line), kept,
                         "a (file,line) collision with G6 is de-duped")
        self.assertTrue(len(recs) >= 1, "non-colliding hits survive")

    # ---- advisory-first + NO-AUTO-CREDIT --------------------------------
    def test_emit_writes_needs_fuzz_jsonl(self):
        ws = Path(tempfile.mkdtemp())
        fs = {"src/goroutines.go": self.src}
        recs, out = self.m._emit_goroutine_no_toplevel_recover_hypotheses(
            ws, fs, [])
        self.assertTrue(out.exists())
        self.assertGreaterEqual(len(recs), 1)
        self.assertTrue(all(r["verdict"] == "needs-fuzz" for r in recs),
                        "every emitted row is NO-AUTO-CREDIT needs-fuzz")
        self.assertTrue(all(r["pattern_id"] == self.m.G12_NORECOVER_PID
                            for r in recs))

    def test_advisory_off_by_default_not_in_patterns(self):
        ws = Path(tempfile.mkdtemp())
        (ws / "src").mkdir()
        (ws / "src" / "goroutines.go").write_text(self.src)
        os.environ.pop(self.m.G12_NORECOVER_ENV, None)
        summary = self.m.scan_workspace(ws, self.m._DEFAULT_GUARDS)
        self.assertNotIn(self.m.G12_NORECOVER_PID, summary["patterns"],
                         "advisory detector must not feed go_findings")
        self.assertFalse(
            (ws / ".auditooor" / self.m.G12_NORECOVER_OUT).exists(),
            "no jsonl emitted when the env flag is unset")

    def test_advisory_emits_when_env_set(self):
        ws = Path(tempfile.mkdtemp())
        (ws / "src").mkdir()
        (ws / "src" / "goroutines.go").write_text(self.src)
        os.environ[self.m.G12_NORECOVER_ENV] = "1"
        try:
            self.m.scan_workspace(ws, self.m._DEFAULT_GUARDS)
        finally:
            os.environ.pop(self.m.G12_NORECOVER_ENV, None)
        self.assertTrue(
            (ws / ".auditooor" / self.m.G12_NORECOVER_OUT).exists(),
            "jsonl emitted when the env flag is set")


if __name__ == "__main__":
    unittest.main()
