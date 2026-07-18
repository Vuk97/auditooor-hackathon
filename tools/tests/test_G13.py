#!/usr/bin/env python3
"""test_G13.py - go.consensus.ctx_cancellation_ignored_verdict (G13).

Extends tools/go-detector-runner.py with an advisory-first, NO-AUTO-CREDIT
(verdict=needs-fuzz) detector that fires when a consensus/validation/state-
commitment function has a finalizing ``select`` performing a blocking channel
SEND with NO cancellation-receive arm, while the file otherwise honours a ctx
cancellation contract. On a cancelled ctx the send commits a verdict/write on
stale/aborted state -> a trusted-but-invalid verdict (freshness invariant).

Non-vacuity: three predicate arms are load-bearing and each is mutation-tested
below - (1) the cancel-receive escape arm defends the CLEAN sibling; (2) a
``default:`` arm defends a non-blocking best-effort send; (3) a send-case must
be present (a pure recv-multiplex is not a verdict commit).

Dedup boundary (A1): the emitter diffs emitted hits vs G12
(goroutine_no_toplevel_recover) by (file,line) - it does NOT re-derive a
covered_by signal. G13's exploit_class attacks the FRESHNESS invariant, DISTINCT
from G3/G12 which attack a PANIC.
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "go-detector-runner.py"
_FIX = Path(__file__).resolve().parent / "fixtures" / "G13"


def _load():
    spec = importlib.util.spec_from_file_location("gdr_g13", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["gdr_g13"] = m
    spec.loader.exec_module(m)
    return m


class TestCtxCancellationIgnoredVerdict(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        self.path = _FIX / "commit_writer.go"
        self.src = self.path.read_text()

    def _hits(self, src=None, rel="consensus/commit_writer.go"):
        src = src if src is not None else self.src
        funcs = self.m._extract_functions(src, Path(rel))
        return self.m._detect_ctx_cancellation_ignored_verdict(funcs, {rel: src})

    def _fns(self, hits):
        return {h.extra.get("function") for h in hits}

    # ---- core predicate matrix ------------------------------------------
    def test_fires_only_on_vuln(self):
        fns = self._fns(self._hits())
        self.assertEqual(
            fns, {"writeLeafVuln"},
            "exactly the ctx.Done-less finalizing send fires")

    def test_clean_sibling_not_fired(self):
        self.assertNotIn("writeLeafClean", self._fns(self._hits()),
                         "a select WITH a ctx.Done() arm is defended")

    def test_default_arm_defended(self):
        self.assertNotIn("fail", self._fns(self._hits()),
                         "a non-blocking best-effort select (default:) is clean")

    def test_pure_recv_not_verdict(self):
        self.assertNotIn("waitForWrites", self._fns(self._hits()),
                         "a pure receive-multiplex is not a finalizing send")

    def test_consensus_anchor_required(self):
        # Generic receiver/name/path (no consensus/validation/state idiom) must
        # not fire even with an identical ctx.Done-less finalizing send.
        generic = (
            "package util\nimport \"context\"\n"
            "type pool struct { ctx context.Context; ch chan int }\n"
            "func (p *pool) push(v int) error {\n"
            "\t_ = p.ctx\n\tselect {\n\tcase p.ch <- v:\n\t\treturn nil\n\t}\n}\n")
        hits = self._hits(generic, rel="util/worker_pool.go")
        self.assertEqual(hits, [], "off-consensus-path code is not in scope")

    def test_file_ctx_contract_required(self):
        # Strip every cancellation reference -> no ctx contract -> no fire even
        # though the vuln select is unchanged (file-level guard is load-bearing).
        stripped = self.src.replace("context", "xxx").replace(
            "w.ctx.Done()", "w.q").replace("w.ctx.Err()", "nil")
        self.assertEqual(
            self._hits(stripped), [],
            "no cancellation contract in the file -> nothing to break")

    # ---- non-vacuity: cancel-arm predicate is load-bearing --------------
    def test_cancel_arm_load_bearing(self):
        # Drop the ctx.Done() arm from the CLEAN method -> it starts firing.
        broke = self.src.replace(
            "\tcase w.kvChan <- op:\n\tcase <-w.ctx.Done():\n\t\treturn w.ctx.Err()\n",
            "\tcase w.kvChan <- op:\n")
        self.assertIn("writeLeafClean", self._fns(self._hits(broke)),
                      "removing the ctx.Done() arm flips the clean sibling")

    def test_test_file_skipped(self):
        hits = self._hits(rel="consensus/commit_writer_test.go")
        self.assertEqual(hits, [], "*_test.go must be skipped")

    def test_testdata_skipped(self):
        hits = self._hits(rel="consensus/testdata/commit_writer.go")
        self.assertEqual(hits, [], "/testdata/ must be skipped")

    # ---- dedup boundary (A1): diff vs G12, not re-derived ----------------
    def test_dedup_drops_g12_overlap(self):
        ws = Path(tempfile.mkdtemp())
        (ws / "consensus").mkdir()
        (ws / "consensus" / "commit_writer.go").write_text(self.src)
        rel = "consensus/commit_writer.go"
        one = self._hits()[0]
        collide = self.m.Hit(file=one.file, line=one.line, snippet="x")
        recs, _ = self.m._emit_ctx_cancellation_ignored_verdict_hypotheses(
            ws, self.m._extract_functions(self.src, Path(rel)),
            {rel: self.src}, [collide])
        kept = {(r["file"], r["line"]) for r in recs}
        self.assertNotIn((one.file, one.line), kept,
                         "a (file,line) collision with G12 is de-duped")

    def test_exploit_class_distinct_from_panic(self):
        # G13 attacks freshness, not a crash: exploit_class differs from G12.
        self.assertNotEqual(self.m.G13_CTXVERDICT_EXPLOIT_CLASS,
                            self.m.G12_NORECOVER_EXPLOIT_CLASS)
        self.assertNotIn("panic", self.m.G13_CTXVERDICT_EXPLOIT_CLASS)

    # ---- advisory-first + NO-AUTO-CREDIT --------------------------------
    def test_emit_writes_needs_fuzz_jsonl(self):
        ws = Path(tempfile.mkdtemp())
        rel = "consensus/commit_writer.go"
        recs, out = self.m._emit_ctx_cancellation_ignored_verdict_hypotheses(
            ws, self.m._extract_functions(self.src, Path(rel)),
            {rel: self.src}, [])
        self.assertTrue(out.exists())
        self.assertGreaterEqual(len(recs), 1)
        self.assertTrue(all(r["verdict"] == "needs-fuzz" for r in recs),
                        "every emitted row is NO-AUTO-CREDIT needs-fuzz")
        self.assertTrue(all(r["pattern_id"] == self.m.G13_CTXVERDICT_PID
                            for r in recs))

    def test_advisory_off_by_default_not_in_patterns(self):
        ws = Path(tempfile.mkdtemp())
        (ws / "consensus").mkdir()
        (ws / "consensus" / "commit_writer.go").write_text(self.src)
        os.environ.pop(self.m.G13_CTXVERDICT_ENV, None)
        summary = self.m.scan_workspace(ws, self.m._DEFAULT_GUARDS)
        self.assertNotIn(self.m.G13_CTXVERDICT_PID, summary["patterns"],
                         "advisory detector must not feed go_findings")
        self.assertFalse(
            (ws / ".auditooor" / self.m.G13_CTXVERDICT_OUT).exists(),
            "no jsonl emitted when the env flag is unset")

    def test_advisory_emits_when_env_set(self):
        ws = Path(tempfile.mkdtemp())
        (ws / "consensus").mkdir()
        (ws / "consensus" / "commit_writer.go").write_text(self.src)
        os.environ[self.m.G13_CTXVERDICT_ENV] = "1"
        try:
            self.m.scan_workspace(ws, self.m._DEFAULT_GUARDS)
        finally:
            os.environ.pop(self.m.G13_CTXVERDICT_ENV, None)
        self.assertTrue(
            (ws / ".auditooor" / self.m.G13_CTXVERDICT_OUT).exists(),
            "jsonl emitted when the env flag is set")


if __name__ == "__main__":
    unittest.main()
