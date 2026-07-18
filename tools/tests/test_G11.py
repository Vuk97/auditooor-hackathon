#!/usr/bin/env python3
"""test_G11.py - go.panic.untrusted_ingress_unbounded_loop_or_panic (G11).

Extends tools/go-detector-runner.py with an advisory-first, NO-AUTO-CREDIT
(verdict=needs-fuzz) detector that fires when a value from an EXTERNAL ingress
(a Cosmos ``sdk.Msg`` receiver / ValidateBasic, or a gRPC ``*...Request``
param) reaches an unbounded sink (``for range`` / ``make([]T,n)`` / index /
``/`` ``%`` divisor) with NO dominating len/zero guard before the sink.

Non-vacuity: the guard predicate (``_g11_guard_before``), the taint-gate
(``_g11_taint_roots``) and the accessor FP-guard (``_G11_ACCESSOR_NAME``) are
load-bearing. Neutralising the accessor filter makes the benign getter fire;
neutralising the sink matcher silences every hit; the mutation-kill pair
(unguarded fires / len-capped silent) is asserted against the fixtures.

Dedup boundary (A1): the emitter diffs emitted hits vs Pattern 36
(loop.untrusted_length_unbounded, the in-file analog of fire7 cap-growth) and
Pattern 11 (gas_price_zero) by (file,line) - it does NOT re-derive a
covered_by signal.
"""
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "go-detector-runner.py"
_FIX = Path(__file__).resolve().parent / "fixtures" / "G11"


def _load():
    spec = importlib.util.spec_from_file_location("gdr_g11", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["gdr_g11"] = m
    spec.loader.exec_module(m)
    return m


class TestIngressUnboundedLoopOrPanic(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        self.path = _FIX / "ingress.go"
        self.src = self.path.read_text()
        self.funcs = self.m._extract_functions(self.src, self.path)

    def _hits(self, funcs=None):
        return self.m._detect_ingress_unbounded_loop_or_panic(
            funcs if funcs is not None else self.funcs)

    def _by_fn(self, funcs=None):
        out = {}
        for h in self._hits(funcs):
            out.setdefault(h.extra.get("function"), []).append(h)
        return out

    # ---- core predicate matrix ------------------------------------------
    def test_fires_on_unguarded_ingress_sinks(self):
        fns = self._by_fn()
        # both ValidateBasic (msg range) and ValidateBasic (msg div) share the
        # name; DoWork is the rpc make sink. Assert on sink kinds present.
        sinks = {(h.extra.get("function"), h.extra.get("sink"))
                 for hs in fns.values() for h in hs}
        self.assertIn(("ValidateBasic", "range"), sinks)
        self.assertIn(("ValidateBasic", "divmod"), sinks)
        self.assertIn(("DoWork", "make_slice"), sinks)

    def test_range_records_msg_entry_kind(self):
        h = [h for h in self._hits()
             if h.extra.get("sink") == "range"
             and h.extra.get("function") == "ValidateBasic"][0]
        self.assertEqual(h.extra.get("entry_kind"), "msg")
        self.assertEqual(h.extra.get("taint_root"), "msg")

    def test_make_records_rpc_entry_kind(self):
        h = [h for h in self._hits()
             if h.extra.get("sink") == "make_slice"][0]
        self.assertEqual(h.extra.get("entry_kind"), "rpc")
        self.assertEqual(h.extra.get("taint_root"), "req")

    # ---- mutation-kill CLEAN half (FP-guards) ---------------------------
    def test_len_cap_suppresses(self):
        self.assertNotIn(
            "MsgCapped", {h.extra.get("receiver", "").split()[-1]
                          for h in self._hits() if h.extra.get("receiver")},
            "a len cap before the range suppresses the benign sibling")

    def test_zero_guard_suppresses_div(self):
        # benignZeroGuard is a ValidateBasic on MsgGuardedRate; assert no
        # divmod hit whose receiver names MsgGuardedRate.
        for h in self._hits():
            if h.extra.get("sink") == "divmod":
                self.assertNotIn("MsgGuardedRate", h.extra.get("receiver", ""),
                                 "a zero-guard before the div suppresses")

    def test_accessor_excluded(self):
        self.assertNotIn("GetIAssets", self._by_fn(),
                         "an accessor/serializer is not an ingress handler")

    def test_local_only_excluded(self):
        self.assertNotIn("Helper", self._by_fn(),
                         "a purely-local range is not tainted ingress")

    def test_test_file_skipped(self):
        skip = _FIX / "ingress_skip_test.go"
        funcs = self.m._extract_functions(skip.read_text(), skip)
        self.assertEqual(self._hits(funcs), [],
                         "*_test.go ingress must be skipped")

    # ---- non-vacuity: predicates are load-bearing -----------------------
    def test_accessor_filter_load_bearing(self):
        saved = self.m._G11_ACCESSOR_NAME
        try:
            self.m._G11_ACCESSOR_NAME = re.compile(r"ZZZ_NEVER_MATCHES")
            self.assertIn("GetIAssets", self._by_fn(),
                          "dropping the accessor filter must (wrongly) fire "
                          "the benign getter")
        finally:
            self.m._G11_ACCESSOR_NAME = saved
        self.assertNotIn("GetIAssets", self._by_fn())

    def test_guard_predicate_load_bearing(self):
        # Neutralise the guard-before-sink check: the benign len-capped and
        # zero-guarded siblings WRONGLY start firing.
        saved = self.m._g11_guard_before
        try:
            self.m._g11_guard_before = lambda *_a, **_k: False
            recvs = {h.extra.get("receiver", "") for h in self._hits()}
            self.assertTrue(
                any("MsgCapped" in r for r in recvs),
                "dropping the guard check must fire the len-capped sibling")
            self.assertTrue(
                any("MsgGuardedRate" in r for r in recvs),
                "dropping the guard check must fire the zero-guarded sibling")
        finally:
            self.m._g11_guard_before = saved
        recvs = {h.extra.get("receiver", "") for h in self._hits()}
        self.assertFalse(any("MsgCapped" in r for r in recvs),
                         "restored guard silences the benign sibling again")

    def test_taint_gate_load_bearing(self):
        # If _g11_sink never matches, no ingress hit survives.
        saved = self.m._g11_sink
        try:
            self.m._g11_sink = lambda *_a, **_k: None
            self.assertEqual(self._hits(), [],
                             "no sink -> no ingress DoS/panic hypothesis")
        finally:
            self.m._g11_sink = saved

    # ---- dedup boundary (A1): diff vs Pattern 36 / 11, not re-derived ---
    def test_dedup_drops_overlap(self):
        ws = Path(tempfile.mkdtemp())
        (ws / "src").mkdir()
        p = ws / "src" / "ingress.go"
        p.write_text(self.src)
        funcs = self.m._extract_functions(self.src, p)
        rng = [h for h in self._hits(funcs)
               if h.extra.get("sink") == "range"][0]
        collide = self.m.Hit(file=rng.file, line=rng.line, snippet="x")
        # collide as a Pattern-36 (growth) hit -> that (file,line) is dropped.
        recs, _ = self.m._emit_ingress_unbounded_loop_or_panic_hypotheses(
            ws, funcs, [collide], [])
        dropped = {(r["file"], r["line"]) for r in recs}
        self.assertNotIn((rng.file, rng.line), dropped,
                         "a (file,line) collision with growth is de-duped")
        # a non-colliding sink still survives.
        self.assertTrue(len(recs) >= 1, "non-colliding hits survive")

    # ---- advisory-first + NO-AUTO-CREDIT -------------------------------
    def test_emit_writes_needs_fuzz_jsonl(self):
        ws = Path(tempfile.mkdtemp())
        (ws / "src").mkdir()
        p = ws / "src" / "ingress.go"
        p.write_text(self.src)
        funcs = self.m._extract_functions(self.src, p)
        recs, out = self.m._emit_ingress_unbounded_loop_or_panic_hypotheses(
            ws, funcs, [], [])
        self.assertTrue(out.exists())
        self.assertGreaterEqual(len(recs), 1)
        self.assertTrue(all(r["verdict"] == "needs-fuzz" for r in recs),
                        "every emitted row is NO-AUTO-CREDIT needs-fuzz")
        self.assertTrue(all(r["pattern_id"] == self.m.G11_INGRESS_PID
                            for r in recs))

    def test_advisory_off_by_default_not_in_patterns(self):
        ws = Path(tempfile.mkdtemp())
        (ws / "src").mkdir()
        (ws / "src" / "ingress.go").write_text(self.src)
        os.environ.pop(self.m.G11_INGRESS_ENV, None)
        summary = self.m.scan_workspace(ws, self.m._DEFAULT_GUARDS)
        self.assertNotIn(self.m.G11_INGRESS_PID, summary["patterns"],
                         "advisory detector must not feed go_findings")
        self.assertFalse(
            (ws / ".auditooor" / self.m.G11_INGRESS_OUT).exists(),
            "no jsonl emitted when the env flag is unset")

    def test_advisory_emits_when_env_set(self):
        ws = Path(tempfile.mkdtemp())
        (ws / "src").mkdir()
        (ws / "src" / "ingress.go").write_text(self.src)
        os.environ[self.m.G11_INGRESS_ENV] = "1"
        try:
            self.m.scan_workspace(ws, self.m._DEFAULT_GUARDS)
        finally:
            os.environ.pop(self.m.G11_INGRESS_ENV, None)
        self.assertTrue(
            (ws / ".auditooor" / self.m.G11_INGRESS_OUT).exists(),
            "jsonl emitted when the env flag is set")


if __name__ == "__main__":
    unittest.main()
