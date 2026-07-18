#!/usr/bin/env python3
"""test_g15_iteration_bound_bypass.py - go.iteration.bound_bypass_sibling_exit (G15).

Extends tools/go-detector-runner.py with an advisory-first, NO-AUTO-CREDIT
(verdict=needs-fuzz) detector that fires when a BOUNDED iteration (a cosmos
``.Walk`` / ``.WalkDue`` / ``.Iterate`` callback, or a ``for ... range`` loop
with a counter) has a per-item cap ``if <counter> ==/>= <bound> { stop }`` that
is BYPASSED by a SIBLING guard-clause continue-exit (``return false`` /
``return nil`` in a callback, ``continue`` in a for-range) positioned BEFORE the
``<counter>++``. Items on the sibling branch are walked WITHOUT being counted,
so the cap does not bound the walk. NORTH STAR: a trusted per-iteration bound is
bypassable by a sibling early-exit path.

Mined from a PoC-confirmed nuva Medium (src/vault/keeper/payout.go:26-37).

Non-vacuity: three predicate arms are load-bearing and each is mutation-tested
below - (1) the sibling continue-exit must precede ``counter++`` (hoisting the
increment above it flips the vuln to SILENT); (2) a per-iteration cap must be
PRESENT (removing it is the G11/Pattern-36 uncapped shape, not G15); (3) the
sibling must be a CONTINUE exit, never the ``return true`` / ``break`` stop.

Dedup boundary: G15 REQUIRES a cap present-but-bypassed; G11
(``ingress_unbounded_loop_or_panic``) and Pattern 36
(``loop.untrusted_length_unbounded``) fire on the OPPOSITE uncapped shape, so
the two lanes are structurally disjoint (no runtime diff needed).
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "go-detector-runner.py"
_FIX = Path(__file__).resolve().parent / "fixtures" / "G15"


def _load():
    spec = importlib.util.spec_from_file_location("gdr_g15", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["gdr_g15"] = m
    spec.loader.exec_module(m)
    return m


class TestIterationBoundBypass(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        self.path = _FIX / "collector.go"
        self.src = self.path.read_text()

    def _hits(self, src=None, rel="keeper/collector.go"):
        src = src if src is not None else self.src
        fbf = {Path(rel): self.m._extract_functions(src, Path(rel))}
        return self.m._detect_iteration_bound_bypass({Path(rel): src}, fbf)

    def _fns(self, hits):
        return {h.extra.get("function") for h in hits}

    # ---- core predicate matrix ------------------------------------------
    def test_fires_on_walk_bypass_and_forrange_bypass(self):
        fns = self._fns(self._hits())
        self.assertEqual(
            fns, {"collectDueVuln", "collectForRangeVuln"},
            "exactly the two cap-present-but-bypassed shapes fire")

    def test_clean_counter_first_not_fired(self):
        self.assertNotIn(
            "collectDueClean", self._fns(self._hits()),
            "counter++ before every continue-exit is defended (no bypass)")

    def test_uncapped_loop_not_fired_dedup_vs_g11(self):
        self.assertNotIn(
            "collectNoBound", self._fns(self._hits()),
            "an uncapped loop is the G11/Pattern-36 shape, not G15")

    def test_walk_hit_fields(self):
        h = next(x for x in self._hits()
                 if x.extra["function"] == "collectDueVuln")
        self.assertEqual(h.extra["counter"], "processed")
        self.assertEqual(h.extra["shape"], "walk-callback")
        # bypass branch is textually BEFORE the bound-check line.
        self.assertLess(h.extra["bypass_branch_line"], h.extra["bound_check_line"])
        # walk-call anchor precedes the bypass line.
        self.assertLess(h.line, h.extra["bypass_branch_line"])

    def test_forrange_hit_fields(self):
        h = next(x for x in self._hits()
                 if x.extra["function"] == "collectForRangeVuln")
        self.assertEqual(h.extra["counter"], "count")
        self.assertEqual(h.extra["shape"], "for-range")

    # ---- non-vacuity: each predicate arm is load-bearing ----------------
    def test_incr_before_bypass_is_load_bearing(self):
        # Hoist `processed++` above the paused-skip in collectDueVuln -> SILENT.
        broke = self.src.replace(
            "\t\tv, ok := k.tryGet(ctx, addr)\n"
            "\t\tif ok && v.Paused {\n\t\t\treturn false, nil\n\t\t}\n"
            "\t\tif processed == batchSize {\n\t\t\treturn true, nil\n\t\t}\n"
            "\t\tprocessed++",
            "\t\tprocessed++\n"
            "\t\tv, ok := k.tryGet(ctx, addr)\n"
            "\t\tif ok && v.Paused {\n\t\t\treturn false, nil\n\t\t}\n"
            "\t\tif processed == batchSize {\n\t\t\treturn true, nil\n\t\t}",
            1)
        self.assertNotEqual(broke, self.src, "mutation anchor must apply")
        self.assertNotIn(
            "collectDueVuln", self._fns(self._hits(broke)),
            "hoisting counter++ above the sibling exit kills the finding")

    def test_cap_presence_is_load_bearing(self):
        # Remove the per-iteration cap from collectDueVuln -> uncapped shape,
        # owned by G11/Pattern-36, NOT G15 -> SILENT here.
        broke = self.src.replace(
            "\t\tif processed == batchSize {\n\t\t\treturn true, nil\n\t\t}\n", "", 1)
        self.assertNotEqual(broke, self.src, "mutation anchor must apply")
        self.assertNotIn(
            "collectDueVuln", self._fns(self._hits(broke)),
            "no per-iteration cap -> not the G15 lane (disjoint from G11)")

    def test_stop_exit_not_treated_as_bypass(self):
        # The bound-check's own `return true` (a STOP) must never be counted as
        # a bypass. collectDueClean has a `return true` cap yet is SILENT.
        self.assertNotIn("collectDueClean", self._fns(self._hits()))

    # ---- masking + skip hygiene -----------------------------------------
    def test_commented_bypass_not_matched(self):
        # A `// return false` comment before counter++ must not fire (masking).
        commented = self.src.replace(
            "\t\tif ok && v.Paused {\n\t\t\treturn false, nil\n\t\t}\n"
            "\t\tif processed == batchSize {\n\t\t\treturn true, nil\n\t\t}\n"
            "\t\tprocessed++",
            "\t\t// if ok { return false, nil }\n"
            "\t\tif processed == batchSize {\n\t\t\treturn true, nil\n\t\t}\n"
            "\t\tprocessed++",
            1)
        self.assertNotIn(
            "collectDueVuln", self._fns(self._hits(commented)),
            "a continue-exit inside a comment is masked and never matches")

    def test_test_file_skipped(self):
        self.assertEqual(
            self._hits(rel="keeper/collector_test.go"), [],
            "*_test.go must be skipped")

    def test_testdata_skipped(self):
        self.assertEqual(
            self._hits(rel="keeper/testdata/collector.go"), [],
            "/testdata/ must be skipped")

    # ---- advisory-first + NO-AUTO-CREDIT --------------------------------
    def test_emit_writes_needs_fuzz_jsonl(self):
        ws = Path(tempfile.mkdtemp())
        rel = "keeper/collector.go"
        fbf = {Path(rel): self.m._extract_functions(self.src, Path(rel))}
        recs, out = self.m._emit_iteration_bound_bypass_hypotheses(
            ws, {Path(rel): self.src}, fbf)
        self.assertTrue(out.exists())
        self.assertGreaterEqual(len(recs), 2)
        self.assertTrue(all(r["verdict"] == "needs-fuzz" for r in recs),
                        "every emitted row is NO-AUTO-CREDIT needs-fuzz")
        self.assertTrue(all(r["pattern_id"] == self.m._G15_PID for r in recs))
        self.assertTrue(all(r["source"] == "G15" for r in recs))
        self.assertTrue(all(
            r["attack_class"] == "iteration-bound-bypass-unbounded"
            for r in recs))

    def test_advisory_off_by_default_not_in_patterns(self):
        ws = Path(tempfile.mkdtemp())
        (ws / "keeper").mkdir()
        (ws / "keeper" / "collector.go").write_text(self.src)
        os.environ.pop(self.m._G15_ITER_BOUND_BYPASS_ENV, None)
        summary = self.m.scan_workspace(ws, self.m._DEFAULT_GUARDS)
        self.assertNotIn(self.m._G15_PID, summary["patterns"],
                         "advisory detector must not feed go_findings")
        self.assertFalse(
            (ws / ".auditooor" / self.m._G15_OUT).exists(),
            "no jsonl emitted when the env flag is unset")

    def test_advisory_emits_when_env_set(self):
        ws = Path(tempfile.mkdtemp())
        (ws / "keeper").mkdir()
        (ws / "keeper" / "collector.go").write_text(self.src)
        os.environ[self.m._G15_ITER_BOUND_BYPASS_ENV] = "1"
        try:
            self.m.scan_workspace(ws, self.m._DEFAULT_GUARDS)
        finally:
            os.environ.pop(self.m._G15_ITER_BOUND_BYPASS_ENV, None)
        self.assertTrue(
            (ws / ".auditooor" / self.m._G15_OUT).exists(),
            "jsonl emitted when the env flag is set")


if __name__ == "__main__":
    unittest.main()
