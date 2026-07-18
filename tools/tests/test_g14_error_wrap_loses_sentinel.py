#!/usr/bin/env python3
"""test_g14_error_wrap_loses_sentinel.py - go.errors.wrap_loses_sentinel (G14).

Extends tools/go-detector-runner.py with an advisory-first, NO-AUTO-CREDIT
(verdict=needs-fuzz) detector that fires when a SENTINEL-identity guard -
``errors.Is(err, ErrSentinel)`` or a direct ``err ==/!= ErrSentinel`` - is
rendered DEAD by a lossy ``fmt.Errorf`` (non-``%w``) wrap of that SAME sentinel
in the same file. The wrap drops the sentinel from the error chain, so the
guard's protected safety branch (retry / refund / pause / reject) silently never
fires. NORTH STAR: the guard's private invariant - that the error still CARRIES
the sentinel - is unsound because a lossy wrap severed the chain.

Anchor: nuva src/vault/keeper/payout.go:224 (getRefundReason keys off
errors.Is(err, sdkerrors.ErrInsufficientFunds)); nuva itself uses %w -> correctly
SILENT there (true-negative). The fixture is a faithful-Go-idiom reproduction.

Non-vacuity: three predicate arms are load-bearing and each is mutation-tested
below - (1) the wrap must be LOSSY (%v->%w flips the finding to SILENT); (2) a
co-located sentinel guard must be PRESENT (removing it is the Pattern-29 /
bare-wrap shape, not G14); (3) the guard must be real source, not a comment
(masking).

Dedup boundary: G14 REQUIRES a sentinel guard PLUS a lossy wrap of that SAME
sentinel; Pattern 29 (``rpc_boundary.bare_fmterrorf_user_input_parse_failure``)
fires on a bare RPC parse-error wrap with no sentinel guard, so the two lanes are
structurally disjoint (no runtime diff needed).
"""
import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "go-detector-runner.py"
_FIX = Path(__file__).resolve().parent / "fixtures" / "G14"


def _load():
    spec = importlib.util.spec_from_file_location("gdr_g14", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["gdr_g14"] = m
    spec.loader.exec_module(m)
    return m


class TestErrorWrapLosesSentinel(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        self.path = _FIX / "refund.go"
        self.src = self.path.read_text()

    def _hits(self, src=None, rel="keeper/refund.go"):
        src = src if src is not None else self.src
        fbf = {Path(rel): self.m._extract_functions(src, Path(rel))}
        return self.m._detect_error_wrap_loses_sentinel({Path(rel): src}, fbf)

    def _fns(self, hits):
        return {h.extra.get("function") for h in hits}

    # ---- core predicate matrix ------------------------------------------
    def test_fires_on_the_three_lossy_guarded_shapes(self):
        fns = self._fns(self._hits())
        self.assertEqual(
            fns, {"refundVuln", "pauseVuln", "closeVuln"},
            "exactly the guard+lossy-wrap co-locations fire (errors.Is, ==, qualified)")

    def test_clean_percent_w_not_fired(self):
        self.assertNotIn(
            "refundClean", self._fns(self._hits()),
            "a %w wrap preserves the sentinel chain -> guard still lives -> SILENT")

    def test_no_guard_wrap_not_fired_dedup_vs_pattern29(self):
        self.assertNotIn(
            "orphanVuln", self._fns(self._hits()),
            "a lossy wrap with NO co-located sentinel guard is the bare-wrap "
            "(Pattern 29) shape, not G14")

    def test_errors_is_hit_fields(self):
        h = next(x for x in self._hits()
                 if x.extra["function"] == "refundVuln")
        self.assertEqual(h.extra["sentinel"], "ErrInsufficientFunds")
        self.assertEqual(h.extra["verb"], "non-%w")
        self.assertIn("%v", h.extra["format"])

    def test_direct_compare_guard_arm(self):
        h = next(x for x in self._hits()
                 if x.extra["function"] == "pauseVuln")
        self.assertEqual(h.extra["sentinel"], "ErrPaused")

    def test_qualified_sentinel_arm(self):
        h = next(x for x in self._hits()
                 if x.extra["function"] == "closeVuln")
        self.assertEqual(h.extra["sentinel"], "sdkerrors.ErrClosed")

    # ---- non-vacuity: each predicate arm is load-bearing ----------------
    def test_lossy_verb_is_load_bearing(self):
        # Benign mutant: %v -> %w in refundVuln preserves the sentinel -> SILENT.
        broke = self.src.replace(
            "return fmt.Errorf(\"payout shortfall %d: %v\", shortfall, ErrInsufficientFunds)",
            "return fmt.Errorf(\"payout shortfall %d: %w\", shortfall, ErrInsufficientFunds)",
            1)
        self.assertNotEqual(broke, self.src, "mutation anchor must apply")
        self.assertNotIn(
            "refundVuln", self._fns(self._hits(broke)),
            "flipping the lossy %v to a chain-preserving %w kills the finding")

    def test_guard_presence_is_load_bearing(self):
        # Remove the co-located errors.Is guard from getReason -> no guard keys
        # off ErrInsufficientFunds -> refundVuln becomes the bare-wrap shape.
        broke = self.src.replace(
            "\tif errors.Is(err, ErrInsufficientFunds) {\n"
            "\t\treturn \"insufficient-funds\"\n\t}\n", "", 1)
        self.assertNotEqual(broke, self.src, "mutation anchor must apply")
        self.assertNotIn(
            "refundVuln", self._fns(self._hits(broke)),
            "no co-located sentinel guard -> not the G14 lane (disjoint from Pattern 29)")

    def test_commented_guard_not_matched(self):
        # A commented-out errors.Is guard must not count (masking).
        commented = self.src.replace(
            "\tif errors.Is(err, ErrInsufficientFunds) {\n"
            "\t\treturn \"insufficient-funds\"\n\t}",
            "\t// if errors.Is(err, ErrInsufficientFunds) { return x }",
            1)
        self.assertNotEqual(commented, self.src, "mutation anchor must apply")
        self.assertNotIn(
            "refundVuln", self._fns(self._hits(commented)),
            "a sentinel guard inside a comment is masked and never counts")

    # ---- masking + skip hygiene -----------------------------------------
    def test_test_file_skipped(self):
        self.assertEqual(
            self._hits(rel="keeper/refund_test.go"), [],
            "*_test.go must be skipped")

    def test_testdata_skipped(self):
        self.assertEqual(
            self._hits(rel="keeper/testdata/refund.go"), [],
            "/testdata/ must be skipped")

    def test_generated_pb_go_skipped(self):
        self.assertEqual(
            self._hits(rel="keeper/refund.pb.go"), [],
            "generated .pb.go must be skipped (proto ErrInvalidLength* FP flood)")

    # ---- advisory-first + NO-AUTO-CREDIT --------------------------------
    def test_emit_writes_needs_fuzz_jsonl(self):
        ws = Path(tempfile.mkdtemp())
        rel = "keeper/refund.go"
        fbf = {Path(rel): self.m._extract_functions(self.src, Path(rel))}
        recs, out = self.m._emit_sentinel_loss_hypotheses(
            ws, {Path(rel): self.src}, fbf)
        self.assertTrue(out.exists())
        self.assertGreaterEqual(len(recs), 3)
        self.assertTrue(all(r["verdict"] == "needs-fuzz" for r in recs),
                        "every emitted row is NO-AUTO-CREDIT needs-fuzz")
        self.assertTrue(all(r["pattern_id"] == self.m._G14_PID for r in recs))
        self.assertTrue(all(r["source"] == "G14" for r in recs))
        self.assertTrue(all(
            r["attack_class"] == "error-wrap-loses-sentinel" for r in recs))

    def test_advisory_off_by_default_not_in_patterns(self):
        ws = Path(tempfile.mkdtemp())
        (ws / "keeper").mkdir()
        (ws / "keeper" / "refund.go").write_text(self.src)
        os.environ.pop(self.m._G14_SENTINEL_LOSS_ENV, None)
        summary = self.m.scan_workspace(ws, self.m._DEFAULT_GUARDS)
        self.assertNotIn(self.m._G14_PID, summary["patterns"],
                         "advisory detector must not feed go_findings")
        self.assertFalse(
            (ws / ".auditooor" / self.m._G14_OUT).exists(),
            "no jsonl emitted when the env flag is unset")

    def test_advisory_emits_when_env_set(self):
        ws = Path(tempfile.mkdtemp())
        (ws / "keeper").mkdir()
        (ws / "keeper" / "refund.go").write_text(self.src)
        os.environ[self.m._G14_SENTINEL_LOSS_ENV] = "1"
        try:
            self.m.scan_workspace(ws, self.m._DEFAULT_GUARDS)
        finally:
            os.environ.pop(self.m._G14_SENTINEL_LOSS_ENV, None)
        self.assertTrue(
            (ws / ".auditooor" / self.m._G14_OUT).exists(),
            "jsonl emitted when the env flag is set")


if __name__ == "__main__":
    unittest.main()
