#!/usr/bin/env python3
"""test_G7.py - go.crypto.counter.onesided_acceptance advisory axis (G7).

Extends tools/go-detector-runner.py with an advisory-first, NO-AUTO-CREDIT
(verdict=needs-fuzz) detector that fires when an accept/reject branch keyed on
a nonce/seq/sequence-named ident ADMITS the boundary-equal (stored-counter)
value into the accept region via ``>=`` / ``>`` / ``==`` without a strict-
successor (``== stored + 1``) validation - the classic nonce/seq REUSE shape.

Non-vacuity: the polarity predicate ``_g7_equal_admitted`` is load-bearing.
Mutating it (dropping the branch-polarity distinction) makes a case flip:
the benign REJECT ``>=`` fixture would start firing OR the mutant REJECT
``>`` fixture would stop. The mutation-kill pair (benign ``>=`` silent /
mutant ``>`` fires) is asserted directly against the fixtures.
"""
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "go-detector-runner.py"
_FIX = Path(__file__).resolve().parent / "fixtures" / "G7"


def _load():
    spec = importlib.util.spec_from_file_location("gdr_g7", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["gdr_g7"] = m
    spec.loader.exec_module(m)
    return m


class TestOnesidedAcceptance(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        src = (_FIX / "onesided.go").read_text()
        self.src = src
        self.funcs = self.m._extract_functions(src, _FIX / "onesided.go")

    def _hit_fns(self):
        hits = self.m._detect_onesided_acceptance(self.funcs)
        return {h.extra.get("function"): h for h in hits}

    # ---- polarity matrix (the load-bearing behaviour) --------------------
    def test_fires_on_expected_functions_only(self):
        fns = set(self._hit_fns())
        self.assertEqual(
            fns,
            {"rejectGT", "acceptGE", "acceptEQ"},
            "detector must fire exactly on the boundary-equal-admitting shapes",
        )

    def test_benign_reject_ge_silent(self):
        # mutation-kill CLEAN half: benign optimism InsertGap ">=" reject.
        self.assertNotIn("rejectGE", self._hit_fns())

    def test_mutant_reject_gt_fires(self):
        # mutation-kill MUTANT half: weakened ">" reject admits equal -> reuse.
        h = self._hit_fns().get("rejectGT")
        self.assertIsNotNone(h)
        self.assertEqual(h.extra.get("op"), ">")
        self.assertEqual(h.extra.get("branch_kind"), "reject")

    def test_accept_gt_silent(self):
        self.assertNotIn("acceptGT", self._hit_fns())

    # ---- FP-guards -------------------------------------------------------
    def test_successor_form_suppresses(self):
        self.assertNotIn("successorGuarded", self._hit_fns(),
                         "a strict-successor '== stored+1' form must suppress")

    def test_nil_operand_silent(self):
        self.assertNotIn("nilCheck", self._hit_fns())

    def test_comment_not_matched(self):
        self.assertNotIn("commentOnly", self._hit_fns(),
                         "an if inside a comment must not fire (comment mask)")

    def test_non_nonce_silent(self):
        self.assertNotIn("nonNonce", self._hit_fns(),
                         "non-nonce/seq operands are out of scope")

    # ---- non-vacuity: the polarity predicate is load-bearing -------------
    def test_polarity_predicate_load_bearing(self):
        saved = self.m._g7_equal_admitted
        try:
            # Neutralise polarity: always-True admits equal for every shape.
            self.m._g7_equal_admitted = lambda op, kind: True
            fns = set(self._hit_fns())
            # Now the benign REJECT ">=" starts firing (regression the real
            # predicate prevents) and the ACCEPT ">" also fires.
            self.assertIn("rejectGE", fns,
                          "dropping polarity must (wrongly) fire benign >=")
            self.assertIn("acceptGT", fns)
        finally:
            self.m._g7_equal_admitted = saved
        # restored predicate: benign silent again.
        self.assertNotIn("rejectGE", self._hit_fns())

    def test_nonce_token_predicate_load_bearing(self):
        saved = self.m._G7_NONCE_TOKEN
        try:
            self.m._G7_NONCE_TOKEN = re.compile(r"ZZZ_NEVER_MATCHES")
            self.assertEqual(self.m._detect_onesided_acceptance(self.funcs), [],
                             "neutralising the nonce-token scope silences all")
        finally:
            self.m._G7_NONCE_TOKEN = saved

    # ---- dedup boundary (A1): diff vs Pattern 40, not re-derived ---------
    def test_dedup_drops_pattern40_overlap(self):
        ws = Path(tempfile.mkdtemp())
        (ws / "src").mkdir()
        (ws / "src" / "onesided.go").write_text(self.src)
        funcs = self.m._extract_functions(
            self.src, ws / "src" / "onesided.go")
        # Fabricate a Pattern-40 hit colliding with the rejectGT hit line.
        gt = [h for h in self.m._detect_onesided_acceptance(funcs)
              if h.extra.get("function") == "rejectGT"][0]
        collide = self.m.Hit(file=gt.file, line=gt.line, snippet="x")
        recs, _ = self.m._emit_onesided_acceptance_hypotheses(
            ws, funcs, [collide])
        emitted = {(r["function"]) for r in recs}
        self.assertNotIn("rejectGT", emitted,
                         "a (file,line) collision with Pattern 40 is de-duped")
        self.assertIn("acceptGE", emitted, "non-colliding hits survive")

    # ---- advisory-first + NO-AUTO-CREDIT ---------------------------------
    def test_emit_writes_needs_fuzz_jsonl(self):
        ws = Path(tempfile.mkdtemp())
        (ws / "src").mkdir()
        (ws / "src" / "onesided.go").write_text(self.src)
        funcs = self.m._extract_functions(
            self.src, ws / "src" / "onesided.go")
        recs, out = self.m._emit_onesided_acceptance_hypotheses(ws, funcs, [])
        self.assertTrue(out.exists())
        self.assertGreaterEqual(len(recs), 1)
        self.assertTrue(all(r["verdict"] == "needs-fuzz" for r in recs),
                        "every emitted row is NO-AUTO-CREDIT needs-fuzz")
        self.assertTrue(all(r["pattern_id"] == self.m.G7_ONESIDED_PID
                            for r in recs))

    def test_advisory_off_by_default_not_in_patterns(self):
        # G7 must NOT be one of the scored `patterns` (kept OUT, env-gated).
        ws = Path(tempfile.mkdtemp())
        (ws / "src").mkdir()
        (ws / "src" / "onesided.go").write_text(self.src)
        os.environ.pop(self.m.G7_ONESIDED_ENV, None)
        summary = self.m.scan_workspace(ws, self.m._DEFAULT_GUARDS)
        self.assertNotIn(self.m.G7_ONESIDED_PID, summary["patterns"],
                         "advisory detector must not feed go_findings")
        self.assertFalse(
            (ws / ".auditooor" / self.m.G7_ONESIDED_OUT).exists(),
            "no jsonl emitted when the env flag is unset")


if __name__ == "__main__":
    unittest.main()
