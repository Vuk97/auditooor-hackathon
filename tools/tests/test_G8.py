#!/usr/bin/env python3
"""test_G8.py - go.crypto.decode_accepts_malformed_then_trusted (G8).

Extends tools/go-detector-runner.py with an advisory-first, NO-AUTO-CREDIT
(verdict=needs-fuzz) detector that fires when a body decodes attacker bytes
(SigToPub / Ecrecover / asn1.Unmarshal / ParseCertificate / SetBytes) and the
value flows (decoder-before-sink) into a trust sink (Check / Verify /
PubkeyToAddress+allowlist) with NO canonical guard (ValidateSignatureValues /
low-S / half-order / len== / IsZero) in-body.

Non-vacuity: the canonical-guard predicate ``_G8_CANONICAL_GUARD`` and the
trust-sink predicate ``_G8_TRUST_SINK`` are load-bearing. Neutralising the
guard predicate makes the benign ``guardedRecover`` fixture (mutation-kill
CLEAN half) START firing; neutralising the sink predicate silences every hit.
The mutation-kill pair (guarded silent / lax fires) is asserted against the
fixtures.

Dedup boundary (A1): the emitter diffs emitted hits vs Pattern 5/6
(gossip_perimeter_trust) hits by (file,line) - it does NOT re-derive a
covered_by signal. Distinct predicate: gossip = decode-with-NO-verify;
G8 = verify-present-but-decode-lax.
"""
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "go-detector-runner.py"
_FIX = Path(__file__).resolve().parent / "fixtures" / "G8"


def _load():
    spec = importlib.util.spec_from_file_location("gdr_g8", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["gdr_g8"] = m
    spec.loader.exec_module(m)
    return m


class TestDecodeMalformedThenTrusted(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        self.path = _FIX / "decode_trust.go"
        self.src = self.path.read_text()
        self.funcs = self.m._extract_functions(self.src, self.path)

    def _hit_fns(self, funcs=None):
        hits = self.m._detect_decode_accepts_malformed_then_trusted(
            funcs if funcs is not None else self.funcs)
        return {h.extra.get("function"): h for h in hits}

    # ---- core predicate matrix ------------------------------------------
    def test_fires_on_lax_decode_trust_only(self):
        self.assertEqual(
            set(self._hit_fns()),
            {"laxRecover", "laxCertParse"},
            "detector fires exactly on lax decode->trust with no guard",
        )

    def test_lax_recover_records_contract(self):
        h = self._hit_fns()["laxRecover"]
        self.assertEqual(h.extra.get("decoder"), "sig_to_pub")
        self.assertTrue(h.extra.get("malleability_matters"))
        self.assertIn("Check", h.extra.get("sink"))

    # ---- mutation-kill CLEAN half (FP-guards) ---------------------------
    def test_canonical_guard_suppresses(self):
        self.assertNotIn("guardedRecover", self._hit_fns(),
                         "a ValidateSignatureValues/low-S guard suppresses")

    def test_len_guard_suppresses(self):
        self.assertNotIn("lenGuardedVerify", self._hit_fns(),
                         "a len== well-formedness guard suppresses")

    def test_impact_contract_required(self):
        self.assertNotIn("decodeThenLog", self._hit_fns(),
                         "decode with no trust sink must not fire")

    def test_flow_proxy_decoder_before_sink(self):
        self.assertNotIn("sinkBeforeDecode", self._hit_fns(),
                         "a sink BEFORE the decoder is not this contract")

    def test_test_file_skipped(self):
        skip = _FIX / "decode_trust_skip_test.go"
        funcs = self.m._extract_functions(skip.read_text(), skip)
        self.assertEqual(self._hit_fns(funcs), {},
                         "*_test.go decode-trust must be skipped")

    # ---- non-vacuity: predicates are load-bearing -----------------------
    def test_canonical_guard_predicate_load_bearing(self):
        saved = self.m._G8_CANONICAL_GUARD
        try:
            # Neutralise the guard: nothing counts as canonical -> the benign
            # guardedRecover / lenGuardedVerify fixtures WRONGLY start firing.
            self.m._G8_CANONICAL_GUARD = re.compile(r"ZZZ_NEVER_MATCHES")
            fns = set(self._hit_fns())
            self.assertIn("guardedRecover", fns,
                          "dropping the guard predicate must (wrongly) fire "
                          "the guarded fixture")
            self.assertIn("lenGuardedVerify", fns)
        finally:
            self.m._G8_CANONICAL_GUARD = saved
        # restored predicate: benign silent again.
        self.assertNotIn("guardedRecover", self._hit_fns())

    def test_trust_sink_predicate_load_bearing(self):
        saved = self.m._G8_TRUST_SINK
        try:
            self.m._G8_TRUST_SINK = re.compile(r"ZZZ_NEVER_MATCHES")
            self.assertEqual(
                self.m._detect_decode_accepts_malformed_then_trusted(
                    self.funcs), [],
                "neutralising the trust-sink (impact_contract) silences all")
        finally:
            self.m._G8_TRUST_SINK = saved

    # ---- dedup boundary (A1): diff vs Pattern 5/6, not re-derived -------
    def test_dedup_drops_gossip_overlap(self):
        ws = Path(tempfile.mkdtemp())
        (ws / "src").mkdir()
        (ws / "src" / "decode_trust.go").write_text(self.src)
        funcs = self.m._extract_functions(
            self.src, ws / "src" / "decode_trust.go")
        lax = [h for h in
               self.m._detect_decode_accepts_malformed_then_trusted(funcs)
               if h.extra.get("function") == "laxRecover"][0]
        collide = self.m.Hit(file=lax.file, line=lax.line, snippet="x")
        recs, _ = self.m._emit_decode_malformed_then_trusted_hypotheses(
            ws, funcs, [collide])
        emitted = {r["function"] for r in recs}
        self.assertNotIn("laxRecover", emitted,
                         "a (file,line) collision with gossip is de-duped")
        self.assertIn("laxCertParse", emitted, "non-colliding hits survive")

    # ---- advisory-first + NO-AUTO-CREDIT -------------------------------
    def test_emit_writes_needs_fuzz_jsonl(self):
        ws = Path(tempfile.mkdtemp())
        (ws / "src").mkdir()
        (ws / "src" / "decode_trust.go").write_text(self.src)
        funcs = self.m._extract_functions(
            self.src, ws / "src" / "decode_trust.go")
        recs, out = self.m._emit_decode_malformed_then_trusted_hypotheses(
            ws, funcs, [])
        self.assertTrue(out.exists())
        self.assertGreaterEqual(len(recs), 1)
        self.assertTrue(all(r["verdict"] == "needs-fuzz" for r in recs),
                        "every emitted row is NO-AUTO-CREDIT needs-fuzz")
        self.assertTrue(all(r["pattern_id"] == self.m.G8_DECODE_PID
                            for r in recs))

    def test_advisory_off_by_default_not_in_patterns(self):
        ws = Path(tempfile.mkdtemp())
        (ws / "src").mkdir()
        (ws / "src" / "decode_trust.go").write_text(self.src)
        os.environ.pop(self.m.G8_DECODE_ENV, None)
        summary = self.m.scan_workspace(ws, self.m._DEFAULT_GUARDS)
        self.assertNotIn(self.m.G8_DECODE_PID, summary["patterns"],
                         "advisory detector must not feed go_findings")
        self.assertFalse(
            (ws / ".auditooor" / self.m.G8_DECODE_OUT).exists(),
            "no jsonl emitted when the env flag is unset")

    def test_advisory_emits_when_env_set(self):
        ws = Path(tempfile.mkdtemp())
        (ws / "src").mkdir()
        (ws / "src" / "decode_trust.go").write_text(self.src)
        os.environ[self.m.G8_DECODE_ENV] = "1"
        try:
            self.m.scan_workspace(ws, self.m._DEFAULT_GUARDS)
        finally:
            os.environ.pop(self.m.G8_DECODE_ENV, None)
        self.assertTrue(
            (ws / ".auditooor" / self.m.G8_DECODE_OUT).exists(),
            "jsonl emitted when the env flag is set")


if __name__ == "__main__":
    unittest.main()
