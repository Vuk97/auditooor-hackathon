#!/usr/bin/env python3
"""test_G9.py - go.consensus.decoded_value_consumed_unchecked_type_nil (G9).

Extends tools/go-detector-runner.py with an advisory-first, NO-AUTO-CREDIT
(verdict=needs-fuzz) DETECTOR that fires when a body deserializes attacker bytes
(proto/json/codec/asn1/gob Unmarshal, (codectypes.)UnpackAny, Any.GetCachedValue,
ParseCertificate) and then CONSUMES the decoded value at a type/nil-unsound
enforcement point:
  * Arm A - a single-return type assertion ``<target>.(T)`` (panics on wrong
    dynamic type);
  * Arm B - an Any consumed via ``GetCachedValue()`` and single-return
    ``.(T)``-asserted or ``.Field``-dereferenced (checked variant absent);
  * Arm C - a decode-target POINTER field-deref before any nil-check (a strict
    decode-taint-gated SUBSET of Pattern 35).

Non-vacuity (the target property missing FIRES; present/guarded SILENT):
  * the DECODE-TAINT gate ``_G9_DECODE`` is load-bearing - neutralising it
    silences every hit (nothing consumes a decoded value);
  * the comma-ok guard ``_G9_COMMAOK_PREFIX`` is load-bearing - neutralising it
    makes the benign ``okAssert`` fixture WRONGLY start firing.
The guarded fixtures (comma-ok / type-switch / nil-checked deref / err-checked
UnpackAny / no-decode-taint bare v.(T)) stay silent; the last asserts R9 does
NOT regress into Pattern-35 breadth.

Dedup boundary (A1): the emitter diffs emitted hits vs Pattern 35
(go.go.panic.dereference_before_nil_check) by (file,line) - it does NOT re-derive
a covered_by signal. R9 Arm C is a strict decode-taint-gated subset of Pattern
35.
"""
import importlib.util
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "go-detector-runner.py"
_FIX = Path(__file__).resolve().parent / "fixtures" / "G9"


def _load():
    spec = importlib.util.spec_from_file_location("gdr_g9", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["gdr_g9"] = m
    spec.loader.exec_module(m)
    return m


class TestDecodedValueConsumedUnchecked(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        self.path = _FIX / "decode_consume.go"
        self.src = self.path.read_text()
        self.funcs = self.m._extract_functions(self.src, self.path)

    def _hit_fns(self, funcs=None):
        hits = self.m._detect_decoded_value_consumed_unchecked_type_nil(
            funcs if funcs is not None else self.funcs)
        return {h.extra.get("function"): h for h in hits}

    # ---- core predicate matrix ------------------------------------------
    def test_fires_on_unchecked_consumption_only(self):
        self.assertEqual(
            set(self._hit_fns()),
            {"laxUnmarshalAssert", "laxCachedAssert",
             "laxCachedFieldDeref", "laxPtrDeref", "ptrParamDeref"},
            "fires exactly on unguarded decode-consumption points",
        )

    def test_arm_labels(self):
        h = self._hit_fns()
        self.assertEqual(h["laxUnmarshalAssert"].extra.get("arm"), "A")
        self.assertEqual(h["laxCachedAssert"].extra.get("arm"), "B")
        self.assertEqual(h["laxCachedFieldDeref"].extra.get("arm"), "B")
        self.assertEqual(h["laxPtrDeref"].extra.get("arm"), "C")
        self.assertEqual(h["ptrParamDeref"].extra.get("arm"), "C")

    def test_records_decode_source_and_type(self):
        h = self._hit_fns()["laxCachedAssert"]
        self.assertIn("GetCachedValue", h.extra.get("decode_source"))
        self.assertEqual(h.extra.get("asserted_type"), "AccountI")

    # ---- FP-guards (guarded => SILENT) ----------------------------------
    def test_commaok_suppresses(self):
        self.assertNotIn("okAssert", self._hit_fns(),
                         "a comma-ok assertion is the checked variant")

    def test_typeswitch_suppresses(self):
        self.assertNotIn("switchAssert", self._hit_fns(),
                         "a switch x.(type) consumes type-safely")

    def test_nil_guard_suppresses(self):
        self.assertNotIn("nilGuardedDeref", self._hit_fns(),
                         "a nil-check before the deref suppresses arm C")

    def test_value_target_field_deref_silent(self):
        # `var dec T; json.Unmarshal(data,&dec); dec.Field` - dec is a VALUE
        # struct captured by &dec that can NEVER be nil, so arm C must NOT fire
        # (the optimism/polygon arm-C value-target FP class).
        self.assertNotIn("valueTargetFieldDeref", self._hit_fns(),
                         "a value-struct decode target can never be nil-deref'd")

    def test_pointer_target_still_fires(self):
        # A genuine pointer decode target (var *T and *T param) STILL fires arm C
        # after the precision gate - the fix kills FPs, not true positives.
        h = self._hit_fns()
        self.assertIn("laxPtrDeref", h)
        self.assertIn("ptrParamDeref", h)
        self.assertEqual(h["laxPtrDeref"].extra.get("arm"), "C")
        self.assertEqual(h["ptrParamDeref"].extra.get("arm"), "C")

    def test_errchecked_unpack_suppresses(self):
        self.assertNotIn("errCheckedUnpack", self._hit_fns(),
                         "an err-checked UnpackAny validates the target")

    def test_no_decode_taint_bare_assert_silent(self):
        self.assertNotIn("noDecodeBareAssert", self._hit_fns(),
                         "a bare v.(T) with NO decode source must NOT fire "
                         "(R9 must not regress into Pattern-35 breadth)")

    def test_test_file_skipped(self):
        skip = _FIX / "decode_consume_skip_test.go"
        funcs = self.m._extract_functions(skip.read_text(), skip)
        self.assertEqual(self._hit_fns(funcs), {},
                         "*_test.go decode-consumption must be skipped")

    # ---- non-vacuity: predicates are load-bearing -----------------------
    def test_decode_gate_predicate_load_bearing(self):
        saved = self.m._G9_DECODE
        try:
            # Neutralise the decode-taint gate: no body has a deserialize source
            # => nothing consumes a decoded value => every hit is silenced.
            self.m._G9_DECODE = re.compile(r"ZZZ_NEVER_MATCHES")
            self.assertEqual(
                self.m._detect_decoded_value_consumed_unchecked_type_nil(
                    self.funcs), [],
                "neutralising the decode-taint gate silences all hits")
        finally:
            self.m._G9_DECODE = saved
        # restored gate: fires again.
        self.assertIn("laxCachedAssert", self._hit_fns())

    def test_pointer_gate_predicate_load_bearing(self):
        saved = self.m._g9_target_is_pointer
        try:
            # Neutralise the arm-C pointer gate (force every target to look like
            # a pointer): the benign value-target fixture WRONGLY starts firing.
            self.m._g9_target_is_pointer = lambda *a, **k: True
            self.assertIn("valueTargetFieldDeref", set(self._hit_fns()),
                          "dropping the pointer gate must (wrongly) fire the "
                          "value-target arm-C fixture")
        finally:
            self.m._g9_target_is_pointer = saved
        # restored predicate: value target silent again, pointer target fires.
        h = self._hit_fns()
        self.assertNotIn("valueTargetFieldDeref", h)
        self.assertIn("laxPtrDeref", h)

    def test_commaok_guard_predicate_load_bearing(self):
        saved = self.m._G9_COMMAOK_PREFIX
        try:
            # Neutralise the comma-ok guard: the benign okAssert fixture WRONGLY
            # starts firing (its checked comma-ok assert is no longer excused).
            self.m._G9_COMMAOK_PREFIX = re.compile(r"ZZZ_NEVER_MATCHES")
            self.assertIn("okAssert", set(self._hit_fns()),
                          "dropping the comma-ok guard must (wrongly) fire the "
                          "guarded fixture")
        finally:
            self.m._G9_COMMAOK_PREFIX = saved
        # restored predicate: benign silent again.
        self.assertNotIn("okAssert", self._hit_fns())

    # ---- dedup boundary (A1): diff vs Pattern 35, not re-derived --------
    def test_dedup_drops_pattern35_overlap(self):
        ws = Path(tempfile.mkdtemp())
        (ws / "src").mkdir()
        (ws / "src" / "decode_consume.go").write_text(self.src)
        funcs = self.m._extract_functions(
            self.src, ws / "src" / "decode_consume.go")
        lax = [h for h in
               self.m._detect_decoded_value_consumed_unchecked_type_nil(funcs)
               if h.extra.get("function") == "laxPtrDeref"][0]
        collide = self.m.Hit(file=lax.file, line=lax.line, snippet="x")
        recs, _ = self.m._emit_decode_consumption_type_nil_hypotheses(
            ws, funcs, [collide])
        emitted = {r["function"] for r in recs}
        self.assertNotIn("laxPtrDeref", emitted,
                         "a (file,line) collision with Pattern 35 is de-duped")
        self.assertIn("laxCachedAssert", emitted,
                      "non-colliding hits survive")

    # ---- advisory-first + NO-AUTO-CREDIT -------------------------------
    def test_emit_writes_needs_fuzz_jsonl(self):
        ws = Path(tempfile.mkdtemp())
        (ws / "src").mkdir()
        (ws / "src" / "decode_consume.go").write_text(self.src)
        funcs = self.m._extract_functions(
            self.src, ws / "src" / "decode_consume.go")
        recs, out = self.m._emit_decode_consumption_type_nil_hypotheses(
            ws, funcs, [])
        self.assertTrue(out.exists())
        self.assertGreaterEqual(len(recs), 1)
        self.assertTrue(all(r["verdict"] == "needs-fuzz" for r in recs),
                        "every emitted row is NO-AUTO-CREDIT needs-fuzz")
        self.assertTrue(all(r["pattern_id"] == self.m.G9_DECODE_CONSUME_PID
                            for r in recs))
        self.assertTrue(all(r["lane"] == "G9" for r in recs))

    def test_advisory_off_by_default_not_in_patterns(self):
        ws = Path(tempfile.mkdtemp())
        (ws / "src").mkdir()
        (ws / "src" / "decode_consume.go").write_text(self.src)
        os.environ.pop(self.m.G9_DECODE_CONSUME_ENV, None)
        summary = self.m.scan_workspace(ws, self.m._DEFAULT_GUARDS)
        self.assertNotIn(self.m.G9_DECODE_CONSUME_PID, summary["patterns"],
                         "advisory detector must not feed go_findings")
        self.assertFalse(
            (ws / ".auditooor" / self.m.G9_DECODE_CONSUME_OUT).exists(),
            "no jsonl emitted when the env flag is unset")

    def test_advisory_emits_when_env_set(self):
        ws = Path(tempfile.mkdtemp())
        (ws / "src").mkdir()
        (ws / "src" / "decode_consume.go").write_text(self.src)
        os.environ[self.m.G9_DECODE_CONSUME_ENV] = "1"
        try:
            self.m.scan_workspace(ws, self.m._DEFAULT_GUARDS)
        finally:
            os.environ.pop(self.m.G9_DECODE_CONSUME_ENV, None)
        self.assertTrue(
            (ws / ".auditooor" / self.m.G9_DECODE_CONSUME_OUT).exists(),
            "jsonl emitted when the env flag is set")


if __name__ == "__main__":
    unittest.main()
