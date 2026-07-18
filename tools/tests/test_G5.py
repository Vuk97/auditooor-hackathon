#!/usr/bin/env python3
"""test_G5.py - go.consensus.unmarshal_type_ambiguity_first_match (G5).

Extends tools/go-detector-runner.py with an advisory-first, NO-AUTO-CREDIT
(verdict=needs-fuzz) Go detector: a body that trial-decodes ONE buffer into
>=2 rival proto message types under a first-``== nil``-wins accept ladder with
NO TypeUrl/version discriminator -> a differential-decode (consensus-
determinism) ambiguity, gated to codec/consensus files.

Non-vacuity: the predicate is load-bearing - mutating the distinct-target
requirement (test_predicate_is_load_bearing) breaks the fire case; the
discriminated CLEAN fixture (TypeUrl switch present) is silent (mutation-kill),
as are the single-decode and distinct-buffer FP-guard cases.
"""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parents[1] / "go-detector-runner.py"
_FIX = Path(__file__).resolve().parent / "fixtures" / "G5"


def _load():
    spec = importlib.util.spec_from_file_location("gdr_g5", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["gdr_g5"] = m
    spec.loader.exec_module(m)
    return m


class TestUnmarshalTypeAmbiguity(unittest.TestCase):
    def setUp(self):
        self.m = _load()
        self.path = _FIX / "ambiguity_codec.go"
        self.src = self.path.read_text()
        self.funcs = self.m._extract_functions(self.src, self.path)

    def _hit_fns(self, funcs=None):
        hits = self.m._detect_unmarshal_type_ambiguity_first_match(
            funcs if funcs is not None else self.funcs)
        return {h.extra.get("function"): h for h in hits}

    # ---- core predicate: fires ONLY on the ambiguous ladder -------------
    def test_fires_on_ambiguous_ladder_only(self):
        self.assertEqual(
            set(self._hit_fns()),
            {"unpackAmbiguous"},
            "fires exactly on the >=2-rival-type first-nil-wins ladder",
        )

    def test_records_ambiguity_shape(self):
        h = self._hit_fns()["unpackAmbiguous"]
        self.assertEqual(h.extra.get("bytes_arg"), "any.Value")
        self.assertGreaterEqual(h.extra.get("decode_attempts"), 3)
        self.assertGreaterEqual(h.extra.get("distinct_types"), 3)

    # ---- mutation-kill CLEAN / FP-guard halves --------------------------
    def test_typeurl_discriminator_suppresses(self):
        self.assertNotIn("unpackDiscriminated", self._hit_fns(),
                         "a TypeUrl switch chooses the type -> not ambiguous")

    def test_single_decode_not_fired(self):
        self.assertNotIn("unpackSingle", self._hit_fns(),
                         "a single decode is Pattern 28's lane, not G5")

    def test_distinct_buffers_not_fired(self):
        self.assertNotIn("unpackDistinctBuffers", self._hit_fns(),
                         "decodes of different buffers are not one-buffer ambiguity")

    # ---- non-test / path gates ------------------------------------------
    def test_non_codec_path_suppressed(self):
        alt = _FIX / "ambiguity_codec.go"
        src = alt.read_text()
        # Re-home the same functions under a non-codec/consensus path.
        funcs = self.m._extract_functions(src, Path("/x/evm/keeper/msg_server.go"))
        self.assertNotIn("unpackAmbiguous", self._hit_fns(funcs),
                         "codec/consensus path gate suppresses other surfaces")

    def test_test_file_suppressed(self):
        src = self.src
        funcs = self.m._extract_functions(src, Path("/x/evm/types/codec_test.go"))
        self.assertEqual(self._hit_fns(funcs), {},
                         "*_test.go is skipped")

    # ---- NON-VACUITY: predicate is load-bearing -------------------------
    def test_predicate_is_load_bearing(self):
        # Break the >=2-distinct-target requirement: if the detector ignored
        # distinct-type-count and fired on any repeated Unmarshal of a buffer,
        # the single-decode and distinct-buffer cases would (wrongly) fire.
        # We assert the guarded behaviour holds; then prove the fixture would
        # flip by collapsing the ambiguous ladder to one decode.
        collapsed = self.src.replace(
            "\tatx := AccessListTx{}\n"
            "\tif proto.Unmarshal(any.Value, &atx) == nil {\n"
            "\t\treturn &atx, nil\n"
            "\t}\n"
            "\tdtx := DynamicFeeTx{}\n"
            "\tif proto.Unmarshal(any.Value, &dtx) == nil {\n"
            "\t\treturn &dtx, nil\n"
            "\t}\n",
            "",
            1,
        )
        self.assertNotEqual(collapsed, self.src, "mutation must apply")
        funcs = self.m._extract_functions(collapsed, self.path)
        self.assertNotIn(
            "unpackAmbiguous", self._hit_fns(funcs),
            "collapsing to a single decode must stop the fire (predicate live)")

    # ---- emitter: verdict + dedup boundary ------------------------------
    def test_emitter_needs_fuzz_and_dedup(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            recs, out = self.m._emit_unmarshal_type_ambiguity_hypotheses(
                ws, self.funcs, [])
            self.assertTrue(out.exists())
            self.assertEqual(len(recs), 1)
            self.assertEqual(recs[0]["verdict"], "needs-fuzz")
            self.assertEqual(recs[0]["lane"], "G5")
            self.assertEqual(recs[0]["pattern_id"],
                             self.m.G5_UNMARSHAL_AMBIG_PID)

    def test_emitter_dedup_drops_pattern28_collision(self):
        # A1 boundary: a Pattern-28 hit at the same (file,line) removes our hit.
        h = self._hit_fns()["unpackAmbiguous"]
        from types import SimpleNamespace
        p28 = [SimpleNamespace(file=h.file, line=h.line)]
        with tempfile.TemporaryDirectory() as d:
            recs, _ = self.m._emit_unmarshal_type_ambiguity_hypotheses(
                Path(d), self.funcs, p28)
            self.assertEqual(recs, [],
                             "collision with Pattern 28 de-dups our record")


if __name__ == "__main__":
    unittest.main()
