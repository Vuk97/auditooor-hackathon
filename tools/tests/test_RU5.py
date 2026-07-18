#!/usr/bin/env python3
"""RU5 - serde/borsh confusion advisory axis on the wave17 detector
serde_untagged_enum_first_variant_shadows_all_sibling_variants.py.

The compiled Slither class hardcodes Yolo/Permissive/Unchecked/NoLimit on
Swap/Order/Request/Trade/Route/Action enums (a strict subset). The RU5
extension adds two net-new advisory axes:
  - serde: ANY #[serde(untagged)] enum with 2+ struct variants (field-set
    subset-overlap enrichment via cross-type parse), and
  - borsh: reorder-changes-discriminant on a persisted/versioned enum.
Advisory-first (default OFF), verdict=needs-fuzz, auto_credit=false, and
deduped against the base narrow detector's OWN _MATCH regexes.

Non-vacuity: mutating any single predicate flips at least one assertion
(untagged gate, >=2-struct gate, deny_unknown_fields guard, field_overlap
computation, base-dedup, borsh persist gate, axis-off).
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DET = ROOT / "detectors" / "wave17" / \
    "serde_untagged_enum_first_variant_shadows_all_sibling_variants.py"
FIX = Path(__file__).resolve().parent / "fixtures" / "RU5" / "cases.rs"


def _mod():
    spec = importlib.util.spec_from_file_location("ru5_det", DET)
    m = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules["ru5_det"] = m
    spec.loader.exec_module(m)
    return m


def _files():
    return [(str(FIX), FIX.read_text(encoding="utf-8"))]


class RU5Axis(unittest.TestCase):
    def setUp(self):
        self.m = _mod()
        self.on = self.m.ru5_analyze(_files(), True)

    def _serde(self):
        return [h for h in self.on if h["axis"] == "serde_untagged_field_overlap"]

    def _borsh(self):
        return [h for h in self.on if h["axis"] == "borsh_reorder_discriminant"]

    def _by_enum(self, name):
        return [h for h in self.on if h["enum"] == name]

    def test_axis_off_by_default(self):
        # Advisory-first: disabled -> no hypotheses at all.
        self.assertEqual(self.m.ru5_analyze(_files(), False), [])

    def test_net_new_serde_fires_on_untagged_struct_enums(self):
        names = {h["enum"] for h in self._serde()}
        self.assertIn("PayloadOverlap", names)
        self.assertIn("PayloadDisjoint", names)

    def test_field_overlap_enrichment_is_computed(self):
        # Cross-type parse: earlier all-optional variant -> overlap true;
        # disjoint required fields -> overlap false. Breaks if hardcoded.
        ov = self._by_enum("PayloadOverlap")[0]
        dj = self._by_enum("PayloadDisjoint")[0]
        self.assertTrue(ov["field_overlap"])
        self.assertFalse(dj["field_overlap"])

    def test_base_narrow_yolo_swap_is_deduped_out(self):
        # SwapRequest{Yolo,...} is what the base Slither class already fires
        # on -> must be dropped (covered_by base), not re-reported.
        self.assertEqual(self._by_enum("SwapRequest"), [])

    def test_benign_tagged_enum_stays_clean(self):
        self.assertEqual(self._by_enum("TaggedFine"), [])

    def test_deny_unknown_fields_untagged_suppressed(self):
        # FP-guard: deny_unknown_fields removes the shadow risk.
        self.assertEqual(self._by_enum("GuardedUntagged"), [])

    def test_borsh_persisted_versioned_fires(self):
        self.assertEqual({h["enum"] for h in self._borsh()}, {"VersionedThing"})

    def test_borsh_nonpersisted_message_suppressed(self):
        # FP-guard: a plain borsh message enum (no version naming/variants,
        # non-versioned path) must NOT fire the reorder axis.
        self.assertNotIn("WireMessage", {h["enum"] for h in self._borsh()})

    def test_all_hyps_needs_fuzz_no_auto_credit(self):
        self.assertTrue(self.on)
        for h in self.on:
            self.assertEqual(h["verdict"], "needs-fuzz")
            self.assertFalse(h["auto_credit"])
            self.assertEqual(h["detector"],
                             "serde-untagged-enum-first-variant-shadows-all-sibling-variants")
            self.assertEqual(h["severity_hint"], "advisory")

    def test_dedup_reuses_base_class_regexes(self):
        # A1 lesson: covered_by signal must come from the class' OWN _MATCH,
        # not a re-derived copy. Assert the base regexes are pulled from it.
        enum_re, variant_re, deny_re = self.m._ru5_base_regexes()
        self.assertIsNotNone(enum_re)
        self.assertIsNotNone(variant_re)
        self.assertIsNotNone(deny_re)
        self.assertTrue(variant_re.search("Yolo {"))


if __name__ == "__main__":
    unittest.main()
