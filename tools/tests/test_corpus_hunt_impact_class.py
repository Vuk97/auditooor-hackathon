#!/usr/bin/env python3
"""Cross-wire #14: corpus-driven-hunt emits a structured impact_class +
severity HINT (from the invariant family) on its exploit_queue rows, instead of
the hardcoded 'unknown' the severity oracle (#5) cannot key on.
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

_T = Path(__file__).resolve().parent.parent / "corpus-driven-hunt.py"
_s = importlib.util.spec_from_file_location("corpus_driven_hunt", _T)
m = importlib.util.module_from_spec(_s)
sys.modules["corpus_driven_hunt"] = m
try:
    _s.loader.exec_module(m)
except SystemExit:
    pass


class CorpusHuntImpactClassTest(unittest.TestCase):
    def test_family_to_impact_mapping(self):
        self.assertEqual(m._family_to_impact("accounting_conservation"),
                         ("direct-theft-funds", "high"))
        self.assertEqual(m._family_to_impact("access_control"),
                         ("access-control-bypass", "high"))
        self.assertEqual(m._family_to_impact("state_freshness"),
                         ("protocol-insolvency", "medium"))

    def test_unmapped_family_stays_unknown(self):
        self.assertEqual(m._family_to_impact("totally-novel-family"),
                         ("unknown", "unknown"))
        self.assertEqual(m._family_to_impact(""), ("unknown", "unknown"))

    def test_proof_row_carries_impact_class(self):
        row = m._proof_row_base(
            lead_id="L", title="t", attack_class="accounting_conservation",
            impact_path="C.f", root_cause="rc", source_refs=[], source="src",
            impact_class="direct-theft-funds", likely_severity="high")
        self.assertEqual(row["impact_class"], "direct-theft-funds")
        self.assertEqual(row["likely_severity"], "high")

    def test_proof_row_default_legacy_unknown(self):
        row = m._proof_row_base(
            lead_id="L", title="t", attack_class="x", impact_path="p",
            root_cause="rc", source_refs=[], source="src")
        self.assertEqual(row["impact_class"], "unknown")
        self.assertEqual(row["likely_severity"], "unknown")


if __name__ == "__main__":
    unittest.main()
