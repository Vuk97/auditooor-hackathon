#!/usr/bin/env python3
"""Cross-wires #2 + #3: the lead-impact -> SEVERITY.md loop.

#2: program-impact-mapping-check.suggest_check31_for_impact gives the table a real
    runtime consumer (resolve a hunt-time impact_id -> Check#31 tier + rubric row).
#3: auto-draft-generator.require_locked_impact_contract derives selected_impact +
    severity from impact_id when a human did not type them - so an impact-classified
    lead is not hard-blocked, while the OTHER proof requirements stay enforced.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_PT = Path(__file__).resolve().parent.parent / "program-impact-mapping-check.py"
_ps = importlib.util.spec_from_file_location("program_impact_mapping_check", _PT)
pim = importlib.util.module_from_spec(_ps)
sys.modules["program_impact_mapping_check"] = pim
try:
    _ps.loader.exec_module(pim)
except SystemExit:
    pass

_AT = Path(__file__).resolve().parent.parent / "auto-draft-generator.py"
_as = importlib.util.spec_from_file_location("auto_draft_generator", _AT)
adg = importlib.util.module_from_spec(_as)
sys.modules["auto_draft_generator"] = adg
try:
    _as.loader.exec_module(adg)
except SystemExit:
    pass


class SuggestCheck31Test(unittest.TestCase):
    def test_direct(self):
        self.assertEqual(pim.suggest_check31_for_impact("direct-theft-funds")[0], "Critical")

    def test_alias(self):
        # renderer vocab -> table key
        self.assertEqual(pim.suggest_check31_for_impact("yield-theft"),
                         ("High", "Theft of unclaimed yield"))

    def test_unknown_is_none(self):
        self.assertIsNone(pim.suggest_check31_for_impact("totally-novel"))
        self.assertIsNone(pim.suggest_check31_for_impact(""))


class AutoDraftImpactFillTest(unittest.TestCase):
    def _ws_with_row(self, row: dict) -> tuple[Path, str]:
        ws = Path(tempfile.mkdtemp())
        (ws / ".auditooor").mkdir(parents=True)
        proof = ws / "poc.t.sol"
        proof.write_text("// poc", encoding="utf-8")
        base = {
            "impact_contract_id": "IC-1", "contract": "C",
            "exact_impact_row": True, "listed_impact_proven": True,
            "proof_artifact": "poc.t.sol",
        }
        base.update(row)
        (ws / ".auditooor" / "impact_contracts.json").write_text(
            json.dumps([base]), encoding="utf-8")
        return ws, "IC-1"

    def test_impact_id_fills_selected_impact(self):
        ws, ic = self._ws_with_row({"impact_id": "direct-theft-funds"})  # no selected_impact/severity
        out = adg.require_locked_impact_contract(ws, {}, "C", ic)
        self.assertTrue(out.get("selected_impact"))
        self.assertIn("theft", out["selected_impact"].lower())
        self.assertEqual(out.get("severity_implied"), "Critical")
        self.assertTrue(out.get("impact_derived_from", "").startswith("impact-methodology:"))

    def test_unknown_impact_id_still_blocks(self):
        # an unrecognized impact class must NOT fabricate a selected_impact
        ws, ic = self._ws_with_row({"impact_id": "totally-novel-class"})
        with self.assertRaises(ValueError) as cm:
            adg.require_locked_impact_contract(ws, {}, "C", ic)
        self.assertIn("selected_impact", str(cm.exception))

    def test_explicit_selected_impact_unchanged(self):
        ws, ic = self._ws_with_row({"impact_id": "direct-theft-funds",
                                    "selected_impact": "Human-typed row", "severity": "High"})
        out = adg.require_locked_impact_contract(ws, {}, "C", ic)
        self.assertEqual(out["selected_impact"], "Human-typed row")  # not overwritten


if __name__ == "__main__":
    unittest.main()
