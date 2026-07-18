#!/usr/bin/env python3
"""Impact-chain cross-wire (gaps #4 + #5): the exploit-queue row carries the
structured impact_class from the lead source, and the severity oracle's impact
selector keys on it (instead of substring-matching free-text impact_path only).
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_QT = Path(__file__).resolve().parent.parent / "exploit-queue.py"
_q = importlib.util.spec_from_file_location("exploit_queue", _QT)
eq = importlib.util.module_from_spec(_q)
sys.modules["exploit_queue"] = eq
_q.loader.exec_module(eq)

_OT = Path(__file__).resolve().parent.parent / "exploit-severity-scope-oracle.py"
_o = importlib.util.spec_from_file_location("exploit_severity_scope_oracle", _OT)
orac = importlib.util.module_from_spec(_o)
sys.modules["exploit_severity_scope_oracle"] = orac
_o.loader.exec_module(orac)

import unittest


class ImpactChainTest(unittest.TestCase):
    def test_base_row_carries_impact_class(self):
        row = eq._make_base_row(
            lead_id="L1", title="t", source_refs=[],
            impact_class="direct-theft-funds", impact_id="direct-theft-funds")
        self.assertEqual(row["impact_class"], "direct-theft-funds")
        self.assertIn("impact_id", row)

    def test_base_row_default_empty_impact_class(self):
        row = eq._make_base_row(lead_id="L", title="t", source_refs=[])
        # The default is now "" (honest "no structured class derived"), NOT the
        # "unknown" placeholder - the L8 gate + severity oracle treat "" and
        # "unknown" identically (both non-populated), and derive_impact_class
        # returns "" when unclassifiable. (2026-06-30 exploit-queue.py:~604.)
        self.assertEqual(row["impact_class"], "")

    def test_oracle_select_impact_prefers_class(self):
        # impact_path is uninformative; the structured class must drive selection.
        row = {"impact_path": "unknown", "impact_class": "direct-theft-funds"}
        self.assertEqual(orac._select_impact(row), "Direct theft of user funds")
        row2 = {"impact_path": "unknown", "impact_class": "protocol-insolvency"}
        self.assertEqual(orac._select_impact(row2), "Protocol insolvency / bad debt")

    def test_oracle_legacy_impact_path_still_resolves(self):
        # no impact_class -> legacy free-text path still maps (no regression).
        self.assertEqual(
            orac._select_impact({"impact_path": "fund theft"}),
            "Direct theft of user funds")
        self.assertEqual(orac._select_impact({"impact_path": "unknown"}), "unknown")


if __name__ == "__main__":
    unittest.main()
