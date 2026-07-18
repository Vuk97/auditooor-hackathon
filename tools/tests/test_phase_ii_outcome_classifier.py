#!/usr/bin/env python3
"""Tests for phase-ii-outcome-classifier.py.

Run:
    python3 -m unittest tools.tests.test_phase_ii_outcome_classifier -v
"""

from __future__ import annotations

import importlib.util
import sys
import unittest

from pathlib import Path


_TOOLS_DIR = Path(__file__).resolve().parents[1]
_MOD_PATH = _TOOLS_DIR / "phase-ii-outcome-classifier.py"


def _load_module():
    mod_name = "phase_ii_outcome_classifier"
    if mod_name in sys.modules:
        return sys.modules[mod_name]
    spec = importlib.util.spec_from_file_location(mod_name, _MOD_PATH)
    assert spec and spec.loader, f"Cannot find {_MOD_PATH}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


_mod = _load_module()

classify_row = _mod.classify_row
_row_lookup = _mod._row_lookup


class PhaseIIOutcomeClassifierTests(unittest.TestCase):
    def test_dydx_fast_node_cache_race_maps_to_r14(self):
        row = {"workspace": "dydx", "row_id": "200", "title": "dYdX iavl fast-node cache race"}
        classification = classify_row(row)
        self.assertEqual(classification.classification, "R14-PRODUCTION-CONFIG-DISABLES-CLAIMED-IMPACT-SURFACE")

    def test_dydx_codec_subcall_cap_weakening_maps_to_r35(self):
        row = {"workspace": "dydx", "row_id": "213", "title": "Cosmos SDK codec subcall cap weakening"}
        classification = classify_row(row)
        self.assertEqual(classification.classification, "R35-DOS-CLASS-REFRAME")

    def test_withdrawn_after_precondition_check_maps_to_r11(self):
        row = {
            "workspace": "base-azul",
            "row_id": "BASE-AZUL-IMMUNEFI-FN1",
            "title": "Parent-loss resolve path pays a successful challenger's bond reward to the proposer",
        }
        ledger_row = {
            "fp_reason": "withdrawn_after_precondition_check",
            "notes": "operator withdrew exploitability claim per branch-invariant precondition lesson",
        }
        classification = classify_row(row, ledger_row)
        self.assertEqual(
            classification.classification,
            "R11-SEVERE-IMPACT-WITHOUT-IN-SCOPE-EXPLOIT-PREREQUISITE",
        )

    def test_event_only_rejection_maps_to_none(self):
        row = {
            "workspace": "polymarket",
            "row_id": "POLY-CANTINA-46",
            "title": "Auth.renounceOperatorRole emits RemovedOperator(operator, operator) misusing the admin-indexed topic",
        }
        ledger_row = {"rejection_reason": "event-only cosmetic; isOperator mapping correctly updated"}
        classification = classify_row(row, ledger_row)
        self.assertEqual(classification.classification, "none")

    def test_by_design_pause_domain_rejection_maps_to_none(self):
        row = {
            "workspace": "polymarket",
            "row_id": "POLY-182",
            "title": "CTFExchange pauseTrading does not halt CtfCollateralAdapter/NegRiskCtfCollateralAdapter position ops",
        }
        ledger_row = {
            "note": "Rejected: adapters + exchange are separate contracts with independent pause mechanisms by design. Adapter operations are fully collateralized.",
            "rejection_class": "architectural-domain-separation-by-design",
        }
        classification = classify_row(row, ledger_row)
        self.assertEqual(classification.classification, "none")

    def test_duplicate_rows_prefer_rejected_entry(self):
        row = {"workspace": "snowbridge", "row_id": "SNOW-ITER8-R67-F001", "title": "SnowbridgeL1Adaptor pre-fund theft via permissionless deposit sweep"}
        ledgers = {
            "snowbridge": [
                {"report_id": "SNOW-ITER8-R67-F001", "status": "Pending", "outcome": "pending"},
                {
                    "report_id": "SNOW-ITER8-R67-F001",
                    "status": "Rejected",
                    "outcome": "rejected",
                    "rejection_reason": "missing decline reason",
                },
            ]
        }
        ledger_row = _row_lookup(row, ledgers)
        self.assertIsNotNone(ledger_row)
        self.assertEqual(ledger_row["outcome"], "rejected")

    def test_missing_decline_reason_becomes_deferred(self):
        row = {"workspace": "snowbridge", "row_id": "SNOW-ITER8-R67-F001", "title": "SnowbridgeL1Adaptor pre-fund theft via permissionless deposit sweep"}
        ledger_row = {"status": "Rejected", "outcome": "rejected"}
        classification = classify_row(row, ledger_row)
        self.assertEqual(classification.classification, "deferred")

    def test_unknown_decline_reason_becomes_deferred(self):
        row = {"workspace": "morpho", "row_id": "MORPHO-CANTINA-638", "title": "MorphoChainlinkOracleV2 constructor: SCALE_FACTOR silently truncates to zero, enables zero-cost liquidation"}
        ledger_row = {"rejection_reason": "unknown:no decline reason provided by platform"}
        classification = classify_row(row, ledger_row)
        self.assertEqual(classification.classification, "deferred")

    def test_duplicate_rejection_maps_to_none(self):
        row = {"workspace": "polymarket", "row_id": "POLY-CANTINA-14", "title": "CollateralOfframp.unwrap() permanently reverts: Offramp missing WRAPPER_ROLE on CollateralToken"}
        ledger_row = {"rejection_reason": "duplicate of rejected original"}
        classification = classify_row(row, ledger_row)
        self.assertEqual(classification.classification, "none")


if __name__ == "__main__":
    unittest.main()
