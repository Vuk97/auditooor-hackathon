#!/usr/bin/env python3
"""Tests for the stateful factory->pool->liveness gate in detector-promote.py.

Covers KNOWN_LIMITATIONS_BURNDOWN_MAP P0-7 / P1-6 / P1-7 stop conditions:
the gate must distinguish a fully-shaped Medium claim (all 6 stateful fields
present + Medium/Low severity-state) from a partial chain (some fields) and
from a non-factory detector (no fields).
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "detector-promote.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("detector_promote_stateful_under_test", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["detector_promote_stateful_under_test"] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_tool()


class FactoryPoolStateFlowGateTests(unittest.TestCase):
    def _full_row(self) -> dict:
        return {
            "tier": "B",
            "entrypoint": "createPool",
            "invalid_config": "amp == 0 || swapFee == type(uint256).max",
            "tracked_pool": "officialPools",
            "liquidity_acceptance": True,
            "downstream_liveness": ["swap", "addLiquidity", "_invariant"],
            "conservative_severity_state": "Medium",
        }

    def test_medium_shaped_when_all_six_fields_present(self) -> None:
        decision = MOD._check_factory_pool_state_flow(self._full_row(), {}, {})
        self.assertEqual(decision, "medium_shaped_unsubmitted")

    def test_low_shaped_when_severity_state_too_strong(self) -> None:
        # Critical/High severity-state must NOT promote to medium-shaped: the
        # severity rubric lives outside this gate.
        row = self._full_row()
        row["conservative_severity_state"] = "Critical"
        self.assertEqual(MOD._check_factory_pool_state_flow(row, {}, {}),
                         "low_shaped_unsubmitted")

    def test_low_shaped_when_partial_chain(self) -> None:
        row = self._full_row()
        row.pop("downstream_liveness")
        row.pop("tracked_pool")
        self.assertEqual(MOD._check_factory_pool_state_flow(row, {}, {}),
                         "low_shaped_unsubmitted")

    def test_not_factory_shape_when_no_fields(self) -> None:
        row = {"tier": "D", "reason": "regex-only"}
        self.assertEqual(MOD._check_factory_pool_state_flow(row, {}, {}),
                         "not_factory_shape")

    def test_malformed_field_demotes_to_low(self) -> None:
        # downstream_liveness must be a non-empty list of strings; an empty
        # list or a wrong type should not count as present.
        row = self._full_row()
        row["downstream_liveness"] = []
        self.assertEqual(MOD._check_factory_pool_state_flow(row, {}, {}),
                         "low_shaped_unsubmitted")
        row["downstream_liveness"] = "swap"  # string, not list
        self.assertEqual(MOD._check_factory_pool_state_flow(row, {}, {}),
                         "low_shaped_unsubmitted")

    def test_liquidity_acceptance_must_be_bool(self) -> None:
        row = self._full_row()
        row["liquidity_acceptance"] = "true"  # string, not bool
        # field is dropped from `present`; remaining 5 means low_shaped
        self.assertEqual(MOD._check_factory_pool_state_flow(row, {}, {}),
                         "low_shaped_unsubmitted")

    def test_build_proposals_returns_stateful_decisions_tuple(self) -> None:
        # build_proposals must return a 4-tuple now, with stateful_decisions last.
        result = MOD.build_proposals(workspace=None)
        self.assertEqual(len(result), 4)
        promote_de, promote_es, demote, stateful = result
        self.assertIsInstance(stateful, list)
        # Confirm the seeded public-factory row appears with medium_shaped:
        names = [d["name"] for d in stateful if d["decision"] == "medium_shaped_unsubmitted"]
        self.assertIn("public-factory-invalid-pool-config-liveness-failure", names)


if __name__ == "__main__":
    unittest.main()
