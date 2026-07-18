#!/usr/bin/env python3
# r36-rebuttal: lane GAP-INTEG-1 registered in .auditooor/agent_pathspec.json via tools/agent-pathspec-register.py
"""Focused regression coverage for orient-prefilter composition mode."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "orient-prefilter.py"
HUNT_JSON = ROOT / "reports" / "v3_iter_2026-05-25" / \
    "lane_HYPERBRIDGE_FULL_HUNT_ORIENT" / "hunt_orient.json"
HYPERBRIDGE_WS = Path("/Users/wolf/audits/hyperbridge")

_spec = importlib.util.spec_from_file_location("orient_prefilter", TOOL)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)  # type: ignore[union-attr]


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
        check=False,
        env=dict(os.environ),
    )


def _run_real_composition() -> dict:
    proc = _run(
        "--candidates", str(HUNT_JSON),
        "--workspace", str(HYPERBRIDGE_WS),
        "--audit-pin", "70c8429d9b5c7c3260e37c02714c4026601dabd3",
        "--composition",
        "--json",
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"orient-prefilter composition exited {proc.returncode}\n"
            f"stdout: {proc.stdout[:600]}\nstderr: {proc.stderr[:600]}"
        )
    return json.loads(proc.stdout)


class OrientPrefilterCompositionAnchorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures_exist = HUNT_JSON.is_file() and HYPERBRIDGE_WS.is_dir()
        if not cls.fixtures_exist:
            return
        cls.payload = _run_real_composition()
        cls.per_candidate = {row["candidate_id"]: row for row in cls.payload["per_candidate"]}

    def setUp(self) -> None:
        if not self.fixtures_exist:
            self.skipTest(
                f"fixtures unavailable: HUNT_JSON={HUNT_JSON} HYPERBRIDGE_WS={HYPERBRIDGE_WS}"
            )

    def test_top_level_mode_and_count(self) -> None:
        self.assertEqual(self.payload["mode"], "composition")
        self.assertEqual(self.payload["prefilter_summary"]["total_candidates"], 5)
        self.assertEqual(self.payload["source_meta"]["mode"], "composition")

    def test_all_composition_candidates_warn_or_fail(self) -> None:
        allowed = {"warn-multi-gate-risk", "fail-high-kill-risk"}
        misses = {}
        for comp_id in ("COMP-1", "COMP-2", "COMP-3", "COMP-4", "COMP-5"):
            self.assertIn(comp_id, self.per_candidate)
            verdict = self.per_candidate[comp_id]["verdict"]
            if verdict not in allowed:
                misses[comp_id] = verdict
        self.assertFalse(misses, f"unexpected composition verdicts: {misses}")

    def test_each_candidate_emits_leg_results(self) -> None:
        for comp_id, row in self.per_candidate.items():
            legs = row.get("leg_results", [])
            self.assertTrue(legs, f"{comp_id} missing leg_results")
            for leg in legs:
                self.assertIn("leg_index", leg)
                self.assertIn("leg_text", leg)
                self.assertIn("linked_dependency_ids", leg)
                self.assertIn("verdict", leg)
                self.assertIn("per_gate_kill_risk", leg)
                # GAP-INTEG-1 (2026-05-26): GAP30-PLATFORM-OOS gate added.
                for gate in ("R45", "R46", "R47", "R48", "R53", "GAP30-PLATFORM-OOS"):
                    self.assertIn(gate, leg["per_gate_kill_risk"])
                self.assertIn("gate_results", leg)
                self.assertEqual(len(leg["gate_results"]), 6)

    def test_each_candidate_emits_aggregate_gate_breakdowns(self) -> None:
        for comp_id, row in self.per_candidate.items():
            gate_results = row.get("gate_results", [])
            # GAP-INTEG-1: 6 gates (R45/R46/R47/R48/R53/GAP30-PLATFORM-OOS).
            self.assertEqual(len(gate_results), 6, comp_id)
            for gate in gate_results:
                self.assertIn("gate", gate)
                self.assertIn("kill_risk", gate)
                self.assertIn("per_leg", gate)
                self.assertTrue(gate["per_leg"], f"{comp_id} missing per_leg breakdown for {gate.get('gate')}")

    def test_comp_1_anchors_edge_legs_to_drill_owners(self) -> None:
        row = self.per_candidate["COMP-1"]
        legs = row["leg_results"]
        self.assertGreaterEqual(len(legs), 3)
        first_leg = legs[0]
        last_leg = legs[-1]
        self.assertIn("DRILL-5", first_leg["linked_dependency_ids"])
        self.assertIn("DRILL-8", last_leg["linked_dependency_ids"])

    def test_comp_5_multi_leg_chain_stays_non_pass(self) -> None:
        row = self.per_candidate["COMP-5"]
        self.assertGreaterEqual(len(row["leg_results"]), 3)
        non_pass_legs = [leg for leg in row["leg_results"] if leg["verdict"] != "pass-likely-fileable"]
        self.assertGreaterEqual(len(non_pass_legs), 2)


class OrientPrefilterCompositionUnitTests(unittest.TestCase):
    def test_leg_mapping_prefers_token_overlap_and_falls_back_to_edges(self) -> None:
        composition = {
            "id": "COMP-X",
            "name": "Synthetic composition",
            "chain": "alpha settles state -> bridge dispatches root -> vault releases funds",
            "depends_on": ["DRILL-A", "DRILL-B"],
        }
        deps = {
            "DRILL-A": {"id": "DRILL-A", "name": "Alpha state finalization bug", "cluster": "alpha-finalization-gap", "attack_class": "theft"},
            "DRILL-B": {"id": "DRILL-B", "name": "Vault release accounting bug", "cluster": "vault-release", "attack_class": "accounting-discrepancy"},
        }
        mapped = mod._map_legs_to_dependencies(composition, deps)
        self.assertEqual(mapped[0]["linked_dependency_ids"], ["DRILL-A"])
        self.assertEqual(mapped[-1]["linked_dependency_ids"], ["DRILL-B"])

    def test_composition_queue_requires_chain_field(self) -> None:
        fd, tmp_name = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        tmp_path = Path(tmp_name)
        tmp_path.write_text(json.dumps({"composition_queue": [{"id": "COMP-BAD"}]}), encoding="utf-8")
        try:
            with self.assertRaises(ValueError):
                mod._load_composition_candidates(tmp_path)
        finally:
            tmp_path.unlink(missing_ok=True)
