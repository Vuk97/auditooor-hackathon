"""HACKERMAN_V3 Lane D2 - runnable chain composition tests.

D2 reads a chained-attack-plans payload (the planner output, which already
carries D1 bridge state) and composes each plan into a runnable-composition
descriptor: hop B's harness consumes hop A's post-state, the composed run is
gated on surviving defense-in-depth, and a concrete composed command is
emitted via the C2 generation pattern.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
D2_TOOL = ROOT / "tools" / "chain-composition-harness.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _bridged_plan(
    chain_id: str,
    *,
    bridging_state: str = "vault_locked_balance",
    traversal_prose: str,
    producer_artifact: str = "/ws/.auditooor/source_artifacts/EQ-A.source_artifact.json",
    consumer_entrypoint: str = "src/Router.go",
) -> dict:
    """A D1-bridged 2-hop chain plan (carries a LIVE-<id> bridge)."""
    return {
        "chain_id": chain_id,
        "causal_evidence_level": "distinct_bridge_signal_present",
        "metadata_overlap_only": False,
        "paired_live_row_ids": ["LIVE-ABCDEF123456"],
        "causal_bridge_signals": ["live-abcdef123456"],
        "composition_harness_requirements": [
            {
                "binding_scope": "composed_chain_harness",
                "chain_id": chain_id,
                "primitive_pair_ids": ["P1", "P2"],
                "producer_lead_id": "EQ-A",
                "consumer_lead_id": "EQ-B",
                "bridging_state": bridging_state,
                "producer_state_artifact": producer_artifact,
                "producer_source_artifact": "src/Vault.go",
                "consumer_entrypoint": consumer_entrypoint,
            }
        ],
        "chain_steps": [
            {"step": 1, "summary": "producer hop produces state"},
            {"step": 2, "summary": "consumer hop", "evidence_required": traversal_prose},
        ],
        "shared_evidence": ["shared_attack_classes:access-control"],
        "source_refs": ["src/Vault.go:10", "src/Router.go:44"],
    }


def _metadata_only_plan(chain_id: str) -> dict:
    """A chain with no D1 LIVE bridge - metadata overlap only."""
    return {
        "chain_id": chain_id,
        "causal_evidence_level": "metadata_overlap_only_unproven",
        "metadata_overlap_only": True,
        "paired_live_row_ids": [],
        "causal_bridge_signals": [],
        "composition_harness_requirements": [],
        "chain_steps": [{"step": 1, "summary": "metadata overlap"}],
        "shared_evidence": ["shared_files:src/Vault.go"],
        "source_refs": [],
    }


class ChainCompositionHarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.d2 = _load(D2_TOOL, "_chain_composition_harness")
        self.tmp = tempfile.TemporaryDirectory(prefix="chain-composition-harness-")
        self.ws = Path(self.tmp.name)
        (self.ws / "swarm").mkdir(parents=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_plan(self, plans: list[dict]) -> Path:
        path = self.ws / "swarm" / "chained_attack_plans.json"
        path.write_text(
            json.dumps({"schema_version": "x", "plans": plans}, indent=2),
            encoding="utf-8",
        )
        return path

    # ------------------------------------------------------------------
    # D1-bridged 2-hop chain -> composed descriptor, hop B consumes hop A
    # ------------------------------------------------------------------
    def test_bridged_chain_yields_composed_descriptor_hop_b_consumes_hop_a(self) -> None:
        # Traversal prose names a real ante decorator + FinalizeBlock path so
        # the defense-in-depth gate passes -> composition_runnable.
        plan = _bridged_plan(
            "CHAIN-001",
            traversal_prose=(
                "exercise the real ante decorators via BroadcastTxSync and "
                "FinalizeBlock; call from an unprivileged caller (access control)"
            ),
        )
        row = self.d2.compose_chain(plan, None)

        self.assertEqual(row["verdict"], "composition_runnable")
        self.assertTrue(row["composition_runnable"])
        self.assertTrue(row["has_d1_live_bridge"])
        self.assertEqual(row["bridge_ids"], ["LIVE-ABCDEF123456"])

        composed = row["composed_harness"]
        self.assertIsNotNone(composed)
        # hop B's setup chains from hop A's POST-state, not a fresh fixture.
        setup = composed["hop_b"]["setup"]
        self.assertEqual(setup["fixture_mode"], "chained_from_hop_a_post_state")
        self.assertFalse(setup["resets_to_fresh_fixture"])
        self.assertEqual(setup["consumes_post_state_of"], "hop_a")
        self.assertEqual(
            setup["post_state_source_artifact"],
            "/ws/.auditooor/source_artifacts/EQ-A.source_artifact.json",
        )
        self.assertIn("vault_locked_balance", setup["bridging_state_tokens"])
        self.assertIn("Do NOT call a fresh-fixture setup", setup["setup_directive"])

        # hop A produces exactly the state hop B consumes.
        self.assertEqual(
            composed["hop_a"]["produces_post_state"],
            setup["bridging_state_tokens"],
        )

        # A concrete runnable composed command exists.
        self.assertTrue(composed["command"]["command_present"])
        self.assertTrue(composed["command"]["composed_harness_command"])

    # ------------------------------------------------------------------
    # metadata-only chain -> no composed harness, stays non-runnable
    # ------------------------------------------------------------------
    def test_metadata_only_chain_yields_no_composed_harness(self) -> None:
        plan = _metadata_only_plan("CHAIN-002")
        row = self.d2.compose_chain(plan, None)

        self.assertEqual(row["verdict"], "non_runnable")
        self.assertFalse(row["composition_runnable"])
        self.assertFalse(row["has_d1_live_bridge"])
        self.assertIsNone(row["composed_harness"])
        self.assertIn("metadata-overlap only", row["reason"])

    # ------------------------------------------------------------------
    # defense-in-depth gate blocks a composition that skips ante / access
    # ------------------------------------------------------------------
    def test_defense_in_depth_gate_blocks_composition_skipping_ante(self) -> None:
        # The chain IS D1-bridged and a command can be generated, but the
        # prose only describes a direct keeper call - no ante / block-execution
        # traversal and no access-control reasoning.
        plan = _bridged_plan(
            "CHAIN-003",
            traversal_prose="just call the keeper method directly in a unit test",
        )
        row = self.d2.compose_chain(plan, None)

        self.assertEqual(row["verdict"], "needs_defense_traversal")
        self.assertFalse(row["composition_runnable"])
        # The descriptor is still emitted - the gate flags what is missing.
        self.assertIsNotNone(row["composed_harness"])
        defense = row["composed_harness"]["defense_in_depth"]
        self.assertFalse(defense["traversed"])
        self.assertIn(
            "ante-handler / block-execution traversal",
            defense["missing_defense_layers"],
        )
        self.assertIn(
            "access-control traversal", defense["missing_defense_layers"]
        )
        self.assertTrue(defense["remediation"])

    # ------------------------------------------------------------------
    # honest R25 walk-back counts as defense traversal done
    # ------------------------------------------------------------------
    def test_honest_walkback_counts_as_defense_traversed(self) -> None:
        plan = _bridged_plan(
            "CHAIN-004",
            traversal_prose=(
                "the composed sequence is structurally rejected at ante - "
                "ValidateNestedMsg means the attack tx never reaches block"
            ),
        )
        row = self.d2.compose_chain(plan, None)
        # An honest walk-back IS the defense analysis -> composition_runnable.
        self.assertEqual(row["verdict"], "composition_runnable")
        defense = row["composed_harness"]["defense_in_depth"]
        self.assertTrue(defense["traversed"])
        self.assertTrue(defense["honest_walkback_signals"])

    # ------------------------------------------------------------------
    # full payload run + verdict counts + strict exit
    # ------------------------------------------------------------------
    def test_compose_plans_summary_and_counts(self) -> None:
        plans = [
            _bridged_plan(
                "CHAIN-001",
                traversal_prose="real ante decorators and FinalizeBlock; access control checked",
            ),
            _bridged_plan(
                "CHAIN-003",
                traversal_prose="direct keeper call only",
            ),
            _metadata_only_plan("CHAIN-002"),
        ]
        summary = self.d2.compose_plans({"plans": plans}, None)
        self.assertEqual(summary["composed_count"], 3)
        self.assertEqual(summary["verdict_counts"]["composition_runnable"], 1)
        self.assertEqual(summary["verdict_counts"]["needs_defense_traversal"], 1)
        self.assertEqual(summary["verdict_counts"]["non_runnable"], 1)
        self.assertFalse(summary["all_runnable"])

    def test_run_from_chain_plan_file(self) -> None:
        plan_path = self._write_plan(
            [
                _bridged_plan(
                    "CHAIN-001",
                    traversal_prose="real ante decorators and FinalizeBlock; access control",
                )
            ]
        )
        summary = self.d2.run(["--chain-plan", str(plan_path)])
        self.assertEqual(summary["source_plan_count"], 1)
        self.assertEqual(summary["verdict_counts"]["composition_runnable"], 1)
        self.assertTrue(summary["all_runnable"])
        self.assertEqual(
            Path(summary["chain_plan_path"]).resolve(), plan_path.resolve()
        )

    def test_strict_exit_nonzero_on_non_runnable(self) -> None:
        plan_path = self._write_plan([_metadata_only_plan("CHAIN-002")])
        rc = self.d2.main(["--chain-plan", str(plan_path), "--strict"])
        self.assertEqual(rc, 1)

    def test_strict_exit_zero_when_all_runnable(self) -> None:
        plan_path = self._write_plan(
            [
                _bridged_plan(
                    "CHAIN-001",
                    traversal_prose="real ante decorators and FinalizeBlock; access control",
                )
            ]
        )
        rc = self.d2.main(["--chain-plan", str(plan_path), "--strict"])
        self.assertEqual(rc, 0)

    def test_bridged_chain_without_composition_requirement_is_non_runnable(self) -> None:
        # D1-bridged but no producer/consumer split row -> cannot compose.
        plan = _bridged_plan("CHAIN-005", traversal_prose="real ante decorators")
        plan["composition_harness_requirements"] = []
        row = self.d2.compose_chain(plan, None)
        self.assertEqual(row["verdict"], "non_runnable")
        self.assertTrue(row["has_d1_live_bridge"])
        self.assertIn("no composition_harness_requirements", row["reason"])


if __name__ == "__main__":
    unittest.main()
