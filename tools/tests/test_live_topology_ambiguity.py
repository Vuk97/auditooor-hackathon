#!/usr/bin/env python3
"""P1-3 burn-down (item #13) — source/target ambiguity coverage.

Pins down four scenarios that the live-check spec synthesizer + runner
must handle without inventing a target for the operator:

  1. one alias candidate -> deterministic, status=ok
  2. two alias candidates with identical scores -> emit ONE
     `synthesis_status: ambiguous-source` row that lists every tied
     candidate in `heuristic_provenance.candidates`; runner converts the
     row to status=ambiguous_source.
  3. two alias candidates with different scores -> deterministic to the
     highest-score alias, with a recorded `discriminator` on the
     provenance citing the signal that broke the tie.
  4. zero alias candidates -> regression-pin: synthesizer emits no row
     at all (we do NOT silently invent a getter).

The fixtures are in-memory only — no RPC, no workspace files. They feed
`generate_relation_checks` and `run_single_check` directly.
"""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]


def load_tool(name: str, relative_path: str):
    spec = importlib.util.spec_from_file_location(name, REPO / relative_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


synth = load_tool("live_check_spec_synthesizer_under_ambiguity_test", "tools/live-check-spec-synthesizer.py")
runner = load_tool("live_check_runner_under_ambiguity_test", "tools/live-check-runner.py")


SOURCE_TEXT_TWO_GETTERS = (
    "contract VaultAdapter {\n"
    "    RiskManager public primaryRiskManager;\n"
    "    RiskManager public backupRiskManager;\n"
    "}\n"
)


def topology_two_resolved() -> dict:
    return {
        "VaultAdapter": {
            "status": "resolved",
            "resolved_address": "0x1111111111111111111111111111111111111111",
            "candidate_addresses": [],
        },
        "RiskManager": {
            "status": "resolved",
            "resolved_address": "0x2222222222222222222222222222222222222222",
            "candidate_addresses": [],
        },
    }


def angle_pair() -> list:
    return [
        {
            "id": "A-AUTH",
            "contracts": ["VaultAdapter", "RiskManager"],
            "title": "risk manager wiring controls adapter",
        }
    ]


class LiveTopologyAmbiguityTests(unittest.TestCase):
    # ------------------------------------------------------------------
    # Case 1: single candidate -> deterministic ok
    # ------------------------------------------------------------------
    def test_single_candidate_is_deterministic_ok(self) -> None:
        checks = synth.generate_relation_checks(
            angles=angle_pair(),
            topology=topology_two_resolved(),
            default_network="mainnet",
            contract_getters={"VaultAdapter": {"riskManager"}, "RiskManager": set()},
            contract_text={
                "VaultAdapter": "contract VaultAdapter { RiskManager public riskManager; }",
            },
            seed_checks=[],
        )
        self.assertEqual(len(checks), 1)
        check = checks[0]
        self.assertEqual(check["synthesis_status"], "ok")
        self.assertEqual(check["heuristic_provenance"]["getter"], "riskManager")
        self.assertFalse(check["heuristic_provenance"]["ambiguous"])
        self.assertEqual(
            [entry["alias"] for entry in check["heuristic_provenance"]["candidates"]],
            ["riskManager"],
        )

        summary = synth.summarize(checks)
        self.assertEqual(summary["generated_relation"], 1)
        self.assertEqual(summary["generated_ambiguous_source"], 0)

    # ------------------------------------------------------------------
    # Case 2: two candidates, identical scores -> ambiguous-source
    # ------------------------------------------------------------------
    def test_tied_candidates_emit_ambiguous_source(self) -> None:
        # Both `primaryRiskManager` and `backupRiskManager` overlap the
        # target tokens (`risk`, `manager`) by exactly the same amount;
        # neither matches a semantic-graph edge nor the exact target
        # name. The scoring is forced into a tie.
        checks = synth.generate_relation_checks(
            angles=angle_pair(),
            topology=topology_two_resolved(),
            default_network="mainnet",
            contract_getters={
                "VaultAdapter": {"primaryRiskManager", "backupRiskManager"},
                "RiskManager": set(),
            },
            contract_text={"VaultAdapter": SOURCE_TEXT_TWO_GETTERS},
            seed_checks=[],
        )

        self.assertEqual(len(checks), 1, msg=f"expected one ambiguous row, got {checks}")
        row = checks[0]
        self.assertEqual(row["synthesis_status"], "ambiguous-source")
        self.assertEqual(
            sorted(row["ambiguous_alias_candidates"]),
            ["backupRiskManager", "primaryRiskManager"],
        )
        provenance = row["heuristic_provenance"]
        self.assertTrue(provenance["ambiguous"])
        candidate_names = sorted(entry["alias"] for entry in provenance["candidates"])
        self.assertEqual(candidate_names, ["backupRiskManager", "primaryRiskManager"])
        # Both candidates must carry their score so the operator can
        # confirm the tie was real, not a mis-comparison.
        scores = {entry["alias"]: entry["score"] for entry in provenance["candidates"]}
        self.assertEqual(scores["primaryRiskManager"], scores["backupRiskManager"])
        self.assertIn(
            "multiple alias candidates tied at the top score",
            " ".join(provenance["limitations"]),
        )
        # Discriminator must be None — no tie-breaker exists.
        self.assertIsNone(provenance["discriminator"])

        summary = synth.summarize(checks)
        self.assertEqual(summary["generated_ambiguous_source"], 1)

        # Runner must surface the ambiguous status, not silently fall
        # through to the address-resolution logic.
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            result = runner.run_single_check(
                ws,
                row,
                topology=topology_two_resolved(),
                workspace_env={},
                force_dry_run=True,
                allow_public_rpc=False,
            )
        self.assertEqual(result["status"], "ambiguous_source")
        self.assertEqual(result["execution_mode"], "skipped")
        self.assertEqual(
            sorted(result["ambiguous_alias_candidates"]),
            ["backupRiskManager", "primaryRiskManager"],
        )
        self.assertIn("synthesizer refused to pick", result["blocked_reason"])

        # Runner summarize() must count the ambiguous row.
        run_summary = runner.summarize([result])
        self.assertEqual(run_summary["ambiguous_source"], 1)

        markdown = runner.render_markdown(
            ws,
            {
                "workspace": str(ws),
                "spec": "spec.json",
                "generated_at": "2026-04-29T00:00:00Z",
                "summary": run_summary,
                "results": [result],
                "manual_imports": {},
                "proof_pairs": [],
                "proof_pair_summary": {},
                "proof_contradictions": [],
            },
        )
        self.assertIn("Ambiguous source: 1", markdown)
        self.assertIn("Ambiguous-source candidates", markdown)
        self.assertIn("backupRiskManager", markdown)
        self.assertIn("primaryRiskManager", markdown)

    # ------------------------------------------------------------------
    # Case 3: two candidates, different scores -> deterministic + discriminator
    # ------------------------------------------------------------------
    def test_distinct_scores_pick_winner_with_discriminator(self) -> None:
        # `riskManager` exactly matches the target name (RiskManager ->
        # `risk` + `manager` overlap AND exact_target_name_match), while
        # `secondaryWiring` has zero meaningful overlap. Score order is
        # strict, so the synthesizer must pick `riskManager` and record
        # the unique discriminator signal.
        source_text = (
            "contract VaultAdapter {\n"
            "    RiskManager public riskManager;\n"
            "    address public secondaryWiring;\n"
            "}\n"
        )
        checks = synth.generate_relation_checks(
            angles=angle_pair(),
            topology=topology_two_resolved(),
            default_network="mainnet",
            contract_getters={
                "VaultAdapter": {"riskManager", "secondaryWiring"},
                "RiskManager": set(),
            },
            contract_text={"VaultAdapter": source_text},
            seed_checks=[],
        )
        # `secondaryWiring` shares zero meaningful tokens with the
        # target type, so `guess_relation_aliases` does not even surface
        # it as a candidate — only `riskManager` makes the cut. The
        # discriminator-vs-runner-up case in scoring is exercised in
        # `test_distinct_scores_pick_winner_via_semantic_edge` below
        # where both candidates are semantically eligible.
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0]["synthesis_status"], "ok")
        self.assertEqual(checks[0]["heuristic_provenance"]["getter"], "riskManager")

    def test_distinct_scores_pick_winner_via_semantic_edge(self) -> None:
        # Both `primaryRiskManager` and `backupRiskManager` clear the
        # token-overlap bar, but the semantic graph cites only
        # `primaryRiskManager` as the registry-write method. Scoring
        # gives `primaryRiskManager` a `+4` boost over `backupRiskManager`
        # so the synthesizer must emit a deterministic ok row whose
        # discriminator names the semantic-graph signal.
        checks = synth.generate_relation_checks(
            angles=angle_pair(),
            topology=topology_two_resolved(),
            default_network="mainnet",
            contract_getters={
                "VaultAdapter": {"primaryRiskManager", "backupRiskManager"},
                "RiskManager": set(),
            },
            contract_text={"VaultAdapter": SOURCE_TEXT_TWO_GETTERS},
            seed_checks=[],
            semantic_graph={
                "schema_version": "auditooor.semantic_graph.v1",
                "relation_edges": [
                    {
                        "kind": "registry-write",
                        "source_contract": "VaultAdapter",
                        "source_function": "configurePrimary",
                        "target": "primaryRiskManager",
                        "method": "primaryRiskManager",
                        "file": "src/VaultAdapter.sol",
                        "line": 42,
                        "confidence": "source-shape",
                    }
                ],
            },
        )
        self.assertEqual(len(checks), 1)
        check = checks[0]
        self.assertEqual(check["synthesis_status"], "ok")
        self.assertEqual(check["heuristic_provenance"]["getter"], "primaryRiskManager")
        self.assertFalse(check["heuristic_provenance"]["ambiguous"])
        discriminator = check["heuristic_provenance"]["discriminator"]
        self.assertIsNotNone(discriminator)
        self.assertEqual(discriminator["winner"], "primaryRiskManager")
        self.assertEqual(discriminator["runner_up"], "backupRiskManager")
        self.assertGreater(discriminator["score_delta"], 0)
        self.assertIn(
            "matches_semantic_graph_method",
            discriminator["unique_signals"],
        )

    # ------------------------------------------------------------------
    # Case 4: zero candidates -> no row emitted
    # ------------------------------------------------------------------
    def test_zero_candidates_emits_no_row(self) -> None:
        # Neither getter shares meaningful tokens with the target type
        # name and no manual alias rule matches. Synthesizer must emit
        # nothing — silently picking the first getter would be the
        # exact failure mode P1-3 burn-down is closing.
        checks = synth.generate_relation_checks(
            angles=angle_pair(),
            topology=topology_two_resolved(),
            default_network="mainnet",
            contract_getters={
                "VaultAdapter": {"unrelatedAddress", "anotherUnrelated"},
                "RiskManager": set(),
            },
            contract_text={
                "VaultAdapter": "contract VaultAdapter { address public unrelatedAddress; address public anotherUnrelated; }",
            },
            seed_checks=[],
        )
        self.assertEqual(checks, [])

        summary = synth.summarize(checks)
        self.assertEqual(summary["generated_relation"], 0)
        self.assertEqual(summary["generated_ambiguous_source"], 0)

    # ------------------------------------------------------------------
    # Internal scoring sanity: deterministic ranking is reproducible
    # ------------------------------------------------------------------
    def test_rank_relation_alias_candidates_is_deterministic(self) -> None:
        first = synth.rank_relation_alias_candidates(
            source="VaultAdapter",
            target="RiskManager",
            candidates=["primaryRiskManager", "backupRiskManager"],
            source_text=SOURCE_TEXT_TWO_GETTERS,
            semantic_graph=None,
        )
        second = synth.rank_relation_alias_candidates(
            source="VaultAdapter",
            target="RiskManager",
            candidates=["backupRiskManager", "primaryRiskManager"],
            source_text=SOURCE_TEXT_TWO_GETTERS,
            semantic_graph=None,
        )
        # Same scores both ways; secondary alphabetical sort makes the
        # tied-top row reproducible regardless of input order.
        self.assertEqual(
            [entry["alias"] for entry in first],
            [entry["alias"] for entry in second],
        )
        self.assertEqual(first[0]["score"], first[1]["score"])


if __name__ == "__main__":
    unittest.main()
