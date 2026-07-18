from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "proof-obligation-queue.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("proof_obligation_queue", TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load proof-obligation-queue.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class ProofObligationQueueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="proof-obligation-queue-")
        self.ws = Path(self.tmp.name)
        (self.ws / ".auditooor").mkdir()
        (self.ws / "swarm").mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_builds_queue_from_hacker_brief_json_questions(self) -> None:
        tool = _load_tool()
        _write_json(
            self.ws / ".auditooor" / "hacker_brief.md.json",
            {
                "schema": "auditooor.hacker_brief_augmenter.v1",
                "lane_id": "H1-vault",
                "sections": {
                    "sec13_question_list": {
                        "items": [
                            {
                                "id": "Q-DET-reentrancy-no-guard",
                                "text": "Can withdraw+callback chain reenter across hook boundary?",
                                "evidence": "Need concrete file:line + local PoC harness",
                            }
                        ]
                    }
                },
            },
        )

        payload = tool.run(["--workspace", str(self.ws)])
        self.assertEqual(payload["schema"], "auditooor.proof_obligation_queue.v1")
        self.assertEqual(payload["summary"]["question_tasks"], 1)
        self.assertEqual(payload["summary"]["chain_blocker_tasks"], 0)
        self.assertRegex(payload["context_pack_hash"], r"^[0-9a-f]{64}$")
        self.assertTrue(payload["context_pack_id"].startswith("auditooor.proof_obligation_queue.v1:"))
        self.assertEqual(payload["tasks"][0]["task_id"], "POQ-001")
        self.assertEqual(payload["tasks"][0]["source_question"], "Q-DET-reentrancy-no-guard")
        self.assertIsNone(payload["tasks"][0]["chain_id"])
        self.assertTrue(payload["tasks"][0]["advisory_only"])
        self.assertEqual(payload["workspace"], "<workspace>")

    def test_extracts_questions_from_markdown_when_json_missing(self) -> None:
        tool = _load_tool()
        (self.ws / ".auditooor" / "hacker_brief.md").write_text(
            "# Hacker Brief\n\n- Q-TRACE-bridge-signer: prove signer-path mismatch with local PoC\n",
            encoding="utf-8",
        )

        payload = tool.run(["--workspace", str(self.ws)])
        self.assertEqual(payload["summary"]["question_tasks"], 1)
        self.assertEqual(payload["tasks"][0]["source_question"], "Q-TRACE-bridge-signer")
        self.assertIn("source_ref", payload["tasks"][0])
        self.assertEqual(payload["tasks"][0]["source_ref"], "<workspace>/.auditooor/hacker_brief.md")

    def test_qdet_tasks_include_sanitized_detector_fire_context(self) -> None:
        tool = _load_tool()
        _write_json(
            self.ws / ".auditooor" / "hacker_brief.md.json",
            {
                "sections": {
                    "sec5_engage_report_fires": {
                        "items": [
                            {
                                "detector": "cap desync",
                                "fires": [
                                    f"[HIGH] {self.ws}/programs/onre/src/lib.rs:42 - supply cap check after mint",
                                    "[MEDIUM] tests/poc.rs:7 - fixture hit",
                                ],
                            }
                        ]
                    },
                    "sec13_question_list": {
                        "items": [
                            {
                                "id": "Q-DET-cap-desync",
                                "text": "Can cap desync become unauthorized minting?",
                                "evidence": "Need local bankrun proof",
                            }
                        ]
                    },
                },
            },
        )

        payload = tool.run(["--workspace", str(self.ws), "--generated-at", "2026-05-13T00:00:00Z"])
        row = payload["tasks"][0]
        self.assertEqual(row["detector"], "cap desync")
        self.assertEqual(row["context_note"], "detector fire context only; not exploit proof")
        self.assertIn("<workspace>/programs/onre/src/lib.rs:42", row["detector_fires"][0])
        self.assertIn("<workspace>/programs/onre/src/lib.rs:42", row["file_hints"])
        self.assertIn("tests/poc.rs:7", row["file_hints"])
        self.assertNotIn(str(self.ws), json.dumps(payload))

    def test_converts_chain_blockers_into_proof_tasks(self) -> None:
        tool = _load_tool()
        _write_json(
            self.ws / "swarm" / "chained_attack_plans.json",
            {
                "schema": "auditooor.chained_attack_plans.v1",
                "plans": [
                    {
                        "chain_id": "CHAIN-002",
                        "proof_steps": ["Build local fork test for solvency invariant break"],
                        "blockers": [
                            "causal bridge is unproven; overlap is metadata-level until distinct bridge evidence exists"
                        ],
                    }
                ],
            },
        )

        payload = tool.run(["--workspace", str(self.ws), "--max-tasks", "10"])
        self.assertEqual(payload["summary"]["question_tasks"], 0)
        self.assertEqual(payload["summary"]["chain_blocker_tasks"], 1)
        row = payload["tasks"][0]
        self.assertEqual(row["chain_id"], "CHAIN-002")
        self.assertIsNone(row["source_question"])
        self.assertIn("local fork test", row["proof_needed"])
        self.assertTrue(row["advisory_only"])

    def test_ingests_detector_action_graph_proof_obligations(self) -> None:
        tool = _load_tool()
        _write_json(
            self.ws / ".auditooor" / "detector_action_graph.json",
            {
                "schema": "auditooor.detector_hit_action_graph.v1",
                "detector_hit": {
                    "detector_slug": "reentrancy-no-guard",
                    "file_path": str(self.ws / "src" / "Vault.sol") + ":42",
                },
                "proof_obligations": [
                    {
                        "id": "P-001",
                        "kind": "source_confirmation",
                        "title": "Confirm the detector hit on real target source",
                        "required_evidence": [
                            "exact source file and line",
                            "surrounding function body",
                        ],
                        "source_refs": [str(self.ws / "src" / "Vault.sol") + ":42"],
                        "status": "open",
                    },
                    {
                        "id": "P-002",
                        "kind": "attacker_control",
                        "title": "Prove unvetted attacker controls the call path",
                        "required_evidence": ["actor model"],
                        "status": "open",
                    },
                ],
            },
        )

        payload = tool.run(["--workspace", str(self.ws), "--generated-at", "2026-05-13T00:00:00Z"])

        self.assertEqual(payload["summary"]["detector_action_graph_tasks"], 2)
        self.assertTrue(payload["summary"]["detector_action_graph_source_found"])
        row = payload["tasks"][0]
        self.assertEqual(row["task_id"], "POQ-001")
        self.assertIsNone(row["source_question"])
        self.assertIsNone(row["chain_id"])
        self.assertEqual(row["detector_action_graph_obligation"], "P-001")
        self.assertEqual(row["obligation_kind"], "source_confirmation")
        self.assertEqual(row["detector"], "reentrancy-no-guard")
        self.assertEqual(row["source_ref"], "<workspace>/.auditooor/detector_action_graph.json")
        self.assertTrue(row["advisory_only"])
        self.assertIn("<workspace>/src/Vault.sol:42", row["source_refs"])
        self.assertIn("<workspace>/src/Vault.sol:42", row["file_hints"])
        self.assertNotIn(str(self.ws), json.dumps(payload))

    def test_defaults_to_bridge_summary_graphs_without_legacy_duplicate(self) -> None:
        tool = _load_tool()
        graph_dir = self.ws / ".auditooor" / "detector_action_graphs"
        graph_a = graph_dir / "hit_000_cap-desync.json"
        graph_b = graph_dir / "hit_001_nav-skew.json"
        _write_json(
            self.ws / ".auditooor" / "audit_hacker_logic_bridge.json",
            {
                "schema": "auditooor.audit_hacker_logic_bridge.v1",
                "graphs": [
                    {"graph_path": ".auditooor/detector_action_graphs/hit_000_cap-desync.json"},
                    {"graph_path": ".auditooor/detector_action_graphs/hit_001_nav-skew.json"},
                ],
            },
        )
        _write_json(
            graph_a,
            {
                "schema": "auditooor.detector_hit_action_graph.v1",
                "detector_hit": {"detector_slug": "cap-desync", "file_path": "src/Offer.sol:17"},
                "proof_obligations": [{"id": "P-001", "kind": "source_confirmation", "title": "fresh A"}],
            },
        )
        _write_json(
            graph_b,
            {
                "schema": "auditooor.detector_hit_action_graph.v1",
                "detector_hit": {"detector_slug": "nav-skew", "file_path": "src/Nav.sol:29"},
                "proof_obligations": [{"id": "P-001", "kind": "source_confirmation", "title": "fresh B"}],
            },
        )
        _write_json(
            self.ws / ".auditooor" / "detector_action_graph.json",
            {
                "schema": "auditooor.detector_hit_action_graph.v1",
                "detector_hit": {"detector_slug": "stale-legacy"},
                "proof_obligations": [{"id": "STALE", "kind": "source_confirmation", "title": "stale"}],
            },
        )

        payload = tool.run(["--workspace", str(self.ws), "--generated-at", "2026-05-13T00:00:00Z"])
        rendered = json.dumps(payload, sort_keys=True)

        self.assertEqual(payload["summary"]["detector_action_graph_tasks"], 2)
        self.assertTrue(payload["summary"]["detector_action_graph_source_found"])
        self.assertEqual(
            [row["detector"] for row in payload["tasks"]],
            ["cap-desync", "nav-skew"],
        )
        self.assertIn("<workspace>/.auditooor/detector_action_graphs/hit_000_cap-desync.json", payload["sources"])
        self.assertIn("<workspace>/.auditooor/detector_action_graphs/hit_001_nav-skew.json", payload["sources"])
        self.assertNotIn("<workspace>/.auditooor/detector_action_graph.json", payload["sources"])
        self.assertNotIn("STALE", rendered)
        self.assertNotIn(str(self.ws), rendered)

    def test_bridge_summary_does_not_glob_unreferenced_stale_sidecars(self) -> None:
        tool = _load_tool()
        graph_dir = self.ws / ".auditooor" / "detector_action_graphs"
        fresh_graph = graph_dir / "hit_000_current.json"
        stale_graph = graph_dir / "hit_999_stale.json"
        _write_json(
            self.ws / ".auditooor" / "audit_hacker_logic_bridge.json",
            {
                "schema": "auditooor.audit_hacker_logic_bridge.v1",
                "graphs": [{"graph_path": ".auditooor/detector_action_graphs/hit_000_current.json"}],
            },
        )
        _write_json(
            fresh_graph,
            {
                "detector_hit": {"detector_slug": "current-hit", "file_path": "src/Current.sol:7"},
                "proof_obligations": [{"id": "P-CURRENT", "kind": "source_confirmation", "title": "fresh proof"}],
            },
        )
        _write_json(
            stale_graph,
            {
                "detector_hit": {"detector_slug": "stale-hit", "file_path": "src/Stale.sol:99"},
                "proof_obligations": [{"id": "P-STALE", "kind": "source_confirmation", "title": "stale proof"}],
            },
        )

        payload = tool.run(["--workspace", str(self.ws), "--generated-at", "2026-05-13T00:00:00Z"])
        rendered = json.dumps(payload, sort_keys=True)

        self.assertEqual(payload["summary"]["detector_action_graph_tasks"], 1)
        self.assertEqual(payload["tasks"][0]["detector"], "current-hit")
        self.assertIn("<workspace>/.auditooor/detector_action_graphs/hit_000_current.json", payload["sources"])
        self.assertNotIn("<workspace>/.auditooor/detector_action_graphs/hit_999_stale.json", payload["sources"])
        self.assertNotIn("stale-hit", rendered)
        self.assertNotIn("P-STALE", rendered)

    def test_stale_bridge_summary_older_than_engage_report_suppresses_graphs(self) -> None:
        tool = _load_tool()
        engage_report = self.ws / "engage_report.json"
        summary = self.ws / ".auditooor" / "audit_hacker_logic_bridge.json"
        graph = self.ws / ".auditooor" / "detector_action_graphs" / "hit_000_old.json"
        _write_json(
            engage_report,
            {"schema": "auditooor.engage_report.v1", "clusters": []},
        )
        _write_json(
            summary,
            {
                "schema": "auditooor.audit_hacker_logic_bridge.v1",
                "engage_report": "engage_report.json",
                "graphs": [{"graph_path": ".auditooor/detector_action_graphs/hit_000_old.json"}],
            },
        )
        _write_json(
            graph,
            {
                "detector_hit": {"detector_slug": "old-hit"},
                "proof_obligations": [{"id": "P-OLD", "kind": "source_confirmation", "title": "old proof"}],
            },
        )
        summary_time = 1_800_000_000
        graph_time = summary_time
        engage_time = summary_time + 60
        summary.touch()
        graph.touch()
        engage_report.touch()
        os.utime(summary, (summary_time, summary_time))
        os.utime(graph, (graph_time, graph_time))
        os.utime(engage_report, (engage_time, engage_time))

        payload = tool.run(["--workspace", str(self.ws), "--generated-at", "2026-05-13T00:00:00Z"])
        rendered = json.dumps(payload, sort_keys=True)

        self.assertEqual(payload["summary"]["detector_action_graph_tasks"], 0)
        self.assertEqual(payload["summary"]["stale_source_warning_count"], 1)
        self.assertTrue(payload["degraded"])
        self.assertIn("older than engage_report", payload["stale_source_warnings"][0])
        self.assertNotIn("old-hit", rendered)
        self.assertNotIn("P-OLD", rendered)

    def test_graph_dir_sidecars_older_than_engage_report_are_suppressed_without_summary(self) -> None:
        tool = _load_tool()
        engage_report = self.ws / "engage_report.json"
        stale_graph = self.ws / ".auditooor" / "detector_action_graphs" / "hit_000_stale.json"
        _write_json(engage_report, {"schema": "auditooor.engage_report.v1", "clusters": []})
        _write_json(
            stale_graph,
            {
                "detector_hit": {"detector_slug": "stale-dir-hit"},
                "proof_obligations": [{"id": "P-DIR-STALE", "kind": "source_confirmation", "title": "stale dir proof"}],
            },
        )
        old_time = 1_800_000_000
        os.utime(stale_graph, (old_time, old_time))
        os.utime(engage_report, (old_time + 60, old_time + 60))

        payload = tool.run(["--workspace", str(self.ws), "--generated-at", "2026-05-13T00:00:00Z"])
        rendered = json.dumps(payload, sort_keys=True)

        self.assertEqual(payload["summary"]["detector_action_graph_tasks"], 0)
        self.assertEqual(payload["summary"]["stale_source_warning_count"], 1)
        self.assertIn("older than engage_report", payload["stale_source_warnings"][0])
        self.assertNotIn("stale-dir-hit", rendered)
        self.assertNotIn("P-DIR-STALE", rendered)

    def test_defaults_to_graph_dir_when_bridge_summary_missing(self) -> None:
        tool = _load_tool()
        graph_dir = self.ws / ".auditooor" / "detector_action_graphs"
        _write_json(
            graph_dir / "a_alpha.json",
            {
                "detector_hit": {"detector_slug": "alpha", "file_path": "src/A.sol:1"},
                "proof_obligations": [{"id": "P-001", "kind": "source_confirmation", "title": "alpha proof"}],
            },
        )
        _write_json(
            graph_dir / "b_beta.json",
            {
                "detector_hit": {"detector_slug": "beta", "file_path": "src/B.sol:2"},
                "proof_obligations": [{"id": "P-001", "kind": "source_confirmation", "title": "beta proof"}],
            },
        )

        payload = tool.run(["--workspace", str(self.ws), "--generated-at", "2026-05-13T00:00:00Z"])

        self.assertEqual(payload["summary"]["detector_action_graph_tasks"], 2)
        self.assertEqual([row["detector"] for row in payload["tasks"]], ["alpha", "beta"])
        self.assertEqual(
            [row["source_ref"] for row in payload["tasks"]],
            [
                "<workspace>/.auditooor/detector_action_graphs/a_alpha.json",
                "<workspace>/.auditooor/detector_action_graphs/b_beta.json",
            ],
        )

    def test_action_graph_obligations_do_not_collapse_when_text_matches(self) -> None:
        tool = _load_tool()
        action_graph = self.ws / "graph.json"
        _write_json(
            action_graph,
            {
                "detector_hit": {"detector_slug": "oracle-stale-read"},
                "proof_obligations": [
                    {
                        "id": "P-010",
                        "kind": "source_confirmation",
                        "title": "Shared proof title",
                        "required_evidence": ["same evidence"],
                    },
                    {
                        "id": "P-011",
                        "kind": "state_and_impact",
                        "title": "Shared proof title",
                        "required_evidence": ["same evidence"],
                    },
                ],
            },
        )

        payload = tool.run(
            [
                "--workspace",
                str(self.ws),
                "--action-graph-json",
                str(action_graph),
                "--generated-at",
                "2026-05-13T00:00:00Z",
            ]
        )

        self.assertEqual(payload["summary"]["detector_action_graph_tasks"], 2)
        self.assertEqual(
            [row["detector_action_graph_obligation"] for row in payload["tasks"]],
            ["P-010", "P-011"],
        )

    def test_proof_complete_obligation_passes_when_current_and_non_advisory(self) -> None:
        tool = _load_tool()
        source = self.ws / "src" / "Vault.sol"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("contract Vault {}\n", encoding="utf-8")
        action_graph = self.ws / ".auditooor" / "graph.json"
        _write_json(
            action_graph,
            {
                "detector_hit": {"detector_slug": "vault-proof", "file_path": "src/Vault.sol:1"},
                "proof_obligations": [
                    {
                        "id": "P-DONE",
                        "kind": "source_confirmation",
                        "title": "proof complete",
                        "source_refs": ["src/Vault.sol:1"],
                        "status": "proof_complete",
                        "advisory_only": False,
                    }
                ],
            },
        )

        payload = tool.run(
            [
                "--workspace",
                str(self.ws),
                "--action-graph-json",
                str(action_graph),
                "--generated-at",
                "2026-05-13T00:00:00Z",
            ]
        )

        row = payload["tasks"][0]
        self.assertTrue(row["proof_complete"])
        self.assertEqual(row["proof_completion_status"], "proof_complete")
        self.assertEqual(row["proof_completion_blockers"], [])
        self.assertEqual(payload["summary"]["proof_complete_tasks"], 1)

    def test_advisory_only_obligation_cannot_be_proof_complete(self) -> None:
        tool = _load_tool()
        source = self.ws / "src" / "Vault.sol"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("contract Vault {}\n", encoding="utf-8")
        action_graph = self.ws / ".auditooor" / "graph.json"
        _write_json(
            action_graph,
            {
                "detector_hit": {"detector_slug": "vault-proof", "file_path": "src/Vault.sol:1"},
                "proof_obligations": [
                    {
                        "id": "P-DONE",
                        "kind": "source_confirmation",
                        "title": "claimed complete but advisory",
                        "source_refs": ["src/Vault.sol:1"],
                        "status": "proof_complete",
                        "advisory_only": True,
                    }
                ],
            },
        )

        payload = tool.run(
            [
                "--workspace",
                str(self.ws),
                "--action-graph-json",
                str(action_graph),
                "--generated-at",
                "2026-05-13T00:00:00Z",
            ]
        )

        row = payload["tasks"][0]
        self.assertFalse(row["proof_complete"])
        self.assertTrue(row["proof_completion_claimed"])
        self.assertIn("advisory_only", row["proof_completion_blockers"])
        self.assertEqual(payload["summary"]["proof_complete_tasks"], 0)

    def test_missing_source_refs_block_proof_complete(self) -> None:
        tool = _load_tool()
        action_graph = self.ws / ".auditooor" / "graph.json"
        _write_json(
            action_graph,
            {
                "detector_hit": {"detector_slug": "vault-proof"},
                "proof_obligations": [
                    {
                        "id": "P-DONE",
                        "kind": "source_confirmation",
                        "title": "claimed complete without refs",
                        "status": "proof_complete",
                        "advisory_only": False,
                    }
                ],
            },
        )

        payload = tool.run(
            [
                "--workspace",
                str(self.ws),
                "--action-graph-json",
                str(action_graph),
                "--generated-at",
                "2026-05-13T00:00:00Z",
            ]
        )

        row = payload["tasks"][0]
        self.assertFalse(row["proof_complete"])
        self.assertIn("missing_source_refs", row["proof_completion_blockers"])
        self.assertEqual(
            payload["summary"]["proof_completion_blocker_counts"]["missing_source_refs"],
            1,
        )

    def test_stale_workspace_refs_block_proof_complete(self) -> None:
        tool = _load_tool()
        source = self.ws / "src" / "Vault.sol"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("contract Vault {}\n", encoding="utf-8")
        action_graph = self.ws / ".auditooor" / "graph.json"
        _write_json(
            action_graph,
            {
                "detector_hit": {"detector_slug": "vault-proof", "file_path": "src/Vault.sol:1"},
                "proof_obligations": [
                    {
                        "id": "P-DONE",
                        "kind": "source_confirmation",
                        "title": "claimed complete on stale graph",
                        "source_refs": ["src/Vault.sol:1"],
                        "status": "proof_complete",
                        "advisory_only": False,
                    }
                ],
            },
        )
        os.utime(source, (1_900_000_060, 1_900_000_060))
        os.utime(action_graph, (1_900_000_000, 1_900_000_000))

        payload = tool.run(
            [
                "--workspace",
                str(self.ws),
                "--action-graph-json",
                str(action_graph),
                "--generated-at",
                "2026-05-13T00:00:00Z",
            ]
        )

        row = payload["tasks"][0]
        self.assertFalse(row["proof_complete"])
        self.assertIn("stale_workspace_ref", row["proof_completion_blockers"])

    def test_declared_blocker_propagates_and_blocks_proof_complete(self) -> None:
        tool = _load_tool()
        source = self.ws / "src" / "Vault.sol"
        source.parent.mkdir(parents=True, exist_ok=True)
        source.write_text("contract Vault {}\n", encoding="utf-8")
        action_graph = self.ws / ".auditooor" / "graph.json"
        _write_json(
            action_graph,
            {
                "detector_hit": {"detector_slug": "vault-proof", "file_path": "src/Vault.sol:1"},
                "proof_obligations": [
                    {
                        "id": "P-DONE",
                        "kind": "source_confirmation",
                        "title": "claimed complete while blocked",
                        "source_refs": ["src/Vault.sol:1"],
                        "status": "proof_complete",
                        "advisory_only": False,
                        "blockers": ["waiting for exact source pin"],
                    }
                ],
            },
        )

        payload = tool.run(
            [
                "--workspace",
                str(self.ws),
                "--action-graph-json",
                str(action_graph),
                "--generated-at",
                "2026-05-13T00:00:00Z",
            ]
        )

        row = payload["tasks"][0]
        self.assertFalse(row["proof_complete"])
        self.assertEqual(row["blocker"], "waiting for exact source pin")
        self.assertEqual(row["blockers"], ["waiting for exact source pin"])
        self.assertIn("blocked_obligation", row["proof_completion_blockers"])

    def test_routes_multi_tx_manifest_into_replay_tasks(self) -> None:
        tool = _load_tool()
        _write_json(
            self.ws / ".auditooor" / "multi-tx-sequences" / "manifest.json",
            {
                "schema_version": "auditooor.fuzz_sequence_to_poc_manifest.v1",
                "lifted": [
                    {
                        "slug": "medusa_echidna_vault_solvent_2step",
                        "engine": "medusa",
                        "violated_invariant": "echidna_vault_solvent",
                        "attack_shape": "setup_then_trigger",
                        "minimized_step_count": 2,
                        "record_path": str(self.ws / ".auditooor" / "multi-tx-sequences" / "medusa_echidna_vault_solvent_2step.multi_tx_attack_sequence.v1.json"),
                        "poc_path": str(self.ws / ".auditooor" / "multi-tx-sequences" / "medusa_echidna_vault_solvent_2step.MultiTxAttackPoC.t.sol"),
                    }
                ],
            },
        )

        payload = tool.run(["--workspace", str(self.ws), "--generated-at", "2026-05-13T00:00:00Z"])

        self.assertEqual(payload["summary"]["multi_tx_candidate_tasks"], 1)
        self.assertTrue(payload["summary"]["multi_tx_source_found"])
        row = payload["tasks"][0]
        self.assertEqual(row["multi_tx_candidate"], "medusa_echidna_vault_solvent_2step")
        self.assertEqual(row["source_ref"], "<workspace>/.auditooor/multi-tx-sequences/manifest.json")
        self.assertIn("execution_manifest.json", row["next_action"])
        self.assertIn("<workspace>/.auditooor/multi-tx-sequences/medusa_echidna_vault_solvent_2step.MultiTxAttackPoC.t.sol", row["source_refs"])
        self.assertIn("t.sol", " ".join(row["file_hints"]))
        self.assertNotIn(str(self.ws), json.dumps(payload))

    def test_multi_tx_candidate_dedupes_by_slug_within_source(self) -> None:
        tool = _load_tool()
        _write_json(
            self.ws / ".auditooor" / "multi-tx-sequences" / "manifest.json",
            {
                "schema_version": "auditooor.fuzz_sequence_to_poc_manifest.v1",
                "lifted": [
                    {
                        "slug": "dup-seq",
                        "engine": "medusa",
                        "attack_shape": "setup_then_trigger",
                        "minimized_step_count": 2,
                        "violated_invariant": "echidna_x",
                        "record_path": str(self.ws / ".auditooor" / "multi-tx-sequences" / "dup-seq.multi_tx_attack_sequence.v1.json"),
                        "poc_path": str(self.ws / ".auditooor" / "multi-tx-sequences" / "dup-seq.MultiTxAttackPoC.t.sol"),
                    },
                    {
                        "slug": "dup-seq",
                        "engine": "medusa",
                        "attack_shape": "setup_then_trigger",
                        "minimized_step_count": 2,
                        "violated_invariant": "echidna_x",
                        "record_path": str(self.ws / ".auditooor" / "multi-tx-sequences" / "dup-seq.multi_tx_attack_sequence.v1.json"),
                        "poc_path": str(self.ws / ".auditooor" / "multi-tx-sequences" / "dup-seq.MultiTxAttackPoC.t.sol"),
                    },
                ],
            },
        )

        payload = tool.run(["--workspace", str(self.ws), "--generated-at", "2026-05-13T00:00:00Z"])

        self.assertEqual(payload["summary"]["multi_tx_candidate_tasks"], 1)
        self.assertEqual(
            [row.get("multi_tx_candidate") for row in payload["tasks"]],
            ["dup-seq"],
        )

    def test_missing_explicit_action_graph_is_degraded_not_silent(self) -> None:
        tool = _load_tool()
        (self.ws / ".auditooor" / "hacker_brief.md").write_text(
            "- Q-DET-cap: prove local cap bypass path\n",
            encoding="utf-8",
        )
        missing = self.ws / ".auditooor" / "missing_detector_action_graph.json"

        payload = tool.run(
            [
                "--workspace",
                str(self.ws),
                "--detector-action-graph",
                str(missing),
                "--generated-at",
                "2026-05-13T00:00:00Z",
            ]
        )

        self.assertEqual(payload["summary"]["task_count"], 1)
        self.assertEqual(payload["status"], "ready_degraded_missing_proof_sources")
        self.assertTrue(payload["degraded"])
        self.assertIn("<workspace>/.auditooor/missing_detector_action_graph.json", payload["missing_sources"])

    def test_sanitizes_explicit_out_of_workspace_paths_and_supports_fixed_generated_at(self) -> None:
        tool = _load_tool()
        with tempfile.TemporaryDirectory(prefix="proof-obligation-external-") as ext_tmp:
            ext_root = Path(ext_tmp)
            ext_json = ext_root / "hacker_brief.md.json"
            _write_json(
                ext_json,
                {
                    "sections": {
                        "sec13_question_list": {
                            "items": [
                                {
                                    "id": "Q-EXT-proof",
                                    "text": "Need proof from external artifact",
                                }
                            ]
                        }
                    }
                },
            )

            argv = [
                "--workspace",
                str(self.ws),
                "--hacker-brief-json",
                str(ext_json),
                "--generated-at",
                "2026-05-13T00:00:00Z",
            ]
            first = tool.run(argv)
            second = tool.run(argv)

        self.assertEqual(first, second)
        self.assertEqual(first["generated_at_utc"], "2026-05-13T00:00:00Z")
        self.assertEqual(first["context_pack_hash"], second["context_pack_hash"])
        self.assertEqual(first["sources"], ["<external-input>"])
        self.assertEqual(first["tasks"][0]["source_ref"], "<external-input>")

    def test_context_pack_hash_ignores_wall_clock_generated_at(self) -> None:
        tool = _load_tool()
        (self.ws / ".auditooor" / "hacker_brief.md").write_text(
            "- Q-AC-rust-nonce-reuse: prove nonce reuse with a local harness\n",
            encoding="utf-8",
        )

        first = tool.run(["--workspace", str(self.ws), "--generated-at", "2026-05-13T00:00:00Z"])
        second = tool.run(["--workspace", str(self.ws), "--generated-at", "2026-05-13T00:01:00Z"])

        self.assertNotEqual(first["generated_at_utc"], second["generated_at_utc"])
        self.assertEqual(first["context_pack_hash"], second["context_pack_hash"])

    def test_empty_workspace_is_explicitly_blocked_missing_sources(self) -> None:
        tool = _load_tool()

        payload = tool.run(["--workspace", str(self.ws), "--generated-at", "2026-05-13T00:00:00Z"])

        self.assertEqual(payload["summary"]["task_count"], 0)
        self.assertEqual(payload["status"], "blocked_missing_proof_sources")
        self.assertTrue(payload["blocked"])
        self.assertTrue(payload["degraded"])
        self.assertEqual(payload["sources"], [])
        self.assertIn("<workspace>/.auditooor/hacker_brief.md.json", payload["missing_sources"])
        self.assertIn("<workspace>/.auditooor/hacker_brief.md", payload["missing_sources"])
        self.assertIn("<workspace>/swarm/chained_attack_plans.json", payload["missing_sources"])

    def test_hacker_brief_without_chained_plans_is_degraded_not_silent_ready(self) -> None:
        tool = _load_tool()
        (self.ws / ".auditooor" / "hacker_brief.md").write_text(
            "- Q-DET-slippage: prove local slippage exploit path\n",
            encoding="utf-8",
        )

        payload = tool.run(["--workspace", str(self.ws), "--generated-at", "2026-05-13T00:00:00Z"])

        self.assertEqual(payload["summary"]["task_count"], 1)
        self.assertEqual(payload["status"], "ready_degraded_missing_proof_sources")
        self.assertFalse(payload["blocked"])
        self.assertTrue(payload["degraded"])
        self.assertIn("<workspace>/swarm/chained_attack_plans.json", payload["missing_sources"])

    def test_chained_plans_without_hacker_brief_is_degraded_not_silent_ready(self) -> None:
        tool = _load_tool()
        _write_json(
            self.ws / "swarm" / "chained_attack_plans.json",
            {
                "plans": [
                    {
                        "chain_id": "CHAIN-LOCAL-001",
                        "proof_steps": ["Build a local harness for the chained exploit hypothesis"],
                        "blockers": ["missing causal bridge proof"],
                    }
                ]
            },
        )

        payload = tool.run(["--workspace", str(self.ws), "--generated-at", "2026-05-13T00:00:00Z"])

        self.assertEqual(payload["summary"]["task_count"], 1)
        self.assertEqual(payload["status"], "ready_degraded_missing_proof_sources")
        self.assertFalse(payload["blocked"])
        self.assertTrue(payload["degraded"])
        self.assertIn("<workspace>/.auditooor/hacker_brief.md.json", payload["missing_sources"])
        self.assertIn("<workspace>/.auditooor/hacker_brief.md", payload["missing_sources"])


if __name__ == "__main__":
    unittest.main()
