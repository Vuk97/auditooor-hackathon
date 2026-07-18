from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from types import SimpleNamespace


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_vault_mcp():
    spec = importlib.util.spec_from_file_location("vault_mcp_server_detector_action_graph", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class _FakeOversizedActionGraphResolver:
    """Resolver stub that returns more rows than the MCP wrapper should expose."""

    class _Parser:
        def parse_args(self, argv: list[str]) -> SimpleNamespace:
            return SimpleNamespace(argv=argv)

    @staticmethod
    def build_parser() -> "_FakeOversizedActionGraphResolver._Parser":
        return _FakeOversizedActionGraphResolver._Parser()

    @staticmethod
    def build_payload(_args: SimpleNamespace) -> dict:
        ranked = [
            {
                "attack_class": f"attack-class-{idx:02d}",
                "score": 100 - idx,
                "confidence": "high",
            }
            for idx in range(10)
        ]
        nodes = [
            {
                "id": f"N-{idx:03d}",
                "kind": "attacker_step",
                "title": f"oversized node {idx}",
            }
            for idx in range(40)
        ]
        edges = [
            {"from": f"N-{idx:03d}", "to": f"N-{idx + 1:03d}", "relation": "next"}
            for idx in range(39)
        ]
        return {
            "schema": "auditooor.detector_hit_action_graph.v1",
            "context_pack_id": "auditooor.detector_hit_action_graph.v1:detector_hit_action_graph:fake",
            "context_pack_hash": "f" * 64,
            "claim_scope": "attacker_worklist_only",
            "submission_posture": "NOT_SUBMIT_READY",
            "proof_boundary": "fake resolver boundary",
            "detector_hit": {
                "detector_slug": "oversized-detector",
                "file_path": "src/Oversized.sol:7",
                "source_ref": "cli",
            },
            "ranked_attack_classes": ranked,
            "action_graph": {"nodes": nodes, "edges": edges},
            "chain_candidates": [
                {
                    "chain_id": f"CHAIN-{idx:03d}",
                    "status": "candidate_not_submit_ready",
                    "score": 100 - idx,
                    "source_refs": [f"workspace:src/Oversized.sol:{idx}"],
                }
                for idx in range(20)
            ],
            "proof_obligations": [
                {
                    "id": f"P-{idx:03d}",
                    "kind": "source_confirmation",
                    "title": f"oversized proof obligation {idx}",
                    "status": "open",
                }
                for idx in range(25)
            ],
            "summary": {
                "ranked_attack_class_count": len(ranked),
                "action_node_count": len(nodes),
                "proof_obligation_count": 25,
                "chain_candidate_count": 20,
            },
            "limitations": ["fake oversized payload"],
        }


class VaultDetectorActionGraphContextTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="vault-detector-action-graph-")
        self.base = Path(self.tmp.name)
        self.repo = self.base / "repo"
        self.vault_dir = self.base / "vault"
        self.ws = self.base / "workspace"
        self.vault_dir.mkdir()
        self.ws.mkdir()
        _write(
            self.repo / "reference" / "patterns.dsl" / "reentrancy-no-guard.yaml",
            textwrap.dedent(
                """
                pattern: reentrancy-no-guard
                source: unit-test
                severity: HIGH
                confidence: HIGH
                help: "withdraw sends value through an external callback before a reentrancy lock is set; reentrant hook can call withdraw again."
                match:
                  - function.name_matches: '(?i)withdraw'
                  - function.body_contains_regex: 'call'
                """
            ).strip()
            + "\n",
        )
        _write_json(
            self.ws / "engage_report.json",
            {
                "schema": "auditooor.engage_report.sidecar.v1",
                "clusters": [
                    {
                        "detector_slug": "reentrancy-no-guard",
                        "hit_count": 1,
                        "hits": [
                            {
                                "severity": "HIGH",
                                "file_path": str(self.ws / "src" / "Vault.sol") + ":42",
                                "snippet": "withdraw callback path sends value before reentrancy lock update",
                            }
                        ],
                    }
                ],
            },
        )
        _write_json(
            self.ws / "swarm" / "chained_attack_plans.json",
            {
                "plans": [
                    {
                        "chain_id": "CHAIN-001",
                        "status": "candidate_not_submit_ready",
                        "score": 9,
                        "composition_rationale": "reentrancy-no-guard composes with stale share accounting",
                        "blockers": ["source proof missing"],
                        "source_refs": ["workspace:src/Vault.sol:42"],
                        "candidate_not_submit_ready": True,
                    }
                ]
            },
        )
        self.vault_mcp = _load_vault_mcp()
        self.vault = self.vault_mcp.VaultQuery(self.vault_dir, repo_root=self.repo)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_happy_path_wraps_advisory_action_graph_without_local_paths(self) -> None:
        result = self.vault.vault_detector_action_graph_context(
            workspace_path=str(self.ws),
            detector_slug="reentrancy_no_guard",
            language="solidity",
            function_name="withdraw",
            top_n=2,
        )

        self.assertEqual(result["schema"], self.vault_mcp.DETECTOR_ACTION_GRAPH_CONTEXT_SCHEMA)
        self.assertEqual(result["resolver_schema"], "auditooor.detector_hit_action_graph.v1")
        self.assertFalse(result["degraded"])
        self.assertTrue(result["advisory_only"])
        self.assertEqual(result["submission_posture"], "NOT_SUBMIT_READY")
        self.assertEqual(result["detector_hit"]["detector_slug"], "reentrancy-no-guard")
        self.assertEqual(result["detector_hit"]["file_path"], "src/Vault.sol:42")
        self.assertEqual(result["ranked_attack_classes"][0]["attack_class"], "reentrancy")
        self.assertEqual(result["hacker_question_schema"], "auditooor.hacker_question.v1")
        self.assertGreaterEqual(result["summary"]["hacker_question_count"], 1)
        self.assertEqual(result["hacker_questions"][0]["schema"], "auditooor.hacker_question.v1")
        self.assertEqual(result["hacker_questions"][0]["detector_slug"], "reentrancy-no-guard")
        self.assertIn("proof_obligation", result["hacker_questions"][0])
        self.assertIn("kill_condition", result["hacker_questions"][0])
        self.assertGreaterEqual(result["summary"]["proof_obligation_count"], 4)
        self.assertEqual(result["summary"]["chain_candidate_count"], 1)
        self.assertTrue(result["context_pack_id"].startswith(result["schema"]))
        self.assertEqual(result["freshness"]["chained_attack_plans"]["status"], "fresh")
        self.assertTrue(result["freshness"]["chained_attack_plans"]["safe_to_treat_as_current"])
        self.assertEqual(result["chain_candidates"][0]["artifact_freshness_status"], "fresh")
        self.assertFalse(result["chain_candidates"][0]["derived_from_stale_artifact"])
        self.assertTrue(result["chain_candidates"][0]["safe_to_treat_as_current"])

        payload = json.dumps(result, sort_keys=True)
        self.assertNotIn(str(self.base), payload)
        self.assertNotIn("/private/", payload)
        self.assertNotIn("/Users/", payload)
        self.assertNotEqual(result["submission_posture"], "SUBMIT_READY")

    def test_external_analogue_refs_reach_proof_obligations(self) -> None:
        _write(
            self.repo / "reference" / "patterns.dsl.r94_solodit_rust" / "hook-reentrancy-analogue.yaml",
            textwrap.dedent(
                """
                id: hook-reentrancy-analogue
                title: "External hook can reenter before accounting is finalized"
                severity: High
                language: rust
                bug_class: reentrancy
                real_world_example: |
                  A callback hook reenters withdraw while accounting is still stale.
                """
            ).strip()
            + "\n",
        )

        result = self.vault.vault_detector_action_graph_context(
            workspace_path=str(self.ws),
            detector_slug="reentrancy-no-guard",
            language="solidity",
            function_name="withdraw",
            top_n=2,
        )

        top = result["ranked_attack_classes"][0]
        self.assertIn("analogue_refs", top)
        self.assertTrue(any(ref["source_kind"] == "external_corpus:rust" for ref in top["analogue_refs"]))
        analogue_obligations = [
            row for row in result["proof_obligations"] if row["kind"] == "corpus_analogue_review"
        ]
        self.assertTrue(
            any(
                any("hook-reentrancy-analogue" in source_ref for source_ref in obligation["source_refs"])
                for obligation in analogue_obligations
            )
        )

    def test_case_study_analogue_refs_reach_proof_obligations(self) -> None:
        _write(
            self.repo / "case_study" / "reentrancy_hook_case.md",
            textwrap.dedent(
                """
                ---
                case_id: reentrancy-hook-case
                mechanism: external hook reenters before stale accounting is finalized
                class: reentrancy
                severity_class: HIGH
                applicable_workspace_classes:
                  - vault
                grep_predicates:
                  - "withdraw|callback|hook"
                extracted_lesson: >
                  Treat callback-capable token or vault hooks as attacker-controlled reentry points
                  until accounting is finalized and a guard is active.
                ---
                # Case Study
                """
            ).strip()
            + "\n",
        )

        result = self.vault.vault_detector_action_graph_context(
            workspace_path=str(self.ws),
            detector_slug="reentrancy-no-guard",
            language="solidity",
            function_name="withdraw",
            top_n=2,
        )

        top = result["ranked_attack_classes"][0]
        self.assertTrue(any(ref["source_kind"] == "external_corpus:case-study" for ref in top["analogue_refs"]))
        analogue_obligations = [
            row for row in result["proof_obligations"] if row["kind"] == "corpus_analogue_review"
        ]
        self.assertTrue(
            any(
                any("reentrancy_hook_case" in source_ref for source_ref in obligation["source_refs"])
                for obligation in analogue_obligations
            )
        )

    def test_call_dispatch_and_list_schema_are_registered(self) -> None:
        listed = self.vault_mcp.handle_request(
            self.vault,
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        by_name = {tool["name"]: tool for tool in listed["result"]["tools"]}
        self.assertIn("vault_detector_action_graph_context", by_name)
        props = by_name["vault_detector_action_graph_context"]["inputSchema"]["properties"]
        self.assertIn("workspace_path", props)
        self.assertIn("detector_slug", props)
        self.assertIn("top_n", props)

        response = self.vault_mcp.handle_request(
            self.vault,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "vault_detector_action_graph_context",
                    "arguments": {
                        "workspace_path": str(self.ws),
                        "detector_slug": "reentrancy-no-guard",
                    },
                },
            },
        )
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertEqual(payload["kind"], "detector_action_graph_context")
        self.assertEqual(payload["detector_hit"]["file_path"], "src/Vault.sol:42")

    def test_context_pack_hash_is_deterministic(self) -> None:
        first = self.vault.vault_detector_action_graph_context(
            workspace_path=str(self.ws),
            detector_slug="reentrancy-no-guard",
        )
        second = self.vault.vault_detector_action_graph_context(
            workspace_path=str(self.ws),
            detector_slug="reentrancy-no-guard",
        )

        self.assertEqual(first["context_pack_hash"], second["context_pack_hash"])
        self.assertEqual(first["context_pack_id"], second["context_pack_id"])

    def test_warns_when_returned_chain_candidates_are_older_than_engage_report(self) -> None:
        chained_plans = self.ws / "swarm" / "chained_attack_plans.json"
        engage_report = self.ws / "engage_report.json"
        os.utime(chained_plans, (1_700_000_000, 1_700_000_000))
        os.utime(engage_report, (1_700_000_300, 1_700_000_300))

        result = self.vault.vault_detector_action_graph_context(
            workspace_path=str(self.ws),
            detector_slug="reentrancy-no-guard",
            language="solidity",
            function_name="withdraw",
            top_n=2,
        )

        self.assertEqual(result["summary"]["chain_candidate_count"], 1)
        self.assertEqual(result["chain_candidates"][0]["chain_id"], "CHAIN-001")
        freshness = result["freshness"]["chained_attack_plans"]
        self.assertEqual(freshness["status"], "stale")
        self.assertEqual(freshness["reason"], "chained_attack_plans_older_than_engage_report")
        self.assertEqual(freshness["freshness_basis"], "mtime_vs_engage_report")
        self.assertFalse(freshness["safe_to_treat_as_current"])
        self.assertIn("chain_plan_mtime_utc", freshness)
        self.assertIn("engage_report_mtime_utc", freshness)
        self.assertEqual(result["chain_candidates"][0]["artifact_freshness_status"], "stale")
        self.assertTrue(result["chain_candidates"][0]["derived_from_stale_artifact"])
        self.assertFalse(result["chain_candidates"][0]["safe_to_treat_as_current"])
        stale_limitations = [
            limitation
            for limitation in result["limitations"]
            if "stale" in limitation.lower()
            and "chained_attack_plans.json" in limitation
            and "engage_report.json" in limitation
        ]
        self.assertTrue(stale_limitations)

    def test_missing_selector_degrades_without_crashing(self) -> None:
        result = self.vault.vault_detector_action_graph_context()

        self.assertTrue(result["degraded"])
        self.assertEqual(result["error"], "missing_selector")
        self.assertEqual(result["submission_posture"], "NOT_SUBMIT_READY")
        self.assertTrue(result["context_pack_id"].startswith(result["schema"]))

    def test_private_file_path_without_workspace_is_rejected(self) -> None:
        result = self.vault.vault_detector_action_graph_context(
            detector_slug="reentrancy-no-guard",
            file_path=str(self.ws / "src" / "Vault.sol"),
        )

        self.assertTrue(result["degraded"])
        self.assertEqual(result["error"], "workspace_path_required_for_private_file_path")
        self.assertNotIn(str(self.ws), json.dumps(result, sort_keys=True))

    def test_oversized_resolver_payload_reports_wrapper_limits(self) -> None:
        original_loader = self.vault_mcp._load_tool_module
        self.vault_mcp._load_tool_module = (
            lambda name: _FakeOversizedActionGraphResolver
            if name == "detector-hit-action-graph"
            else original_loader(name)
        )
        try:
            result = self.vault.vault_detector_action_graph_context(
                detector_slug="oversized-detector",
                file_path="src/Oversized.sol:7",
                top_n=2,
            )
        finally:
            self.vault_mcp._load_tool_module = original_loader

        self.assertEqual(result["schema"], self.vault_mcp.DETECTOR_ACTION_GRAPH_CONTEXT_SCHEMA)
        self.assertFalse(result["degraded"])
        self.assertIn("limits", result)
        self.assertEqual(result["limits"]["max_ranked_attack_classes"], 2)
        self.assertEqual(
            result["limits"]["max_chain_candidates"],
            self.vault_mcp.MAX_DETECTOR_ACTION_GRAPH_TOP_N,
        )
        self.assertEqual(result["limits"]["max_action_graph_nodes"], self.vault_mcp.MAX_CONTEXT_ITEMS)
        self.assertEqual(result["limits"]["max_proof_obligations"], self.vault_mcp.MAX_CONTEXT_ITEMS)

    def test_oversized_resolver_payload_is_bounded_by_wrapper(self) -> None:
        original_loader = self.vault_mcp._load_tool_module
        self.vault_mcp._load_tool_module = (
            lambda name: _FakeOversizedActionGraphResolver
            if name == "detector-hit-action-graph"
            else original_loader(name)
        )
        try:
            result = self.vault.vault_detector_action_graph_context(
                detector_slug="oversized-detector",
                file_path="src/Oversized.sol:7",
                top_n=2,
            )
        finally:
            self.vault_mcp._load_tool_module = original_loader

        self.assertEqual(
            [row["attack_class"] for row in result["ranked_attack_classes"]],
            ["attack-class-00", "attack-class-01"],
        )
        self.assertLessEqual(
            len(result["chain_candidates"]),
            self.vault_mcp.MAX_DETECTOR_ACTION_GRAPH_TOP_N,
        )
        self.assertLessEqual(
            len(result["action_graph"]["nodes"]),
            self.vault_mcp.MAX_CONTEXT_ITEMS,
        )
        self.assertLessEqual(
            len(result["action_graph"]["edges"]),
            self.vault_mcp.MAX_CONTEXT_ITEMS,
        )
        self.assertLessEqual(
            len(result["proof_obligations"]),
            self.vault_mcp.MAX_CONTEXT_ITEMS,
        )
        self.assertEqual(result["summary"]["ranked_attack_class_count"], 2)
        self.assertEqual(
            result["summary"]["chain_candidate_count"],
            len(result["chain_candidates"]),
        )


if __name__ == "__main__":
    unittest.main()
