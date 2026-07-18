from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_vault_mcp():
    spec = importlib.util.spec_from_file_location("vault_mcp_server_causal_chain", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


class VaultCausalChainLookupTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="vault-causal-chain-")
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.vault_dir = self.root / "vault"
        self.repo.mkdir()
        self.vault_dir.mkdir()
        self.chains_path = self.repo / "audit" / "corpus_tags" / "derived" / "causal_chains.jsonl"
        self.index_path = self.repo / "audit" / "corpus_tags" / "derived" / "causal_chain_index.json"
        self.hyperbridge_workspace = self.root / "hyperbridge"
        self.spark_workspace = self.root / "spark"
        self.dydx_workspace = self.root / "dydx"
        self.rows = [
            {
                "schema_version": "auditooor.causal_chain.v1",
                "chain_id": "chain:withdraw-001",
                "source_record_id": "audit:demo:withdraw-001",
                "source_refs": ["audit/corpus_tags/tags/demo/withdraw.yaml"],
                "preconditions": ["Victim has shares", "Public withdrawFor entrypoint"],
                "trigger": "Attacker calls withdrawFor(victim) without authorization",
                "defense": "Patch by binding msg.sender to owner or approved operator",
                "impact": [{"impact_class": "fund-loss", "severity_at_finding": "high"}],
                "verification_tier": "tier-2-verified-public-archive",
                "attack_class": "unauthorized-withdrawal",
                "bug_class": "access-control",
                "target_domain": "vault",
                "target_language": "solidity",
                "requires_state": ["state:victim-balance-positive"],
                "produces_state": ["state:protocol-funds-displaced"],
            },
            {
                "schema_version": "auditooor.causal_chain.v1",
                "chain_id": "chain:oracle-002",
                "source_record_id": "audit:demo:oracle-002",
                "source_refs": ["audit/corpus_tags/tags/demo/oracle.yaml"],
                "preconditions": ["Oracle price is stale"],
                "trigger": "Attacker liquidates against stale price",
                "defense": "Reject stale oracle rounds",
                "impact": [{"impact_class": "fund-loss", "severity_at_finding": "medium"}],
                "verification_tier": "public-corpus",
                "attack_class": "oracle-staleness",
                "bug_class": "oracle",
                "target_domain": "lending",
                "target_language": "solidity",
            },
        ]
        _write_jsonl(self.chains_path, self.rows)
        _write_json(
            self.index_path,
            {
                "schema": "auditooor.causal_chain_index.v1",
                "schema_version": "auditooor.causal_chain.v1.index",
                "row_count": 2,
                "quality_gate": {
                    "profile": "canonical",
                    "met": True,
                    "accepted_rows": 2,
                    "target_records": 1,
                    "requirements": [
                        "verification_tier != unknown",
                        "preconditions non-empty",
                        "preconditions exclude placeholder tbd/todo",
                        "defense must not be fallback/placeholder",
                    ],
                },
            },
        )
        _write_jsonl(
            self.repo / "audit" / "corpus_tags" / "hyperbridge" / "invariants_extracted.jsonl",
            [
                {
                    "schema_version": "auditooor.invariant_candidate.v1",
                    "invariant_id": "INV-HYPERBRIDGE-001",
                    "statement": "Hyperbridge finality and timeout checks must gate relay acceptance.",
                    "attack_signature": "bridge-finality|timeout|hyperbridge",
                    "source_finding_ids": ["prior-audit:hyperbridge:receipt-timeout"],
                    "target_lang": "rust",
                }
            ],
        )
        _write_jsonl(
            self.repo / "audit" / "corpus_tags" / "spark" / "invariants_extracted.jsonl",
            [
                {
                    "schema_version": "auditooor.invariant_candidate.v1",
                    "invariant_id": "INV-SPARK-GOV-001",
                    "statement": "Spark governance proposal authority must require explicit role checks.",
                    "attack_signature": "governance|proposal|authority|spark",
                    "source_finding_ids": ["prior-audit:spark:governance-authority"],
                    "target_lang": "rust",
                }
            ],
        )
        _write_jsonl(
            self.repo / "audit" / "corpus_tags" / "dydx" / "invariants_extracted.jsonl",
            [
                {
                    "schema_version": "auditooor.invariant_candidate.v1",
                    "invariant_id": "INV-DYDX-ORACLE-001",
                    "statement": "dydx settlement must reject stale oracle prices before liquidation.",
                    "attack_signature": "oracle|settlement|liquidation|dydx",
                    "source_finding_ids": ["prior-audit:dydx:settlement-vs-oracle"],
                    "target_lang": "go",
                }
            ],
        )
        self.hyperbridge_workspace.mkdir()
        self.spark_workspace.mkdir()
        self.dydx_workspace.mkdir()
        self.vault_mcp = _load_vault_mcp()
        self.vault = self.vault_mcp.VaultQuery(self.vault_dir, repo_root=self.repo)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_lookup_filters_by_chain_id_and_returns_quality_gate(self) -> None:
        result = self.vault.vault_causal_chain_lookup(chain_id="chain:withdraw-001", limit=5)

        self.assertEqual(result["schema"], self.vault_mcp.CAUSAL_CHAIN_LOOKUP_SCHEMA)
        self.assertFalse(result["degraded"], result.get("degraded_reason"))
        self.assertEqual(result["summary"]["total_records_available"], 9)
        self.assertEqual(result["summary"]["matching_records"], 1)
        self.assertEqual(result["summary"]["quality_gate_profile"], "canonical")
        self.assertTrue(result["summary"]["quality_gate_met"])
        self.assertEqual(result["chains"][0]["chain_id"], "chain:withdraw-001")
        self.assertIn("withdrawFor", result["chains"][0]["trigger"])

    def test_prefix_match_scores_trigger_and_state_tokens(self) -> None:
        result = self.vault.vault_chain_prefix_match(prefix="withdrawFor", target_domain="vault", limit=5)

        self.assertEqual(result["schema"], self.vault_mcp.CHAIN_PREFIX_MATCH_SCHEMA)
        self.assertFalse(result["degraded"], result.get("degraded_reason"))
        self.assertEqual(result["summary"]["matching_records"], 1)
        self.assertEqual(result["prefix_matches"][0]["chain_id"], "chain:withdraw-001")
        self.assertIn("trigger", result["prefix_matches"][0]["matched_fields"])
        self.assertGreater(result["prefix_matches"][0]["match_score"], 0)

    def test_lookup_surfaces_phase_d_template_chains(self) -> None:
        result = self.vault.vault_causal_chain_lookup(limit=20)
        chain_ids = {row["chain_id"] for row in result["chains"]}
        self.assertIn("template:bridge-finality", chain_ids)
        self.assertIn("template:settlement-vs-oracle", chain_ids)
        self.assertIn("template:liquidation-cascade", chain_ids)
        self.assertIn("template:governance-takeover", chain_ids)
        self.assertIn("template:dex-liquidation-cascade", chain_ids)
        self.assertIn("template:lending-oracle-drift", chain_ids)
        self.assertIn("template:governance-vote-dilution", chain_ids)

    def test_default_lookup_prioritizes_phase_d_template_chains(self) -> None:
        result = self.vault.vault_causal_chain_lookup(limit=4)
        self.assertEqual(
            [row["chain_id"] for row in result["chains"]],
            [
                "template:bridge-finality",
                "template:settlement-vs-oracle",
                "template:liquidation-cascade",
                "template:governance-takeover",
            ],
        )

    def test_prefix_match_includes_bridge_finality_template(self) -> None:
        result = self.vault.vault_chain_prefix_match(prefix="bridge finality", target_domain="bridge", limit=5)
        self.assertFalse(result["degraded"], result.get("degraded_reason"))
        self.assertGreaterEqual(result["summary"]["matching_records"], 1)
        self.assertEqual(result["prefix_matches"][0]["chain_id"], "template:bridge-finality")

    def test_non_bridge_template_lookup_and_prefix_matches(self) -> None:
        checks = (
            ("template:dex-liquidation-cascade", "dex", "dex liquidation cascade"),
            ("template:lending-oracle-drift", "lending", "lending oracle drift"),
            ("template:governance-vote-dilution", "governance", "governance vote dilution"),
        )
        for chain_id, domain, prefix in checks:
            lookup = self.vault.vault_causal_chain_lookup(chain_id=chain_id, limit=1)
            self.assertFalse(lookup["degraded"], lookup.get("degraded_reason"))
            self.assertEqual(lookup["summary"]["matching_records"], 1)
            self.assertEqual(lookup["chains"][0]["chain_id"], chain_id)
            self.assertEqual(lookup["chains"][0]["target_domain"], domain)

            prefix_result = self.vault.vault_chain_prefix_match(prefix=prefix, target_domain=domain, limit=3)
            self.assertFalse(prefix_result["degraded"], prefix_result.get("degraded_reason"))
            self.assertGreaterEqual(prefix_result["summary"]["matching_records"], 1)
            self.assertEqual(prefix_result["prefix_matches"][0]["chain_id"], chain_id)
            self.assertIn("trigger", prefix_result["prefix_matches"][0]["matched_fields"])

    def test_workspace_specific_template_anchor_selection(self) -> None:
        hyperbridge = self.vault.vault_causal_chain_lookup(
            chain_id="template:bridge-finality",
            workspace_path=str(self.hyperbridge_workspace),
            limit=1,
        )
        spark = self.vault.vault_causal_chain_lookup(
            chain_id="template:governance-takeover",
            workspace_path=str(self.spark_workspace),
            limit=1,
        )
        dydx = self.vault.vault_causal_chain_lookup(
            chain_id="template:settlement-vs-oracle",
            workspace_path=str(self.dydx_workspace),
            limit=1,
        )

        self.assertIn("INV-HYPERBRIDGE-001", hyperbridge["chains"][0]["source_record_id"])
        self.assertIn("audit/corpus_tags/hyperbridge/invariants_extracted.jsonl:", hyperbridge["chains"][0]["source_refs"][0])
        self.assertIn("INV-SPARK-GOV-001", spark["chains"][0]["source_record_id"])
        self.assertIn("audit/corpus_tags/spark/invariants_extracted.jsonl:", spark["chains"][0]["source_refs"][0])
        self.assertIn("INV-DYDX-ORACLE-001", dydx["chains"][0]["source_record_id"])
        self.assertIn("audit/corpus_tags/dydx/invariants_extracted.jsonl:", dydx["chains"][0]["source_refs"][0])

    def test_repo_local_anchor_fallback_covers_external_workspace_slug(self) -> None:
        _write_jsonl(
            self.repo / "audit" / "corpus_tags" / self.repo.name / "invariants_extracted.jsonl",
            [
                {
                    "schema_version": "auditooor.invariant_candidate.v1",
                    "invariant_id": "INV-REPO-HYPERBRIDGE-LOCAL",
                    "statement": "Hyperbridge bridge finality timeout checks are repo-local.",
                    "attack_signature": "bridge-finality|timeout|hyperbridge",
                    "source_finding_ids": ["prior-audit:hyperbridge:repo-local-finality"],
                    "target_lang": "rust",
                }
            ],
        )
        external_workspace = self.root / "external-hyperbridge"
        external_workspace.mkdir()

        result = self.vault.vault_causal_chain_lookup(
            chain_id="template:bridge-finality",
            workspace_path=str(external_workspace),
            limit=1,
        )

        self.assertIn("INV-REPO-HYPERBRIDGE-LOCAL", result["chains"][0]["source_record_id"])
        self.assertIn(
            "audit/corpus_tags/repo/invariants_extracted.jsonl:",
            result["chains"][0]["source_refs"][0],
        )

    def test_tools_list_and_call_register_phase_d_callables(self) -> None:
        listed = self.vault_mcp.handle_request(
            self.vault,
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        )
        by_name = {tool["name"]: tool for tool in listed["result"]["tools"]}
        self.assertIn("vault_causal_chain_lookup", by_name)
        self.assertIn("vault_chain_prefix_match", by_name)
        self.assertIn("chain_id", by_name["vault_causal_chain_lookup"]["inputSchema"]["properties"])
        self.assertIn("prefix", by_name["vault_chain_prefix_match"]["inputSchema"]["properties"])

        response = self.vault_mcp.handle_request(
            self.vault,
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "vault_chain_prefix_match",
                    "arguments": {"prefix": "stale price", "limit": 1},
                },
            },
        )
        payload = json.loads(response["result"]["content"][0]["text"])
        self.assertEqual(payload["schema"], self.vault_mcp.CHAIN_PREFIX_MATCH_SCHEMA)
        self.assertEqual(payload["prefix_matches"][0]["chain_id"], "chain:oracle-002")


if __name__ == "__main__":
    unittest.main()
