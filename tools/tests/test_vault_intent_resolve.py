"""Tests for vault_intent_resolve (SP-INTENT, W2 plan 09 §4).

Ten cases (T01..T10) covering the spec'd behaviors:
  T01: empty intent → degraded:true reason:"empty_intent"
  T02: "find frost nonce reuse" → routes include recall_exploit with score>0.5
  T03: "show me dupes for reentrancy" → top route = recall_dupe,
       recommended_callable = vault_dupe_rejection_context
  T04: "language patterns rust" → top route = recall_pattern,
       recommended = vault_language_patterns
  T05: synonym expansion: "chain watcher" → variants include "exit-txid"
  T06: top_k cap honored (request top_k=2 → returns 2)
  T07: top_k > 8 → clamped to 8
  T08: response envelope contains synonym_expansion field
  T09: response envelope contains context_pack_id matching schema
  T10: confidence_score is float in [0.0, 1.0]
"""

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module()


SYNONYM_FIXTURE = """\
schema_version: 1
schema: auditooor.vault_search_synonyms.v1
total_rows: 3

synonyms:

  - canonical: "chain watcher"
    expands_to:
      - chain-watcher
      - exit-txid
      - spark
    callable_hint: vault_exploit_context
    confidence_if_matched: high

  - canonical: "FROST"
    expands_to:
      - threshold-signing
      - schnorr
    callable_hint: vault_exploit_context
    confidence_if_matched: high

  - canonical: "nonce reuse"
    expands_to:
      - replay
      - signature-replay
    callable_hint: vault_exploit_context
    confidence_if_matched: high
"""


def _make_vault_with_synonyms(tmp_root: Path):
    (tmp_root / "obsidian-vault").mkdir(parents=True, exist_ok=True)
    (tmp_root / "reference").mkdir(parents=True, exist_ok=True)
    (tmp_root / "reference" / "vault_search_synonyms.yaml").write_text(
        SYNONYM_FIXTURE, encoding="utf-8"
    )
    # Reset the synonym cache so the per-test fixture takes effect.
    vault_mcp_server._SYNONYM_CACHE["path"] = None
    vault_mcp_server._SYNONYM_CACHE["mtime"] = None
    vault_mcp_server._SYNONYM_CACHE["map"] = None
    # Patch SEARCH_SYNONYMS_PATH to the fixture for this test.
    vault_mcp_server.SEARCH_SYNONYMS_PATH = (
        tmp_root / "reference" / "vault_search_synonyms.yaml"
    )
    return vault_mcp_server.VaultQuery(tmp_root / "obsidian-vault", tmp_root)


class TestVaultIntentResolve(unittest.TestCase):

    def setUp(self):
        # Save original synonyms path so we can restore it after each test.
        self._orig_path = vault_mcp_server.SEARCH_SYNONYMS_PATH
        self._orig_cache = dict(vault_mcp_server._SYNONYM_CACHE)
        self.tmp = tempfile.TemporaryDirectory(prefix="vir-")
        self.root = Path(self.tmp.name)
        self.vault = _make_vault_with_synonyms(self.root)

    def tearDown(self):
        vault_mcp_server.SEARCH_SYNONYMS_PATH = self._orig_path
        vault_mcp_server._SYNONYM_CACHE.clear()
        vault_mcp_server._SYNONYM_CACHE.update(self._orig_cache)
        self.tmp.cleanup()

    # T01
    def test_empty_intent_degraded(self):
        result = self.vault.vault_intent_resolve(intent="")
        self.assertTrue(result["degraded"])
        self.assertEqual(result.get("reason"), "empty_intent")
        # The envelope shape is still valid.
        self.assertIn("context_pack_id", result)
        self.assertIn("context_pack_hash", result)

    # T02
    def test_frost_nonce_reuse_routes_exploit(self):
        result = self.vault.vault_intent_resolve(
            intent="find frost nonce reuse"
        )
        self.assertFalse(result["degraded"])
        exploit_routes = [
            r for r in result["routes"] if r["route"] == "recall_exploit"
        ]
        self.assertGreaterEqual(
            len(exploit_routes), 1,
            f"recall_exploit should fire for 'find frost nonce reuse'; "
            f"got routes: {[r['route'] for r in result['routes']]}",
        )
        self.assertGreater(exploit_routes[0]["confidence_score"], 0.5)

    # T03
    def test_dupes_routes_dupe_rejection(self):
        result = self.vault.vault_intent_resolve(
            intent="show me dupes for reentrancy"
        )
        self.assertFalse(result["degraded"])
        top = result["top_recommendation"]
        self.assertEqual(top["route"], "recall_dupe")
        self.assertEqual(
            top["recommended_callable"], "vault_dupe_rejection_context"
        )

    # T04
    def test_language_patterns_routes_pattern(self):
        result = self.vault.vault_intent_resolve(
            intent="language patterns rust"
        )
        self.assertFalse(result["degraded"])
        top = result["top_recommendation"]
        self.assertEqual(top["route"], "recall_pattern")
        self.assertEqual(top["recommended_callable"], "vault_language_patterns")

    # T05
    def test_chain_watcher_synonym_expands_to_exit_txid(self):
        result = self.vault.vault_intent_resolve(intent="chain watcher")
        variants = result["synonym_expansion"]["variants"]
        # "exit-txid" is one of the synonym substitutions per the fixture.
        self.assertIn("exit-txid", variants)
        self.assertIn("chain watcher", result["synonym_expansion"]["matched_canonicals"])

    # T06
    def test_top_k_cap_two(self):
        result = self.vault.vault_intent_resolve(
            intent="show me dupes for reentrancy", top_k=2
        )
        self.assertLessEqual(len(result["routes"]), 2)
        self.assertEqual(result["top_k"], 2)

    # T07
    def test_top_k_clamped_to_eight(self):
        result = self.vault.vault_intent_resolve(
            intent="find finding exploit dupe pattern", top_k=99
        )
        # top_k clamped to 8 in the envelope
        self.assertLessEqual(result["top_k"], 8)
        self.assertEqual(result["top_k"], vault_mcp_server.MAX_INTENT_TOP_K)
        self.assertLessEqual(len(result["routes"]), 8)

    # T08
    def test_envelope_contains_synonym_expansion(self):
        result = self.vault.vault_intent_resolve(intent="frost signing")
        self.assertIn("synonym_expansion", result)
        self.assertIn("variants", result["synonym_expansion"])
        self.assertIn("matched_canonicals", result["synonym_expansion"])

    # T09
    def test_context_pack_id_schema(self):
        result = self.vault.vault_intent_resolve(intent="reentrancy bypass")
        pack_id = result["context_pack_id"]
        self.assertTrue(
            pack_id.startswith("auditooor.vault_intent_resolve.v1:"),
            f"context_pack_id should start with the v1 schema prefix; got: {pack_id}",
        )
        # hash is 64 hex chars; pack_id suffix is the first 16
        self.assertEqual(len(result["context_pack_hash"]), 64)
        suffix = pack_id.split(":", 1)[1]
        self.assertEqual(len(suffix), 16)

    # T10
    def test_confidence_score_in_unit_interval(self):
        result = self.vault.vault_intent_resolve(
            intent="exploit attack vector reentrancy nonce reuse"
        )
        for route in result["routes"]:
            score = route["confidence_score"]
            self.assertIsInstance(score, float)
            self.assertGreaterEqual(score, 0.0)
            self.assertLessEqual(score, 1.0)


if __name__ == "__main__":
    unittest.main()
