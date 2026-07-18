"""Tests for vault_route SPARK_DOMAIN_KEYWORDS routing (FIX-PASS Gap 4).

Verifies:
  1. SPARK_DOMAIN_KEYWORDS constant exists at module level.
  2. Spark-domain task_keywords (frost, coop_exit, permafreeze) route to
     vault_exploit_context — not the default vault_resume_context.
  3. Harness-domain task_keywords (regtest, halmos) route to
     vault_harness_context.
  4. Empty / unrelated keywords still default to vault_resume_context.
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


class TestVaultRouteSparkKeywords(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="vroute-spark-")
        self.root = Path(self.tmp.name)
        (self.root / "obsidian-vault").mkdir(parents=True)
        self.vault = vault_mcp_server.VaultQuery(
            self.root / "obsidian-vault", self.root
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_spark_domain_keywords_constant_exists(self):
        self.assertTrue(hasattr(vault_mcp_server, "SPARK_DOMAIN_KEYWORDS"))
        spark_kw = vault_mcp_server.SPARK_DOMAIN_KEYWORDS
        self.assertIn("vault_exploit_context", spark_kw)
        # Spot-check that a few canonical Spark terms are present.
        exploit_set = set(spark_kw["vault_exploit_context"])
        for term in ("frost", "coop_exit", "chain_watcher", "permafreeze"):
            self.assertIn(term, exploit_set, f"missing {term!r} in SPARK_DOMAIN_KEYWORDS")

    def test_spark_keywords_route_to_exploit(self):
        result = self.vault.vault_route(
            task_keywords=["frost", "coop_exit", "permafreeze"]
        )
        self.assertEqual(
            result.get("routed_pack"),
            "vault_exploit_context",
            f"expected vault_exploit_context, got {result.get('routed_pack')} — "
            f"reasoning: {result.get('reasoning')!r}",
        )

    def test_harness_keywords_route_to_harness(self):
        result = self.vault.vault_route(task_keywords=["regtest", "halmos"])
        self.assertEqual(result.get("routed_pack"), "vault_harness_context")

    def test_default_pack_for_unrelated(self):
        # Unrelated keywords still default to resume.
        result = self.vault.vault_route(task_keywords=["unrelated_garbage_term"])
        self.assertEqual(result.get("routed_pack"), "vault_resume_context")


if __name__ == "__main__":
    unittest.main()
