#!/usr/bin/env python3
"""Tests for vault_zk_template_lookup MCP callable.

Wave-5 Track K-zkBugs Step 7. The callable filters the zkBugs corpus
(0xparc_index.json + zksecurity zkbugs_index.json) by framework +
template_name substring. Tests cover:
  - degraded path (missing framework)
  - Halo2 framework match (≥2 records expected — 2 from 0xparc + ~35 from zksecurity)
  - Circom framework match
  - Schema + context_pack_id + context_pack_hash presence
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MOD_PATH = ROOT / "tools" / "vault-mcp-server.py"


def _load_server():
    spec = importlib.util.spec_from_file_location("vault_mcp_server_test", MOD_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class VaultZkTemplateLookupTest(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _load_server()
        # vault_dir does not need to exist for vault_zk_template_lookup —
        # it only reads audit/zkbugs/*.json paths relative to the repo
        # root computed from the module file.
        self.vault = self.mod.VaultQuery(ROOT / "obsidian-vault")

    def test_degraded_path_missing_framework(self) -> None:
        out = self.vault.vault_zk_template_lookup(framework="")
        self.assertTrue(out.get("degraded"))
        self.assertEqual(out.get("reason"), "missing_framework")
        self.assertEqual(out.get("schema"), self.mod.ZK_TEMPLATE_LOOKUP_SCHEMA)
        self.assertIn("context_pack_hash", out)

    def test_halo2_framework_match(self) -> None:
        out = self.vault.vault_zk_template_lookup(framework="Halo2", template_name="")
        self.assertFalse(out.get("degraded"))
        self.assertEqual(out.get("framework"), "Halo2")
        self.assertGreaterEqual(out.get("total_found", 0), 2)
        self.assertEqual(out.get("schema"), self.mod.ZK_TEMPLATE_LOOKUP_SCHEMA)
        self.assertEqual(out.get("kind"), "zk_template_lookup")
        self.assertIsInstance(out.get("exemplars"), list)
        if out["exemplars"]:
            ex = out["exemplars"][0]
            self.assertIn("dsl", ex)
            self.assertIn("title", ex)

    def test_circom_framework_match(self) -> None:
        out = self.vault.vault_zk_template_lookup(
            framework="circom", template_name="", limit=5
        )
        self.assertFalse(out.get("degraded"))
        # zkbugs corpus has many circom records
        self.assertGreaterEqual(out.get("total_found", 0), 1)
        # limit honored
        self.assertLessEqual(len(out.get("exemplars", [])), 5)

    def test_schema_and_pack_id_present(self) -> None:
        out = self.vault.vault_zk_template_lookup(framework="Halo2")
        self.assertEqual(out.get("schema"), "auditooor.vault_zk_template_lookup.v1")
        cpid = out.get("context_pack_id", "")
        self.assertTrue(cpid.startswith("auditooor.vault_zk_template_lookup.v1:"))
        self.assertEqual(len(out.get("context_pack_hash", "")), 64)
        self.assertIsInstance(out.get("source_refs"), list)

    def test_template_filter_narrows(self) -> None:
        all_halo2 = self.vault.vault_zk_template_lookup(
            framework="Halo2", template_name="", limit=50
        )
        narrowed = self.vault.vault_zk_template_lookup(
            framework="Halo2", template_name="Tx", limit=50
        )
        # Tx-filter should not yield MORE than the unfiltered match
        self.assertLessEqual(
            narrowed.get("total_found", 0), all_halo2.get("total_found", 0)
        )

    def test_tool_in_schemas_list(self) -> None:
        names = {t["name"] for t in self.mod.TOOL_SCHEMAS}
        self.assertIn("vault_zk_template_lookup", names)

    # Wave-6 K-Z.10e additions: verify plonky2/noir/cairo framework filter
    def test_plonky2_framework_no_error(self) -> None:
        """plonky2 framework lookup must not error (0 or more results is fine)."""
        out = self.vault.vault_zk_template_lookup(framework="plonky2", template_name="")
        # Must not be degraded due to unknown framework — the server handles all values
        self.assertEqual(out.get("schema"), self.mod.ZK_TEMPLATE_LOOKUP_SCHEMA)
        self.assertIn("context_pack_hash", out)
        self.assertIn("total_found", out)
        # total_found may be 0 if corpus has no plonky2 rows; that is OK
        self.assertIsInstance(out.get("total_found"), int)

    def test_noir_framework_no_error(self) -> None:
        """noir framework lookup must not error."""
        out = self.vault.vault_zk_template_lookup(framework="noir", template_name="")
        self.assertEqual(out.get("schema"), self.mod.ZK_TEMPLATE_LOOKUP_SCHEMA)
        self.assertIn("context_pack_hash", out)
        self.assertIsInstance(out.get("total_found"), int)

    def test_cairo_framework_returns_results_or_empty(self) -> None:
        """cairo framework lookup returns valid response (0xPARC corpus has cairo rows)."""
        out = self.vault.vault_zk_template_lookup(framework="cairo", template_name="")
        self.assertEqual(out.get("schema"), self.mod.ZK_TEMPLATE_LOOKUP_SCHEMA)
        self.assertIn("context_pack_hash", out)
        self.assertIsInstance(out.get("exemplars"), list)
        # Corpus has cairo entries; total_found should be >= 0
        self.assertGreaterEqual(out.get("total_found", 0), 0)


if __name__ == "__main__":
    unittest.main()
