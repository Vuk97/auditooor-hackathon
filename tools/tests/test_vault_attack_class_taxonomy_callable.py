"""Tests for the ``vault_attack_class_taxonomy`` MCP callable.

Wave-1 hackerman capability lift (PR #726). Exercises:

- envelope shape (schema / context_pack_id / context_pack_hash);
- inventory-missing degrade path;
- inventory-malformed degrade path;
- min_records filter;
- min_tier_coverage_pct filter;
- limit clamping;
- ``<missing-attack-class>`` skipped;
- orphan / well-covered classifier consistency with the underlying tool;
- dispatch routing (call via the ``call_tool`` entrypoint).
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "vault_mcp_server_taxonomy_test", MODULE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module()


def _synthetic_inventory() -> dict[str, Any]:
    """Inventory with three classes representative of the corpus shapes."""
    return {
        "schema": "auditooor.hackerman_attack_class_taxonomy.v1",
        "tags_dir": "/synthetic/tags",
        "total_records": 71,
        "subtrees": ["a", "b", "c", "d"],
        "classes": [
            {
                "attack_class": "reentrancy",
                "total_records": 60,
                "subtrees": ["a", "b", "c"],
                "tier_counts": {"tier-1": 38, "tier-2": 20, "tier-3": 2},
                "tier1_count": 38,
                "tier2_count": 20,
                "tier12_count": 58,
                "tier12_pct": 96.67,
            },
            {
                "attack_class": "unconstrained-variable",
                "total_records": 10,
                "subtrees": ["d"],
                "tier_counts": {"tier-3": 5, "tier-5": 3, "no-tier": 2},
                "tier1_count": 0,
                "tier2_count": 0,
                "tier12_count": 0,
                "tier12_pct": 0.0,
            },
            {
                "attack_class": "<missing-attack-class>",
                "total_records": 1,
                "subtrees": ["a"],
                "tier_counts": {"tier-1": 1},
                "tier1_count": 1,
                "tier2_count": 0,
                "tier12_count": 1,
                "tier12_pct": 100.0,
            },
        ],
        "per_subtree": {
            "a": {"total_records": 30, "distinct_classes": 2, "tier_counts": {"tier-1": 28, "tier-2": 0}, "tier1_count": 28, "tier2_count": 0, "tier12_count": 28, "tier12_pct": 93.33},
            "b": {"total_records": 20, "distinct_classes": 1, "tier_counts": {"tier-2": 20}, "tier1_count": 0, "tier2_count": 20, "tier12_count": 20, "tier12_pct": 100.0},
            "c": {"total_records": 11, "distinct_classes": 1, "tier_counts": {"tier-1": 10, "tier-3": 1}, "tier1_count": 10, "tier2_count": 0, "tier12_count": 10, "tier12_pct": 90.91},
            "d": {"total_records": 10, "distinct_classes": 1, "tier_counts": {"tier-3": 5, "tier-5": 3, "no-tier": 2}, "tier1_count": 0, "tier2_count": 0, "tier12_count": 0, "tier12_pct": 0.0},
        },
    }


class AttackClassTaxonomyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="taxonomy-mcp-test-")
        self.root = Path(self.tmp.name)
        self.inv_path = self.root / "attack_class_taxonomy.json"
        self.inv_path.write_text(
            json.dumps(_synthetic_inventory()), encoding="utf-8"
        )
        self.vault_dir = self.root / "obsidian-vault"
        self.vault_dir.mkdir()
        self.vault = vault_mcp_server.VaultQuery(self.vault_dir, self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    # 1.
    def test_envelope_shape(self):
        result = self.vault.vault_attack_class_taxonomy(
            inventory_path=str(self.inv_path),
        )
        self.assertEqual(result["schema"], vault_mcp_server.ATTACK_CLASS_TAXONOMY_SCHEMA)
        self.assertTrue(
            result["context_pack_id"].startswith(
                vault_mcp_server.ATTACK_CLASS_TAXONOMY_SCHEMA + ":"
            )
        )
        self.assertEqual(len(result["context_pack_hash"]), 64)
        # ``<missing-attack-class>`` is filtered out.
        names = [c["attack_class"] for c in result["classes"]]
        self.assertNotIn("<missing-attack-class>", names)
        self.assertIn("reentrancy", names)
        self.assertIn("unconstrained-variable", names)
        self.assertFalse(result["degraded"])

    # 2.
    def test_inventory_missing_degrades_gracefully(self):
        result = self.vault.vault_attack_class_taxonomy(
            inventory_path=str(self.root / "does-not-exist.json"),
        )
        self.assertTrue(result["degraded"])
        self.assertEqual(result["reason"], "inventory_missing")
        self.assertIn("context_pack_id", result)
        self.assertEqual(result["classes"], [])

    # 3.
    def test_inventory_malformed_json_degrades(self):
        bad = self.root / "bad.json"
        bad.write_text("not-json{{{", encoding="utf-8")
        result = self.vault.vault_attack_class_taxonomy(inventory_path=str(bad))
        self.assertTrue(result["degraded"])
        self.assertTrue(result["reason"].startswith("inventory_load_error"))

    # 4.
    def test_inventory_schema_invalid_degrades(self):
        bad = self.root / "schema-invalid.json"
        bad.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
        result = self.vault.vault_attack_class_taxonomy(inventory_path=str(bad))
        self.assertTrue(result["degraded"])
        self.assertEqual(result["reason"], "inventory_schema_invalid")

    # 5.
    def test_min_records_filter(self):
        result = self.vault.vault_attack_class_taxonomy(
            inventory_path=str(self.inv_path),
            min_records=50,
        )
        names = [c["attack_class"] for c in result["classes"]]
        # Only reentrancy has >=50 records.
        self.assertEqual(names, ["reentrancy"])
        # Orphans are also derived from the filtered set, so unconstrained-variable drops out.
        self.assertEqual(result["orphans"], [])

    # 6.
    def test_min_tier_coverage_pct_filter(self):
        result = self.vault.vault_attack_class_taxonomy(
            inventory_path=str(self.inv_path),
            min_tier_coverage_pct=80.0,
        )
        names = [c["attack_class"] for c in result["classes"]]
        self.assertEqual(names, ["reentrancy"])

    # 7.
    def test_limit_clamping(self):
        # Limit above max clamps to 200. (Limit=0 falls back to the default
        # via the falsy ``or`` guard, which mirrors the v1 evidence callable
        # convention.)
        result_high = self.vault.vault_attack_class_taxonomy(
            inventory_path=str(self.inv_path), limit=10_000
        )
        self.assertEqual(result_high["limit"], 200)
        # Explicit limit of 1 retains exactly one record.
        result_low = self.vault.vault_attack_class_taxonomy(
            inventory_path=str(self.inv_path), limit=1
        )
        self.assertEqual(result_low["limit"], 1)
        self.assertEqual(len(result_low["classes"]), 1)
        self.assertEqual(result_low["classes"][0]["attack_class"], "reentrancy")

    # 8.
    def test_orphan_and_well_covered_classifiers(self):
        result = self.vault.vault_attack_class_taxonomy(
            inventory_path=str(self.inv_path),
        )
        orphan_names = [r["attack_class"] for r in result["orphans"]]
        well_names = [r["attack_class"] for r in result["well_covered"]]
        self.assertIn("unconstrained-variable", orphan_names)
        self.assertNotIn("reentrancy", orphan_names)
        self.assertIn("reentrancy", well_names)

    # 9.
    def test_dispatch_routing(self):
        # Confirm the new callable is wired into the _dispatch table.
        result = self.vault._dispatch(
            "vault_attack_class_taxonomy",
            {"inventory_path": str(self.inv_path), "limit": 5},
        )
        self.assertEqual(result["schema"], vault_mcp_server.ATTACK_CLASS_TAXONOMY_SCHEMA)
        self.assertFalse(result["degraded"])

    # 10.
    def test_source_refs_includes_inventory_path(self):
        result = self.vault.vault_attack_class_taxonomy(
            inventory_path=str(self.inv_path),
        )
        # The inventory path is outside repo_root for synthetic tests; the
        # callable falls back to the filename. Either way, source_refs is
        # non-empty.
        self.assertTrue(len(result["source_refs"]) >= 1)

    # 11.
    def test_deterministic_context_pack_hash(self):
        r1 = self.vault.vault_attack_class_taxonomy(inventory_path=str(self.inv_path))
        r2 = self.vault.vault_attack_class_taxonomy(inventory_path=str(self.inv_path))
        self.assertEqual(r1["context_pack_hash"], r2["context_pack_hash"])

    # 12.
    def test_per_subtree_passthrough(self):
        result = self.vault.vault_attack_class_taxonomy(
            inventory_path=str(self.inv_path),
        )
        self.assertIn("a", result["per_subtree"])
        self.assertEqual(result["per_subtree"]["a"]["total_records"], 30)
        self.assertEqual(result["subtrees"], ["a", "b", "c", "d"])


if __name__ == "__main__":
    unittest.main()
