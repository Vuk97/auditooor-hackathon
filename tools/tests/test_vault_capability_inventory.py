#!/usr/bin/env python3
"""Regression coverage for vault_capability_inventory."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "vault-mcp-server.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server_capability_inventory", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


vault_mcp_server = _load_module()


class VaultCapabilityInventoryTests(unittest.TestCase):
    def test_combines_present_inventories_and_filters(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vault-capability-inventory-") as td:
            repo = Path(td)
            reference = repo / "reference"
            _write_jsonl(
                reference / "capability_inventory.jsonl",
                [
                    {
                        "id": "CAP-solidity-1",
                        "name": "solidity capability",
                        "category": "mcp-callable",
                        "status": "NOMINAL-WIRED",
                        "target_language": "solidity",
                    },
                    {
                        "id": "CAP-solidity-2",
                        "name": "second solidity capability",
                        "category": "mcp-callable",
                        "status": "NOMINAL-WIRED",
                        "target_language": "solidity",
                    },
                    {
                        "id": "CAP-rust",
                        "name": "rust capability",
                        "category": "python-tool",
                        "status": "PARTIAL",
                        "target_language": "rust",
                    },
                ],
            )
            _write_jsonl(
                reference / "detector_libraries_inventory.jsonl",
                [
                    {
                        "schema": "auditooor.detector_libraries_inventory.v1",
                        "wave": "solidity_wave",
                        "language": "solidity",
                        "wiring_status": "NOMINAL-WIRED",
                    }
                ],
            )
            _write_jsonl(
                reference / "canonical_flows.jsonl",
                [
                    {
                        "id": "FLOW-001",
                        "name": "capability inventory flow",
                        "purpose": "non-inventory sibling exposed by the callable",
                    }
                ],
            )

            query = vault_mcp_server.VaultQuery(repo, repo_root=repo)
            result = query.vault_capability_inventory(
                filter={"health_status": "NOMINAL-WIRED", "target_language": "solidity"},
                limit=2,
            )

        self.assertEqual(result["schema"], "auditooor.vault_capability_inventory.v1")
        self.assertTrue(result["degraded"])
        self.assertIn("missing_siblings:", result["degraded_reason"])
        self.assertEqual(result["summary"]["files_loaded"], 3)
        self.assertEqual(result["summary"]["total_records_matched"], 3)
        self.assertEqual(result["summary"]["records_returned"], 2)
        self.assertEqual(
            result["source_refs"],
            [
                "reference/capability_inventory.jsonl",
                "reference/canonical_flows.jsonl",
                "reference/detector_libraries_inventory.jsonl",
            ],
        )
        self.assertEqual(
            [file_summary["source_ref"] for file_summary in result["files"]],
            [
                "reference/capability_inventory.jsonl",
                "reference/canonical_flows.jsonl",
                "reference/detector_libraries_inventory.jsonl",
                "reference/makefile_target_inventory.jsonl",
                "reference/mcp_callables_inventory.jsonl",
                "reference/pre_submit_checks_inventory.jsonl",
                "reference/r_rules_inventory.jsonl",
            ],
        )

    def test_call_dispatch_and_schema_registration(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vault-capability-dispatch-") as td:
            repo = Path(td)
            _write_jsonl(
                repo / "reference" / "capability_inventory.jsonl",
                [
                    {
                        "id": "CAP-dispatch",
                        "name": "dispatch capability",
                        "category": "mcp-callable",
                        "status": "WORKING",
                    }
                ],
            )
            query = vault_mcp_server.VaultQuery(repo, repo_root=repo)
            result = query.call(
                "vault_capability_inventory",
                {"filter": {"lane_type": "mcp-callable"}, "limit": 1},
            )

        self.assertEqual(result["kind"], "capability_inventory")
        self.assertEqual(result["records"][0]["row"]["id"], "CAP-dispatch")
        names = {tool["name"] for tool in vault_mcp_server.TOOL_SCHEMAS}
        self.assertIn("vault_capability_inventory", names)
        schema = next(tool for tool in vault_mcp_server.TOOL_SCHEMAS if tool["name"] == "vault_capability_inventory")
        self.assertIn("filter", schema["inputSchema"]["properties"])
        self.assertIn("limit", schema["inputSchema"]["properties"])

    def test_missing_primary_returns_degraded_empty_pack(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vault-capability-missing-") as td:
            repo = Path(td)
            (repo / "reference").mkdir(parents=True)
            query = vault_mcp_server.VaultQuery(repo, repo_root=repo)
            result = query.vault_capability_inventory(limit=3)

        self.assertTrue(result["degraded"])
        self.assertIn("capability_inventory_jsonl_missing", result["degraded_reason"])
        self.assertEqual(result["summary"]["total_records_available"], 0)
        self.assertEqual(result["records"], [])


if __name__ == "__main__":
    unittest.main()
