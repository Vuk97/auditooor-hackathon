"""Tests for the vault_aggregated_learning cross-workspace learning callable."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = load_module()


AGG_REL = "audit/corpus_tags/derived/agent_learning_ledger_aggregated.jsonl"

ROWS = [
    {
        "artifact_id": "a1",
        "workspace": "/Users/x/audits/dydx",
        "terminal_kind": "typed_lesson",
        "primary_for": "severity_cap",
        "proposition": "lesson one",
    },
    {
        "artifact_id": "a2",
        "workspace": "/Users/x/audits/spark",
        "terminal_kind": "kill_reason",
        "selected_impact": "direct loss of funds",
        "proposition": "lesson two",
    },
    {
        "artifact_id": "a3",
        "workspace": "/Users/x/audits/dydx",
        "terminal_kind": "proof_obligation",
        "proposition": "lesson three",
    },
]


def _build_server(repo_root):
    vault_dir = repo_root / "obsidian-vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    return vault_mcp_server.VaultQuery(vault_dir, repo_root=repo_root)


def _write_agg(repo_root, rows):
    p = repo_root / AGG_REL
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    return p


class TestVaultAggregatedLearning(unittest.TestCase):
    def test_summary_and_rows(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_agg(root, ROWS)
            srv = _build_server(root)
            out = srv.vault_aggregated_learning(limit=10)
            self.assertEqual(out["schema"], "auditooor.vault_aggregated_learning.v1")
            self.assertTrue(out["file_present"])
            self.assertEqual(out["summary"]["total_rows"], 3)
            self.assertEqual(out["summary"]["distinct_workspaces"], 2)
            self.assertEqual(out["summary"]["distinct_attack_classes"], 2)
            self.assertEqual(len(out["rows"]), 3)
            self.assertIn("context_pack_hash", out)

    def test_limit_caps_returned_rows(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_agg(root, ROWS)
            srv = _build_server(root)
            out = srv.vault_aggregated_learning(limit=1)
            self.assertEqual(out["summary"]["returned_rows"], 1)
            self.assertEqual(out["summary"]["total_rows"], 3)

    def test_workspace_filter(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_agg(root, ROWS)
            srv = _build_server(root)
            out = srv.vault_aggregated_learning(workspace="dydx", limit=10)
            self.assertEqual(out["summary"]["returned_rows"], 2)
            self.assertTrue(all("dydx" in r["workspace"] for r in out["rows"]))

    def test_terminal_kind_filter(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_agg(root, ROWS)
            srv = _build_server(root)
            out = srv.vault_aggregated_learning(terminal_kind="kill_reason", limit=10)
            self.assertEqual(out["summary"]["returned_rows"], 1)
            self.assertEqual(out["rows"][0]["terminal_kind"], "kill_reason")

    def test_attack_class_filter(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_agg(root, ROWS)
            srv = _build_server(root)
            out = srv.vault_aggregated_learning(attack_class="severity_cap", limit=10)
            self.assertEqual(out["summary"]["returned_rows"], 1)
            self.assertEqual(out["rows"][0]["artifact_id"], "a1")

    def test_absent_file_degrades_to_empty(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            srv = _build_server(root)
            out = srv.vault_aggregated_learning(limit=5)
            self.assertFalse(out["file_present"])
            self.assertEqual(out["summary"]["total_rows"], 0)
            self.assertEqual(out["rows"], [])

    def test_dispatch_routes_callable(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _write_agg(root, ROWS)
            srv = _build_server(root)
            out = srv.call("vault_aggregated_learning", {"limit": 2})
            self.assertEqual(out["schema"], "auditooor.vault_aggregated_learning.v1")
            self.assertNotIn("error", out)

    def test_registered_in_tool_schemas(self):
        names = {t["name"] for t in vault_mcp_server.TOOL_SCHEMAS}
        self.assertIn("vault_aggregated_learning", names)

    def test_real_aggregate_present(self):
        srv = vault_mcp_server.VaultQuery(
            REPO_ROOT / "obsidian-vault", repo_root=REPO_ROOT
        )
        out = srv.vault_aggregated_learning(limit=3)
        if (REPO_ROOT / AGG_REL).is_file():
            self.assertTrue(out["file_present"])
            self.assertGreater(out["summary"]["total_rows"], 0)
            self.assertGreater(out["summary"]["distinct_workspaces"], 0)


if __name__ == "__main__":
    unittest.main()
