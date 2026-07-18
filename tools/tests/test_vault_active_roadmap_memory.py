"""Focused tests for roadmap result-time memory and prior output injection."""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
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


ROADMAP = """# Consolidated Roadmap for Codex - memory test

## PHASE 0 - Foundation

### 0.1 Build the result memory lane
**Owner**: CODEX

## PHASE I - Dependent work

### I.1 Consume prior lane output
**Owner**: CLAUDE
"""


class VaultActiveRoadmapMemoryTests(unittest.TestCase):
    def setUp(self) -> None:
        os.environ.setdefault("AUDITOOOR_MCP_SECRET", "active-roadmap-memory-test")
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-roadmap-memory-")
        self.root = Path(self.tmp.name)
        self.vault_dir = self.root / "obsidian-vault"
        self.vault_dir.mkdir()
        self.roadmap_path = self.root / "roadmap.md"
        self.state_path = self.root / "state.json"
        self.roadmap_path.write_text(ROADMAP, encoding="utf-8")
        self.vault = vault_mcp_server.VaultQuery(self.vault_dir, self.root)
        self.memory_dirs: list[Path] = []

    def tearDown(self) -> None:
        for path in self.memory_dirs:
            if path.exists():
                shutil.rmtree(path, ignore_errors=True)
        self.tmp.cleanup()

    def _args(self, **extra):
        base = {
            "side": "codex",
            "roadmap_path": str(self.roadmap_path),
            "state_path": str(self.state_path),
        }
        base.update(extra)
        return base

    def test_result_time_remember_records_memory_and_state_receipt(self) -> None:
        claimed = self.vault.vault_active_roadmap(
            **self._args(claim=True, item_id="PHASE-0.1")
        )
        result = self.vault.vault_active_roadmap(
            **self._args(
                item_id="PHASE-0.1",
                claim_token=claimed["claim_token"],
                result_status="LANDED",
                result_summary="Result-time memory path landed through vault_remember.",
            )
        )

        remember = result["result_remember"]
        self.assertTrue(remember["attempted"], msg=remember)
        self.assertTrue(remember["accepted"], msg=remember)
        memory_path = Path(remember["memory_path"])
        self.memory_dirs.append(memory_path.parent)
        self.assertTrue(memory_path.exists())
        self.assertIn(
            "Result-time memory path landed",
            memory_path.read_text(encoding="utf-8"),
        )

        state = json.loads(self.state_path.read_text(encoding="utf-8"))
        row = state["items"]["PHASE-0.1"]
        self.assertEqual(row["result_summary"], "Result-time memory path landed through vault_remember.")
        self.assertTrue(row["result_remember"]["accepted"])
        self.assertEqual(
            row["result_remember"]["memory_path"],
            f"memory/{remember['derived_filename']}",
        )
        self.assertFalse(Path(row["result_remember"]["memory_path"]).is_absolute())

    def test_prior_lane_output_header_appears_once_when_context_injected(self) -> None:
        claimed = self.vault.vault_active_roadmap(
            **self._args(claim=True, item_id="PHASE-0.1")
        )
        result = self.vault.vault_active_roadmap(
            **self._args(
                item_id="PHASE-0.1",
                claim_token=claimed["claim_token"],
                result_status="LANDED",
                result_summary="Prior context summary for the dependent lane.",
            )
        )
        self.memory_dirs.append(Path(result["result_remember"]["memory_path"]).parent)

        preview = self.vault.vault_active_roadmap(**self._args(claim=False))
        brief = preview["lane_brief_template"]
        self.assertEqual(preview["next_item_id"], "PHASE-I.1")
        self.assertEqual(brief.count("prior_lane_output:"), 1)
        self.assertIn("PHASE-0.1 [LANDED]: Prior context summary", brief)
        self.assertEqual(len(preview["next_item"]["prior_lane_output"]), 1)


if __name__ == "__main__":
    unittest.main()
