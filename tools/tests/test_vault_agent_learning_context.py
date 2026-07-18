"""Tests for VaultQuery.vault_agent_learning_context callable (Lane K K7).

synthetic_fixture: true

Verifies:
  1. Degraded when workspace_path is absent.
  2. Degraded when learning_ledger.jsonl is missing (with hint).
  3. Happy-path returns the bounded learning-context pack: open_objections,
     recent_kill_reasons, new_hacker_questions, proof_artifacts,
     no_action_summary, unclassified_count.
  4. Each bounded category is capped to the limit.
  5. Envelope carries schema + context_pack_id + context_pack_hash.
  6. callable appears in TOOL_SCHEMAS and dispatches via call().
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server_agent_learning", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module()


def _make_minimal_vault(vault_dir: Path) -> None:
    vault_dir.mkdir(parents=True, exist_ok=True)
    (vault_dir / "INDEX.md").write_text("# INDEX\n\n- entry\n", encoding="utf-8")
    (vault_dir / "INDEX_active.md").write_text("# active\n- item\n", encoding="utf-8")
    (vault_dir / "NEXT_LOOP.md").write_text("# NEXT_LOOP\n\n## Section\n- item\n", encoding="utf-8")
    goals = vault_dir / "goals"
    goals.mkdir(exist_ok=True)
    (goals / "current.md").write_text("---\nobjective: synth\n---\n# goal\n", encoding="utf-8")


def _row(artifact_id: str, kind: str, **extra: object) -> dict:
    row = {
        "schema": "auditooor.agent_learning_ledger.v1",
        "artifact_id": artifact_id,
        "terminal_kind": kind,
        "proposition": f"Disposition for {artifact_id}",
        "evidence_polarity": "limits",
        "primary_for": "methodology",
        "reuse_action": "none",
    }
    row.update(extra)
    return row


class TestVaultAgentLearningContext(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="agent-learning-ctx-test-")
        self.root = Path(self.tmp.name)
        self.vault = self.root / "obsidian-vault"
        _make_minimal_vault(self.vault)
        self.query = vault_mcp_server.VaultQuery(self.vault, self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def _write_ledger(self, rows: list[dict], workspace: Path | None = None) -> Path:
        ws = workspace or self.root / "ws"
        ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
        ledger.parent.mkdir(parents=True, exist_ok=True)
        ledger.write_text(
            "\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n",
            encoding="utf-8",
        )
        return ws

    def test_degraded_no_workspace(self):
        result = self.query.vault_agent_learning_context()
        self.assertTrue(result.get("degraded"))
        self.assertEqual(result.get("reason"), "workspace_path_required")
        self.assertEqual(result.get("lesson_pack_rows"), 0)

    def test_degraded_missing_ledger(self):
        ws = self.root / "no-ledger-ws"
        ws.mkdir(parents=True, exist_ok=True)
        result = self.query.vault_agent_learning_context(workspace_path=str(ws))
        self.assertTrue(result.get("degraded"))
        self.assertEqual(result.get("reason"), "ledger_not_found")
        self.assertIn("hint", result)
        self.assertIn("checked_path", result)

    def test_happy_path_bounded_pack(self):
        rows = [
            _row("k1", "kill_reason", reuse_action="add_kill_rubric"),
            _row("o1", "triager_objection", reuse_action="add_pre_submit_gate"),
            _row("q1", "hacker_question", reuse_action="add_hacker_question"),
            _row("po1", "proof_obligation", reuse_action="add_hacker_question"),
            _row(
                "pf1",
                "proof_artifact",
                reuse_action="add_detector",
                is_primary_signal=True,
                can_promote_to_proof=True,
            ),
            _row("na1", "NO_ACTION", evidence_polarity="context_only", reason="provider_only"),
            _row("na2", "NO_ACTION", evidence_polarity="context_only", reason="duplicate"),
        ]
        ws = self._write_ledger(rows)
        result = self.query.vault_agent_learning_context(workspace_path=str(ws))
        self.assertFalse(result.get("degraded"))
        self.assertEqual(result["ledger_rows"], 7)
        self.assertEqual(len(result["recent_kill_reasons"]), 1)
        self.assertEqual(result["recent_kill_reasons"][0]["artifact_id"], "k1")
        self.assertEqual(len(result["open_objections"]), 1)
        # hacker_question + proof_obligation both surface as new_hacker_questions.
        self.assertEqual(len(result["new_hacker_questions"]), 2)
        self.assertEqual(len(result["proof_artifacts"]), 1)
        self.assertEqual(result["no_action_summary"], {"duplicate": 1, "provider_only": 1})
        self.assertEqual(result["unclassified_count"], 0)
        self.assertEqual(result["lesson_packs"], [])
        # Envelope.
        self.assertTrue(result["context_pack_id"].startswith(vault_mcp_server.AGENT_LEARNING_CONTEXT_SCHEMA))
        self.assertEqual(len(result["context_pack_hash"]), 64)

    def test_lesson_pack_jsonl_is_surfaced(self):
        rows = [_row("k1", "kill_reason")]
        ws = self._write_ledger(rows)
        derived = self.root / "audit" / "corpus_tags" / "derived"
        derived.mkdir(parents=True, exist_ok=True)
        lp_path = derived / f"lesson_pack_{ws.name}_2026-05-28.jsonl"
        lp_path.write_text(
            json.dumps({
                "schema": "auditooor.lesson_pack_persistence.v1",
                "workspace": ws.name,
                "source_path": "packet.json",
                "severity": "High",
                "packet_id": "pkt-1",
                "lesson_pack_hash": "abc123",
                "lesson_pack": {
                    "selection_keys": {
                        "attack_class": "theft",
                        "function_shape": "withdraw",
                    }
                },
            }) + "\n",
            encoding="utf-8",
        )
        result = self.query.vault_agent_learning_context(workspace_path=str(ws))
        self.assertEqual(result["lesson_pack_rows"], 1)
        self.assertEqual(result["lesson_packs"][0]["packet_id"], "pkt-1")
        self.assertEqual(result["lesson_packs"][0]["attack_class"], "theft")

    def test_categories_capped_to_limit(self):
        rows = [_row(f"q{i}", "hacker_question") for i in range(20)]
        ws = self._write_ledger(rows)
        result = self.query.vault_agent_learning_context(workspace_path=str(ws), limit=3)
        self.assertEqual(len(result["new_hacker_questions"]), 3)
        self.assertEqual(result["bound_limit"], 3)

    def test_registered_and_dispatchable(self):
        names = {tool["name"] for tool in vault_mcp_server.TOOL_SCHEMAS}
        self.assertIn("vault_agent_learning_context", names)
        ws = self._write_ledger([_row("k1", "kill_reason")])
        dispatched = self.query.call(
            "vault_agent_learning_context", {"workspace_path": str(ws)}
        )
        self.assertEqual(dispatched["schema"], vault_mcp_server.AGENT_LEARNING_CONTEXT_SCHEMA)


if __name__ == "__main__":
    unittest.main()
