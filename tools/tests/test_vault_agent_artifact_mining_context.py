"""Tests for VaultQuery.vault_agent_artifact_mining_context callable (Lane 6, Wave-6).

synthetic_fixture: true

Verifies:
  1. Degraded when workspace_path is absent.
  2. Degraded when agent_artifact_mining_report.json is missing (with hint).
  3. Happy-path with a synthetic report returns total_artifacts, artifact_type_counts,
     no_learning_reason, and a bounded artifact_titles_sample.
  4. artifact_titles_sample is capped to limit (not the full artifact list).
  5. Envelope carries schema + context_pack_id + context_pack_hash.
  6. CLI dispatch exits 0 for a degraded workspace (no report) and returns JSON.
  7. callable appears in TOOL_SCHEMAS.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server_agent_artifact", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec is not None and spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _make_minimal_vault(vault_dir: Path) -> None:
    # synthetic_fixture: true
    vault_dir.mkdir(parents=True, exist_ok=True)
    (vault_dir / "INDEX.md").write_text("# INDEX\n\n- entry\n", encoding="utf-8")
    (vault_dir / "INDEX_active.md").write_text("# active\n- item\n", encoding="utf-8")
    (vault_dir / "NEXT_LOOP.md").write_text("# NEXT_LOOP\n\n## Section\n- item\n", encoding="utf-8")
    goals = vault_dir / "goals"
    goals.mkdir(exist_ok=True)
    (goals / "current.md").write_text("---\nobjective: synth\n---\n# goal\n", encoding="utf-8")


vault_mcp_server = _load_module()

_FIXTURE_REPORT = {
    "schema_version": "auditooor.agent_artifact_mining.v1",
    "workspace": "/fake/workspace",
    "generated_at": "2026-05-19T00:00:00+00:00",
    "total_artifacts": 5,
    "no_learning_reason": False,
    "artifact_type_counts": {
        "candidate_detector_pattern": 2,
        "rejection_pattern": 2,
        "falsification_template": 1,
    },
    "artifacts": [
        {"artifact_type": "candidate_detector_pattern", "title": "Detector pattern seed in agent_outputs/lane1"},
        {"artifact_type": "candidate_detector_pattern", "title": "Detector pattern seed in agent_outputs/lane2"},
        {"artifact_type": "rejection_pattern", "title": "Kill reasons from provider dispatch lane3.json"},
        {"artifact_type": "rejection_pattern", "title": "Kill reasons from provider dispatch lane4.json"},
        {"artifact_type": "falsification_template", "title": "Failed PoC - negative control template (poc_lane5.go)"},
    ],
}

_FIXTURE_EMPTY = {
    "schema_version": "auditooor.agent_artifact_mining.v1",
    "workspace": "/fake/workspace",
    "generated_at": "2026-05-19T00:00:00+00:00",
    "total_artifacts": 0,
    "no_learning_reason": True,
    "artifact_type_counts": {},
    "artifacts": [],
}


class TestVaultAgentArtifactMiningContext(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="agent-artifact-ctx-test-")
        self.root = Path(self.tmp.name)
        self.vault = self.root / "obsidian-vault"
        _make_minimal_vault(self.vault)
        self.query = vault_mcp_server.VaultQuery(self.vault, self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def _write_report(self, data: dict, workspace: Path | None = None) -> Path:
        ws = workspace or self.root / "fake-workspace"
        ws.mkdir(parents=True, exist_ok=True)
        report = ws / "agent_artifact_mining_report.json"
        report.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return ws

    # ------------------------------------------------------------------
    # Degraded paths
    # ------------------------------------------------------------------

    def test_degraded_no_workspace(self):
        # synthetic_fixture: true
        result = self.query.vault_agent_artifact_mining_context()
        self.assertTrue(result.get("degraded"))
        self.assertEqual(result.get("reason"), "workspace_path_required")

    def test_degraded_missing_report(self):
        # synthetic_fixture: true
        ws = self.root / "no-report-workspace"
        ws.mkdir(parents=True, exist_ok=True)
        result = self.query.vault_agent_artifact_mining_context(workspace_path=str(ws))
        self.assertTrue(result.get("degraded"))
        self.assertEqual(result.get("reason"), "report_not_found")
        self.assertIn("hint", result)
        self.assertIn("checked_path", result)

    # ------------------------------------------------------------------
    # Happy paths
    # ------------------------------------------------------------------

    def test_happy_path_bounded_summary(self):
        # synthetic_fixture: true
        ws = self._write_report(_FIXTURE_REPORT)
        result = self.query.vault_agent_artifact_mining_context(workspace_path=str(ws))
        self.assertFalse(result.get("degraded"))
        self.assertEqual(result["total_artifacts"], 5)
        self.assertFalse(result["no_learning_reason"])
        self.assertEqual(result["artifact_type_counts"]["candidate_detector_pattern"], 2)
        self.assertEqual(result["artifact_type_counts"]["rejection_pattern"], 2)
        self.assertEqual(result["artifact_type_counts"]["falsification_template"], 1)
        self.assertIsInstance(result["artifact_titles_sample"], list)
        # All 5 artifacts fit within default limit=10
        self.assertEqual(len(result["artifact_titles_sample"]), 5)
        self.assertIn("Detector pattern seed", result["artifact_titles_sample"][0])

    def test_happy_path_empty_report(self):
        # synthetic_fixture: true
        ws = self._write_report(_FIXTURE_EMPTY)
        result = self.query.vault_agent_artifact_mining_context(workspace_path=str(ws))
        self.assertFalse(result.get("degraded"))
        self.assertEqual(result["total_artifacts"], 0)
        self.assertTrue(result["no_learning_reason"])
        self.assertEqual(result["artifact_titles_sample"], [])

    def test_titles_sample_capped_by_limit(self):
        # synthetic_fixture: true - verify limit parameter caps the titles sample
        ws = self._write_report(_FIXTURE_REPORT)
        result = self.query.vault_agent_artifact_mining_context(workspace_path=str(ws), limit=2)
        self.assertFalse(result.get("degraded"))
        # total_artifacts is the full count from the report, not capped
        self.assertEqual(result["total_artifacts"], 5)
        # titles sample is capped to limit=2
        self.assertLessEqual(len(result["artifact_titles_sample"]), 2)
        self.assertEqual(result["titles_sample_limit"], 2)

    def test_workspace_alias(self):
        # synthetic_fixture: true - verify 'workspace' kwarg is accepted as alias
        ws = self._write_report(_FIXTURE_REPORT)
        result = self.query.vault_agent_artifact_mining_context(workspace=str(ws))
        self.assertFalse(result.get("degraded"))
        self.assertEqual(result["total_artifacts"], 5)

    # ------------------------------------------------------------------
    # Schema envelope
    # ------------------------------------------------------------------

    def test_schema_envelope(self):
        # synthetic_fixture: true
        ws = self._write_report(_FIXTURE_REPORT)
        result = self.query.vault_agent_artifact_mining_context(workspace_path=str(ws))
        self.assertEqual(
            result.get("schema"),
            vault_mcp_server.AGENT_ARTIFACT_MINING_CONTEXT_SCHEMA,
        )
        self.assertIn("context_pack_id", result)
        self.assertIn("context_pack_hash", result)
        self.assertIn(vault_mcp_server.AGENT_ARTIFACT_MINING_CONTEXT_SCHEMA,
                      result["context_pack_id"])

    def test_degraded_schema_envelope(self):
        # synthetic_fixture: true - degraded path also has schema + pack fields
        result = self.query.vault_agent_artifact_mining_context()
        self.assertEqual(
            result.get("schema"),
            vault_mcp_server.AGENT_ARTIFACT_MINING_CONTEXT_SCHEMA,
        )
        self.assertIn("context_pack_id", result)
        self.assertIn("context_pack_hash", result)

    # ------------------------------------------------------------------
    # CLI dispatch
    # ------------------------------------------------------------------

    def test_cli_dispatch_exits_zero_degraded(self):
        # synthetic_fixture: true - CLI exits 0 even on degraded (no report)
        ws = self.root / "no-report-cli"
        ws.mkdir(parents=True, exist_ok=True)
        proc = subprocess.run(
            [
                sys.executable, str(MODULE_PATH),
                "--repo-root", str(self.root),
                "--vault-dir", str(self.vault),
                "--call", "vault_agent_artifact_mining_context",
                "--args", json.dumps({"workspace_path": str(ws)}),
            ],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr[:300])
        parsed = json.loads(proc.stdout)
        self.assertTrue(parsed.get("degraded"))
        self.assertEqual(parsed.get("reason"), "report_not_found")

    def test_cli_dispatch_exits_zero_happy(self):
        # synthetic_fixture: true
        ws = self._write_report(_FIXTURE_REPORT)
        proc = subprocess.run(
            [
                sys.executable, str(MODULE_PATH),
                "--repo-root", str(self.root),
                "--vault-dir", str(self.vault),
                "--call", "vault_agent_artifact_mining_context",
                "--args", json.dumps({"workspace_path": str(ws), "limit": 3}),
            ],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr[:300])
        parsed = json.loads(proc.stdout)
        self.assertFalse(parsed.get("degraded"))
        self.assertEqual(parsed["total_artifacts"], 5)
        self.assertLessEqual(len(parsed["artifact_titles_sample"]), 3)

    # ------------------------------------------------------------------
    # TOOL_SCHEMAS registration
    # ------------------------------------------------------------------

    def test_callable_in_tool_schemas(self):
        # synthetic_fixture: true
        names = [t["name"] for t in vault_mcp_server.TOOL_SCHEMAS]
        self.assertIn("vault_agent_artifact_mining_context", names)


if __name__ == "__main__":
    unittest.main()
