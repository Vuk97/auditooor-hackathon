"""Tests for VaultQuery.vault_fanout_pattern_library callable (W5-M3).

synthetic_fixture: true

Verifies:
  1. Degraded envelope when the patterns dir is absent.
  2. Happy path on a synthetic patterns dir returns the seeded record.
  3. bug_class / severity filters narrow the result set.
  4. Envelope carries schema + context_pack_id + context_pack_hash.
  5. CLI dispatch exits 0 and returns valid JSON.
  6. Callable appears in TOOL_SCHEMAS list.

Notes: every call passes a synthetic `patterns_dir` so the production
audit/fanout_patterns/ tree is never walked - keeps the test hermetic.
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
    spec = importlib.util.spec_from_file_location("vault_mcp_server", MODULE_PATH)
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


class TestVaultFanoutPatternLibrary(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="w5m3-fanout-")
        self.root = Path(self.tmp.name)
        self.vault = self.root / "obsidian-vault"
        _make_minimal_vault(self.vault)
        self.query = vault_mcp_server.VaultQuery(self.vault, self.root)
        # synthetic_fixture: true
        self.patterns_dir = self.root / "synth_fanout_patterns"
        self.patterns_dir.mkdir(parents=True, exist_ok=True)
        (self.patterns_dir / "synth_reentrancy-CRITICAL.yaml").write_text(
            "source_engagement: synth\n"
            "source_verdict_id: staging/synth-reentrancy-CRITICAL.md\n"
            "bug_class: reentrancy\n"
            "severity: CRITICAL\n"
            "target_repo: synth/repo\n"
            "file_path_pattern: '.*/vault\\.sol$'\n"
            "key_invariants:\n"
            "- (?i)reentrancy\n"
            "function_names: []\n",
            encoding="utf-8",
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_degraded_when_dir_absent(self):
        # synthetic_fixture: true
        result = self.query.vault_fanout_pattern_library(
            patterns_dir=str(self.root / "does_not_exist")
        )
        self.assertTrue(result.get("degraded"))
        self.assertEqual(result.get("reason"), "patterns_dir_not_found")
        self.assertIn("context_pack_hash", result)

    def test_happy_path_returns_seeded_record(self):
        # synthetic_fixture: true
        result = self.query.vault_fanout_pattern_library(patterns_dir=str(self.patterns_dir))
        self.assertFalse(result.get("degraded"))
        self.assertEqual(result["patterns_count"], 1)
        self.assertEqual(result["patterns"][0]["bug_class"], "reentrancy")

    def test_severity_filter_narrows(self):
        # synthetic_fixture: true
        hit = self.query.vault_fanout_pattern_library(
            patterns_dir=str(self.patterns_dir), severity="critical"
        )
        miss = self.query.vault_fanout_pattern_library(
            patterns_dir=str(self.patterns_dir), severity="low"
        )
        self.assertEqual(hit["patterns_count"], 1)
        self.assertEqual(miss["patterns_count"], 0)

    def test_schema_envelope_present(self):
        # synthetic_fixture: true
        result = self.query.vault_fanout_pattern_library(patterns_dir=str(self.patterns_dir))
        self.assertEqual(result.get("schema"), vault_mcp_server.FANOUT_PATTERN_LIBRARY_SCHEMA)
        self.assertIn("context_pack_id", result)
        self.assertIn("context_pack_hash", result)

    def test_cli_dispatch_exits_zero(self):
        # synthetic_fixture: true
        args_json = json.dumps({"patterns_dir": str(self.patterns_dir)})
        proc = subprocess.run(
            [sys.executable, str(MODULE_PATH), "--repo-root", str(self.root),
             "--vault-dir", str(self.vault), "--call", "vault_fanout_pattern_library",
             "--args", args_json],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr[:300])
        parsed = json.loads(proc.stdout[proc.stdout.index("{"):])
        self.assertEqual(parsed["patterns_count"], 1)

    def test_callable_in_tool_schemas(self):
        # synthetic_fixture: true
        names = [t["name"] for t in vault_mcp_server.TOOL_SCHEMAS]
        self.assertIn("vault_fanout_pattern_library", names)


if __name__ == "__main__":
    unittest.main()
