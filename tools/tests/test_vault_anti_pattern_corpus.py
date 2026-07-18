"""Tests for VaultQuery.vault_anti_pattern_corpus callable (W5-M3).

synthetic_fixture: true

Verifies:
  1. Degraded envelope when the anti-patterns dir is absent.
  2. Happy path on a synthetic anti-pattern note returns the record.
  3. confidence and min_sample_size filters narrow the result set.
  4. query substring filter narrows the result set.
  5. Envelope carries schema + context_pack_id + context_pack_hash.
  6. CLI dispatch exits 0; callable appears in TOOL_SCHEMAS.
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


class TestVaultAntiPatternCorpus(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="w5m3-antipattern-")
        self.root = Path(self.tmp.name)
        self.vault = self.root / "obsidian-vault"
        _make_minimal_vault(self.vault)
        self.query = vault_mcp_server.VaultQuery(self.vault, self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def _seed(self):
        # synthetic_fixture: true
        ap = self.vault / "anti-patterns"
        ap.mkdir(parents=True, exist_ok=True)
        (ap / "synth-high.md").write_text(
            "---\ntitle: Synth high foot-gun\nrecommendation: true\n"
            "sample_size: 5\nconfidence: high\ncounter_examples: 0\n"
            "last_validated_at: 2026-05-10\n---\n# Synth high\n\n"
            "Avoid the m14 trap shape.\n",
            encoding="utf-8",
        )
        (ap / "synth-low.md").write_text(
            "---\ntitle: Synth low foot-gun\nrecommendation: false\n"
            "sample_size: 1\nconfidence: low\ncounter_examples: 2\n"
            "last_validated_at: 2026-05-01\n---\n# Synth low\n\n"
            "Weak signal note.\n",
            encoding="utf-8",
        )

    def test_degraded_when_dir_absent(self):
        # synthetic_fixture: true
        result = self.query.vault_anti_pattern_corpus()
        self.assertTrue(result.get("degraded"))
        self.assertEqual(result.get("reason"), "anti_pattern_dir_not_found")

    def test_happy_path_returns_records(self):
        # synthetic_fixture: true
        self._seed()
        result = self.query.vault_anti_pattern_corpus()
        self.assertFalse(result.get("degraded"))
        self.assertEqual(result["anti_patterns_count"], 2)

    def test_confidence_filter_narrows(self):
        # synthetic_fixture: true
        self._seed()
        result = self.query.vault_anti_pattern_corpus(confidence="high")
        self.assertEqual(result["anti_patterns_count"], 1)
        self.assertEqual(result["anti_patterns"][0]["anti_pattern_id"], "synth-high")

    def test_min_sample_size_filter_narrows(self):
        # synthetic_fixture: true
        self._seed()
        result = self.query.vault_anti_pattern_corpus(min_sample_size=3)
        self.assertEqual(result["anti_patterns_count"], 1)
        self.assertEqual(result["anti_patterns"][0]["sample_size"], 5)

    def test_query_substring_filter(self):
        # synthetic_fixture: true
        self._seed()
        result = self.query.vault_anti_pattern_corpus(query="m14 trap")
        self.assertEqual(result["anti_patterns_count"], 1)

    def test_schema_envelope_present(self):
        # synthetic_fixture: true
        self._seed()
        result = self.query.vault_anti_pattern_corpus()
        self.assertEqual(result.get("schema"), vault_mcp_server.ANTI_PATTERN_CORPUS_SCHEMA)
        self.assertIn("context_pack_id", result)
        self.assertIn("context_pack_hash", result)

    def test_cli_dispatch_exits_zero(self):
        # synthetic_fixture: true
        self._seed()
        proc = subprocess.run(
            [sys.executable, str(MODULE_PATH), "--repo-root", str(self.root),
             "--vault-dir", str(self.vault), "--call", "vault_anti_pattern_corpus",
             "--args", "{}"],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr[:300])
        parsed = json.loads(proc.stdout[proc.stdout.index("{"):])
        self.assertEqual(parsed["anti_patterns_count"], 2)

    def test_callable_in_tool_schemas(self):
        # synthetic_fixture: true
        names = [t["name"] for t in vault_mcp_server.TOOL_SCHEMAS]
        self.assertIn("vault_anti_pattern_corpus", names)


if __name__ == "__main__":
    unittest.main()
