"""Tests for VaultQuery.vault_anti_pattern_corpus v2 catalog extension (WG-011).

synthetic_fixture: true

<!-- r36-rebuttal: lane-WG-011-ANTI-PATTERN-V2 registered in
.auditooor/agent_pathspec.json; new test file declared in pathspec -->

Verifies WG-011 (LANE-94 wiring sprint, 2026-05-26) extension that lifts
the v2 per-language YAML catalog into the existing MCP callable:

  1. v1 flat *.md record is still ingested with language_family='flat-v1'
     and source_layout='v1' (backward-compat).
  2. v2 *.yaml record under v2/<lang>/ is ingested with language_family
     equal to the subdir name and source_layout='v2'.
  3. Mixed v1+v2 query returns both, correctly tagged.
  4. language_family filter narrows correctly.
  5. source_layout filter narrows correctly.
  6. Per-language scan counter and aggregate v1/v2 scan counters are
     emitted in the envelope.
  7. Schema is unchanged (auditooor.vault_anti_pattern_corpus.v1).
  8. Existing v1 record shape is unchanged (new fields are additive).
"""

from __future__ import annotations

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


class TestVaultAntiPatternCorpusV2(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="wg011-antipattern-v2-")
        self.root = Path(self.tmp.name)
        self.vault = self.root / "obsidian-vault"
        _make_minimal_vault(self.vault)
        self.query = vault_mcp_server.VaultQuery(self.vault, self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def _seed_v1(self) -> None:
        # synthetic_fixture: true
        ap = self.vault / "anti-patterns"
        ap.mkdir(parents=True, exist_ok=True)
        (ap / "v1-synth-high.md").write_text(
            "---\ntitle: V1 high foot-gun\nrecommendation: true\n"
            "sample_size: 5\nconfidence: high\ncounter_examples: 0\n"
            "last_validated_at: 2026-05-10\n---\n# V1 high\n\n"
            "Avoid the m14 trap shape.\n",
            encoding="utf-8",
        )

    def _seed_v2(self) -> None:
        # synthetic_fixture: true
        v2 = self.vault / "anti-patterns" / "v2"
        for lang in ("go", "solidity", "zk"):
            (v2 / lang).mkdir(parents=True, exist_ok=True)
        (v2 / "go" / "go.concurrent-map-write.yaml").write_text(
            "schema_version: auditooor.antipattern_catalog.v1\n"
            "pattern_id: go.concurrent-map-write-no-sync\n"
            "category: atomicity-and-ordering\n"
            "language: go\n"
            "severity_floor: medium\n"
            "severity_ceiling: critical\n"
            "description: 'Go map written from >=2 goroutines without mutex.'\n",
            encoding="utf-8",
        )
        (v2 / "solidity" / "batch02-foo.yaml").write_text(
            "schema_version: auditooor.antipattern_catalog.v1\n"
            "pattern_id: solidity.batch02-foo\n"
            "title: Solidity Foo Anti-Pattern\n"
            "category: accounting\n"
            "language: solidity\n"
            "severity_floor: low\n"
            "severity_ceiling: high\n"
            "description: 'Foo bar.'\n",
            encoding="utf-8",
        )
        (v2 / "zk" / "circom.nullifier-leak.yaml").write_text(
            "schema_version: auditooor.antipattern_catalog.v1\n"
            "pattern_id: circom.nullifier-leak\n"
            "category: zk-soundness\n"
            "language: circom\n"
            "severity_floor: critical\n"
            "severity_ceiling: critical\n"
            "description: 'Nullifier hash missing domain separator.'\n",
            encoding="utf-8",
        )

    # ---- Test cases ----

    def test_v1_record_still_ingested_with_language_family_tag(self):
        # synthetic_fixture: true
        self._seed_v1()
        result = self.query.vault_anti_pattern_corpus()
        self.assertFalse(result.get("degraded"))
        self.assertEqual(result["anti_patterns_count"], 1)
        rec = result["anti_patterns"][0]
        self.assertEqual(rec["anti_pattern_id"], "v1-synth-high")
        self.assertEqual(rec["language_family"], "flat-v1")
        self.assertEqual(rec["source_layout"], "v1")

    def test_v2_record_ingested_with_language_family_from_subdir(self):
        # synthetic_fixture: true
        self._seed_v2()
        result = self.query.vault_anti_pattern_corpus(limit=20)
        self.assertFalse(result.get("degraded"))
        self.assertEqual(result["anti_patterns_count"], 3)
        ids_to_lang = {r["anti_pattern_id"]: r["language_family"] for r in result["anti_patterns"]}
        self.assertEqual(ids_to_lang["go.concurrent-map-write-no-sync"], "go")
        self.assertEqual(ids_to_lang["solidity.batch02-foo"], "solidity")
        self.assertEqual(ids_to_lang["circom.nullifier-leak"], "zk")
        for rec in result["anti_patterns"]:
            self.assertEqual(rec["source_layout"], "v2")

    def test_mixed_v1_v2_returns_both_tagged_correctly(self):
        # synthetic_fixture: true
        self._seed_v1()
        self._seed_v2()
        result = self.query.vault_anti_pattern_corpus(limit=20)
        self.assertEqual(result["anti_patterns_count"], 4)
        self.assertEqual(result["anti_patterns_v1_scanned"], 1)
        self.assertEqual(result["anti_patterns_v2_scanned"], 3)
        layouts = {r["source_layout"] for r in result["anti_patterns"]}
        self.assertEqual(layouts, {"v1", "v2"})
        langs = {r["language_family"] for r in result["anti_patterns"]}
        self.assertEqual(langs, {"flat-v1", "go", "solidity", "zk"})

    def test_language_family_filter_narrows(self):
        # synthetic_fixture: true
        self._seed_v1()
        self._seed_v2()
        result = self.query.vault_anti_pattern_corpus(language_family="zk", limit=20)
        self.assertEqual(result["anti_patterns_count"], 1)
        self.assertEqual(result["anti_patterns"][0]["language_family"], "zk")

    def test_language_family_filter_flat_v1(self):
        # synthetic_fixture: true
        self._seed_v1()
        self._seed_v2()
        result = self.query.vault_anti_pattern_corpus(language_family="flat-v1", limit=20)
        self.assertEqual(result["anti_patterns_count"], 1)
        self.assertEqual(result["anti_patterns"][0]["source_layout"], "v1")

    def test_source_layout_filter_narrows(self):
        # synthetic_fixture: true
        self._seed_v1()
        self._seed_v2()
        result_v1 = self.query.vault_anti_pattern_corpus(source_layout="v1", limit=20)
        self.assertEqual(result_v1["anti_patterns_count"], 1)
        self.assertTrue(all(r["source_layout"] == "v1" for r in result_v1["anti_patterns"]))

        result_v2 = self.query.vault_anti_pattern_corpus(source_layout="v2", limit=20)
        self.assertEqual(result_v2["anti_patterns_count"], 3)
        self.assertTrue(all(r["source_layout"] == "v2" for r in result_v2["anti_patterns"]))

    def test_per_language_scan_counter_present(self):
        # synthetic_fixture: true
        self._seed_v1()
        self._seed_v2()
        result = self.query.vault_anti_pattern_corpus(limit=20)
        per_lang = result.get("anti_patterns_per_language_scanned")
        self.assertIsInstance(per_lang, dict)
        self.assertEqual(per_lang.get("flat-v1"), 1)
        self.assertEqual(per_lang.get("go"), 1)
        self.assertEqual(per_lang.get("solidity"), 1)
        self.assertEqual(per_lang.get("zk"), 1)

    def test_schema_unchanged_for_v1_records(self):
        # synthetic_fixture: true
        self._seed_v1()
        result = self.query.vault_anti_pattern_corpus()
        self.assertEqual(result["schema"], vault_mcp_server.ANTI_PATTERN_CORPUS_SCHEMA)
        rec = result["anti_patterns"][0]
        # Original v1 fields still present (backward-compat).
        for key in (
            "anti_pattern_id",
            "note_path",
            "title",
            "confidence",
            "sample_size",
            "counter_examples",
            "last_validated_at",
            "recommendation",
            "body",
            "body_truncated",
        ):
            self.assertIn(key, rec, f"v1 record missing legacy field: {key}")

    def test_v2_record_carries_severity_floor_ceiling(self):
        # synthetic_fixture: true
        self._seed_v2()
        result = self.query.vault_anti_pattern_corpus(language_family="solidity", limit=10)
        self.assertEqual(result["anti_patterns_count"], 1)
        rec = result["anti_patterns"][0]
        self.assertEqual(rec.get("severity_floor"), "low")
        self.assertEqual(rec.get("severity_ceiling"), "high")
        self.assertEqual(rec.get("category"), "accounting")

    def test_query_filter_matches_v2_body(self):
        # synthetic_fixture: true
        self._seed_v2()
        result = self.query.vault_anti_pattern_corpus(query="nullifier", limit=10)
        self.assertEqual(result["anti_patterns_count"], 1)
        self.assertEqual(result["anti_patterns"][0]["anti_pattern_id"], "circom.nullifier-leak")

    def test_v2_only_when_no_v1_present(self):
        # synthetic_fixture: true
        # Edge case: only v2 catalog exists, no flat *.md records.
        self._seed_v2()
        result = self.query.vault_anti_pattern_corpus(limit=20)
        self.assertEqual(result["anti_patterns_count"], 3)
        self.assertEqual(result["anti_patterns_v1_scanned"], 0)
        self.assertEqual(result["anti_patterns_v2_scanned"], 3)

    def test_v1_only_no_v2_dir_does_not_break(self):
        # synthetic_fixture: true
        # Backward-compat: workspaces without v2/ subdir still work.
        self._seed_v1()
        result = self.query.vault_anti_pattern_corpus()
        self.assertEqual(result["anti_patterns_count"], 1)
        self.assertEqual(result["anti_patterns_v1_scanned"], 1)
        self.assertEqual(result["anti_patterns_v2_scanned"], 0)


if __name__ == "__main__":
    unittest.main()
