"""Tests for the W2.8 ``vault_corpus_lineage`` MCP callable.

Schema: ``auditooor.vault_corpus_lineage.v1``. The callable traces a
corpus record back through its provenance chain (origin -> etl_miner ->
corpus_index -> attribution_trail), mirroring ``vault_finding_lineage``
envelope shape but operating on the upstream corpus pipeline.

Minimum 10 cases per the W2.8 spec
(``docs/WAVE2_W28_MCP_CALLABLE_EXTENSIONS_SPEC_2026-05-16.md`` §1.6).
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def load_module():
    spec = importlib.util.spec_from_file_location(
        "vault_mcp_server_corpus_lineage", MODULE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = load_module()


class VaultCorpusLineageTest(unittest.TestCase):
    """Cases 1-10 (plus dispatch + envelope shape) for vault_corpus_lineage."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-corpus-lin-")
        self.repo = Path(self.tmp.name) / "repo"
        self.repo.mkdir()

        # reference/corpus_mined/INDEX.md + a slice that references our slug.
        self.corpus_root = self.repo / "reference" / "corpus_mined"
        self.corpus_root.mkdir(parents=True)
        (self.corpus_root / "INDEX.md").write_text(
            "# Corpus mining consolidated index\n\n"
            "| Slice | slug |\n"
            "| --- | --- |\n"
            "| aa | fei-rari-fuse-pool-8 |\n",
            encoding="utf-8",
        )
        (self.corpus_root / "defihacklabs_catalog.md").write_text(
            "# DefiHackLabs catalog\n\n"
            "## fei-rari-fuse-pool-8\n"
            "Title: Fei Rari Fuse pool 8 cross-function reentrancy\n"
            "attack_class: cross-function-reentrancy\n"
            "Severity: CRITICAL\n"
            "Notes: 2022-04-12 postmortem.\n",
            encoding="utf-8",
        )

        # tools/audit/etl_miner_registry/<miner>.json containing our slug.
        self.etl_dir = self.repo / "tools" / "audit" / "etl_miner_registry"
        self.etl_dir.mkdir(parents=True)
        (self.etl_dir / "defihacklabs.json").write_text(
            json.dumps(
                {
                    "miner": "defihacklabs",
                    "run_id": "2026-05-10T11:19Z-run",
                    "input_records_count": 421,
                    "output_records_count": 138,
                    "records": [
                        {"slug": "fei-rari-fuse-pool-8", "year": 2022}
                    ],
                }
            ),
            encoding="utf-8",
        )

        # auditooor-mcp/case_study/<file>.md for attribution.
        self.case_dir = self.repo / "auditooor-mcp" / "case_study"
        self.case_dir.mkdir(parents=True)
        (self.case_dir / "defihacklabs_catalog.md").write_text(
            "# DefiHackLabs catalog citation\n\n"
            "Citation: DefiHackLabs (2022-04-12). Fei Rari Fuse pool 8 "
            "reentrancy. SunWeb3Sec / DeFiHackLabs.\n\n"
            "Primary: https://github.com/SunWeb3Sec/DeFiHackLabs/blob/main/"
            "past/2022-04/FeiRari_exp.sol\n"
            "Secondary: https://medium.com/immunefi/fei-rari-postmortem\n\n"
            "Record id: fei-rari-fuse-pool-8\n",
            encoding="utf-8",
        )

        self.vault_dir = self.repo / "obsidian-vault"
        self.vault_dir.mkdir()
        self.vault = vault_mcp_server.VaultQuery(self.vault_dir, self.repo)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    # ------------------------------------------------------------------
    # Case 1 - happy path
    # ------------------------------------------------------------------
    def test_happy_path_resolves_lineage_chain(self) -> None:
        result = self.vault.vault_corpus_lineage(
            record_id="fei-rari-fuse-pool-8",
            max_depth=6,
        )
        self.assertEqual(
            result["schema"], vault_mcp_server.CORPUS_LINEAGE_SCHEMA
        )
        self.assertTrue(result["found"])
        self.assertEqual(result["record_id"], "fei-rari-fuse-pool-8")
        chain = result["lineage_chain"]
        kinds = {entry["kind"] for entry in chain}
        # Should contain origin, etl_miner, corpus_index, attribution_trail.
        self.assertIn("origin", kinds)
        self.assertIn("etl_miner", kinds)
        self.assertIn("corpus_index", kinds)
        self.assertIn("attribution_trail", kinds)
        # Levels are strictly increasing.
        levels = [entry["level"] for entry in chain]
        self.assertEqual(levels, sorted(levels))
        self.assertEqual(levels[0], 0)
        # Standard envelope keys.
        self.assertIn("context_pack_id", result)
        self.assertIn("context_pack_hash", result)
        self.assertIn("source_refs", result)
        self.assertIn("privacy_guards", result)
        self.assertIn("generated_at_utc", result)
        self.assertTrue(
            result["context_pack_id"].startswith(
                vault_mcp_server.CORPUS_LINEAGE_SCHEMA
            )
        )

    # ------------------------------------------------------------------
    # Case 2 - unknown record_id
    # ------------------------------------------------------------------
    def test_unknown_record_id_returns_not_found(self) -> None:
        result = self.vault.vault_corpus_lineage(
            record_id="not-a-real-corpus-slug-zzz"
        )
        self.assertFalse(result["found"])
        self.assertEqual(result["lineage_chain"], [])
        self.assertIsNone(result["record_summary"])
        self.assertEqual(
            result["schema"], vault_mcp_server.CORPUS_LINEAGE_SCHEMA
        )

    # ------------------------------------------------------------------
    # Case 3 - record_id regex rejection
    # ------------------------------------------------------------------
    def test_invalid_record_id_regex_returns_degraded(self) -> None:
        result = self.vault.vault_corpus_lineage(
            record_id="bad id with spaces!"
        )
        self.assertTrue(result["degraded"])
        self.assertIn("record_id must match", result["degraded_reason"])
        self.assertFalse(result["found"])

    # ------------------------------------------------------------------
    # Case 4 - max_depth truncates the chain
    # ------------------------------------------------------------------
    def test_max_depth_truncates_chain_and_marks_degraded(self) -> None:
        result = self.vault.vault_corpus_lineage(
            record_id="fei-rari-fuse-pool-8",
            max_depth=1,
        )
        # max_depth=1 means at most 2 levels (level 0 + level 1).
        self.assertLessEqual(len(result["lineage_chain"]), 2)
        # No attribution_trail reached -> degraded.
        kinds = {entry["kind"] for entry in result["lineage_chain"]}
        self.assertNotIn("attribution_trail", kinds)
        self.assertTrue(result["degraded"])
        self.assertIn(
            "max_depth_reached_before_attribution", result["degraded_reason"]
        )

    # ------------------------------------------------------------------
    # Case 5 - etl_miner_runs populated when miner registry hit
    # ------------------------------------------------------------------
    def test_etl_miner_runs_populated(self) -> None:
        result = self.vault.vault_corpus_lineage(
            record_id="fei-rari-fuse-pool-8",
            include_etl_trace=True,
        )
        runs = result["etl_miner_runs"]
        self.assertTrue(runs)
        first = runs[0]
        self.assertIn("miner_script", first)
        self.assertIn("input_records_count", first)
        self.assertIn("output_records_count", first)
        self.assertEqual(first["input_records_count"], 421)
        self.assertEqual(first["output_records_count"], 138)
        self.assertEqual(first["miner_run_id"], "2026-05-10T11:19Z-run")

    # ------------------------------------------------------------------
    # Case 6 - include_etl_trace=false skips miner walk
    # ------------------------------------------------------------------
    def test_include_etl_trace_false_skips_miner_walk(self) -> None:
        result = self.vault.vault_corpus_lineage(
            record_id="fei-rari-fuse-pool-8",
            include_etl_trace=False,
            include_source_ref=True,
        )
        self.assertEqual(result["etl_miner_runs"], [])
        kinds = {entry["kind"] for entry in result["lineage_chain"]}
        self.assertNotIn("etl_miner", kinds)

    # ------------------------------------------------------------------
    # Case 7 - include_source_ref=false skips attribution
    # ------------------------------------------------------------------
    def test_include_source_ref_false_skips_attribution(self) -> None:
        result = self.vault.vault_corpus_lineage(
            record_id="fei-rari-fuse-pool-8",
            include_source_ref=False,
        )
        self.assertEqual(result["attribution"]["primary_source_url"], "")
        self.assertEqual(result["attribution"]["citation_block"], "")
        kinds = {entry["kind"] for entry in result["lineage_chain"]}
        self.assertNotIn("attribution_trail", kinds)

    # ------------------------------------------------------------------
    # Case 8 - attribution extracted from case study
    # ------------------------------------------------------------------
    def test_attribution_extracted_from_case_study(self) -> None:
        result = self.vault.vault_corpus_lineage(
            record_id="fei-rari-fuse-pool-8",
            include_source_ref=True,
        )
        attr = result["attribution"]
        self.assertTrue(attr["primary_source_url"].startswith("https://"))
        self.assertIn("DefiHackLabs", attr["citation_block"])
        self.assertTrue(
            any("immunefi" in u for u in attr["secondary_source_urls"])
        )

    # ------------------------------------------------------------------
    # Case 9 - context_pack_hash stable across calls
    # ------------------------------------------------------------------
    def test_context_pack_hash_stable_with_frozen_utc(self) -> None:
        frozen = "2026-05-16T12:00:00Z"
        a = self.vault.vault_corpus_lineage(
            record_id="fei-rari-fuse-pool-8",
            max_depth=6,
            _frozen_utc=frozen,
        )
        b = self.vault.vault_corpus_lineage(
            record_id="fei-rari-fuse-pool-8",
            max_depth=6,
            _frozen_utc=frozen,
        )
        self.assertEqual(a["context_pack_hash"], b["context_pack_hash"])
        self.assertEqual(a["context_pack_id"], b["context_pack_id"])
        # Different inputs -> different hash.
        c = self.vault.vault_corpus_lineage(
            record_id="fei-rari-fuse-pool-8",
            max_depth=2,
            _frozen_utc=frozen,
        )
        self.assertNotEqual(a["context_pack_hash"], c["context_pack_hash"])

    # ------------------------------------------------------------------
    # Case 10 - privacy: symlinks blocked + absolute paths not leaked
    # ------------------------------------------------------------------
    def test_symlinks_in_corpus_blocked_and_no_absolute_paths(self) -> None:
        # Set up a symlinked corpus md file - the walker MUST skip it.
        target = self.corpus_root / "real_target.md"
        target.write_text(
            "# real target file\n\nfei-rari-fuse-pool-8\n", encoding="utf-8"
        )
        link = self.corpus_root / "symlink_to_target.md"
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError):  # pragma: no cover - Windows
            self.skipTest("symlinks not supported on this filesystem")
        result = self.vault.vault_corpus_lineage(
            record_id="fei-rari-fuse-pool-8",
        )
        for ref in result["source_refs"]:
            # Never absolute, never contain the symlink filename.
            self.assertFalse(
                Path(ref).is_absolute(),
                f"source ref escaped to absolute path: {ref}",
            )
            self.assertNotIn("symlink_to_target.md", ref)
        blob = json.dumps(result)
        self.assertNotIn(str(self.repo.resolve()), blob)
        self.assertTrue(result["privacy_guards"]["symlinks_blocked"])

    # ------------------------------------------------------------------
    # Case 11 - dispatch via VaultQuery.call
    # ------------------------------------------------------------------
    def test_dispatch_via_call_method(self) -> None:
        result = self.vault.call(
            "vault_corpus_lineage",
            {"record_id": "fei-rari-fuse-pool-8", "max_depth": 4},
        )
        self.assertEqual(
            result["schema"], vault_mcp_server.CORPUS_LINEAGE_SCHEMA
        )
        self.assertTrue(result["found"])

    # ------------------------------------------------------------------
    # Case 12 - TOOL_SCHEMAS registration is correct
    # ------------------------------------------------------------------
    def test_tool_schemas_entry_registered(self) -> None:
        names = [t["name"] for t in vault_mcp_server.TOOL_SCHEMAS]
        self.assertIn("vault_corpus_lineage", names)
        entry = next(
            t for t in vault_mcp_server.TOOL_SCHEMAS
            if t["name"] == "vault_corpus_lineage"
        )
        props = entry["inputSchema"]["properties"]
        self.assertIn("record_id", props)
        self.assertIn("max_depth", props)
        self.assertIn("include_etl_trace", props)
        self.assertIn("include_source_ref", props)
        self.assertIn("corpus_root", props)
        self.assertIn("workspace_path", props)
        self.assertEqual(entry["inputSchema"]["required"], ["record_id"])
        # record_id has the documented regex.
        self.assertEqual(
            props["record_id"]["pattern"], r"^[A-Za-z0-9._:/\-]{8,160}$"
        )

    # ------------------------------------------------------------------
    # Case 13 - missing record_id input
    # ------------------------------------------------------------------
    def test_missing_record_id_returns_degraded(self) -> None:
        result = self.vault.vault_corpus_lineage()
        self.assertTrue(result["degraded"])
        self.assertEqual(result["degraded_reason"], "missing_record_id")
        self.assertFalse(result["found"])
        # Schema and envelope still present.
        self.assertEqual(
            result["schema"], vault_mcp_server.CORPUS_LINEAGE_SCHEMA
        )
        self.assertIn("context_pack_id", result)
        self.assertIn("privacy_guards", result)


if __name__ == "__main__":
    unittest.main()
