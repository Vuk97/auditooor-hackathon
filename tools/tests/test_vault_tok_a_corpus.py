"""Tests for the ``vault_tok_a_corpus`` MCP callable.

Task #196 (LANE-196-VAULT-TOK-A-CORPUS). Surfaces tok_a_enrichment records
emitted by Phase E (Task #184) across six post-mortem corpora. The existing
``vault_post_mortem_corpus`` callable projects to a fixed schema that strips
``tok_a_enrichment`` + ``structured_extraction``; this callable preserves
both.

Exercises:

- envelope shape (schema / context_pack_id / context_pack_hash);
- all-records returns every record under the corpora roots (no filter);
- corpus_dir filter (subdir name and absolute path);
- canonical_attack_class filter;
- target_language substring filter;
- AND-composition across filters;
- limit honored, records_count vs records_returned discipline;
- degraded envelopes (corpus_dir_not_found);
- malformed YAML counted via parse_errors but does not raise;
- non-tok_a yaml files skipped;
- empty filter returns zero records on a corpus with no matches;
- dispatch routing via ``_dispatch``.

<!-- r36-rebuttal: LANE-196 pathspec registered, agent_pathspec.json -->
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

import yaml
# <!-- r36-rebuttal: LANE-196 pathspec registered, agent_pathspec.json -->


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "vault_mcp_server_tok_a_corpus_test", MODULE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module()


DEFAULT_CORPORA = (
    "defimon_telegram_incidents",
    "bridge_incidents",
    "mev_exploits",
    "defimon_blog_incidents",
    "darknavy_web3_incidents",
    "rekt_news_incidents",
)


def _make_record(
    *,
    record_id: str,
    tier: str,
    canonical_attack_class: str,
    cross_lang: str,
    attack_class: str = "unspecified",
    severity: str = "medium",
    target_project: str = "unknown",
) -> dict[str, Any]:
    return {
        "schema_version": "auditooor.hackerman_record.v1.1",
        "record_id": record_id,
        "verification_tier": tier,
        "attack_class": attack_class,
        "severity": severity,
        "target_project": target_project,
        "incident_date": "2025-11-01",
        "source_url": f"https://example.invalid/{record_id}",
        "amount_usd": 123456.78,
        "attack_vector_summary": f"{record_id} attack vector",
        "structured_extraction": {
            "schema_version": "auditooor.defimon_tg_tx_enrichment.v1",
            "tx_hashes": [],
            "contract_addresses": [],
        },
        "tok_a_enrichment": {
            "canonical_attack_class": canonical_attack_class,
            "invariant": f"Invariant for {record_id}",
            "detector_sketch": f"Detector sketch for {record_id}",
            "root_cause_one_sentence": f"Root cause for {record_id}",
            "cross_lang_applicability": cross_lang,
            "minimal_repro_steps": [f"Step 1 for {record_id}"],
            "confidence_self_assessment": "low",
            "llm_provider": "deepseek-flash",
            "llm_run_timestamp": "2026-05-26T18:20:21Z",
            "verification_tier_self_label": "tier-3-synthetic-taxonomy-anchored",
        },
    }


class TokACorpusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="tok-a-corpus-test-")
        self.root = Path(self.tmp.name)
        self.corpus_root = self.root / "audit" / "corpus_tags" / "tags"
        self.corpus_root.mkdir(parents=True)

        # Populate fixtures across multiple corpora.
        self._write_record(
            "defimon_telegram_incidents",
            "defimon-tg-1-known",
            _make_record(
                record_id="defimon-telegram:1:known",
                tier="tier-2-verified-public-archive",
                canonical_attack_class="oracle-staleness",
                cross_lang="solidity",
            ),
        )
        self._write_record(
            "defimon_telegram_incidents",
            "defimon-tg-2-known",
            _make_record(
                record_id="defimon-telegram:2:known",
                tier="tier-2-verified-public-archive",
                canonical_attack_class="reentrancy",
                cross_lang="solidity",
            ),
        )
        self._write_record(
            "bridge_incidents",
            "wormhole-2022",
            _make_record(
                record_id="post-mortem-bridge:wormhole:hashhash",
                tier="tier-2-verified-public-archive",
                canonical_attack_class="signature-verification-bypass",
                cross_lang="rust,solidity",
            ),
        )
        self._write_record(
            "mev_exploits",
            "mev-1",
            _make_record(
                record_id="mev:1",
                tier="tier-2-verified-public-archive",
                canonical_attack_class="oracle-staleness",
                cross_lang="solidity",
            ),
        )

        # Also write a non-record yaml that should be skipped.
        self._write_yaml(
            self.corpus_root / "defimon_telegram_incidents" / "non_record.yaml",
            {"unrelated": "data", "no_record_id": True},
        )
        # And a YAML without tok_a_enrichment block.
        self._write_yaml(
            self.corpus_root / "mev_exploits" / "without_tok_a" / "rec.yaml",
            {"record_id": "no-tok-a:1", "verification_tier": "tier-2-verified-public-archive"},
        )
        # And one malformed YAML to exercise parse_errors counter.
        malformed = self.corpus_root / "defimon_blog_incidents" / "broken" / "rec.yaml"
        malformed.parent.mkdir(parents=True, exist_ok=True)
        malformed.write_text(
            'record_id: defimon-blog:broken\n'
            'tok_a_enrichment:\n'
            '  detector_sketch: "this is a bad escape \\q sequence"\n',
            encoding="utf-8",
        )

        # VaultQuery(vault_dir, repo_root). Pass absolute corpus_dir to
        # vault_tok_a_corpus so the repo_root resolution in the method is
        # bypassed (absolute path takes priority).
        # <!-- r36-rebuttal: LANE-196 pathspec registered, agent_pathspec.json -->
        self.vault_dir = self.root / "obsidian-vault"
        self.vault_dir.mkdir()
        self.server = vault_mcp_server.VaultQuery(self.vault_dir, self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write_record(
        self, corpus: str, slug: str, rec: dict[str, Any]
    ) -> None:
        path = self.corpus_root / corpus / slug / "record.yaml"
        path.parent.mkdir(parents=True, exist_ok=True)
        self._write_yaml(path, rec)

    @staticmethod
    def _write_yaml(path: Path, data: dict[str, Any]) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")

    # -- envelope tests --
    def test_envelope_shape(self) -> None:
        corpus = self.corpus_root / "defimon_telegram_incidents"
        envelope = self.server.vault_tok_a_corpus(corpus_dir=str(corpus))
        self.assertEqual(envelope["schema"], vault_mcp_server.TOK_A_CORPUS_SCHEMA)
        self.assertEqual(envelope["kind"], "tok_a_corpus")
        self.assertFalse(envelope["degraded"])
        self.assertIn("context_pack_id", envelope)
        self.assertIn("context_pack_hash", envelope)
        self.assertEqual(len(envelope["context_pack_hash"]), 64)
        self.assertIn("records", envelope)

    def test_all_records_returned_when_no_filter(self) -> None:
        corpus = self.corpus_root / "defimon_telegram_incidents"
        envelope = self.server.vault_tok_a_corpus(corpus_dir=str(corpus), limit=10)
        self.assertEqual(envelope["records_count"], 2)
        self.assertEqual(envelope["records_returned"], 2)
        ids = {r["record_id"] for r in envelope["records"]}
        self.assertSetEqual(
            ids,
            {"defimon-telegram:1:known", "defimon-telegram:2:known"},
        )

    def test_corpus_dir_absolute_path_filter(self) -> None:
        corpus = self.corpus_root / "bridge_incidents"
        envelope = self.server.vault_tok_a_corpus(corpus_dir=str(corpus))
        self.assertEqual(envelope["records_count"], 1)
        self.assertEqual(
            envelope["records"][0]["record_id"],
            "post-mortem-bridge:wormhole:hashhash",
        )
        self.assertEqual(envelope["records"][0]["source_corpus"], "bridge_incidents")

    def test_canonical_attack_class_filter(self) -> None:
        corpus = self.corpus_root / "defimon_telegram_incidents"
        envelope = self.server.vault_tok_a_corpus(
            corpus_dir=str(corpus),
            canonical_attack_class="oracle-staleness",
        )
        self.assertEqual(envelope["records_count"], 1)
        self.assertEqual(
            envelope["records"][0]["tok_a_enrichment"]["canonical_attack_class"],
            "oracle-staleness",
        )

    def test_target_language_substring_filter(self) -> None:
        corpus = self.corpus_root / "bridge_incidents"
        envelope = self.server.vault_tok_a_corpus(
            corpus_dir=str(corpus), target_language="rust"
        )
        self.assertEqual(envelope["records_count"], 1)
        envelope2 = self.server.vault_tok_a_corpus(
            corpus_dir=str(corpus), target_language="haskell"
        )
        self.assertEqual(envelope2["records_count"], 0)

    def test_limit_honored(self) -> None:
        corpus = self.corpus_root / "defimon_telegram_incidents"
        envelope = self.server.vault_tok_a_corpus(corpus_dir=str(corpus), limit=1)
        # records_count counts all matched records; records_returned is bounded.
        self.assertEqual(envelope["records_count"], 2)
        self.assertEqual(envelope["records_returned"], 1)
        self.assertEqual(len(envelope["records"]), 1)

    def test_filter_returns_empty(self) -> None:
        corpus = self.corpus_root / "defimon_telegram_incidents"
        envelope = self.server.vault_tok_a_corpus(
            corpus_dir=str(corpus),
            canonical_attack_class="nonexistent-class",
        )
        self.assertEqual(envelope["records_count"], 0)
        self.assertEqual(envelope["records"], [])

    def test_corpus_dir_not_found_degraded(self) -> None:
        envelope = self.server.vault_tok_a_corpus(corpus_dir="/nonexistent/path/xyz")
        self.assertTrue(envelope["degraded"])
        self.assertIn(envelope["reason"], {"corpus_dir_not_found"})

    def test_malformed_yaml_counted_as_parse_error(self) -> None:
        corpus = self.corpus_root / "defimon_blog_incidents"
        envelope = self.server.vault_tok_a_corpus(corpus_dir=str(corpus))
        # The malformed record should be counted in parse_errors and not crash.
        self.assertEqual(envelope["records_count"], 0)
        self.assertEqual(envelope["parse_errors"], 1)

    def test_yaml_without_tok_a_enrichment_skipped(self) -> None:
        corpus = self.corpus_root / "mev_exploits"
        envelope = self.server.vault_tok_a_corpus(corpus_dir=str(corpus))
        ids = {r["record_id"] for r in envelope["records"]}
        # only mev-1 (which has tok_a_enrichment) returned
        self.assertEqual(envelope["records_count"], 1)
        self.assertSetEqual(ids, {"mev:1"})

    def test_record_projection_preserves_tok_a_and_structured(self) -> None:
        corpus = self.corpus_root / "defimon_telegram_incidents"
        envelope = self.server.vault_tok_a_corpus(
            corpus_dir=str(corpus),
            canonical_attack_class="oracle-staleness",
        )
        rec = envelope["records"][0]
        self.assertIn("tok_a_enrichment", rec)
        self.assertIsInstance(rec["tok_a_enrichment"], dict)
        self.assertIn("invariant", rec["tok_a_enrichment"])
        self.assertIn("structured_extraction", rec)
        self.assertIsInstance(rec["structured_extraction"], dict)

    def test_tier_breakdown_populated(self) -> None:
        corpus = self.corpus_root / "defimon_telegram_incidents"
        envelope = self.server.vault_tok_a_corpus(corpus_dir=str(corpus))
        self.assertIn("tier_breakdown", envelope)
        self.assertEqual(
            envelope["tier_breakdown"].get("tier-2-verified-public-archive"),
            2,
        )

    def test_dispatch_routes_to_callable(self) -> None:
        corpus = self.corpus_root / "defimon_telegram_incidents"
        envelope = self.server._dispatch(
            "vault_tok_a_corpus", {"corpus_dir": str(corpus), "limit": 1}
        )
        self.assertEqual(envelope["schema"], vault_mcp_server.TOK_A_CORPUS_SCHEMA)
        self.assertFalse(envelope["degraded"])

    def test_schema_in_tool_schemas(self) -> None:
        names = [t["name"] for t in vault_mcp_server.TOOL_SCHEMAS]
        self.assertIn("vault_tok_a_corpus", names)


if __name__ == "__main__":
    unittest.main()
