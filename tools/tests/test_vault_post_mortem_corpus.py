"""Tests for the ``vault_post_mortem_corpus`` MCP callable.

Wave-4 capability lift (W4.9). Surfaces post-mortem ETL corpus records
emitted by ``tools/hackerman-etl-from-post-mortem.py`` (rekt / defillama
/ public exploit writeups), carrying ``verification_tier``.

Exercises:

- envelope shape (schema / context_pack_id / context_pack_hash);
- degraded envelopes (corpus_dir_required, corpus_dir_not_found);
- Rule 37 tier discipline: default tier-1/tier-2-only;
  ``include_synthetic=true`` widens to tier-3+;
- source / attack_class / target_project substring filters;
- AND-composition across filters;
- limit clamping of records;
- dispatch routing via ``_dispatch``.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "vault_mcp_server_post_mortem_corpus_test", MODULE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module()


def _record(
    *,
    record_id: str,
    source: str,
    tier: str,
    attack_class: str,
    target_project: str,
    amount_usd: float | None = 1000000.0,
) -> dict[str, Any]:
    return {
        "record_id": record_id,
        "record_tier": "public-corpus",
        "verification_tier": tier,
        "source_extraction_method": f"web-scrape-{source}",
        "source_audit_ref": {
            "url": f"https://{source}.example.invalid/{record_id}",
            "fetched_at_utc": "2026-05-10T00:00:00Z",
            "payload_sha256": "0" * 64,
        },
        "target_project": target_project,
        "attack_class": attack_class,
        "severity": "critical",
        "amount_usd": amount_usd,
        "incident_date": "2025-11-01",
        "attack_vector_summary": f"{target_project} exploited via {attack_class}.",
        "fix_commit_refs": ["https://github.com/x/y/commit/abc1234"],
    }


class PostMortemCorpusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="post-mortem-mcp-test-")
        self.root = Path(self.tmp.name)
        self.corpus = self.root / "corpus"
        self.corpus.mkdir()

        # tier-2 rekt record
        self._write(
            "rekt/euler-r1",
            _record(
                record_id="post-mortem-rekt:euler:aaaa1111bbbb",
                source="rekt",
                tier="tier-2-verified-public-archive",
                attack_class="donation-attack",
                target_project="Euler Finance",
            ),
        )
        # tier-2 defillama record
        self._write(
            "defillama/wormhole-r2",
            _record(
                record_id="post-mortem-defillama:wormhole:cccc2222dddd",
                source="defillama",
                tier="tier-2-verified-public-archive",
                attack_class="signature-replay",
                target_project="Wormhole Bridge",
            ),
        )
        # tier-1 rekt record
        self._write(
            "rekt/curve-r3",
            _record(
                record_id="post-mortem-rekt:curve:eeee3333ffff",
                source="rekt",
                tier="tier-1-officially-disclosed",
                attack_class="reentrancy-external-call",
                target_project="Curve Finance",
            ),
        )
        # tier-3 synthetic record (filtered out by default)
        self._write(
            "rekt/synthetic-r4",
            _record(
                record_id="post-mortem-rekt:synthetic:9999gggg0000",
                source="rekt",
                tier="tier-3-synthetic-taxonomy-anchored",
                attack_class="donation-attack",
                target_project="Synthetic Protocol",
            ),
        )

        self.vault_dir = self.root / "obsidian-vault"
        self.vault_dir.mkdir()
        self.vault = vault_mcp_server.VaultQuery(self.vault_dir, self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _write(self, rel: str, record: dict[str, Any]) -> None:
        path = self.corpus / f"{rel}.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(record), encoding="utf-8")

    def _call(self, **kwargs: Any) -> dict[str, Any]:
        return self.vault.vault_post_mortem_corpus(
            corpus_dir=str(self.corpus), **kwargs
        )

    # 1.
    def test_envelope_shape(self):
        r = self._call()
        self.assertEqual(r["schema"], vault_mcp_server.POST_MORTEM_CORPUS_SCHEMA)
        self.assertTrue(
            r["context_pack_id"].startswith(
                vault_mcp_server.POST_MORTEM_CORPUS_SCHEMA + ":"
            )
        )
        self.assertEqual(len(r["context_pack_hash"]), 64)
        self.assertFalse(r["degraded"])

    # 2.
    def test_default_tier_discipline_excludes_synthetic(self):
        r = self._call()
        # 4 records scanned, tier-3 synthetic filtered out -> 3 returned.
        self.assertEqual(r["records_scanned"], 4)
        self.assertEqual(r["records_count"], 3)
        self.assertEqual(r["tier_filtered_out"], 1)
        self.assertFalse(r["include_synthetic"])
        for rec in r["records"]:
            self.assertIn(
                rec["verification_tier"],
                {"tier-1-officially-disclosed", "tier-2-verified-public-archive"},
            )

    # 3.
    def test_include_synthetic_widens(self):
        r = self._call(include_synthetic=True)
        self.assertEqual(r["records_count"], 4)
        self.assertEqual(r["tier_filtered_out"], 0)
        self.assertTrue(r["include_synthetic"])

    # 4.
    def test_source_filter(self):
        r = self._call(source="defillama")
        self.assertEqual(r["records_count"], 1)
        self.assertEqual(r["records"][0]["target_project"], "Wormhole Bridge")

    # 5.
    def test_attack_class_filter(self):
        r = self._call(attack_class="signature-replay")
        self.assertEqual(r["records_count"], 1)
        self.assertEqual(r["records"][0]["attack_class"], "signature-replay")

    # 6.
    def test_attack_class_filter_case_insensitive(self):
        r = self._call(attack_class="REENTRANCY-external-call")
        self.assertEqual(r["records_count"], 1)
        self.assertEqual(r["records"][0]["target_project"], "Curve Finance")

    # 7.
    def test_target_project_substring_filter(self):
        r = self._call(target_project="finance")
        # Euler Finance + Curve Finance (tier-1/2); synthetic excluded.
        self.assertEqual(r["records_count"], 2)

    # 8.
    def test_and_composition(self):
        # rekt + donation-attack: Euler (tier-2) + synthetic (tier-3,
        # filtered by default) -> 1.
        r = self._call(source="rekt", attack_class="donation-attack")
        self.assertEqual(r["records_count"], 1)
        self.assertEqual(r["records"][0]["target_project"], "Euler Finance")
        # With include_synthetic, both match.
        wide = self._call(
            source="rekt", attack_class="donation-attack", include_synthetic=True
        )
        self.assertEqual(wide["records_count"], 2)

    # 9.
    def test_limit_clamps_records(self):
        r = self._call(limit=1)
        self.assertEqual(r["records_returned"], 1)
        self.assertEqual(r["records_count"], 3)

    # 10.
    def test_corpus_dir_required_degraded(self):
        r = self.vault.vault_post_mortem_corpus()
        self.assertTrue(r["degraded"])
        self.assertEqual(r["reason"], "corpus_dir_required")

    # 11.
    def test_corpus_dir_not_found_degraded(self):
        r = self.vault.vault_post_mortem_corpus(
            corpus_dir=str(self.root / "nonexistent")
        )
        self.assertTrue(r["degraded"])
        self.assertEqual(r["reason"], "corpus_dir_not_found")

    # 12.
    def test_source_url_and_fix_refs_passthrough(self):
        r = self._call(source="defillama")
        rec = r["records"][0]
        self.assertTrue(rec["source_url"].startswith("https://defillama"))
        self.assertEqual(len(rec["fix_commit_refs"]), 1)

    # 13.
    def test_dispatch_via_call(self):
        r = self.vault._dispatch(
            "vault_post_mortem_corpus", {"corpus_dir": str(self.corpus)}
        )
        self.assertEqual(r["schema"], vault_mcp_server.POST_MORTEM_CORPUS_SCHEMA)
        self.assertEqual(r["records_count"], 3)


if __name__ == "__main__":
    unittest.main()
