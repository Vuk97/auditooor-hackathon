"""Tests for the ``vault_corpus_freshness`` MCP callable.

Wave-2 PR-B (W2.x) - corpus freshness reporter. Exercises:

- envelope shape (schema / context_pack_id / context_pack_hash);
- empty-tags-dir degraded envelope;
- empty-result envelope when filter matches zero records;
- predicates (target_repo / attack_class / target_domain) individually;
- most_recent_year derivation from ``year`` field;
- youngest_iso derivation from ``Published-at`` in ``required_preconditions``;
- freshness_band thresholds (hot / warm / cool / stale);
- suggested_refresh_after_iso delta math;
- deterministic ``current_date_iso`` override;
- AND-composition across multiple predicates;
- dispatch routing via ``call_tool``.
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
        "vault_mcp_server_corpus_freshness_test", MODULE_PATH
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
    target_repo: str,
    target_domain: str,
    attack_class: str,
    year: int | None,
    published_at: str | None = None,
) -> dict[str, Any]:
    preconds: list[str] = []
    if published_at:
        preconds.append(f"Published-at {published_at}")
    return {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": record_id,
        "target_repo": target_repo,
        "target_domain": target_domain,
        "target_language": "solidity",
        "attack_class": attack_class,
        "bug_class": "test-bug-class",
        "severity_at_finding": "medium",
        "year": year,
        "required_preconditions": preconds,
        "source_audit_ref": f"https://example.invalid/{record_id}",
        "function_shape": {
            "shape_tags": ["verification_tier:tier-2-static-fixture-passed"],
        },
    }


class CorpusFreshnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="corpus-freshness-mcp-test-")
        self.root = Path(self.tmp.name)
        self.tags_dir = self.root / "tags"
        self.tags_dir.mkdir()

        # Hot record: 2026-05-01 (within ~2 weeks of frozen-today 2026-05-15)
        self._write(
            "lending_protocols/hot-aave-r1",
            _record(
                record_id="lending:aave:hot:r1",
                target_repo="aave/aave-v3-core",
                target_domain="lending",
                attack_class="reentrancy-external-call",
                year=2026,
                published_at="2026-05-01T00:00:00Z",
            ),
        )

        # Warm record: 2026-01-01 (~135 days ago vs 2026-05-15)
        self._write(
            "oracle_advisories/warm-chainlink-r2",
            _record(
                record_id="oracle:chainlink:warm:r2",
                target_repo="smartcontractkit/chainlink",
                target_domain="oracle",
                attack_class="oracle-manipulation",
                year=2026,
                published_at="2026-01-01T00:00:00Z",
            ),
        )

        # Cool record: 2025-09-01 (~256 days ago)
        self._write(
            "amm/cool-uniswap-r3",
            _record(
                record_id="amm:uniswap:cool:r3",
                target_repo="uniswap/v3-core",
                target_domain="amm",
                attack_class="price-manipulation",
                year=2025,
                published_at="2025-09-01T00:00:00Z",
            ),
        )

        # Stale record: 2023-06-15 (way over 365 days)
        self._write(
            "bridges/stale-bridge-r4",
            _record(
                record_id="bridges:misc:stale:r4",
                target_repo="bridge/foo",
                target_domain="bridge",
                attack_class="signature-replay",
                year=2023,
                published_at="2023-06-15T00:00:00Z",
            ),
        )

        # Year-only record (no Published-at): 2024 -> falls back to
        # 2024-12-31 -> ~500 days ago vs 2026-05-15 -> stale.
        self._write(
            "year_only/r5",
            _record(
                record_id="year-only:r5",
                target_repo="year/only",
                target_domain="lending",
                attack_class="reentrancy-external-call",
                year=2024,
                published_at=None,
            ),
        )

        self.vault_dir = self.root / "obsidian-vault"
        self.vault_dir.mkdir()
        self.vault = vault_mcp_server.VaultQuery(self.vault_dir, self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    # ---- helpers --------------------------------------------------------

    def _write(self, rel_dir: str, record: dict[str, Any]) -> None:
        d = self.tags_dir / rel_dir
        d.mkdir(parents=True, exist_ok=True)
        (d / "record.json").write_text(json.dumps(record), encoding="utf-8")

    def _call(self, **kwargs: Any) -> dict[str, Any]:
        return self.vault.vault_corpus_freshness(
            workspace_path=str(self.root),
            tags_dir=str(self.tags_dir),
            current_date_iso="2026-05-15",
            **kwargs,
        )

    # ---- tests ----------------------------------------------------------

    # 1.
    def test_envelope_shape(self):
        result = self._call()
        self.assertEqual(
            result["schema"], vault_mcp_server.CORPUS_FRESHNESS_SCHEMA
        )
        self.assertTrue(
            result["context_pack_id"].startswith(
                vault_mcp_server.CORPUS_FRESHNESS_SCHEMA + ":"
            )
        )
        self.assertEqual(len(result["context_pack_hash"]), 64)
        self.assertFalse(result["degraded"])
        self.assertEqual(result["records_count"], 5)
        self.assertEqual(result["most_recent_year"], 2026)
        # Hot record (2026-05-01) dominates -> hot band.
        self.assertEqual(result["freshness_band"], "hot")

    # 2.
    def test_tags_dir_missing_degraded(self):
        result = self.vault.vault_corpus_freshness(
            workspace_path=str(self.root),
            tags_dir=str(self.root / "nonexistent"),
            current_date_iso="2026-05-15",
        )
        self.assertTrue(result["degraded"])
        self.assertEqual(result["degraded_reason"], "tags_dir_missing")
        self.assertEqual(result["records_count"], 0)
        self.assertIsNone(result["most_recent_year"])
        self.assertEqual(result["freshness_band"], "stale")
        # delta = 7 days -> 2026-05-22.
        self.assertEqual(result["suggested_refresh_after_iso"], "2026-05-22")

    # 3.
    def test_empty_result_envelope(self):
        result = self._call(target_repo="totally-nonexistent-repo-xyz")
        self.assertFalse(result["degraded"])
        self.assertEqual(result["records_count"], 0)
        self.assertIsNone(result["most_recent_year"])
        self.assertIsNone(result["days_since_youngest"])
        self.assertEqual(result["freshness_band"], "stale")
        # delta = 7 days when stale.
        self.assertEqual(result["suggested_refresh_after_iso"], "2026-05-22")

    # 4.
    def test_predicate_target_repo(self):
        result = self._call(target_repo="aave")
        self.assertEqual(result["records_count"], 1)
        self.assertEqual(result["most_recent_year"], 2026)
        self.assertEqual(result["youngest_iso"], "2026-05-01T00:00:00Z")
        self.assertEqual(result["freshness_band"], "hot")

    # 5.
    def test_predicate_attack_class(self):
        result = self._call(attack_class="signature-replay")
        self.assertEqual(result["records_count"], 1)
        self.assertEqual(result["most_recent_year"], 2023)
        self.assertEqual(result["freshness_band"], "stale")

    # 6.
    def test_predicate_target_domain(self):
        result = self._call(target_domain="oracle")
        self.assertEqual(result["records_count"], 1)
        self.assertEqual(result["youngest_iso"], "2026-01-01T00:00:00Z")
        # 2026-05-15 - 2026-01-01 = 134 days -> warm (<180d).
        self.assertEqual(result["freshness_band"], "warm")

    # 7.
    def test_freshness_band_cool(self):
        result = self._call(target_domain="amm")
        self.assertEqual(result["records_count"], 1)
        self.assertEqual(result["freshness_band"], "cool")
        # delta = 90 days -> 2026-08-13.
        self.assertEqual(result["suggested_refresh_after_iso"], "2026-08-13")

    # 8.
    def test_freshness_band_stale(self):
        result = self._call(target_domain="bridge")
        self.assertEqual(result["records_count"], 1)
        self.assertEqual(result["freshness_band"], "stale")
        self.assertGreater(result["days_since_youngest"], 365.0)

    # 9.
    def test_year_only_fallback(self):
        # year_only record has year=2024, no Published-at -> uses
        # 2024-12-31 as youngest. days_since_youngest > 365 -> stale.
        result = self._call(target_repo="year/only")
        self.assertEqual(result["records_count"], 1)
        self.assertEqual(result["most_recent_year"], 2024)
        self.assertEqual(result["youngest_iso"], "2024-12-31T00:00:00Z")
        self.assertEqual(result["freshness_band"], "stale")

    # 10.
    def test_and_composition(self):
        # attack_class=reentrancy-external-call appears in 2 records:
        # hot (2026-05-01, aave) and stale (year-only, 2024).
        # Adding target_domain=lending should keep both.
        result = self._call(
            attack_class="reentrancy-external-call",
            target_domain="lending",
        )
        self.assertEqual(result["records_count"], 2)
        # Youngest = 2026-05-01 -> hot.
        self.assertEqual(result["freshness_band"], "hot")
        # Adding target_repo=aave narrows to 1.
        narrowed = self._call(
            attack_class="reentrancy-external-call",
            target_domain="lending",
            target_repo="aave",
        )
        self.assertEqual(narrowed["records_count"], 1)

    # 11.
    def test_suggested_refresh_after_iso_per_band(self):
        # hot band -> +30 days from 2026-05-15 -> 2026-06-14.
        hot = self._call(target_repo="aave")
        self.assertEqual(hot["freshness_band"], "hot")
        self.assertEqual(hot["suggested_refresh_after_iso"], "2026-06-14")
        # warm band -> +60 days -> 2026-07-14.
        warm = self._call(target_domain="oracle")
        self.assertEqual(warm["freshness_band"], "warm")
        self.assertEqual(warm["suggested_refresh_after_iso"], "2026-07-14")
        # stale -> +7 days -> 2026-05-22.
        stale = self._call(target_domain="bridge")
        self.assertEqual(stale["freshness_band"], "stale")
        self.assertEqual(stale["suggested_refresh_after_iso"], "2026-05-22")

    # 12.
    def test_filter_echo(self):
        result = self._call(
            target_repo="AAVE", attack_class="Reentrancy-EXTERNAL-call"
        )
        self.assertEqual(result["filter"]["target_repo"], "AAVE")
        self.assertEqual(result["filter"]["attack_class"], "Reentrancy-EXTERNAL-call")
        self.assertEqual(result["filter"]["target_domain"], "")

    # 13.
    def test_dispatch_via_call_tool(self):
        result = self.vault._dispatch(
            "vault_corpus_freshness",
            {
                "workspace_path": str(self.root),
                "tags_dir": str(self.tags_dir),
                "current_date_iso": "2026-05-15",
                "target_repo": "aave",
            },
        )
        self.assertEqual(
            result["schema"], vault_mcp_server.CORPUS_FRESHNESS_SCHEMA
        )
        self.assertEqual(result["records_count"], 1)
        self.assertEqual(result["freshness_band"], "hot")


if __name__ == "__main__":
    unittest.main()
