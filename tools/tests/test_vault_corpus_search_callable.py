"""Tests for the ``vault_corpus_search`` MCP callable.

Wave-1 hackerman capability lift (PR #726). Exercises:

- envelope shape (schema / context_pack_id / context_pack_hash);
- empty-result envelope when no predicate matches;
- each predicate individually:
  - target_repo (substring, case-insensitive);
  - attack_class (matches attack_class + attack_classes_to_try);
  - target_domain;
  - language;
  - severity;
  - slug_substring;
  - source_url_substring;
- min_verification_tier filter (rank tier-1 above tier-2);
- exclude_quarantine (drops tier-5 by default; opt-in to keep);
- AND-composition across multiple predicates;
- limit clamping;
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
        "vault_mcp_server_corpus_search_test", MODULE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module()


def _record_tier1_reentrancy_solidity_aave() -> dict[str, Any]:
    return {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": "lending-protocols:aave-v3:r1:t1",
        "source_audit_ref": "https://github.com/aave/aave-v3-core/security/advisories/GHSA-aaaa-bbbb-cccc",
        "target_repo": "aave/aave-v3-core",
        "target_domain": "lending",
        "target_language": "solidity",
        "attack_class": "reentrancy-external-call",
        "bug_class": "smart-contract-lending-vulnerability",
        "severity_at_finding": "high",
        "function_shape": {
            "raw_signature": "solidity-lending-package",
            "shape_tags": [
                "aave-v3-core",
                "verification_tier:tier-1-verified-realtime-api",
            ],
        },
    }


def _record_tier2_oracle_solidity() -> dict[str, Any]:
    return {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": "oracle-advisories:chainlink:r2:t2",
        "source_audit_ref": "https://github.com/smartcontractkit/chainlink/security/advisories/GHSA-dddd",
        "target_repo": "smartcontractkit/chainlink",
        "target_domain": "oracle",
        "target_language": "solidity",
        "attack_class": "oracle-manipulation",
        "bug_class": "oracle-vulnerability",
        "severity_at_finding": "medium",
        "function_shape": {
            "raw_signature": "solidity-oracle-package",
            "shape_tags": [
                "chainlink",
                "verification_tier:tier-2-static-fixture-passed",
            ],
        },
    }


def _record_tier3_lending_rust() -> dict[str, Any]:
    return {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": "lending-protocols:solend:r3:t3",
        "source_audit_ref": "https://github.com/solendprotocol/solana-program-library/issues/42",
        "target_repo": "solendprotocol/solana-program-library",
        "target_domain": "lending",
        "target_language": "rust",
        "attack_class": "reentrancy-external-call",
        "bug_class": "lending-vulnerability",
        "severity_at_finding": "low",
        "function_shape": {
            "raw_signature": "rust-lending-package",
            "shape_tags": [
                "verification_tier:tier-3-heuristic-derived",
            ],
        },
    }


def _record_tier5_quarantine() -> dict[str, Any]:
    return {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": "_quarantine:fabricated:r5",
        "source_audit_ref": "https://example.invalid/fabricated",
        "target_repo": "fabricated/repo",
        "target_domain": "lending",
        "target_language": "solidity",
        "attack_class": "reentrancy-external-call",
        "bug_class": "fabricated",
        "severity_at_finding": "critical",
        "function_shape": {
            "shape_tags": [
                "verification_tier:tier-5-quarantine-fabricated",
            ],
        },
    }


def _record_no_tier_cosmos_go() -> dict[str, Any]:
    """Record without a verification_tier tag. Kept when no floor set."""
    return {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": "cosmos-sdk:ibc:r4:notier",
        "source_audit_ref": "https://github.com/cosmos/ibc-go/security/advisories/GHSA-eeee",
        "target_repo": "cosmos/ibc-go",
        "target_domain": "ibc",
        "target_language": "go",
        "attack_class": "signature-replay",
        "bug_class": "ibc-vulnerability",
        "severity_at_finding": "medium",
        "function_shape": {
            "shape_tags": ["cosmos-sdk"],
        },
    }


def _record_flat_yaml_dsl_pattern() -> dict[str, Any]:
    """Flat YAML record (dsl_pattern_*.yaml style)."""
    return {
        "verdict_id": "dsl_pattern/reduce-only-inflates-open-interest",
        "target_repo": "unknown/dsl-synthetic",
        "language": "solidity",
        "bug_class": "denial-of-service",
        "severity_claimed": "MEDIUM",
        "attack_classes_to_try": [
            "dos-cap-weakening",
            "gas-griefing-dos",
        ],
        "function_shape": {
            "shape_tags": [
                "verification_tier:tier-4-pattern-synthesis",
            ],
        },
    }


class CorpusSearchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="corpus-search-mcp-test-")
        self.root = Path(self.tmp.name)
        self.tags_dir = self.root / "tags"
        self.tags_dir.mkdir()

        # Per-record nested directory layout (record.json variant).
        self._write_nested_record(
            "lending_protocols/aave-v3-core-r1",
            _record_tier1_reentrancy_solidity_aave(),
            fmt="json",
        )
        self._write_nested_record(
            "oracle_advisories/chainlink-r2",
            _record_tier2_oracle_solidity(),
            fmt="json",
        )
        self._write_nested_record(
            "lending_protocols/solend-r3",
            _record_tier3_lending_rust(),
            fmt="yaml",
        )
        self._write_nested_record(
            "_QUARANTINE_FABRICATED_CVE/fab-r5",
            _record_tier5_quarantine(),
            fmt="json",
        )
        self._write_nested_record(
            "cosmos_sdk_ibc/r4-notier",
            _record_no_tier_cosmos_go(),
            fmt="yaml",
        )

        # Flat YAML record (dsl_pattern style).
        flat_path = self.tags_dir / "dsl_pattern_reduce-only.yaml"
        flat_path.write_text(
            self._yaml_dump(_record_flat_yaml_dsl_pattern()), encoding="utf-8"
        )

        self.vault_dir = self.root / "obsidian-vault"
        self.vault_dir.mkdir()
        self.vault = vault_mcp_server.VaultQuery(self.vault_dir, self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    # ---- helpers --------------------------------------------------------

    @staticmethod
    def _yaml_dump(data: dict[str, Any]) -> str:
        try:
            import yaml  # type: ignore

            return yaml.safe_dump(data, sort_keys=False)
        except Exception:  # noqa: BLE001
            return json.dumps(data, indent=2)

    def _write_nested_record(
        self, rel_dir: str, record: dict[str, Any], *, fmt: str = "json"
    ) -> None:
        d = self.tags_dir / rel_dir
        d.mkdir(parents=True, exist_ok=True)
        if fmt == "json":
            (d / "record.json").write_text(json.dumps(record), encoding="utf-8")
        else:
            (d / "record.yaml").write_text(self._yaml_dump(record), encoding="utf-8")

    def _call(self, **query: Any) -> dict[str, Any]:
        return self.vault.vault_corpus_search(
            workspace_path=str(self.root),
            query=query,
            tags_dir=str(self.tags_dir),
        )

    # ---- tests ----------------------------------------------------------

    # 1.
    def test_envelope_shape(self):
        result = self._call()
        self.assertEqual(result["schema"], vault_mcp_server.CORPUS_SEARCH_SCHEMA)
        self.assertTrue(
            result["context_pack_id"].startswith(
                vault_mcp_server.CORPUS_SEARCH_SCHEMA + ":"
            )
        )
        self.assertEqual(len(result["context_pack_hash"]), 64)
        self.assertFalse(result["degraded"])
        self.assertIn("records", result)
        # Tier-5 quarantine excluded by default; 5 non-quarantine records.
        self.assertEqual(result["total_records_matched"], 5)
        ids = [r["record_id"] for r in result["records"]]
        self.assertNotIn("_quarantine:fabricated:r5", ids)

    # 2.
    def test_empty_result_envelope(self):
        result = self._call(target_repo="totally-nonexistent-repo-xyz")
        self.assertEqual(result["schema"], vault_mcp_server.CORPUS_SEARCH_SCHEMA)
        self.assertFalse(result["degraded"])
        self.assertEqual(result["total_records_matched"], 0)
        self.assertEqual(result["records"], [])
        self.assertEqual(result["by_tier"], {})
        self.assertEqual(len(result["context_pack_hash"]), 64)

    # 3.
    def test_predicate_target_repo(self):
        result = self._call(target_repo="aave")
        ids = [r["record_id"] for r in result["records"]]
        self.assertIn("lending-protocols:aave-v3:r1:t1", ids)
        self.assertEqual(len(ids), 1)

    # 4.
    def test_predicate_attack_class(self):
        result = self._call(attack_class="reentrancy-external-call")
        ids = {r["record_id"] for r in result["records"]}
        # Both aave-tier1 and solend-tier3 share the attack class; the
        # quarantine record is excluded by default.
        self.assertIn("lending-protocols:aave-v3:r1:t1", ids)
        self.assertIn("lending-protocols:solend:r3:t3", ids)
        self.assertNotIn("_quarantine:fabricated:r5", ids)
        # Tier rank: aave (tier-1) must precede solend (tier-3).
        ordered = [r["record_id"] for r in result["records"]]
        self.assertLess(
            ordered.index("lending-protocols:aave-v3:r1:t1"),
            ordered.index("lending-protocols:solend:r3:t3"),
        )

    # 5.
    def test_predicate_attack_class_via_attack_classes_to_try(self):
        # The flat dsl_pattern record only has attack_classes_to_try, not
        # attack_class. The predicate must still match.
        result = self._call(attack_class="dos-cap-weakening")
        ids = [r["record_id"] for r in result["records"]]
        self.assertEqual(
            ids, ["dsl_pattern/reduce-only-inflates-open-interest"]
        )

    # 6.
    def test_predicate_target_domain(self):
        result = self._call(target_domain="lending")
        ids = {r["record_id"] for r in result["records"]}
        self.assertIn("lending-protocols:aave-v3:r1:t1", ids)
        self.assertIn("lending-protocols:solend:r3:t3", ids)
        self.assertNotIn("oracle-advisories:chainlink:r2:t2", ids)

    # 7.
    def test_predicate_language(self):
        result_sol = self._call(language="solidity")
        sol_ids = {r["record_id"] for r in result_sol["records"]}
        self.assertIn("lending-protocols:aave-v3:r1:t1", sol_ids)
        self.assertIn("oracle-advisories:chainlink:r2:t2", sol_ids)
        # Rust record excluded.
        self.assertNotIn("lending-protocols:solend:r3:t3", sol_ids)

        result_go = self._call(language="go")
        go_ids = {r["record_id"] for r in result_go["records"]}
        self.assertEqual(go_ids, {"cosmos-sdk:ibc:r4:notier"})

    # 8.
    def test_predicate_severity(self):
        result = self._call(severity="medium")
        ids = {r["record_id"] for r in result["records"]}
        # chainlink and cosmos record (both "medium") + the flat
        # dsl_pattern record where severity_claimed="MEDIUM".
        self.assertIn("oracle-advisories:chainlink:r2:t2", ids)
        self.assertIn("cosmos-sdk:ibc:r4:notier", ids)
        self.assertIn(
            "dsl_pattern/reduce-only-inflates-open-interest", ids
        )
        self.assertNotIn("lending-protocols:aave-v3:r1:t1", ids)  # high

    # 9.
    def test_predicate_min_verification_tier(self):
        # Tier <= 2 keeps aave (tier-1) and chainlink (tier-2). The
        # no-tier cosmos record is dropped under an explicit floor.
        result = self._call(min_verification_tier=2)
        ids = [r["record_id"] for r in result["records"]]
        self.assertIn("lending-protocols:aave-v3:r1:t1", ids)
        self.assertIn("oracle-advisories:chainlink:r2:t2", ids)
        self.assertNotIn("lending-protocols:solend:r3:t3", ids)  # tier-3
        self.assertNotIn("cosmos-sdk:ibc:r4:notier", ids)  # no tier
        # Tier-1 must precede tier-2 in the ranked list.
        self.assertLess(
            ids.index("lending-protocols:aave-v3:r1:t1"),
            ids.index("oracle-advisories:chainlink:r2:t2"),
        )

    # 10.
    def test_exclude_quarantine_keep_when_opted_in(self):
        result = self._call(
            attack_class="reentrancy-external-call",
            exclude_quarantine=False,
        )
        ids = {r["record_id"] for r in result["records"]}
        self.assertIn("_quarantine:fabricated:r5", ids)

    # 11.
    def test_predicate_slug_substring(self):
        result = self._call(slug_substring="solend")
        ids = [r["record_id"] for r in result["records"]]
        self.assertEqual(ids, ["lending-protocols:solend:r3:t3"])

    # 12.
    def test_predicate_source_url_substring(self):
        result = self._call(source_url_substring="ibc-go")
        ids = [r["record_id"] for r in result["records"]]
        self.assertEqual(ids, ["cosmos-sdk:ibc:r4:notier"])

    # 13.
    def test_and_composition_multiple_predicates(self):
        # solidity + lending + tier<=2 => only aave-tier1.
        result = self._call(
            language="solidity",
            target_domain="lending",
            min_verification_tier=2,
        )
        ids = [r["record_id"] for r in result["records"]]
        self.assertEqual(ids, ["lending-protocols:aave-v3:r1:t1"])

    # 14.
    def test_limit_clamping(self):
        result_low = self.vault.vault_corpus_search(
            workspace_path=str(self.root),
            query={},
            tags_dir=str(self.tags_dir),
            limit=1,
        )
        self.assertEqual(result_low["limit"], 1)
        self.assertEqual(len(result_low["records"]), 1)

        result_huge = self.vault.vault_corpus_search(
            workspace_path=str(self.root),
            query={},
            tags_dir=str(self.tags_dir),
            limit=99999,
        )
        # Clamped at 200.
        self.assertEqual(result_huge["limit"], 200)

    # 15.
    def test_dispatch_routing(self):
        result = self.vault._dispatch(
            "vault_corpus_search",
            {
                "workspace_path": str(self.root),
                "query": {"attack_class": "reentrancy-external-call"},
                "tags_dir": str(self.tags_dir),
                "limit": 5,
            },
        )
        self.assertEqual(result["schema"], vault_mcp_server.CORPUS_SEARCH_SCHEMA)
        self.assertFalse(result["degraded"])
        ids = {r["record_id"] for r in result["records"]}
        self.assertIn("lending-protocols:aave-v3:r1:t1", ids)

    # 16.
    def test_invalid_query_degrades(self):
        result = self.vault.vault_corpus_search(
            workspace_path=str(self.root),
            query="not-an-object",
            tags_dir=str(self.tags_dir),
        )
        self.assertTrue(result["degraded"])
        self.assertEqual(result["reason"], "query_must_be_object")

    # 17.
    def test_missing_tags_dir_degrades(self):
        result = self.vault.vault_corpus_search(
            workspace_path=str(self.root),
            query={},
            tags_dir=str(self.root / "does-not-exist"),
        )
        self.assertTrue(result["degraded"])
        self.assertEqual(result["reason"], "tags_dir_missing")
        self.assertEqual(result["records"], [])

    # 18.
    def test_deterministic_context_pack_hash(self):
        r1 = self._call(attack_class="reentrancy-external-call")
        r2 = self._call(attack_class="reentrancy-external-call")
        self.assertEqual(r1["context_pack_hash"], r2["context_pack_hash"])


if __name__ == "__main__":
    unittest.main()
