"""Tests for the Wave-3 Hackerman MCP callables (PR #726).

Exercises three new MCP callables defined in ``tools/vault-mcp-server.py``:

1. ``vault_corpus_subtree_summary``
2. ``vault_dupe_advisory_check``
3. ``vault_attack_class_orphan_report``

Each callable gets >=4 focused cases for envelope shape, predicate
behaviour, degraded paths, and dispatch routing.
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
        "vault_mcp_server_v3_test", MODULE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module()


def _yaml_dump(data: dict[str, Any]) -> str:
    try:
        import yaml  # type: ignore

        return yaml.safe_dump(data, sort_keys=False)
    except Exception:  # noqa: BLE001
        return json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


def _record_aave_tier1() -> dict[str, Any]:
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
        "extensions": {"cve_id": "CVE-2024-12345"},
        "function_shape": {
            "shape_tags": [
                "verification_tier:tier-1-verified-realtime-api",
            ],
        },
    }


def _record_aave_tier2_sha() -> dict[str, Any]:
    # 40-hex SHA tied to aave repo for commit_repo_sha matching.
    return {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": "lending-protocols:aave-v3:r2",
        "source_audit_ref": (
            "https://github.com/aave/aave-v3-core/commit/"
            "abcdef0123456789abcdef0123456789abcdef01"
        ),
        "target_repo": "aave/aave-v3-core",
        "target_domain": "lending",
        "target_language": "solidity",
        "attack_class": "oracle-manipulation",
        "severity_at_finding": "medium",
        "function_shape": {
            "shape_tags": ["verification_tier:tier-2-static-fixture-passed"],
        },
    }


def _record_oracle_chainlink() -> dict[str, Any]:
    return {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": "oracle-advisories:chainlink:r2",
        "source_audit_ref": "https://github.com/smartcontractkit/chainlink/security/advisories/GHSA-dddd-eeee-ffff",
        "target_repo": "smartcontractkit/chainlink",
        "target_domain": "oracle",
        "target_language": "solidity",
        "attack_class": "oracle-manipulation",
        "severity_at_finding": "medium",
        "function_shape": {
            "shape_tags": ["verification_tier:tier-2-static-fixture-passed"],
        },
    }


def _record_cosmos_notier() -> dict[str, Any]:
    return {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": "cosmos-sdk:ibc:r4",
        "source_audit_ref": "https://github.com/cosmos/ibc-go/security/advisories/GHSA-eeee-1111-2222",
        "target_repo": "cosmos/ibc-go",
        "target_domain": "ibc",
        "target_language": "go",
        "attack_class": "signature-replay",
        "severity_at_finding": "medium",
        "function_shape": {"shape_tags": ["cosmos-sdk"]},
    }


def _record_quarantine() -> dict[str, Any]:
    return {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": "_quarantine:fabricated:r5",
        "source_audit_ref": "https://example.invalid/fabricated",
        "target_repo": "fabricated/repo",
        "target_domain": "lending",
        "target_language": "solidity",
        "attack_class": "reentrancy-external-call",
        "severity_at_finding": "critical",
        "extensions": {"cve_id": "CVE-2024-12345"},
        "function_shape": {
            "shape_tags": ["verification_tier:tier-5-quarantine-fabricated"],
        },
    }


# ---------------------------------------------------------------------------
# Shared corpus fixture
# ---------------------------------------------------------------------------


class _CorpusFixture:
    """Tiny on-disk corpus used by both subtree-summary and dupe-advisory tests."""

    def __init__(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="vault-mcp-v3-test-")
        self.root = Path(self.tmp.name)
        self.tags_dir = self.root / "tags"
        self.tags_dir.mkdir()
        self.vault_dir = self.root / "obsidian-vault"
        self.vault_dir.mkdir()

        self._write_nested(
            "lending_protocols/aave-v3-r1", _record_aave_tier1(), fmt="json"
        )
        self._write_nested(
            "lending_protocols/aave-v3-r2", _record_aave_tier2_sha(), fmt="json"
        )
        self._write_nested(
            "oracle_advisories/chainlink-r2",
            _record_oracle_chainlink(),
            fmt="json",
        )
        self._write_nested(
            "cosmos_sdk_ibc/r4-notier",
            _record_cosmos_notier(),
            fmt="yaml",
        )
        self._write_nested(
            "_QUARANTINE_FABRICATED_CVE/fab-r5",
            _record_quarantine(),
            fmt="json",
        )

        # Acceptance-exemptions fixture: mark cosmos_sdk_ibc as tier-3-by-design.
        self.exemptions_path = self.root / "acceptance_exemptions.yaml"
        self.exemptions_path.write_text(
            _yaml_dump(
                {
                    "schema": "auditooor.hackerman_corpus_acceptance_exemptions.v1",
                    "exemptions": [
                        {
                            "corpus_dir": "cosmos_sdk_ibc",
                            "category": "B",
                            "reason": "mixed-wave anchor + fan-out",
                            "review_at": "indefinite",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

        self.vault = vault_mcp_server.VaultQuery(self.vault_dir, self.root)

    def _write_nested(self, rel_dir: str, record: dict[str, Any], *, fmt: str) -> None:
        d = self.tags_dir / rel_dir
        d.mkdir(parents=True, exist_ok=True)
        if fmt == "json":
            (d / "record.json").write_text(json.dumps(record), encoding="utf-8")
        else:
            (d / "record.yaml").write_text(_yaml_dump(record), encoding="utf-8")

    def cleanup(self) -> None:
        self.tmp.cleanup()


# ---------------------------------------------------------------------------
# vault_corpus_subtree_summary
# ---------------------------------------------------------------------------


class CorpusSubtreeSummaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = _CorpusFixture()

    def tearDown(self) -> None:
        self.fx.cleanup()

    def _call(self, **kwargs: Any) -> dict[str, Any]:
        kwargs.setdefault("workspace_path", str(self.fx.root))
        kwargs.setdefault("tags_dir", str(self.fx.tags_dir))
        kwargs.setdefault("exemptions_path", str(self.fx.exemptions_path))
        return self.fx.vault.vault_corpus_subtree_summary(**kwargs)

    # 1.
    def test_envelope_shape_all_subtrees(self):
        result = self._call()
        self.assertEqual(
            result["schema"], vault_mcp_server.CORPUS_SUBTREE_SUMMARY_SCHEMA
        )
        self.assertTrue(
            result["context_pack_id"].startswith(
                vault_mcp_server.CORPUS_SUBTREE_SUMMARY_SCHEMA + ":"
            )
        )
        self.assertEqual(len(result["context_pack_hash"]), 64)
        self.assertFalse(result["degraded"])
        # 4 healthy subtrees + 1 quarantine subtree.
        names = [r["subtree"] for r in result["subtrees"]]
        self.assertIn("lending_protocols", names)
        self.assertIn("oracle_advisories", names)
        self.assertIn("cosmos_sdk_ibc", names)
        self.assertIn("_QUARANTINE_FABRICATED_CVE", names)
        self.assertEqual(result["total_records"], 5)
        self.assertEqual(result["exemptions_present"], 1)
        # Sorted alphabetically.
        self.assertEqual(names, sorted(names))

    # 2.
    def test_subtree_filter_selects_single_row(self):
        result = self._call(subtree="lending_protocols")
        self.assertEqual(len(result["subtrees"]), 1)
        row = result["subtrees"][0]
        self.assertEqual(row["subtree"], "lending_protocols")
        self.assertEqual(row["records"], 2)
        tier_keys = set(row["tier_counts"].keys())
        # tier-1 and tier-2 represented.
        self.assertIn("tier-1", tier_keys)
        self.assertIn("tier-2", tier_keys)
        # Top attack_classes correctly populated (reentrancy + oracle).
        top_classes = {p["value"] for p in row["top_attack_classes"]}
        self.assertIn("reentrancy-external-call", top_classes)
        self.assertIn("oracle-manipulation", top_classes)
        # Target repo top hit = aave/aave-v3-core.
        self.assertEqual(
            row["top_target_repos"][0]["value"], "aave/aave-v3-core"
        )
        self.assertEqual(row["top_target_repos"][0]["count"], 2)
        # Exemption status reflects no exemption for lending_protocols.
        self.assertIsNone(row["exemption"])

    # 3.
    def test_exemption_join_surfaces_tier3_by_design(self):
        result = self._call(subtree="cosmos_sdk_ibc")
        self.assertEqual(len(result["subtrees"]), 1)
        row = result["subtrees"][0]
        self.assertIsNotNone(row["exemption"])
        self.assertEqual(row["exemption"]["category"], "B")
        self.assertIn("mixed-wave", row["exemption"]["reason"])
        self.assertEqual(row["exemption"]["review_at"], "indefinite")

    # 4.
    def test_missing_tags_dir_degrades(self):
        result = self.fx.vault.vault_corpus_subtree_summary(
            workspace_path=str(self.fx.root),
            tags_dir=str(self.fx.root / "does-not-exist"),
        )
        self.assertTrue(result["degraded"])
        self.assertEqual(result["reason"], "tags_dir_missing")
        self.assertEqual(result["subtrees"], [])
        self.assertEqual(len(result["context_pack_hash"]), 64)

    # 5.
    def test_dispatch_routing(self):
        result = self.fx.vault._dispatch(
            "vault_corpus_subtree_summary",
            {
                "workspace_path": str(self.fx.root),
                "tags_dir": str(self.fx.tags_dir),
                "exemptions_path": str(self.fx.exemptions_path),
                "subtree": "oracle_advisories",
            },
        )
        self.assertEqual(
            result["schema"], vault_mcp_server.CORPUS_SUBTREE_SUMMARY_SCHEMA
        )
        self.assertEqual(len(result["subtrees"]), 1)
        self.assertEqual(result["subtrees"][0]["subtree"], "oracle_advisories")


# ---------------------------------------------------------------------------
# vault_dupe_advisory_check
# ---------------------------------------------------------------------------


class DupeAdvisoryCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = _CorpusFixture()

    def tearDown(self) -> None:
        self.fx.cleanup()

    def _call(self, **kwargs: Any) -> dict[str, Any]:
        kwargs.setdefault("workspace_path", str(self.fx.root))
        kwargs.setdefault("tags_dir", str(self.fx.tags_dir))
        return self.fx.vault.vault_dupe_advisory_check(**kwargs)

    # 1.
    def test_cve_match_excludes_quarantine_by_default(self):
        # Both aave-tier1 and the quarantine record cite CVE-2024-12345; the
        # quarantine record must be filtered out by default.
        result = self._call(cve_id="CVE-2024-12345")
        self.assertEqual(
            result["schema"], vault_mcp_server.DUPE_ADVISORY_CHECK_SCHEMA
        )
        self.assertFalse(result["degraded"])
        ids = [r["record_id"] for r in result["records"]]
        self.assertIn("lending-protocols:aave-v3:r1:t1", ids)
        self.assertNotIn("_quarantine:fabricated:r5", ids)
        # The hit_via vector must include cve_id.
        first = result["records"][0]
        self.assertIn("cve_id", first["hit_via"])
        self.assertEqual(len(result["context_pack_hash"]), 64)

    # 2.
    def test_ghsa_match_finds_record(self):
        result = self._call(ghsa_id="GHSA-DDDD-EEEE-FFFF")
        ids = [r["record_id"] for r in result["records"]]
        self.assertEqual(ids, ["oracle-advisories:chainlink:r2"])
        self.assertIn("ghsa_id", result["records"][0]["hit_via"])

    # 3.
    def test_commit_repo_sha_match_requires_repo_cite(self):
        # Scoped to the canonical `aave/aave` repo coord matches the tier-2
        # aave record. (The repo regex mirrors hackerman-cross-corpus-dupe-
        # finder.py's REPO_RE which captures the first two path segments
        # after github.com/<owner>/<repo>; aave-v3-core lives on the third
        # segment after the bare repo coord. The dupe-finder uses the same
        # liberal pairing so this callable matches its behaviour.)
        result_scoped = self._call(
            commit_repo_sha=(
                "aave/aave@abcdef0123456789abcdef0123456789abcdef01"
            )
        )
        ids = [r["record_id"] for r in result_scoped["records"]]
        self.assertEqual(ids, ["lending-protocols:aave-v3:r2"])
        self.assertIn(
            "commit_repo_sha", result_scoped["records"][0]["hit_via"]
        )
        # Wrong repo scope -> no match even though the SHA exists in corpus.
        result_wrong = self._call(
            commit_repo_sha=(
                "uniswap/v3-core@abcdef0123456789abcdef0123456789abcdef01"
            )
        )
        self.assertEqual(result_wrong["records"], [])
        # Bare SHA (no owner/repo) -> hit_via tags as `commit_sha` (weak).
        result_bare = self._call(
            commit_repo_sha="abcdef0123456789abcdef0123456789abcdef01"
        )
        bare_ids = [r["record_id"] for r in result_bare["records"]]
        self.assertIn("lending-protocols:aave-v3:r2", bare_ids)
        self.assertIn(
            "commit_sha", result_bare["records"][0]["hit_via"]
        )

    # 4.
    def test_source_url_substring_match(self):
        result = self._call(source_url="ibc-go")
        ids = [r["record_id"] for r in result["records"]]
        self.assertEqual(ids, ["cosmos-sdk:ibc:r4"])
        # source_url match recorded in hit_via.
        self.assertIn("source_url", result["records"][0]["hit_via"])

    # 5.
    def test_missing_identifier_degrades(self):
        result = self._call()
        self.assertTrue(result["degraded"])
        self.assertEqual(result["reason"], "missing_identifier")
        self.assertEqual(result["records"], [])
        # Envelope still well-formed.
        self.assertEqual(
            result["schema"], vault_mcp_server.DUPE_ADVISORY_CHECK_SCHEMA
        )
        self.assertEqual(len(result["context_pack_hash"]), 64)

    # 6.
    def test_invalid_cve_id_degrades(self):
        result = self._call(cve_id="not-a-cve")
        self.assertTrue(result["degraded"])
        self.assertEqual(result["reason"], "invalid_cve_id")

    # 7.
    def test_dispatch_routing(self):
        result = self.fx.vault._dispatch(
            "vault_dupe_advisory_check",
            {
                "workspace_path": str(self.fx.root),
                "tags_dir": str(self.fx.tags_dir),
                "cve_id": "CVE-2024-12345",
            },
        )
        self.assertEqual(
            result["schema"], vault_mcp_server.DUPE_ADVISORY_CHECK_SCHEMA
        )
        self.assertFalse(result["degraded"])
        self.assertGreaterEqual(result["total_records_matched"], 1)


# ---------------------------------------------------------------------------
# vault_attack_class_orphan_report
# ---------------------------------------------------------------------------


class AttackClassOrphanReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="orphan-report-mcp-test-")
        self.root = Path(self.tmp.name)
        self.vault_dir = self.root / "obsidian-vault"
        self.vault_dir.mkdir()
        self.inventory_path = self.root / "attack_class_taxonomy.json"
        self.inventory_path.write_text(
            json.dumps(
                {
                    "schema": "auditooor.hackerman_attack_class_taxonomy.v1",
                    "tags_dir": str(self.root / "tags"),
                    "total_records": 1234,
                    "subtrees": [
                        "lending_protocols",
                        "oracle_advisories",
                        "cosmos_sdk_ibc",
                        "bridge_incidents",
                    ],
                    "classes": [
                        {
                            "attack_class": "reentrancy-external-call",
                            "subtrees": [
                                "lending_protocols",
                                "oracle_advisories",
                                "bridge_incidents",
                            ],
                            "tier12_count": 80,
                            "tier12_pct": 88.0,
                            "tier1_count": 50,
                            "tier2_count": 30,
                            "tier_counts": {"tier-1": 50, "tier-2": 30, "tier-3": 11},
                            "total_records": 91,
                        },
                        {
                            "attack_class": "novel-cosmos-fork-bug",
                            "subtrees": ["cosmos_sdk_ibc"],
                            "tier12_count": 0,
                            "tier12_pct": 0.0,
                            "tier1_count": 0,
                            "tier2_count": 0,
                            "tier_counts": {"tier-3": 12},
                            "total_records": 12,
                        },
                        {
                            "attack_class": "audit-firm-public-report",
                            "subtrees": ["audit_firm_public_reports"],
                            "tier12_count": 0,
                            "tier12_pct": 0.0,
                            "tier1_count": 0,
                            "tier2_count": 0,
                            "tier_counts": {"no-tier": 1681},
                            "total_records": 1681,
                        },
                        {
                            "attack_class": "<missing-attack-class>",
                            "subtrees": ["lending_protocols"],
                            "tier12_count": 0,
                            "tier12_pct": 0.0,
                            "tier1_count": 0,
                            "tier2_count": 0,
                            "tier_counts": {"no-tier": 3},
                            "total_records": 3,
                        },
                        {
                            "attack_class": "single-record-orphan",
                            "subtrees": ["bridge_incidents"],
                            "tier12_count": 0,
                            "tier12_pct": 0.0,
                            "tier1_count": 0,
                            "tier2_count": 0,
                            "tier_counts": {"tier-3": 1},
                            "total_records": 1,
                        },
                    ],
                    "per_subtree": {
                        "lending_protocols": {
                            "distinct_classes": 6,
                            "tier12_count": 80,
                            "tier12_pct": 90.0,
                            "tier1_count": 50,
                            "tier2_count": 30,
                            "tier_counts": {"tier-1": 50, "tier-2": 30},
                            "total_records": 80,
                        },
                        "cosmos_sdk_ibc": {
                            "distinct_classes": 1,
                            "tier12_count": 0,
                            "tier12_pct": 0.0,
                            "tier1_count": 0,
                            "tier2_count": 0,
                            "tier_counts": {"tier-3": 12},
                            "total_records": 12,
                        },
                    },
                }
            ),
            encoding="utf-8",
        )
        self.vault = vault_mcp_server.VaultQuery(self.vault_dir, self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _call(self, **kwargs: Any) -> dict[str, Any]:
        kwargs.setdefault("workspace_path", str(self.root))
        kwargs.setdefault("inventory_path", str(self.inventory_path))
        return self.vault.vault_attack_class_orphan_report(**kwargs)

    # 1.
    def test_envelope_shape_and_orphan_extraction(self):
        result = self._call()
        self.assertEqual(
            result["schema"], vault_mcp_server.ATTACK_CLASS_ORPHAN_REPORT_SCHEMA
        )
        self.assertTrue(
            result["context_pack_id"].startswith(
                vault_mcp_server.ATTACK_CLASS_ORPHAN_REPORT_SCHEMA + ":"
            )
        )
        self.assertEqual(len(result["context_pack_hash"]), 64)
        self.assertFalse(result["degraded"])
        ids = [r["attack_class"] for r in result["orphans"]]
        # 3 orphans (audit-firm + novel-cosmos + single-record),
        # missing-attack-class sentinel filtered out, reentrancy NOT an orphan
        # (3 subtrees).
        self.assertEqual(set(ids), {
            "audit-firm-public-report",
            "novel-cosmos-fork-bug",
            "single-record-orphan",
        })
        self.assertNotIn("reentrancy-external-call", ids)
        self.assertNotIn("<missing-attack-class>", ids)
        # Ranked by total_records desc.
        self.assertEqual(ids[0], "audit-firm-public-report")
        self.assertEqual(result["total_orphans"], 3)

    # 2.
    def test_well_covered_class_surfaced(self):
        result = self._call()
        well = [r["attack_class"] for r in result["well_covered"]]
        self.assertIn("reentrancy-external-call", well)

    # 3.
    def test_min_records_filter(self):
        result = self._call(min_records=10)
        ids = [r["attack_class"] for r in result["orphans"]]
        self.assertIn("audit-firm-public-report", ids)
        self.assertIn("novel-cosmos-fork-bug", ids)
        self.assertNotIn("single-record-orphan", ids)
        self.assertEqual(result["total_orphans"], 2)

    # 4.
    def test_orphan_summary_present(self):
        result = self._call()
        summary = result["orphan_summary"]
        self.assertEqual(summary["total_orphan_classes"], 3)
        # 1681 + 12 + 1.
        self.assertEqual(summary["total_orphan_records"], 1694)
        self.assertEqual(summary["tier12_records_in_orphans"], 0)
        self.assertEqual(summary["tier12_pct_in_orphans"], 0.0)
        by_sub = summary["orphans_by_subtree"]
        self.assertEqual(by_sub.get("audit_firm_public_reports"), 1)
        self.assertEqual(by_sub.get("cosmos_sdk_ibc"), 1)
        self.assertEqual(by_sub.get("bridge_incidents"), 1)

    # 5.
    def test_missing_inventory_degrades(self):
        result = self.vault.vault_attack_class_orphan_report(
            workspace_path=str(self.root),
            inventory_path=str(self.root / "does-not-exist.json"),
        )
        self.assertTrue(result["degraded"])
        self.assertEqual(result["reason"], "inventory_missing")
        self.assertEqual(result["orphans"], [])
        self.assertEqual(len(result["context_pack_hash"]), 64)

    # 6.
    def test_dispatch_routing(self):
        result = self.vault._dispatch(
            "vault_attack_class_orphan_report",
            {
                "workspace_path": str(self.root),
                "inventory_path": str(self.inventory_path),
                "min_records": 1,
            },
        )
        self.assertEqual(
            result["schema"],
            vault_mcp_server.ATTACK_CLASS_ORPHAN_REPORT_SCHEMA,
        )
        self.assertFalse(result["degraded"])
        self.assertGreaterEqual(result["total_orphans"], 1)


if __name__ == "__main__":
    unittest.main()
