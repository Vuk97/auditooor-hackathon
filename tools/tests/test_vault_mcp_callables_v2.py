"""Tests for Wave-1 hackerman v2 MCP callables.

Covers `vault_attack_class_evidence_v2` and `vault_hacker_brief_for_lane_v2`:

- tier-filter correctness (min_verification_tier);
- quarantine (tier-5) exclusion;
- missing-tier graceful handling;
- empty-result envelope;
- attack-class match;
- ranking (tier-1 > tier-2 > tier-3 > tier-4);
- backward compatibility (v1 callables still work).
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
    spec = importlib.util.spec_from_file_location("vault_mcp_server_v2_test", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module()


# Reusable raw-record bodies. Keep them small but schema-valid enough that
# `hackerman_query_common.load_tag_file` returns the dict we expect.
def _record_yaml(
    record_id: str,
    attack_class: str,
    shape_tags: list[str],
    *,
    target_language: str = "go",
    target_domain: str = "consensus",
    target_repo: str = "owner/repo",
) -> str:
    tag_lines = "\n".join(f"    - {t}" for t in shape_tags)
    return (
        "schema_version: auditooor.hackerman_record.v1\n"
        f"record_id: {record_id}\n"
        f"target_domain: {target_domain}\n"
        f"target_language: {target_language}\n"
        f"target_repo: {target_repo}\n"
        f"target_component: synthetic-{record_id}\n"
        "function_shape:\n"
        "  raw_signature: synthetic\n"
        "  shape_tags:\n"
        f"{tag_lines}\n"
        f"bug_class: {attack_class}\n"
        f"attack_class: {attack_class}\n"
        "attacker_role: unprivileged\n"
        "attacker_action_sequence: synthetic\n"
        "required_preconditions:\n"
        "  - synthetic\n"
        "impact_class: dos\n"
        "impact_actor: validator-set\n"
        f"severity_at_finding: medium\n"
        "year: 2024\n"
        "record_tier: public-corpus\n"
        "record_quality_score: 3.0\n"
        "source_extraction_method: synthetic-test\n"
        "source_extraction_confidence: 0.9\n"
    )


class V2HelperUnitTests(unittest.TestCase):
    """Unit tests for the pure helper methods (no I/O)."""

    def test_extract_verification_tier_tier1(self):
        rec = {
            "function_shape": {
                "shape_tags": [
                    "ghsa-real",
                    "verification_tier:tier-1-verified-realtime-api",
                ],
            },
        }
        tier, tag = vault_mcp_server.VaultQuery._extract_verification_tier(rec)
        self.assertEqual(tier, 1)
        self.assertEqual(tag, "verification_tier:tier-1-verified-realtime-api")

    def test_extract_verification_tier_quarantine(self):
        rec = {
            "function_shape": {
                "shape_tags": ["foo", "verification_tier:tier-5-quarantine"],
            },
        }
        tier, tag = vault_mcp_server.VaultQuery._extract_verification_tier(rec)
        self.assertEqual(tier, 5)
        self.assertEqual(tag, "verification_tier:tier-5-quarantine")

    def test_extract_verification_tier_missing(self):
        rec = {"function_shape": {"shape_tags": ["foo", "bar"]}}
        tier, tag = vault_mcp_server.VaultQuery._extract_verification_tier(rec)
        self.assertIsNone(tier)
        self.assertEqual(tag, "")

    def test_extract_verification_tier_bad_record(self):
        for bad in [None, {}, {"function_shape": None}, {"function_shape": {"shape_tags": None}}]:
            tier, tag = vault_mcp_server.VaultQuery._extract_verification_tier(bad)
            self.assertIsNone(tier)
            self.assertEqual(tag, "")

    def test_filter_records_quarantine_exclusion(self):
        records = [
            {"record_id": "a", "verification_tier": 1},
            {"record_id": "b", "verification_tier": 5},
            {"record_id": "c", "verification_tier": 2},
        ]
        out = vault_mcp_server.VaultQuery._filter_records_by_tier(
            records,
            min_verification_tier=None,
            exclude_quarantine=True,
        )
        self.assertEqual([r["record_id"] for r in out], ["a", "c"])

    def test_filter_records_min_tier_keeps_only_at_or_below(self):
        records = [
            {"record_id": "a", "verification_tier": 1},
            {"record_id": "b", "verification_tier": 2},
            {"record_id": "c", "verification_tier": 3},
            {"record_id": "d", "verification_tier": 4},
            {"record_id": "e", "verification_tier": None},
        ]
        out = vault_mcp_server.VaultQuery._filter_records_by_tier(
            records,
            min_verification_tier=2,
            exclude_quarantine=True,
        )
        ids = {r["record_id"] for r in out}
        # 'a' (tier-1) and 'b' (tier-2) kept. 'c'/'d' over floor; 'e' missing tier dropped.
        self.assertEqual(ids, {"a", "b"})

    def test_filter_records_no_floor_keeps_missing_tier(self):
        records = [
            {"record_id": "a", "verification_tier": 2},
            {"record_id": "b", "verification_tier": None},
        ]
        out = vault_mcp_server.VaultQuery._filter_records_by_tier(
            records,
            min_verification_tier=None,
            exclude_quarantine=True,
        )
        ids = {r["record_id"] for r in out}
        self.assertEqual(ids, {"a", "b"})

    def test_filter_records_ranking(self):
        records = [
            {"record_id": "c", "verification_tier": 3},
            {"record_id": "a", "verification_tier": 1},
            {"record_id": "b", "verification_tier": 2},
            {"record_id": "d", "verification_tier": 4},
        ]
        out = vault_mcp_server.VaultQuery._filter_records_by_tier(
            records,
            min_verification_tier=None,
            exclude_quarantine=True,
        )
        # ranked tier-1 > tier-2 > tier-3 > tier-4
        self.assertEqual([r["record_id"] for r in out], ["a", "b", "c", "d"])


class V2CorpusBackedTests(unittest.TestCase):
    """End-to-end tests with a synthetic hackerman corpus on disk."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-mcp-v2-test-")
        self.root = Path(self.tmp.name)
        self.tags_dir = self.root / "audit" / "corpus_tags" / "tags" / "synthetic"
        self.tags_dir.mkdir(parents=True)
        self.index_dir = self.root / "audit" / "corpus_tags" / "index"
        self.index_dir.mkdir(parents=True)
        self.derived_dir = self.root / "audit" / "corpus_tags" / "derived"
        self.derived_dir.mkdir(parents=True)
        self.vault_dir = self.root / "obsidian-vault"
        self.vault_dir.mkdir()
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        (self.workspace / "SCOPE.md").write_text("synthetic scope", encoding="utf-8")

        # Five synthetic records: tiers 1..5 plus one with no tier.
        self.records = [
            ("rec-tier1", "reentrancy-class", ["foo", "verification_tier:tier-1-verified-realtime-api"]),
            ("rec-tier2", "reentrancy-class", ["foo", "verification_tier:tier-2-verified-public-archive"]),
            ("rec-tier3", "reentrancy-class", ["foo", "verification_tier:tier-3-synthetic-taxonomy-anchored"]),
            ("rec-tier4", "reentrancy-class", ["foo", "verification_tier:tier-4-bundled-fixture"]),
            ("rec-tier5", "reentrancy-class", ["foo", "verification_tier:tier-5-quarantine"]),
            ("rec-notier", "reentrancy-class", ["foo", "bar"]),
            ("rec-other", "double-spend-class", ["foo", "verification_tier:tier-1-verified-realtime-api"]),
        ]
        index_rows: list[dict[str, Any]] = []
        for rid, ac, tags in self.records:
            yaml_path = self.tags_dir / f"{rid}.yaml"
            yaml_path.write_text(_record_yaml(rid, ac, tags), encoding="utf-8")
            index_rows.append(
                {
                    "attack_class": ac,
                    "bug_class": ac,
                    "key": ac,
                    "record_id": rid,
                    "severity_at_finding": "medium",
                    "source_audit_ref": f"synthetic:{rid}",
                    "tag_file": str(yaml_path),
                    "target_domain": "consensus",
                    "target_language": "go",
                    "target_repo": "owner/repo",
                    "year": 2024,
                }
            )
        with (self.index_dir / "by_attack_class.jsonl").open("w", encoding="utf-8") as fh:
            for row in index_rows:
                fh.write(json.dumps(row, sort_keys=True) + "\n")
        # Lane-brief helper also looks at these (empty rows is fine — the
        # helper falls back to the by_attack_class index for `attack_class`).
        for axis in ("by_language", "by_target_domain", "by_target_repo"):
            (self.index_dir / f"{axis}.jsonl").write_text("", encoding="utf-8")

        # Empty sidecars — they're optional.
        (self.derived_dir / "record_quality.jsonl").write_text("", encoding="utf-8")
        (self.derived_dir / "proof_hardening.jsonl").write_text("", encoding="utf-8")
        (self.derived_dir / "cross_language_analogues.jsonl").write_text("", encoding="utf-8")

        # Minimal vault directory for VaultQuery instantiation.
        self.vault = vault_mcp_server.VaultQuery(self.vault_dir, self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    # ---- vault_attack_class_evidence_v2 ----

    def _attack_kwargs(self, **overrides: Any) -> dict[str, Any]:
        base = {
            "attack_class": "reentrancy-class",
            "index_dir": str(self.index_dir),
            "tags_dir": str(self.tags_dir.parent),  # parent: tags/ root for sidecars
            "quality_sidecar": str(self.derived_dir / "record_quality.jsonl"),
            "proof_hardening_sidecar": str(self.derived_dir / "proof_hardening.jsonl"),
        }
        # The query helper reads from <tags_dir> + index_dir; for our synthetic
        # records we want load_tag_file to pick up absolute tag_file values.
        base["tags_dir"] = str(self.tags_dir.parent)
        base.update(overrides)
        return base

    def test_attack_v2_missing_attack_class_envelope(self):
        result = self.vault.vault_attack_class_evidence_v2(attack_class="")
        self.assertEqual(result["schema"], vault_mcp_server.ATTACK_CLASS_EVIDENCE_V2_SCHEMA)
        self.assertTrue(result["degraded"])
        self.assertEqual(result["reason"], "missing_attack_class")
        self.assertIn("context_pack_id", result)
        self.assertIn("context_pack_hash", result)
        self.assertEqual(result["records"], [])

    def test_attack_v2_envelope_keys_match_v1_pattern(self):
        result = self.vault.vault_attack_class_evidence_v2(**self._attack_kwargs())
        # Receipt envelope keys are present and well-formed.
        self.assertEqual(result["schema"], vault_mcp_server.ATTACK_CLASS_EVIDENCE_V2_SCHEMA)
        self.assertTrue(result["context_pack_id"].startswith(
            vault_mcp_server.ATTACK_CLASS_EVIDENCE_V2_SCHEMA + ":"
        ))
        self.assertEqual(len(result["context_pack_hash"]), 64)
        self.assertIn("records", result)
        self.assertIn("by_tier", result)
        self.assertIn("source_refs", result)

    def test_attack_v2_quarantine_excluded_by_default(self):
        result = self.vault.vault_attack_class_evidence_v2(**self._attack_kwargs())
        ids = [r.get("record_id") for r in result["records"]]
        self.assertNotIn("rec-tier5", ids)
        # tier-5 not counted in by_tier under default exclusion
        self.assertNotIn("tier-5", result["by_tier"])

    def test_attack_v2_min_tier_filter(self):
        result = self.vault.vault_attack_class_evidence_v2(
            **self._attack_kwargs(min_verification_tier=2)
        )
        ids = {r.get("record_id") for r in result["records"]}
        # Only tier-1 and tier-2 should survive; tier-3/tier-4 over floor.
        # rec-notier has no tier and is dropped under an explicit floor.
        self.assertIn("rec-tier1", ids)
        self.assertIn("rec-tier2", ids)
        self.assertNotIn("rec-tier3", ids)
        self.assertNotIn("rec-tier4", ids)
        self.assertNotIn("rec-notier", ids)
        self.assertNotIn("rec-tier5", ids)

    def test_attack_v2_missing_tier_kept_when_no_floor(self):
        result = self.vault.vault_attack_class_evidence_v2(
            **self._attack_kwargs(min_verification_tier=None)
        )
        ids = {r.get("record_id") for r in result["records"]}
        # No floor — tier-1..4 + rec-notier (no tier) all kept. tier-5 still dropped.
        self.assertIn("rec-tier1", ids)
        self.assertIn("rec-notier", ids)
        self.assertNotIn("rec-tier5", ids)

    def test_attack_v2_ranks_tier1_first(self):
        result = self.vault.vault_attack_class_evidence_v2(
            **self._attack_kwargs(min_verification_tier=4)
        )
        ranks = [r.get("verification_tier") for r in result["records"]]
        # First record must be tier-1 (lowest int = strongest verification).
        self.assertEqual(ranks[0], 1)
        # Tiers must be monotonically non-decreasing.
        numeric_ranks = [r for r in ranks if isinstance(r, int)]
        self.assertEqual(numeric_ranks, sorted(numeric_ranks))

    def test_attack_v2_attack_class_match(self):
        # Synthetic corpus has two attack classes; v2 must only return rows
        # whose attack_class matches the requested filter.
        result = self.vault.vault_attack_class_evidence_v2(
            **self._attack_kwargs(attack_class="double-spend-class")
        )
        for rec in result["records"]:
            self.assertEqual(rec.get("attack_class"), "double-spend-class")

    def test_attack_v2_explicit_include_quarantine(self):
        result = self.vault.vault_attack_class_evidence_v2(
            **self._attack_kwargs(exclude_quarantine=False)
        )
        ids = {r.get("record_id") for r in result["records"]}
        self.assertIn("rec-tier5", ids)
        self.assertIn("tier-5", result["by_tier"])

    def test_attack_v2_empty_result_envelope(self):
        # Unknown class — helper returns no records; envelope must still be
        # well-formed and not crash.
        result = self.vault.vault_attack_class_evidence_v2(
            **self._attack_kwargs(attack_class="nonexistent-class-xyz")
        )
        self.assertEqual(result["records"], [])
        self.assertEqual(result["total_records_matched"], 0)
        self.assertEqual(result["by_tier"], {})
        self.assertIn("context_pack_hash", result)

    # ---- vault_hacker_brief_for_lane_v2 ----

    def _brief_kwargs(self, **overrides: Any) -> dict[str, Any]:
        base = {
            "workspace_path": str(self.workspace),
            "lane_id": "H1-test-lane",
            "files": ["SCOPE.md"],
            "attack_class": "reentrancy-class",
            "index_dir": str(self.index_dir),
            "tags_dir": str(self.tags_dir.parent),
            "quality_sidecar": str(self.derived_dir / "record_quality.jsonl"),
            "proof_hardening_sidecar": str(self.derived_dir / "proof_hardening.jsonl"),
            "cross_language_sidecar": str(self.derived_dir / "cross_language_analogues.jsonl"),
        }
        base.update(overrides)
        return base

    def test_brief_v2_missing_workspace(self):
        result = self.vault.vault_hacker_brief_for_lane_v2(
            workspace_path="",
            lane_id="x",
        )
        self.assertTrue(result["degraded"])
        self.assertEqual(result["reason"], "missing_workspace_path")
        self.assertEqual(result["schema"], vault_mcp_server.HACKER_BRIEF_FOR_LANE_V2_SCHEMA)
        self.assertIn("context_pack_hash", result)

    def test_brief_v2_bad_lane_id(self):
        result = self.vault.vault_hacker_brief_for_lane_v2(
            workspace_path=str(self.workspace),
            lane_id="bad lane id with spaces!",
        )
        self.assertTrue(result["degraded"])
        self.assertIn("lane_id", result["reason"])

    def test_brief_v2_envelope_keys(self):
        result = self.vault.vault_hacker_brief_for_lane_v2(**self._brief_kwargs())
        self.assertEqual(result["schema"], vault_mcp_server.HACKER_BRIEF_FOR_LANE_V2_SCHEMA)
        self.assertTrue(result["context_pack_id"].startswith(
            vault_mcp_server.HACKER_BRIEF_FOR_LANE_V2_SCHEMA + ":"
        ))
        self.assertEqual(len(result["context_pack_hash"]), 64)
        self.assertIn("records_by_attack_class", result)
        self.assertIn("by_tier", result)

    def test_brief_v2_quarantine_excluded(self):
        result = self.vault.vault_hacker_brief_for_lane_v2(**self._brief_kwargs())
        for rec in result["records"]:
            self.assertNotEqual(rec.get("verification_tier"), 5)

    def test_brief_v2_min_tier_filter(self):
        result = self.vault.vault_hacker_brief_for_lane_v2(
            **self._brief_kwargs(min_verification_tier=2)
        )
        # Every returned record must have tier <= 2 (or be from the
        # candidate set which had all tiers, hence the filter must work).
        for rec in result["records"]:
            tier = rec.get("verification_tier")
            self.assertIsInstance(tier, int)
            self.assertLessEqual(tier, 2)

    def test_brief_v2_attack_class_filter(self):
        result = self.vault.vault_hacker_brief_for_lane_v2(
            **self._brief_kwargs(attack_class_filter=["double-spend-class"])
        )
        for rec in result["records"]:
            self.assertEqual(rec.get("attack_class"), "double-spend-class")
        # records_by_attack_class should only have the filtered class
        for cls in result["records_by_attack_class"].keys():
            self.assertEqual(cls, "double-spend-class")


class V1BackwardCompatibilityTests(unittest.TestCase):
    """v1 callables continue to work after v2 lands."""

    def test_v1_attack_class_evidence_still_callable(self):
        # Ensure the v1 method is still callable and uses the v1 schema —
        # i.e. adding v2 did not regress v1.
        m = vault_mcp_server
        with tempfile.TemporaryDirectory(prefix="auditooor-mcp-v1-compat-") as td:
            root = Path(td)
            (root / "obsidian-vault").mkdir()
            vault = m.VaultQuery(root / "obsidian-vault", root)
            result = vault.vault_attack_class_evidence(attack_class="")
            self.assertEqual(result["schema"], m.ATTACK_CLASS_EVIDENCE_SCHEMA)
            self.assertTrue(result["degraded"])
            self.assertEqual(result["reason"], "missing_attack_class")

    def test_v1_hacker_brief_for_lane_still_callable(self):
        m = vault_mcp_server
        with tempfile.TemporaryDirectory(prefix="auditooor-mcp-v1b-compat-") as td:
            root = Path(td)
            (root / "obsidian-vault").mkdir()
            vault = m.VaultQuery(root / "obsidian-vault", root)
            result = vault.vault_hacker_brief_for_lane(
                workspace_path="",
                lane_id="x",
            )
            # v1 returns its own schema and degraded envelope on empty input.
            self.assertEqual(
                result["context_pack_id"].split(":", 1)[0],
                m.HACKER_BRIEF_FOR_LANE_SCHEMA,
            )
            self.assertTrue(result.get("degraded"))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
