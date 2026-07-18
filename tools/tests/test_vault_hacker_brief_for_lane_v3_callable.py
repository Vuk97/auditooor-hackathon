"""Regression tests for Wave-2 W2.8 ``vault_hacker_brief_for_lane_v3``.

Covers:

1. v2-parity short-circuit when both extension flags are off.
2. Default-flag envelope shape (schema, context_pack_id, calibration block).
3. Cross-corpus dedupe groups same-source records from different subtrees.
4. Cross-corpus dedupe disabled preserves v2 ordering.
5. Severity calibration attaches per-attack-class block with histogram.
6. Severity calibration disabled produces empty block.
7. `calibration_scope=cross_workspace` echoes onto each calibration entry.
8. Bad `calibration_scope` value gets clamped to `workspace_local`,
   `degraded_extensions.calibration_scope_invalid=true`.
9. Missing workspace_path returns degraded envelope with v3 schema.
10. Missing attack-class in pool produces empty calibration without
    failing the brief (no records present -> no per-class calibration).
11. Lane-id regex rejection mirrors v2.
12. Context-pack hash binds the v3 knobs (toggling a flag changes hash).
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
        "vault_mcp_server_v3_brief_test", MODULE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module()


def _record_yaml(
    record_id: str,
    attack_class: str,
    shape_tags: list[str],
    *,
    target_language: str = "go",
    target_domain: str = "consensus",
    target_repo: str = "owner/repo",
    source_audit_ref: str | None = None,
    source_url: str | None = None,
) -> str:
    tag_lines = "\n".join(f"    - {t}" for t in shape_tags)
    sar = source_audit_ref or f"synthetic:{record_id}"
    extra = ""
    if source_url:
        extra = f"source_url: {source_url}\n"
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
        "severity_at_finding: high\n"
        "year: 2024\n"
        "record_tier: public-corpus\n"
        "record_quality_score: 3.0\n"
        f"source_audit_ref: {sar}\n"
        f"{extra}"
        "source_extraction_method: synthetic-test\n"
        "source_extraction_confidence: 0.9\n"
    )


class HackerBriefV3CallableTests(unittest.TestCase):
    """End-to-end tests against a synthetic corpus on disk."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-mcp-v3-brief-test-")
        self.root = Path(self.tmp.name)
        # Two corpus subtrees to exercise cross-subtree dedupe.
        self.subtree_a_dir = self.root / "audit" / "corpus_tags" / "tags" / "subtree-a"
        self.subtree_b_dir = self.root / "audit" / "corpus_tags" / "tags" / "subtree-b"
        self.subtree_a_dir.mkdir(parents=True)
        self.subtree_b_dir.mkdir(parents=True)
        self.tags_root = self.root / "audit" / "corpus_tags" / "tags"
        self.index_dir = self.root / "audit" / "corpus_tags" / "index"
        self.index_dir.mkdir(parents=True)
        self.derived_dir = self.root / "audit" / "corpus_tags" / "derived"
        self.derived_dir.mkdir(parents=True)
        self.vault_dir = self.root / "obsidian-vault"
        self.vault_dir.mkdir()
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        (self.workspace / "SCOPE.md").write_text("synthetic scope", encoding="utf-8")

        # 6 synthetic records:
        # - rec-a-tier1 (subtree-a, reentrancy-class, source X)
        # - rec-b-tier1 (subtree-b, reentrancy-class, source X)  <- cross-subtree dupe of rec-a-tier1
        # - rec-a-tier2 (subtree-a, double-spend-class, source Y)
        # - rec-b-tier2 (subtree-b, double-spend-class, source Z) <- distinct
        # - rec-a-tier3 (subtree-a, reentrancy-class, source W)  <- distinct
        # - rec-a-quarantine (subtree-a, reentrancy-class, tier-5; excluded)
        self.records: list[tuple[Path, str, str, list[str], str]] = [
            (
                self.subtree_a_dir,
                "rec-a-tier1",
                "reentrancy-class",
                ["foo", "verification_tier:tier-1-verified-realtime-api"],
                "https://example.com/upstream/X",
            ),
            (
                self.subtree_b_dir,
                "rec-b-tier1",
                "reentrancy-class",
                ["foo", "verification_tier:tier-1-verified-realtime-api"],
                "https://example.com/upstream/X",  # same source as rec-a-tier1
            ),
            (
                self.subtree_a_dir,
                "rec-a-tier2",
                "double-spend-class",
                ["foo", "verification_tier:tier-2-verified-public-archive"],
                "https://example.com/upstream/Y",
            ),
            (
                self.subtree_b_dir,
                "rec-b-tier2",
                "double-spend-class",
                ["foo", "verification_tier:tier-2-verified-public-archive"],
                "https://example.com/upstream/Z",  # distinct
            ),
            (
                self.subtree_a_dir,
                "rec-a-tier3",
                "reentrancy-class",
                ["foo", "verification_tier:tier-3-synthetic-taxonomy-anchored"],
                "https://example.com/upstream/W",
            ),
            (
                self.subtree_a_dir,
                "rec-a-quarantine",
                "reentrancy-class",
                ["foo", "verification_tier:tier-5-quarantine"],
                "https://example.com/upstream/Q",
            ),
        ]

        index_rows: list[dict[str, Any]] = []
        for d, rid, ac, tags, sar in self.records:
            # Use the canonical per-record-directory layout so both the
            # index-loader path (v2 brief) and the walker path
            # (vault_severity_calibration) can see the same records:
            #   <subtree>/<rid>/record.yaml
            record_dir = d / rid
            record_dir.mkdir(parents=True, exist_ok=True)
            yaml_path = record_dir / "record.yaml"
            yaml_path.write_text(
                _record_yaml(rid, ac, tags, source_audit_ref=sar),
                encoding="utf-8",
            )
            index_rows.append(
                {
                    "attack_class": ac,
                    "bug_class": ac,
                    "key": ac,
                    "record_id": rid,
                    "severity_at_finding": "high",
                    "source_audit_ref": sar,
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
        for axis in ("by_language", "by_target_domain", "by_target_repo"):
            (self.index_dir / f"{axis}.jsonl").write_text("", encoding="utf-8")
        for sidecar in (
            "record_quality.jsonl",
            "proof_hardening.jsonl",
            "cross_language_analogues.jsonl",
        ):
            (self.derived_dir / sidecar).write_text("", encoding="utf-8")

        self.vault = vault_mcp_server.VaultQuery(self.vault_dir, self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _brief_kwargs(self, **overrides: Any) -> dict[str, Any]:
        base = {
            "workspace_path": str(self.workspace),
            "lane_id": "H1-v3-test",
            "files": ["SCOPE.md"],
            "attack_class": "reentrancy-class",
            "index_dir": str(self.index_dir),
            "tags_dir": str(self.tags_root),
            "quality_sidecar": str(self.derived_dir / "record_quality.jsonl"),
            "proof_hardening_sidecar": str(self.derived_dir / "proof_hardening.jsonl"),
            "cross_language_sidecar": str(self.derived_dir / "cross_language_analogues.jsonl"),
        }
        base.update(overrides)
        return base

    # 1. v2-parity short-circuit: both flags off, schema is v3 but the
    #    `records` list mirrors v2 (no dedupe, no calibration).
    def test_v2_parity_when_flags_off(self) -> None:
        v2 = self.vault.vault_hacker_brief_for_lane_v2(**self._brief_kwargs())
        v3 = self.vault.vault_hacker_brief_for_lane_v3(
            **self._brief_kwargs(
                cross_corpus_dedupe=False, with_severity_calibration=False
            )
        )
        self.assertFalse(v2.get("degraded"))
        self.assertFalse(v3.get("degraded"))
        self.assertEqual(
            v3["schema"], vault_mcp_server.HACKER_BRIEF_FOR_LANE_V3_SCHEMA
        )
        self.assertEqual(
            [r.get("record_id") for r in v3["records"]],
            [r.get("record_id") for r in v2["records"]],
        )
        self.assertEqual(v3["cross_corpus_dupes"], [])
        self.assertEqual(v3["severity_calibration"], {})

    # 2. Default flags ON: envelope carries schema + dupes + calibration blocks.
    def test_default_envelope_carries_v3_blocks(self) -> None:
        result = self.vault.vault_hacker_brief_for_lane_v3(**self._brief_kwargs())
        self.assertEqual(
            result["schema"], vault_mcp_server.HACKER_BRIEF_FOR_LANE_V3_SCHEMA
        )
        self.assertTrue(
            result["context_pack_id"].startswith(
                vault_mcp_server.HACKER_BRIEF_FOR_LANE_V3_SCHEMA + ":"
            )
        )
        self.assertEqual(len(result["context_pack_hash"]), 64)
        self.assertIn("cross_corpus_dupes", result)
        self.assertIn("severity_calibration", result)
        self.assertIn("degraded_extensions", result)
        self.assertTrue(result["cross_corpus_dedupe"])
        self.assertTrue(result["with_severity_calibration"])
        self.assertEqual(result["calibration_scope"], "workspace_local")

    # 3. Cross-corpus dedupe collapses the same-source pair from
    #    subtree-a and subtree-b. rec-a-tier1 and rec-b-tier1 share
    #    source_audit_ref "https://example.com/upstream/X".
    def test_cross_corpus_dedupe_collapses_same_source(self) -> None:
        result = self.vault.vault_hacker_brief_for_lane_v3(
            **self._brief_kwargs(cross_corpus_dedupe=True, attack_class_filter=[])
        )
        kept_ids = {r.get("record_id") for r in result["records"]}
        dupe_ids = {d.get("record_id") for d in result["cross_corpus_dupes"]}
        # Exactly one of rec-a-tier1 / rec-b-tier1 ends up in records[],
        # the other in cross_corpus_dupes[].
        self.assertEqual(
            len({"rec-a-tier1", "rec-b-tier1"} & kept_ids),
            1,
            f"kept_ids={kept_ids}, dupe_ids={dupe_ids}",
        )
        self.assertEqual(
            len({"rec-a-tier1", "rec-b-tier1"} & dupe_ids),
            1,
        )
        # The dupe entry carries a pointer back to the canonical kept record.
        cross_dupes = result["cross_corpus_dupes"]
        self.assertTrue(all("dupe_of_record_id" in d for d in cross_dupes))
        # Distinct-source rec-b-tier2 is NOT a cross-corpus dupe.
        self.assertNotIn("rec-b-tier2", dupe_ids)

    # 4. With dedupe disabled, both records appear in records[].
    def test_cross_corpus_dedupe_disabled_keeps_both_records(self) -> None:
        result = self.vault.vault_hacker_brief_for_lane_v3(
            **self._brief_kwargs(
                cross_corpus_dedupe=False, attack_class_filter=[]
            )
        )
        kept_ids = {r.get("record_id") for r in result["records"]}
        self.assertIn("rec-a-tier1", kept_ids)
        self.assertIn("rec-b-tier1", kept_ids)
        self.assertEqual(result["cross_corpus_dupes"], [])

    # 5. Severity calibration block populated per attack-class.
    def test_severity_calibration_inline(self) -> None:
        result = self.vault.vault_hacker_brief_for_lane_v3(
            **self._brief_kwargs(attack_class_filter=[])
        )
        cal = result["severity_calibration"]
        self.assertIsInstance(cal, dict)
        # At least reentrancy-class should have a calibration entry given
        # the synthetic records all set severity_at_finding=high.
        self.assertIn("reentrancy-class", cal)
        entry = cal["reentrancy-class"]
        self.assertIn("class_observed_modes", entry)
        self.assertIn("scope_used", entry)
        self.assertEqual(entry["scope_used"], "workspace_local")
        self.assertIn("severity_distribution", entry)
        # synthetic records all set severity_at_finding=high
        self.assertGreaterEqual(int(entry["severity_distribution"].get("high") or 0), 1)
        self.assertFalse(result["degraded_extensions"].get("severity_calibration"))

    # 6. Disabling severity calibration produces empty block.
    def test_severity_calibration_disabled(self) -> None:
        result = self.vault.vault_hacker_brief_for_lane_v3(
            **self._brief_kwargs(with_severity_calibration=False)
        )
        self.assertEqual(result["severity_calibration"], {})

    # 7. cross_workspace scope echoes onto each calibration entry.
    def test_cross_workspace_scope_echoes(self) -> None:
        result = self.vault.vault_hacker_brief_for_lane_v3(
            **self._brief_kwargs(
                calibration_scope="cross_workspace",
                attack_class_filter=[],
            )
        )
        self.assertEqual(result["calibration_scope"], "cross_workspace")
        for cls, entry in result["severity_calibration"].items():
            self.assertEqual(entry["scope_used"], "cross_workspace")

    # 8. Invalid `calibration_scope` clamps to workspace_local and sets
    #    the degraded-extension flag.
    def test_invalid_calibration_scope_clamps(self) -> None:
        result = self.vault.vault_hacker_brief_for_lane_v3(
            **self._brief_kwargs(calibration_scope="not_a_real_scope")
        )
        self.assertEqual(result["calibration_scope"], "workspace_local")
        self.assertTrue(
            result["degraded_extensions"].get("calibration_scope_invalid")
        )

    # 9. Missing workspace_path returns degraded envelope re-keyed to v3.
    def test_missing_workspace_path_degrades(self) -> None:
        result = self.vault.vault_hacker_brief_for_lane_v3(
            workspace_path="",
            lane_id="H1",
        )
        self.assertTrue(result["degraded"])
        self.assertEqual(
            result["schema"], vault_mcp_server.HACKER_BRIEF_FOR_LANE_V3_SCHEMA
        )
        self.assertEqual(result["reason"], "missing_workspace_path")
        # Extension blocks still present so callers don't KeyError.
        self.assertIn("cross_corpus_dupes", result)
        self.assertIn("severity_calibration", result)
        self.assertIn("degraded_extensions", result)

    # 10. Empty record pool (attack class with no corpus rows) returns
    #     well-formed envelope with empty calibration (no per-class entries).
    def test_missing_attack_class_yields_empty_calibration(self) -> None:
        result = self.vault.vault_hacker_brief_for_lane_v3(
            **self._brief_kwargs(attack_class_filter=["nonexistent-class-xyz"])
        )
        self.assertEqual(result["records"], [])
        # No matching class -> empty calibration. Extension did not fail.
        self.assertEqual(result["severity_calibration"], {})
        self.assertFalse(
            result["degraded_extensions"].get("severity_calibration")
        )
        self.assertEqual(
            result["schema"], vault_mcp_server.HACKER_BRIEF_FOR_LANE_V3_SCHEMA
        )

    # 11. Lane id regex rejection mirrors v2.
    def test_bad_lane_id_degrades(self) -> None:
        result = self.vault.vault_hacker_brief_for_lane_v3(
            workspace_path=str(self.workspace),
            lane_id="bad lane id with spaces!",
        )
        self.assertTrue(result["degraded"])
        self.assertIn("lane_id", result["reason"])
        self.assertEqual(
            result["schema"], vault_mcp_server.HACKER_BRIEF_FOR_LANE_V3_SCHEMA
        )

    # 12. Context-pack hash binds v3 knobs: flipping a flag changes the hash.
    def test_context_pack_hash_binds_v3_knobs(self) -> None:
        with_dedupe = self.vault.vault_hacker_brief_for_lane_v3(
            **self._brief_kwargs(cross_corpus_dedupe=True, attack_class_filter=[])
        )
        without_dedupe = self.vault.vault_hacker_brief_for_lane_v3(
            **self._brief_kwargs(cross_corpus_dedupe=False, attack_class_filter=[])
        )
        self.assertNotEqual(
            with_dedupe["context_pack_hash"],
            without_dedupe["context_pack_hash"],
        )
        # v2_context_pack_hash should be present and equal between the two
        # (v2 doesn't see the v3 knobs).
        self.assertEqual(
            with_dedupe.get("v2_context_pack_hash"),
            without_dedupe.get("v2_context_pack_hash"),
        )


class HackerBriefV3DispatchTests(unittest.TestCase):
    """Confirm the dispatch table routes the new method name."""

    def test_dispatch_routing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="auditooor-mcp-v3-dispatch-") as td:
            root = Path(td)
            (root / "obsidian-vault").mkdir()
            vault = vault_mcp_server.VaultQuery(root / "obsidian-vault", root)
            result = vault.call(
                "vault_hacker_brief_for_lane_v3",
                {"workspace_path": "", "lane_id": "H1"},
            )
            self.assertTrue(result.get("degraded"))
            self.assertEqual(
                result["schema"], vault_mcp_server.HACKER_BRIEF_FOR_LANE_V3_SCHEMA
            )


if __name__ == "__main__":
    unittest.main()
