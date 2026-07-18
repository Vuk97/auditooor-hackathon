from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-index-build.py"
FIXTURE_DIR = REPO_ROOT / "tools" / "tests" / "fixtures" / "hackerman_records"


def _load_tool():
    spec = importlib.util.spec_from_file_location("_hackerman_index_build", str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class HackermanIndexBuildTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.tag_dir = self.tmp_path / "tags"
        self.index_dir = self.tmp_path / "index"
        self.tag_dir.mkdir()
        for name in (
            "valid_lending_share_inflation.yaml",
            "valid_go_fee_bypass.yml",
            "legacy_verdict_tag.yaml",
        ):
            shutil.copy(FIXTURE_DIR / name, self.tag_dir / name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _read_rows(self, name: str):
        path = self.index_dir / f"{name}.jsonl"
        if path.exists():
            return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        shard_dir = self.index_dir / f"{name}.d"
        rows = []
        for shard in sorted(shard_dir.glob("*.jsonl")):
            rows.extend(json.loads(line) for line in shard.read_text(encoding="utf-8").splitlines())
        return rows

    def _read_manifest(self):
        return json.loads((self.index_dir / "manifest.json").read_text(encoding="utf-8"))

    def test_build_emits_all_indices_and_skips_legacy_yaml(self) -> None:
        counts = self.tool.build_indices(self.tag_dir, self.index_dir)
        self.assertEqual(counts["records_indexed"], 2)
        self.assertEqual(counts["records_skipped"], 1)
        self.assertRegex(counts["corpus_index_hash"], r"^[0-9a-f]{64}$")
        for name in self.tool.INDEX_NAMES:
            self.assertTrue(
                (self.index_dir / f"{name}.jsonl").exists()
                or (self.index_dir / f"{name}.d" / "manifest.json").exists(),
                name,
            )
        self.assertFalse((self.index_dir / "by_function_shape.jsonl").exists())
        self.assertTrue((self.index_dir / "by_function_shape.d" / "manifest.json").exists())
        self.assertTrue((self.index_dir / "manifest.json").exists())

    def test_build_emits_root_manifest(self) -> None:
        self.tool.build_indices(self.tag_dir, self.index_dir, preserve_existing=False)

        manifest = self._read_manifest()
        self.assertEqual(manifest["schema"], self.tool.ROOT_INDEX_MANIFEST_SCHEMA)
        self.assertEqual(manifest["index_names"], list(self.tool.INDEX_NAMES))
        self.assertEqual(manifest["sharded_index_names"], sorted(self.tool.SHARDED_INDEX_NAMES))
        self.assertFalse(manifest["preserve_existing"])
        self.assertRegex(manifest["corpus_index_hash"], r"^[0-9a-f]{64}$")
        file_paths = {row["path"] for row in manifest["files"]}
        self.assertIn("by_attack_class.jsonl", file_paths)
        self.assertIn("by_function_shape.d/manifest.json", file_paths)
        self.assertTrue(any(path.startswith("by_function_shape.d/") and path.endswith(".jsonl") for path in file_paths))
        self.assertNotIn("manifest.json", file_paths)

    def test_root_manifest_ignores_unknown_index_files(self) -> None:
        self.index_dir.mkdir()
        (self.index_dir / "by_extra.jsonl").write_text(
            json.dumps({"key": "x", "record_id": "x"}, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        self.tool.build_indices(self.tag_dir, self.index_dir, preserve_existing=False)

        manifest = self._read_manifest()
        file_paths = {row["path"] for row in manifest["files"]}
        self.assertNotIn("by_extra.jsonl", file_paths)

    def test_root_manifest_records_preserve_existing_mode_and_counts(self) -> None:
        self.index_dir.mkdir()
        legacy_row = {
            "key": "admin-bypass",
            "tag_file": "legacy.yaml",
            "verdict_id": "legacy/1",
        }
        (self.index_dir / "by_attack_class.jsonl").write_text(
            json.dumps(legacy_row, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        self.tool.build_indices(self.tag_dir, self.index_dir, preserve_existing=True)
        preserved_manifest = self._read_manifest()
        preserved_hash = preserved_manifest["corpus_index_hash"]
        self.assertTrue(preserved_manifest["preserve_existing"])
        self.assertEqual(preserved_manifest["preserved_rows_by_index"]["by_attack_class"], 1)
        self.assertEqual(
            preserved_manifest["row_counts_by_index"]["by_attack_class"],
            len(self._read_rows("by_attack_class")),
        )

        self.tool.build_indices(self.tag_dir, self.index_dir, preserve_existing=False)
        fresh_manifest = self._read_manifest()
        self.assertFalse(fresh_manifest["preserve_existing"])
        self.assertEqual(fresh_manifest["preserved_rows_by_index"], {})
        self.assertNotEqual(preserved_hash, fresh_manifest["corpus_index_hash"])

    def test_scalar_indices_have_expected_keys(self) -> None:
        self.tool.build_indices(self.tag_dir, self.index_dir)
        self.assertEqual(
            [row["key"] for row in self._read_rows("by_attack_class")],
            ["blocked-addr-fee-redirect", "first-deposit-share-inflation"],
        )
        self.assertEqual(
            [row["key"] for row in self._read_rows("by_target_repo")],
            ["dydxprotocol/v4-chain", "euler-xyz/euler-vault-kit"],
        )
        self.assertEqual([row["key"] for row in self._read_rows("by_language")], ["go", "solidity"])
        self.assertEqual([row["key"] for row in self._read_rows("by_target_domain")], ["dex", "lending"])
        self.assertEqual([row["key"] for row in self._read_rows("by_audit_year")], ["2024", "2025"])
        self.assertEqual(
            [row["key"] for row in self._read_rows("by_attacker_role")],
            ["privileged-compromised", "unprivileged"],
        )
        self.assertEqual([row["key"] for row in self._read_rows("by_severity")], ["high", "medium"])

    def test_heuristic_attack_class_backfill_provenance_surfaces_in_index_rows(self) -> None:
        (self.tag_dir / "audit_firm_bridge_report.yaml").write_text(
            """
schema_version: auditooor.hackerman_record.v1.1
record_id: audit-firm:cyfrin:bridge:aaaaaaaaaaaa
source_audit_ref: audit-firm:cyfrin:reports/bridge.pdf
target_domain: bridge
target_language: solidity
target_repo: unknown
target_component: Cyfrin/reports/bridge.pdf
function_shape:
  raw_signature: audit-firm-report::cyfrin/bridge
  shape_tags:
    - audit-firm-public-report
bug_class: audit-firm-public-report-index
attack_class: bridge-proof-domain-bypass
attacker_role: unprivileged
attacker_action_sequence: metadata-only bridge report classification
required_preconditions:
  - public report metadata only
impact_class: theft
impact_actor: arbitrary-user
impact_dollar_class: non-financial
fix_pattern: apply report recommendations
fix_anti_pattern_avoided: treating metadata-only report labels as finding proof
severity_at_finding: info
year: 2026
cross_language_analogues: []
related_records: []
verification_tier: tier-2-verified-public-archive
record_extensions:
  heuristic_attack_class_backfill:
    old_attack_class: audit-firm-public-report
    new_attack_class: bridge-proof-domain-bypass
    confidence: 0.92
    classification_scope: report-title-and-metadata-only
""".lstrip(),
            encoding="utf-8",
        )

        self.tool.build_indices(self.tag_dir, self.index_dir)

        rows = [
            row
            for row in self._read_rows("by_attack_class")
            if row.get("record_id") == "audit-firm:cyfrin:bridge:aaaaaaaaaaaa"
        ]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["attack_class_provenance"], "heuristic")
        self.assertEqual(rows[0]["classification_scope"], "report-title-and-metadata-only")
        self.assertEqual(rows[0]["attack_class_confidence"], 0.92)

    def test_solodit_year_2000_sentinel_indexes_as_unknown_audit_year(self) -> None:
        (self.tag_dir / "solodit_unknown_year.yaml").write_text(
            """
schema_version: auditooor.hackerman_record.v1
record_id: solodit-spec:1000:abcdefabcdef
source_audit_ref: solodit-spec:detectors/_specs/drafts_solodit/undated.yaml:1000
target_domain: vault
target_language: solidity
target_repo: unknown/solodit
target_component: Undated Solodit finding
function_shape:
  raw_signature: "function-name-hint: undated"
  shape_tags:
    - inferred-function-name
bug_class: logic-error
attack_class: protocol-invariant-bypass
attacker_role: unprivileged
attacker_action_sequence: exploit the undated Solodit finding
required_preconditions:
  - source spec has no preserved audit date
impact_class: griefing
impact_actor: arbitrary-user
impact_dollar_class: "$10K-$100K"
fix_pattern: preserve source date metadata before backfill
fix_anti_pattern_avoided: treating unknown Solodit dates as real year 2000 reports
severity_at_finding: medium
year: 2000
cross_language_analogues: []
related_records: []
""".lstrip(),
            encoding="utf-8",
        )

        self.tool.build_indices(self.tag_dir, self.index_dir)

        rows = self._read_rows("by_audit_year")
        solodit_rows = [row for row in rows if row.get("record_id") == "solodit-spec:1000:abcdefabcdef"]
        self.assertEqual(len(solodit_rows), 1)
        self.assertEqual(solodit_rows[0]["key"], self.tool.UNKNOWN_AUDIT_YEAR_KEY)
        self.assertEqual(solodit_rows[0]["year"], 2000)
        self.assertNotIn("2000", [row["key"] for row in rows])

    def test_function_name_hints_do_not_pollute_shape_hash_index(self) -> None:
        record_id = "solodit-spec:hint-only:abcdefabcdef"
        (self.tag_dir / "solodit_function_hint.yaml").write_text(
            f"""
schema_version: auditooor.hackerman_record.v1
record_id: {record_id}
source_audit_ref: solodit-spec:detectors/_specs/drafts_solodit/hint-only.yaml:hint-only
target_domain: vault
target_language: solidity
target_repo: unknown/solodit
target_component: Function hint only finding
function_shape:
  raw_signature: "function-name-hint: withdraw"
  shape_tags:
    - inferred-function-name
bug_class: logic-error
attack_class: protocol-invariant-bypass
attacker_role: unprivileged
attacker_action_sequence: exercise the hinted path
required_preconditions:
  - detector inferred a function name but no real source signature
impact_class: griefing
impact_actor: arbitrary-user
impact_dollar_class: "$10K-$100K"
fix_pattern: verify the real source callsite before shape matching
fix_anti_pattern_avoided: indexing all function-name hints under the empty function shape
severity_at_finding: medium
year: 2000
cross_language_analogues: []
related_records: []
""".lstrip(),
            encoding="utf-8",
        )

        self.tool.build_indices(self.tag_dir, self.index_dir)

        self.assertNotIn(record_id, [row.get("record_id") for row in self._read_rows("by_shape_hash")])
        hint_rows = [row for row in self._read_rows("by_function_shape") if row.get("record_id") == record_id]
        self.assertEqual([row["key"] for row in hint_rows], ["inferred-function-name"])

    def test_function_shape_index_expands_shape_tags(self) -> None:
        self.tool.build_indices(self.tag_dir, self.index_dir)
        rows = self._read_rows("by_function_shape")
        keys = [row["key"] for row in rows]
        self.assertIn("erc4626-preview-vs-actual-rounding", keys)
        self.assertIn("external-nonpayable-share-mint-after-asset-transfer", keys)
        self.assertIn("permissioned-msg-handler-with-fee-recipient-write", keys)
        self.assertTrue(all(row.get("function_signature") for row in rows))

    def test_shape_hash_index_is_built_from_raw_signatures(self) -> None:
        self.tool.build_indices(self.tag_dir, self.index_dir)
        rows = self._read_rows("by_shape_hash")
        self.assertGreaterEqual(len(rows), 2)
        self.assertTrue(all(row.get("shape_hash") == row.get("key") for row in rows))
        self.assertTrue(all(len(row["key"]) == 16 for row in rows))

    def test_invalid_hackerman_record_blocks_index_build(self) -> None:
        shutil.copy(FIXTURE_DIR / "invalid_missing_attack_class.yaml", self.tag_dir)
        with self.assertRaises(ValueError) as ctx:
            self.tool.build_indices(self.tag_dir, self.index_dir)
        self.assertIn("attack_class", str(ctx.exception))

    def test_build_is_deterministic(self) -> None:
        first = self.tool.build_indices(self.tag_dir, self.index_dir)
        first_contents = {
            path.relative_to(self.index_dir).as_posix(): path.read_text(encoding="utf-8")
            for path in sorted(self.index_dir.rglob("*"))
            if path.is_file() and (path.suffix == ".jsonl" or path.name == "manifest.json")
        }
        first_manifest_hash = self._read_manifest()["corpus_index_hash"]
        second = self.tool.build_indices(self.tag_dir, self.index_dir)
        second_contents = {
            path.relative_to(self.index_dir).as_posix(): path.read_text(encoding="utf-8")
            for path in sorted(self.index_dir.rglob("*"))
            if path.is_file() and (path.suffix == ".jsonl" or path.name == "manifest.json")
        }
        second_manifest_hash = self._read_manifest()["corpus_index_hash"]
        self.assertEqual(first, second)
        self.assertEqual(first_contents, second_contents)
        self.assertEqual(first_manifest_hash, second_manifest_hash)

    def test_preserve_existing_loads_legacy_function_shape_monolith_into_shards(self) -> None:
        self.index_dir.mkdir()
        legacy_row = {
            "key": "legacy-shape",
            "tag_file": "legacy.yaml",
            "verdict_id": "legacy/shape",
        }
        (self.index_dir / "by_function_shape.jsonl").write_text(
            json.dumps(legacy_row, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        counts = self.tool.build_indices(self.tag_dir, self.index_dir)

        self.assertIn("by_function_shape.d", counts)
        self.assertFalse((self.index_dir / "by_function_shape.jsonl").exists())
        rows = self._read_rows("by_function_shape")
        self.assertIn(legacy_row, rows)
        self.assertIn("erc4626-preview-vs-actual-rounding", [row["key"] for row in rows])

    def test_preserves_existing_legacy_index_rows_by_default(self) -> None:
        self.index_dir.mkdir()
        legacy_row = {
            "key": "admin-bypass",
            "tag_file": "legacy.yaml",
            "verdict_id": "legacy/1",
        }
        (self.index_dir / "by_attack_class.jsonl").write_text(
            json.dumps(legacy_row, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        self.tool.build_indices(self.tag_dir, self.index_dir)

        rows = self._read_rows("by_attack_class")
        self.assertIn(legacy_row, rows)
        self.assertIn("first-deposit-share-inflation", [row["key"] for row in rows])

    def test_preserve_existing_replaces_stale_hackerman_rows(self) -> None:
        self.index_dir.mkdir()
        stale_row = {
            "key": "2000",
            "record_id": "solodit/spec/1",
            "source_audit_ref": "solodit:old",
            "tag_file": "old.yaml",
            "target_repo": "old/repo",
        }
        (self.index_dir / "by_audit_year.jsonl").write_text(
            json.dumps(stale_row, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (self.tag_dir / "replacement.yaml").write_text(
            """
schema_version: auditooor.hackerman_record.v1
record_id: solodit/spec/1
source_audit_ref: solodit:new
target_domain: lending
target_language: solidity
target_repo: example/new
target_component: Vault
function_shape:
  raw_signature: "function withdraw(uint256 amount) external"
  shape_tags:
    - withdrawal
bug_class: withdrawal
attack_class: withdrawal-bypass
attacker_role: unprivileged
attacker_action_sequence: withdraw through the vulnerable path
required_preconditions:
  - funded vault
impact_class: theft
impact_actor: arbitrary-user
impact_dollar_class: "$100K-$1M"
fix_pattern: validate withdrawal accounting
fix_anti_pattern_avoided: stale row preservation
severity_at_finding: high
year: 2025
cross_language_analogues: []
related_records: []
""".lstrip(),
            encoding="utf-8",
        )

        self.tool.build_indices(self.tag_dir, self.index_dir)

        rows = self._read_rows("by_audit_year")
        self.assertNotIn(stale_row, rows)
        self.assertIn("2025", [row["key"] for row in rows])
        self.assertNotIn("old.yaml", [row.get("tag_file") for row in rows])

    def test_preserve_existing_prunes_missing_tag_file_rows_with_record_identity(self) -> None:
        self.index_dir.mkdir()
        stale_row = {
            "key": "admin-bypass",
            "record_id": "prior-audit:dydx:stale",
            "source_audit_ref": "prior-audit:dydx:old:L1:S1",
            "tag_file": "missing-prior-audit.yaml",
            "target_repo": "dydxprotocol/v4-chain",
        }
        legacy_row = {
            "key": "admin-bypass",
            "tag_file": "legacy.yaml",
            "verdict_id": "legacy/1",
        }
        (self.index_dir / "by_attack_class.jsonl").write_text(
            json.dumps(stale_row, sort_keys=True) + "\n"
            + json.dumps(legacy_row, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        self.tool.build_indices(self.tag_dir, self.index_dir)

        rows = self._read_rows("by_attack_class")
        self.assertNotIn(stale_row, rows)
        self.assertIn(legacy_row, rows)

    def test_preserve_existing_prunes_stale_nested_record_yaml_rows(self) -> None:
        (self.tag_dir / "valid_go_fee_bypass.yml").unlink()
        nested = self.tag_dir / "nested"
        nested.mkdir()
        shutil.copy(FIXTURE_DIR / "valid_go_fee_bypass.yml", nested / "record.yaml")
        self.index_dir.mkdir()
        stale_row = {
            "key": "admin-bypass",
            "record_id": "prior-audit:stale:nested-record",
            "source_audit_ref": "prior-audit:stale:nested-record",
            "tag_file": "record.yaml",
            "target_repo": "example/stale",
        }
        (self.index_dir / "by_attack_class.jsonl").write_text(
            json.dumps(stale_row, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        self.tool.build_indices(self.tag_dir, self.index_dir)

        rows = self._read_rows("by_attack_class")
        self.assertNotIn(stale_row, rows)
        self.assertIn("nested/record.yaml", [row.get("tag_file") for row in rows])
        self.assertNotIn("record.yaml", [row.get("tag_file") for row in rows])

    def test_no_preserve_existing_rebuilds_hackerman_rows_only(self) -> None:
        self.index_dir.mkdir()
        (self.index_dir / "by_attack_class.jsonl").write_text(
            json.dumps(
                {"key": "admin-bypass", "tag_file": "legacy.yaml", "verdict_id": "legacy/1"},
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        self.tool.build_indices(self.tag_dir, self.index_dir, preserve_existing=False)

        rows = self._read_rows("by_attack_class")
        self.assertNotIn("admin-bypass", [row["key"] for row in rows])
        self.assertEqual(len(rows), 2)


if __name__ == "__main__":
    unittest.main()
