"""Wave-2 PR-A: tests for the 5 additive index emitters.

Covers ``by_cve_id``, ``by_ghsa_id``, ``by_firm``, ``by_verification_tier``,
and ``by_incident_date`` against both v1 (shape_tag fallback / regex
extraction) and v1.1 (first-class field) records.
"""
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


V1_1_RECORD_TEMPLATE = """schema_version: auditooor.hackerman_record.v1.1
record_id: {record_id}
source_audit_ref: {source_audit_ref}
target_domain: lending
target_language: solidity
target_repo: example/vault
target_component: Example.deposit
function_shape:
  raw_signature: "function deposit(uint256 amount) external"
  shape_tags:
{shape_tags}
bug_class: logic-error
attack_class: first-deposit-share-inflation
attacker_role: unprivileged
attacker_action_sequence: "{action}"
required_preconditions:
  - empty vault
impact_class: theft
impact_actor: arbitrary-user
impact_dollar_class: "$10K-$100K"
fix_pattern: validate
fix_anti_pattern_avoided: trust
severity_at_finding: high
year: {year}
cross_language_analogues: []
related_records: []
{extras}
"""


def _render(record_id, source_audit_ref, year=2024, shape_tags=("simple",), action="exploit", extras=""):
    tags = "\n".join(f"    - {tag}" for tag in shape_tags)
    return V1_1_RECORD_TEMPLATE.format(
        record_id=record_id,
        source_audit_ref=source_audit_ref,
        shape_tags=tags,
        action=action,
        year=year,
        extras=extras,
    )


class HackermanIndexBuildV1_1FieldsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.tag_dir = self.tmp_path / "tags"
        self.index_dir = self.tmp_path / "index"
        self.tag_dir.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _read_rows(self, name: str):
        path = self.index_dir / f"{name}.jsonl"
        if path.exists():
            return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        shard_dir = self.index_dir / f"{name}.d"
        rows = []
        for shard in sorted(shard_dir.glob("*.jsonl")):
            rows.extend(json.loads(line) for line in shard.read_text(encoding="utf-8").splitlines() if line.strip())
        return rows

    def _read_manifest(self):
        return json.loads((self.index_dir / "manifest.json").read_text(encoding="utf-8"))

    def test_index_names_includes_five_wave2_indexes(self) -> None:
        for name in (
            "by_cve_id",
            "by_ghsa_id",
            "by_firm",
            "by_verification_tier",
            "by_incident_date",
        ):
            self.assertIn(name, self.tool.INDEX_NAMES, name)

    def test_v1_1_top_level_cve_id_indexed(self) -> None:
        (self.tag_dir / "with_cve.yaml").write_text(
            _render(
                "example:cve-rec:abcdef123456",
                "example:cve-rec:1",
                extras="cve_id: CVE-2024-12345\n",
            ),
            encoding="utf-8",
        )
        self.tool.build_indices(self.tag_dir, self.index_dir, preserve_existing=False)
        rows = self._read_rows("by_cve_id")
        self.assertEqual([row["key"] for row in rows], ["CVE-2024-12345"])
        self.assertEqual(rows[0]["record_id"], "example:cve-rec:abcdef123456")

    def test_v1_cve_extracted_from_source_audit_ref(self) -> None:
        # v1 record without top-level cve_id: regex extraction over source_audit_ref.
        (self.tag_dir / "legacy_cve.yaml").write_text(
            _render(
                "example:legacy-cve:111111111111",
                "findings-go:ext-CVE-2023-99999",
                action="legacy",
            ),
            encoding="utf-8",
        )
        self.tool.build_indices(self.tag_dir, self.index_dir, preserve_existing=False)
        rows = self._read_rows("by_cve_id")
        self.assertEqual([row["key"] for row in rows], ["CVE-2023-99999"])

    def test_v1_1_top_level_ghsa_id_indexed(self) -> None:
        (self.tag_dir / "with_ghsa.yaml").write_text(
            _render(
                "example:ghsa-rec:222222222222",
                "example:ghsa-rec:1",
                extras="ghsa_id: GHSA-abcd-1234-wxyz\n",
            ),
            encoding="utf-8",
        )
        self.tool.build_indices(self.tag_dir, self.index_dir, preserve_existing=False)
        rows = self._read_rows("by_ghsa_id")
        self.assertEqual([row["key"] for row in rows], ["GHSA-abcd-1234-wxyz"])

    def test_v1_ghsa_extracted_from_record_id(self) -> None:
        (self.tag_dir / "legacy_ghsa.yaml").write_text(
            _render(
                "findings-go:GHSA-9gxx-58q6-42p7:33333333",
                "findings-go:reference/findings_go.jsonl:GHSA-9gxx-58q6-42p7",
                action="legacy",
            ),
            encoding="utf-8",
        )
        self.tool.build_indices(self.tag_dir, self.index_dir, preserve_existing=False)
        rows = self._read_rows("by_ghsa_id")
        self.assertEqual([row["key"] for row in rows], ["GHSA-9gxx-58q6-42p7"])

    def test_firm_extracted_from_shape_tag(self) -> None:
        (self.tag_dir / "firm_shape.yaml").write_text(
            _render(
                "example:firm-shape:444444444444",
                "example:firm-shape:1",
                shape_tags=("audit-firm-public-report", "firm-pashov-audits"),
            ),
            encoding="utf-8",
        )
        self.tool.build_indices(self.tag_dir, self.index_dir, preserve_existing=False)
        rows = self._read_rows("by_firm")
        self.assertEqual([row["key"] for row in rows], ["pashov-audits"])

    def test_firm_extracted_from_audit_firm_source_audit_ref(self) -> None:
        (self.tag_dir / "firm_ref.yaml").write_text(
            _render(
                "example:firm-ref:555555555555",
                "audit-firm:zellic-publications:Chainflip-Solana.pdf",
                shape_tags=("simple",),
            ),
            encoding="utf-8",
        )
        self.tool.build_indices(self.tag_dir, self.index_dir, preserve_existing=False)
        rows = self._read_rows("by_firm")
        self.assertEqual([row["key"] for row in rows], ["zellic-publications"])

    def test_verification_tier_top_level_takes_precedence(self) -> None:
        (self.tag_dir / "tier_top.yaml").write_text(
            _render(
                "example:tier-top:666666666666",
                "example:tier-top:1",
                shape_tags=("simple", "verification_tier:tier-4-bundled-fixture"),
                extras="verification_tier: tier-2-verified-public-archive\n",
            ),
            encoding="utf-8",
        )
        self.tool.build_indices(self.tag_dir, self.index_dir, preserve_existing=False)
        rows = self._read_rows("by_verification_tier")
        keys = sorted({row["key"] for row in rows})
        # Both surfaces are emitted (top-level + shape_tag fallback) so a
        # query for either resolves the same record_id. Top-level appears
        # first in extraction order so it's the canonical key.
        self.assertIn("tier-2-verified-public-archive", keys)
        self.assertIn("tier-4-bundled-fixture", keys)
        # Record id must appear at least once for each surface key.
        for row in rows:
            self.assertEqual(row["record_id"], "example:tier-top:666666666666")

    def test_verification_tier_shape_tag_fallback(self) -> None:
        (self.tag_dir / "tier_shape.yaml").write_text(
            _render(
                "example:tier-shape:777777777777",
                "example:tier-shape:1",
                shape_tags=("simple", "verification_tier:tier-3-synthetic-taxonomy-anchored"),
            ),
            encoding="utf-8",
        )
        self.tool.build_indices(self.tag_dir, self.index_dir, preserve_existing=False)
        rows = self._read_rows("by_verification_tier")
        self.assertEqual([row["key"] for row in rows], ["tier-3-synthetic-taxonomy-anchored"])

    def test_incident_date_indexes_year(self) -> None:
        (self.tag_dir / "year_real.yaml").write_text(
            _render("example:year:888888888888", "example:year:1", year=2025),
            encoding="utf-8",
        )
        self.tool.build_indices(self.tag_dir, self.index_dir, preserve_existing=False)
        rows = self._read_rows("by_incident_date")
        self.assertEqual([row["key"] for row in rows], ["2025"])

    def test_incident_date_solodit_2000_sentinel_indexed_as_unknown(self) -> None:
        (self.tag_dir / "solodit_undated.yaml").write_text(
            _render(
                "solodit-spec:undated:999999999999",
                "solodit-spec:detectors/_specs/drafts/undated.yaml:1",
                year=2000,
                shape_tags=("inferred-function-name",),
            ),
            encoding="utf-8",
        )
        self.tool.build_indices(self.tag_dir, self.index_dir, preserve_existing=False)
        rows = self._read_rows("by_incident_date")
        self.assertEqual(
            [row["key"] for row in rows], [self.tool.UNKNOWN_INCIDENT_DATE_KEY]
        )
        self.assertEqual(rows[0]["year"], 2000)

    def test_record_without_cve_or_ghsa_skips_those_indexes(self) -> None:
        (self.tag_dir / "no_ids.yaml").write_text(
            _render("example:no-ids:aaaaaaaaaaaa", "example:no-ids:1"),
            encoding="utf-8",
        )
        self.tool.build_indices(self.tag_dir, self.index_dir, preserve_existing=False)
        # Files exist (write_indices creates empty monoliths) but should have zero rows.
        self.assertEqual(self._read_rows("by_cve_id"), [])
        self.assertEqual(self._read_rows("by_ghsa_id"), [])
        # by_incident_date always emits exactly one row per record.
        self.assertEqual(len(self._read_rows("by_incident_date")), 1)

    def test_build_is_deterministic_with_new_indexes(self) -> None:
        # ``valid_lending_share_inflation`` (v1) and the v1.1 sibling share a
        # record_id; load only the v1.1 fixture plus the v1 go-fee one so the
        # duplicate-record-id guard does not fire.
        for fixture_name in ("valid_go_fee_bypass.yml", "valid_v1_1_lending_share_inflation.yaml"):
            shutil.copy(FIXTURE_DIR / fixture_name, self.tag_dir / fixture_name)
        first = self.tool.build_indices(self.tag_dir, self.index_dir, preserve_existing=False)
        first_contents = {
            path.name: path.read_text(encoding="utf-8")
            for path in sorted(self.index_dir.rglob("*.jsonl"))
        }
        second = self.tool.build_indices(self.tag_dir, self.index_dir, preserve_existing=False)
        second_contents = {
            path.name: path.read_text(encoding="utf-8")
            for path in sorted(self.index_dir.rglob("*.jsonl"))
        }
        self.assertEqual(first, second)
        self.assertEqual(first_contents, second_contents)

    def test_build_emits_root_manifest_with_corpus_index_hash(self) -> None:
        (self.tag_dir / "manifest_record.yaml").write_text(
            _render("example:manifest:bbbbbbbbbbbb", "example:manifest:1"),
            encoding="utf-8",
        )
        self.tool.build_indices(self.tag_dir, self.index_dir, preserve_existing=False)

        manifest = self._read_manifest()
        self.assertEqual(manifest["schema"], self.tool.ROOT_INDEX_MANIFEST_SCHEMA)
        self.assertRegex(manifest["corpus_index_hash"], r"^[0-9a-f]{64}$")
        file_paths = {row["path"] for row in manifest["files"]}
        self.assertIn("by_attack_class.jsonl", file_paths)
        self.assertIn("by_function_shape.d/manifest.json", file_paths)
        self.assertTrue(any(path.startswith("by_function_shape.d/") and path.endswith(".jsonl") for path in file_paths))
        self.assertNotIn("manifest.json", file_paths)

    def test_root_manifest_is_byte_stable_across_rebuilds(self) -> None:
        (self.tag_dir / "stable_record.yaml").write_text(
            _render("example:stable:cccccccccccc", "example:stable:1"),
            encoding="utf-8",
        )
        self.tool.build_indices(self.tag_dir, self.index_dir, preserve_existing=False)
        first_bytes = (self.index_dir / "manifest.json").read_bytes()
        first_hash = self._read_manifest()["corpus_index_hash"]

        self.tool.build_indices(self.tag_dir, self.index_dir, preserve_existing=False)
        second_bytes = (self.index_dir / "manifest.json").read_bytes()
        second_hash = self._read_manifest()["corpus_index_hash"]

        self.assertEqual(first_bytes, second_bytes)
        self.assertEqual(first_hash, second_hash)

    def test_root_manifest_hash_changes_when_index_content_changes(self) -> None:
        (self.tag_dir / "first_record.yaml").write_text(
            _render("example:first:dddddddddddd", "example:first:1"),
            encoding="utf-8",
        )
        self.tool.build_indices(self.tag_dir, self.index_dir, preserve_existing=False)
        first_hash = self._read_manifest()["corpus_index_hash"]

        (self.tag_dir / "second_record.yaml").write_text(
            _render("example:second:eeeeeeeeeeee", "example:second:1"),
            encoding="utf-8",
        )
        self.tool.build_indices(self.tag_dir, self.index_dir, preserve_existing=False)
        second_hash = self._read_manifest()["corpus_index_hash"]

        self.assertNotEqual(first_hash, second_hash)


if __name__ == "__main__":
    unittest.main()
