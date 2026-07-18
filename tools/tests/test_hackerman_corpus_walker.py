"""Tests for hackerman-corpus-walker.py (B7 shared recursive walker coverage tool).

Verifies:
- Flat YAML, nested record.yaml, nested record.json, dual YAML/JSON (YAML canonical)
- Excluded subtrees (_QUARANTINE_*, _deprecated) skipped by default
- include_excluded surfaces quarantine records
- compare_with_sidecar reports coverage_ok when sidecar file_count matches
- JSON CLI output structure
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-corpus-walker.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("_hackerman_corpus_walker", str(TOOL))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_YAML_RECORD = textwrap.dedent("""\
    schema_version: auditooor.hackerman_record.v1.1
    record_id: {rid}
    source_audit_ref: test:source:{n}
    target_domain: lending
    target_language: solidity
    target_repo: test/proto
    target_component: Vault.sol
    function_shape:
      raw_signature: "function deposit(uint256 a) external"
      shape_tags:
        - deposit-shape
    bug_class: share-inflation
    attack_class: first-deposit-share-inflation
    attacker_role: unprivileged
    attacker_action_sequence: "Step 1: seed. Step 2: inflate."
    required_preconditions:
      - empty vault
    impact_class: theft
    impact_actor: depositor-class
    impact_dollar_class: "$100K-$1M"
    fix_pattern: virtual shares
    fix_anti_pattern_avoided: raw balance rate
    severity_at_finding: high
    year: 2024
    cross_language_analogues: []
    related_records: []
    verification_tier: tier-2-verified-public-archive
""")


def _write_yaml(path: Path, n: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rid = f"test:walker:{n}:{'abcdef'[:8]}{n:04d}"
    path.write_text(_YAML_RECORD.format(rid=rid, n=n), encoding="utf-8")


def _write_json(path: Path, n: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rid = f"test:walker-json:{n}:{'fedcba'[:8]}{n:04d}"
    record = {
        "schema_version": "auditooor.hackerman_record.v1.1",
        "record_id": rid,
        "source_audit_ref": f"test:source:json:{n}",
        "target_domain": "lending",
        "target_language": "solidity",
        "target_repo": "test/proto",
        "target_component": "Vault.sol",
        "function_shape": {
            "raw_signature": "function deposit(uint256 a) external",
            "shape_tags": ["deposit-shape"],
        },
        "bug_class": "share-inflation",
        "attack_class": "first-deposit-share-inflation",
        "attacker_role": "unprivileged",
        "attacker_action_sequence": "Step 1: seed. Step 2: inflate.",
        "required_preconditions": ["empty vault"],
        "impact_class": "theft",
        "impact_actor": "depositor-class",
        "impact_dollar_class": "$100K-$1M",
        "fix_pattern": "virtual shares",
        "fix_anti_pattern_avoided": "raw balance rate",
        "severity_at_finding": "high",
        "year": 2024,
        "cross_language_analogues": [],
        "related_records": [],
        "verification_tier": "tier-2-verified-public-archive",
    }
    path.write_text(json.dumps(record), encoding="utf-8")


class HackermanCorpusWalkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()
        self.tmp = tempfile.TemporaryDirectory(prefix="walker-")
        self.tag_dir = Path(self.tmp.name) / "tags"
        self.tag_dir.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_flat_yaml_counted(self) -> None:
        _write_yaml(self.tag_dir / "flat_rec0.yaml", 0)
        report = self.tool.walk_corpus(self.tag_dir)
        self.assertEqual(report["canonical_record_files"], 1)
        self.assertEqual(report["active_records"], 1)
        self.assertEqual(report["files_by_kind"].get("flat.yaml"), 1)

    def test_nested_record_yaml_counted(self) -> None:
        _write_yaml(self.tag_dir / "subtree" / "finding-1" / "record.yaml", 1)
        report = self.tool.walk_corpus(self.tag_dir)
        self.assertEqual(report["canonical_record_files"], 1)
        self.assertEqual(report["files_by_kind"].get("nested-record.yaml"), 1)

    def test_nested_record_json_counted(self) -> None:
        """B7: JSON-only nested records must appear in the walker count."""
        _write_json(self.tag_dir / "lending_protocols" / "finding-json-001" / "record.json", 2)
        report = self.tool.walk_corpus(self.tag_dir)
        self.assertEqual(report["canonical_record_files"], 1)
        self.assertEqual(report["active_records"], 1)
        self.assertEqual(report["files_by_kind"].get("nested-record.json"), 1)

    def test_dual_yaml_json_yaml_wins(self) -> None:
        """B7: When both record.yaml and record.json exist, YAML is canonical (no double-count)."""
        dual_dir = self.tag_dir / "subtree" / "dual-form"
        _write_yaml(dual_dir / "record.yaml", 3)
        _write_json(dual_dir / "record.json", 999)  # should be ignored
        report = self.tool.walk_corpus(self.tag_dir)
        self.assertEqual(report["canonical_record_files"], 1)
        self.assertEqual(report["files_by_kind"].get("nested-record.yaml"), 1)
        self.assertIsNone(report["files_by_kind"].get("nested-record.json"))

    def test_flat_plus_nested_both_counted(self) -> None:
        _write_yaml(self.tag_dir / "flat.yaml", 0)
        _write_yaml(self.tag_dir / "subtree" / "finding" / "record.yaml", 1)
        _write_json(self.tag_dir / "other" / "finding-j" / "record.json", 2)
        report = self.tool.walk_corpus(self.tag_dir)
        self.assertEqual(report["canonical_record_files"], 3)
        self.assertEqual(report["active_records"], 3)

    def test_quarantine_excluded_by_default(self) -> None:
        """B7: _QUARANTINE_* subtrees must be skipped in the default walk."""
        _write_yaml(self.tag_dir / "clean_rec.yaml", 0)
        _write_yaml(
            self.tag_dir / "_QUARANTINE_FABRICATED_CVE" / "bad.yaml", 99
        )
        report = self.tool.walk_corpus(self.tag_dir)
        self.assertEqual(report["canonical_record_files"], 1)
        self.assertEqual(report["active_records"], 1)

    def test_deprecated_excluded_by_default(self) -> None:
        """B7: _deprecated subtrees must be skipped in the default walk."""
        _write_yaml(self.tag_dir / "clean_rec.yaml", 0)
        _write_yaml(self.tag_dir / "_deprecated" / "old_format" / "record.yaml", 88)
        report = self.tool.walk_corpus(self.tag_dir)
        self.assertEqual(report["canonical_record_files"], 1)

    def test_include_excluded_surfaces_quarantine(self) -> None:
        """B7: include_excluded=True must include quarantine records."""
        _write_yaml(self.tag_dir / "clean_rec.yaml", 0)
        _write_yaml(
            self.tag_dir / "_QUARANTINE_FABRICATED_CVE" / "bad.yaml", 99
        )
        report_default = self.tool.walk_corpus(self.tag_dir, include_excluded=False)
        report_with = self.tool.walk_corpus(self.tag_dir, include_excluded=True)
        self.assertEqual(report_default["canonical_record_files"], 1)
        self.assertEqual(report_with["canonical_record_files"], 2)

    def test_report_schema_version_present(self) -> None:
        report = self.tool.walk_corpus(self.tag_dir)
        self.assertEqual(report["schema_version"], self.tool.SCHEMA_VERSION)
        self.assertTrue(report["generated_at_utc"])
        self.assertTrue(report["corpus_fingerprint"])

    def test_compare_with_sidecar_coverage_ok(self) -> None:
        """compare_with_sidecar reports coverage_ok when file counts match."""
        _write_yaml(self.tag_dir / "rec0.yaml", 0)
        _write_yaml(self.tag_dir / "rec1.yaml", 1)
        report = self.tool.walk_corpus(self.tag_dir)

        # Manufacture a fake sidecar JSONL whose meta says file_count=2.
        sidecar_path = Path(self.tmp.name) / "fake.jsonl"
        from hackerman_query_common import corpus_content_fingerprint
        fp, fc = corpus_content_fingerprint(self.tag_dir, recursive=True)
        meta = {
            "schema_version": "auditooor.hackerman_chain_candidates_sidecar.meta.v1",
            "corpus_fingerprint": fp,
            "corpus_file_count": fc,
            "records_emitted": 2,
        }
        sidecar_path.write_text(json.dumps(meta) + "\n", encoding="utf-8")

        cmp = self.tool.compare_with_sidecar(report, sidecar_path)
        self.assertEqual(cmp["walker_canonical_record_files"], 2)
        self.assertEqual(cmp["sidecar_meta_corpus_file_count"], 2)
        self.assertGreaterEqual(cmp["sidecar_file_coverage_ratio"], 0.98)
        self.assertTrue(cmp["coverage_ok"])

    def test_cli_json_output_structure(self) -> None:
        _write_yaml(self.tag_dir / "rec.yaml", 0)
        lines = []

        class _Capture:
            def write(self, s):
                lines.append(s)
            def flush(self):
                pass

        import io
        buf = io.StringIO()
        orig_stdout = sys.stdout
        sys.stdout = buf
        try:
            rc = self.tool.main(["--tag-dir", str(self.tag_dir), "--json"])
        finally:
            sys.stdout = orig_stdout

        self.assertEqual(rc, 0)
        doc = json.loads(buf.getvalue())
        self.assertIn("canonical_record_files", doc)
        self.assertIn("active_records", doc)
        self.assertIn("files_by_kind", doc)
        self.assertEqual(doc["canonical_record_files"], 1)


if __name__ == "__main__":
    unittest.main()
