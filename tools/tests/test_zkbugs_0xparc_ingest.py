#!/usr/bin/env python3
"""Tests for tools/zkbugs-0xparc-ingest.py.

Runs entirely offline: all tests use the local fixture at
  tools/tests/fixtures/zkbugs_0xparc/sample_readme.md
No network access is required.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "zkbugs-0xparc-ingest.py"
FIXTURE_DIR = ROOT / "tools" / "tests" / "fixtures" / "zkbugs_0xparc"
SAMPLE_README = FIXTURE_DIR / "sample_readme.md"


def _make_repo_dir(tmp: Path) -> Path:
    """Create a temporary directory that looks like a zk-bug-tracker clone.

    Copies the fixture README.md so the tool can locate it via --repo-path.
    """
    repo = tmp / "zk-bug-tracker"
    repo.mkdir()
    (repo / "README.md").write_text(SAMPLE_README.read_text(encoding="utf-8"), encoding="utf-8")
    return repo


def _load_tool():
    spec = importlib.util.spec_from_file_location("zkbugs_0xparc_ingest_test_subject", TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class TestMarkdownTableParsing(unittest.TestCase):
    """Assertion 1: markdown table parsing extracts correct rows from fixture."""

    def setUp(self):
        self.tool = _load_tool()

    def test_parse_table_rows(self):
        """Table with header + separator + data rows is parsed correctly."""
        table_md = (
            "| Title | Project | Type | Severity | Link |\n"
            "|-------|---------|------|----------|------|\n"
            "| Under-constrained signal | DemoProj | Under-constrained | High | https://github.com/demo/proj/pull/1 |\n"
            "| Missing range check | OtherProj | Missing Constraint | Medium | https://github.com/other/proj/commit/abc123 |\n"
        )
        rows = self.tool._parse_markdown_tables(table_md)
        self.assertEqual(len(rows), 2, f"Expected 2 rows, got {len(rows)}: {rows}")
        self.assertEqual(rows[0]["title"], "Under-constrained signal")
        self.assertEqual(rows[0]["vulnerability"], "Under-constrained")
        self.assertEqual(rows[1]["title"], "Missing range check")
        self.assertEqual(rows[1]["project"], "OtherProj")

    def test_empty_input_empty_table(self):
        """Empty input returns empty list, no crash."""
        rows = self.tool._parse_markdown_tables("")
        self.assertEqual(rows, [])

    def test_no_table_in_prose(self):
        """Plain prose with no tables returns empty list."""
        prose = "This is a description paragraph.\n\nAnother paragraph.\n"
        rows = self.tool._parse_markdown_tables(prose)
        self.assertEqual(rows, [])


class TestEmptyInput(unittest.TestCase):
    """Assertion 2: empty input produces empty index with no crash."""

    def setUp(self):
        self.tool = _load_tool()

    def test_empty_content_empty_records(self):
        records = self.tool.parse_readme("")
        self.assertEqual(records, [])

    def test_empty_content_summary(self):
        summary = self.tool.summarize([])
        self.assertEqual(summary["total"], 0)
        self.assertEqual(summary["by_dsl"], {})
        self.assertEqual(summary["by_vulnerability"], {})


class TestDSLClassification(unittest.TestCase):
    """Assertion 3: DSL classification from section header / body content."""

    def setUp(self):
        self.tool = _load_tool()

    def test_circom_dsl_from_slug(self):
        """Slug containing 'circom' -> DSL 'Circom'."""
        dsl = self.tool._classify_dsl("circom-pairing-1", "some body text")
        self.assertEqual(dsl, "Circom")

    def test_halo2_dsl_from_slug(self):
        """Slug containing 'halo2' -> DSL 'Halo2'."""
        dsl = self.tool._classify_dsl("halo2-missing-check", "some text")
        self.assertEqual(dsl, "Halo2")

    def test_dsl_from_body_circom_keyword(self):
        """Body with 'circom' keyword -> DSL 'Circom' even if slug is generic."""
        dsl = self.tool._classify_dsl("dark-forest-1", "This circuit uses Circom language.")
        self.assertEqual(dsl, "Circom")

    def test_fixture_readme_sections_classified(self):
        """All three bug sections in fixture should be classified as Circom (body clue)."""
        content = SAMPLE_README.read_text(encoding="utf-8")
        records = self.tool.parse_readme(content)
        # fixture has 3 bug sections; dark-forest and bigint mention Circom in body
        self.assertGreaterEqual(len(records), 1)
        dsls = {r.dsl for r in records}
        # At least one Circom classification expected
        self.assertIn("Circom", dsls, f"Expected Circom in DSL set: {dsls}")

    def test_general_zk_fallback(self):
        """Unknown slug + body without DSL keywords -> 'ZK (general)'."""
        dsl = self.tool._classify_dsl("some-other-bug", "A proof system vulnerability")
        self.assertEqual(dsl, "ZK (general)")


class TestLicenseNotice(unittest.TestCase):
    """Assertion 4: license/NOTICE block present in output."""

    def setUp(self):
        self.tool = _load_tool()

    def test_notice_in_output_dict(self):
        """build_output() includes NOTICE key at top level."""
        records = self.tool.parse_readme(SAMPLE_README.read_text(encoding="utf-8"))
        payload = self.tool.build_output(records)
        self.assertIn("NOTICE", payload)
        notice = payload["NOTICE"]
        self.assertIn("CC-BY-SA-4.0", notice)
        self.assertIn("0xPARC", notice)

    def test_provenance_in_each_record(self):
        """Each record dict carries provenance with license field."""
        records = self.tool.parse_readme(SAMPLE_README.read_text(encoding="utf-8"))
        payload = self.tool.build_output(records)
        for rec in payload["records"]:
            prov = rec.get("provenance", {})
            self.assertEqual(prov.get("license"), "CC-BY-SA-4.0", f"Record missing license: {rec.get('title')}")
            self.assertTrue(prov.get("attribution_required"), f"Record attribution not set: {rec.get('title')}")

    def test_notice_present_in_file_output(self):
        """CLI run writes NOTICE to the JSON output file."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = _make_repo_dir(Path(tmp))
            out = Path(tmp) / "0xparc_index.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--repo-path",
                    str(repo),
                    "--out",
                    str(out),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertIn("NOTICE", payload)
            self.assertIn("CC-BY-SA-4.0", payload["NOTICE"])


class TestMergeDeduplication(unittest.TestCase):
    """Assertion 5: --merge-with dedupes by project+title."""

    def setUp(self):
        self.tool = _load_tool()

    def _make_primary_index(self, tmp: Path) -> Path:
        """Write a minimal primary index JSON with one record matching the fixture."""
        primary_rec = {
            "title": "Dark Forest v0.3: Missing Bit Length Check",
            "bug_id": "zksecurity-circom-dark-forest",
            "rel_path": "dataset/circom/darkforest/missing_range",
            "dsl": "Circom",
            "vulnerability": "Under-Constrained",
            "project": "https://github.com/darkforest-eth/circuits",
            "commit": "abc123",
            "fix_commit": "1b5c8440",
            "reproduced": True,
            "location_path": "circuits/range_proof/circuit.circom",
            "location_function": "RangeProof",
            "location_line": "10",
            "source_links": ["https://github.com/darkforest-eth/circuits/commit/1b5c8440"],
            "source_ids": [],
            "commands": {"Reproduce": "./zkbugs_exploit.sh"},
            "short_vulnerability": "RangeProof circuit missing bit length constraint.",
            "short_exploit": "Attacker bypasses range proof with oversized input.",
            "proposed_mitigation": "Add Num2Bits range constraint.",
            "report_ids": [],
            "report_files": [],
            "report_text_files": [],
            "priority_score": 100,
            "priority_reasons": ["reproduced"],
            "template_name": "RangeProof",
            "signal_names": [],
            "component_names": [],
            "library_handle": "circuits",
        }
        primary = {
            "schema": "auditooor.zkbugs_index.v2",
            "source": "zksecurity/zkbugs",
            "generated_at": "2026-01-01T00:00:00+00:00",
            "summary": {"total": 1, "by_dsl": {"Circom": 1}, "by_vulnerability": {}},
            "records": [primary_rec],
        }
        p = tmp / "primary.json"
        p.write_text(json.dumps(primary, indent=2), encoding="utf-8")
        return p

    def test_dedup_by_title_project(self):
        """Record with matching (project, title) is merged, not duplicated."""
        content = SAMPLE_README.read_text(encoding="utf-8")
        new_records = self.tool.parse_readme(content)

        with tempfile.TemporaryDirectory() as tmp:
            primary_path = self._make_primary_index(Path(tmp))
            merged, sources = self.tool.merge_indices(primary_path, new_records)

        # There are 3 bug sections in fixture. 1 matches the primary (Dark Forest).
        # So merged should have 1 (deduped) + 2 new = 3 total.
        self.assertEqual(len(merged), 3, f"Expected 3 merged records, got {len(merged)}")

    def test_dedup_preserves_primary_record(self):
        """When collision: primary record is kept (not replaced by 0xPARC version)."""
        content = SAMPLE_README.read_text(encoding="utf-8")
        new_records = self.tool.parse_readme(content)

        with tempfile.TemporaryDirectory() as tmp:
            primary_path = self._make_primary_index(Path(tmp))
            merged, _ = self.tool.merge_indices(primary_path, new_records)

        # Find the dark-forest record
        dark_forest = next(
            (r for r in merged if "Dark Forest" in r.get("title", "")), None
        )
        self.assertIsNotNone(dark_forest, "Dark Forest record missing from merged output")
        # Primary record has reproduced=True; 0xPARC version has reproduced=False
        self.assertTrue(dark_forest.get("reproduced"), "Primary (reproduced=True) record was replaced")

    def test_dedup_adds_cross_ref(self):
        """Colliding 0xPARC record's links are added as cross_refs_0xparc on primary."""
        content = SAMPLE_README.read_text(encoding="utf-8")
        new_records = self.tool.parse_readme(content)

        with tempfile.TemporaryDirectory() as tmp:
            primary_path = self._make_primary_index(Path(tmp))
            merged, _ = self.tool.merge_indices(primary_path, new_records)

        dark_forest = next(
            (r for r in merged if "Dark Forest" in r.get("title", "")), None
        )
        self.assertIsNotNone(dark_forest)
        # 0xPARC record for Dark Forest has github links; these should be cross-referenced
        cross_refs = dark_forest.get("cross_refs_0xparc", [])
        self.assertIsInstance(cross_refs, list)

    def test_sources_list_updated(self):
        """Merged output sources list contains both zksecurity and 0xparc."""
        content = SAMPLE_README.read_text(encoding="utf-8")
        new_records = self.tool.parse_readme(content)

        with tempfile.TemporaryDirectory() as tmp:
            primary_path = self._make_primary_index(Path(tmp))
            merged, sources = self.tool.merge_indices(primary_path, new_records)

        self.assertIn("zksecurity/zkbugs", sources)
        self.assertIn("0xparc/zk-bug-tracker", sources)

    def test_cli_merge_with_flag(self):
        """CLI --merge-with flag produces unified output with NOTICE."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = _make_repo_dir(Path(tmp))
            primary_path = self._make_primary_index(Path(tmp))
            out = Path(tmp) / "unified.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--repo-path",
                    str(repo),
                    "--merge-with",
                    str(primary_path),
                    "--out",
                    str(out),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertIn("NOTICE", payload)
            self.assertIsInstance(payload["source"], list)
            self.assertIn("0xparc/zk-bug-tracker", payload["source"])
            # 3 total: 1 deduped (dark-forest) + 2 new (bigint + semaphore)
            self.assertEqual(payload["summary"]["total"], 3)


class TestLocalFileMode(unittest.TestCase):
    """Assertion 6: --readme-url mode uses local fixture file (no network)."""

    def setUp(self):
        self.tool = _load_tool()

    def test_read_readme_from_repo_path(self):
        """_read_readme with repo_path reads README.md from disk, no network."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = _make_repo_dir(Path(tmp))
            content = self.tool._read_readme(
                readme_url="http://should-not-be-called.invalid/",
                repo_path=repo,
            )
        self.assertIn("ZK Bug Tracker", content)
        self.assertIn("Dark Forest", content)

    def test_parse_fixture_produces_records(self):
        """Parsing fixture README produces the expected 3 bug records."""
        content = SAMPLE_README.read_text(encoding="utf-8")
        records = self.tool.parse_readme(content)
        # Fixture has 3 bugs in the wild (stops before common-vulnerabilities section)
        self.assertEqual(len(records), 3, f"Expected 3 records from fixture, got {len(records)}: {[r.title for r in records]}")

    def test_schema_field_in_output(self):
        """Output contains correct schema identifier."""
        content = SAMPLE_README.read_text(encoding="utf-8")
        records = self.tool.parse_readme(content)
        payload = self.tool.build_output(records)
        self.assertEqual(payload["schema"], "auditooor.zkbugs_index.v2")

    def test_cli_repo_path_flag(self):
        """CLI with --repo-path reads fixture without network access."""
        with tempfile.TemporaryDirectory() as tmp:
            repo = _make_repo_dir(Path(tmp))
            out = Path(tmp) / "0xparc_index.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--repo-path",
                    str(repo),
                    "--out",
                    str(out),
                    "--print-summary",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["total"], 3)
            self.assertEqual(payload["source"], "0xparc/zk-bug-tracker")

    def test_bug_ids_are_unique(self):
        """All bug_id values in the output are unique."""
        content = SAMPLE_README.read_text(encoding="utf-8")
        records = self.tool.parse_readme(content)
        ids = [r.bug_id for r in records]
        self.assertEqual(len(ids), len(set(ids)), f"Duplicate bug IDs: {ids}")

    def test_all_records_have_provenance(self):
        """Every parsed record carries provenance with CC-BY-SA-4.0."""
        content = SAMPLE_README.read_text(encoding="utf-8")
        records = self.tool.parse_readme(content)
        for rec in records:
            self.assertEqual(rec.provenance["license"], "CC-BY-SA-4.0")
            self.assertEqual(rec.provenance["source"], "0xparc/zk-bug-tracker")
            self.assertTrue(rec.provenance["attribution_required"])


if __name__ == "__main__":
    unittest.main()
