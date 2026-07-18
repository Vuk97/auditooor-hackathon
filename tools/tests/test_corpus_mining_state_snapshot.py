#!/usr/bin/env python3
"""Tests for tools/corpus-mining-state-snapshot.py — Phase A."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

# Load module under test (hyphen in filename requires importlib)
TOOL = Path(__file__).resolve().parents[2] / "tools" / "corpus-mining-state-snapshot.py"
spec = importlib.util.spec_from_file_location("corpus_mining_state_snapshot", TOOL)
mod = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
spec.loader.exec_module(mod)  # type: ignore[union-attr]


class TestSnapshotRuns(unittest.TestCase):
    """Smoke test: snapshot builds without error on the current worktree."""

    def test_snapshot_runs_without_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_json = str(Path(tmpdir) / "state.json")
            out_md = str(Path(tmpdir) / "state.md")
            sys.argv = ["corpus-mining-state-snapshot.py",
                        "--out-json", out_json, "--out-md", out_md, "--quiet"]
            rc = mod.main()
        self.assertEqual(rc, 0)


class TestJsonOutput(unittest.TestCase):
    """JSON output has correct schema and required top-level keys."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        out_json = str(Path(self.tmpdir.name) / "state.json")
        out_md = str(Path(self.tmpdir.name) / "state.md")
        sys.argv = ["corpus-mining-state-snapshot.py",
                    "--out-json", out_json, "--out-md", out_md, "--quiet"]
        mod.main()
        self.snap = json.loads(Path(out_json).read_text())

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def test_required_top_level_keys(self) -> None:
        for key in ("schema", "generated_at", "stale_corpora", "corpora"):
            self.assertIn(key, self.snap, f"Missing key: {key}")

    def test_schema_version(self) -> None:
        self.assertEqual(self.snap["schema"], "auditooor.corpus_mining_state.v1")

    def test_corpora_is_list(self) -> None:
        self.assertIsInstance(self.snap["corpora"], list)
        self.assertGreater(len(self.snap["corpora"]), 0)

    def test_each_corpus_has_required_fields(self) -> None:
        required = {"corpus", "source_path", "last_mined_at", "volume", "staleness_category"}
        for entry in self.snap["corpora"]:
            for field in required:
                self.assertIn(field, entry, f"{entry.get('corpus', '?')} missing {field}")

    def test_stale_corpora_is_list(self) -> None:
        self.assertIsInstance(self.snap["stale_corpora"], list)

    def test_expected_corpora_present(self) -> None:
        names = {c["corpus"] for c in self.snap["corpora"]}
        for expected in ("defimon", "solodit", "audit_pdfs", "defihacklabs_catalog",
                         "big_loss_templates", "case_studies", "contest_cache",
                         "multi_language_coverage"):
            self.assertIn(expected, names, f"Missing corpus: {expected}")

    def test_solodit_reports_alternate_cursor_metadata(self) -> None:
        solodit = next(c for c in self.snap["corpora"] if c["corpus"] == "solodit")
        self.assertIn("cursor_max_id", solodit)
        self.assertIn("alternate_cursor_count", solodit)


class TestMarkdownOutput(unittest.TestCase):
    """Markdown output has expected H1 header and summary table."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.TemporaryDirectory()
        self.out_md = Path(self.tmpdir.name) / "state.md"
        sys.argv = ["corpus-mining-state-snapshot.py",
                    "--out-json", str(Path(self.tmpdir.name) / "state.json"),
                    "--out-md", str(self.out_md), "--quiet"]
        mod.main()
        self.content = self.out_md.read_text()

    def tearDown(self) -> None:
        self.tmpdir.cleanup()

    def test_h1_header(self) -> None:
        self.assertTrue(self.content.startswith("# Corpus Mining State Snapshot"))

    def test_summary_table_present(self) -> None:
        self.assertIn("| Corpus |", self.content)

    def test_stale_section_present(self) -> None:
        self.assertIn("## Stale corpora", self.content)


class TestStalenessCategorization(unittest.TestCase):
    """Staleness function covers all 3 buckets correctly."""

    def test_fresh(self) -> None:
        dt = datetime.now(timezone.utc)
        self.assertEqual(mod.staleness(dt), "fresh")

    def test_aging(self) -> None:
        from datetime import timedelta
        dt = datetime.now(timezone.utc) - timedelta(days=10)
        self.assertEqual(mod.staleness(dt), "aging")

    def test_stale(self) -> None:
        from datetime import timedelta
        dt = datetime.now(timezone.utc) - timedelta(days=30)
        self.assertEqual(mod.staleness(dt), "stale")

    def test_none_is_stale(self) -> None:
        self.assertEqual(mod.staleness(None), "stale")


class TestAuditPdfsProbe(unittest.TestCase):
    """Audit PDF freshness should reflect existing mining artifacts."""

    def test_uses_mining_artifacts_when_available(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_root = Path(tmpdir)
            tmp_audits = tmp_root / "audits"
            tmp_ref = tmp_root / "reference"
            mined_dir = tmp_ref / "patterns.dsl" / "r99_pdf_mined"
            source_dir = tmp_audits / "proj" / "prior_audits"
            source_dir.mkdir(parents=True, exist_ok=True)
            mined_dir.mkdir(parents=True, exist_ok=True)

            (source_dir / "report.pdf").write_bytes(b"%PDF-1.4\n")
            (mined_dir / "report.yaml.candidate").write_text("name: report\n")

            with patch.object(mod, "ROOT", tmp_root), \
                 patch.object(mod, "REF", tmp_ref), \
                 patch.object(mod, "AUDITS_DIR", tmp_audits), \
                 patch.object(mod, "NOW", datetime.now(timezone.utc)):
                result = mod.probe_audit_pdfs()

        self.assertEqual(result["corpus"], "audit_pdfs")
        self.assertEqual(result["staleness_category"], "fresh")
        self.assertEqual(result["volume"]["pdf_files"], 1)
        self.assertEqual(result["volume"]["yaml_candidates"], 1)
        self.assertIsNotNone(result["last_mined_at"])
        self.assertIn("miner", result["note"].lower())


class TestCaseStudyLogicExtraction(unittest.TestCase):
    """probe_case_studies must DETECT extracted logic (grep/runtime predicates)
    in case-study frontmatter, not hardcode logic_extracted=0 (regression guard
    for the stale 'none yet per plan doc' hardcode)."""

    def _write(self, d: Path, name: str, body: str) -> None:
        (d / name).write_text(body, encoding="utf-8")

    def test_detects_predicates_and_counts_extracted(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            csd = Path(tmpdir) / "case_study"
            csd.mkdir()
            # File WITH class-matcher-consumable logic
            self._write(csd, "with_logic.md",
                        "---\n"
                        "case_id: demo-1\n"
                        "class: bridge\n"
                        "grep_predicates:\n"
                        "  - \"transferFrom|approve\"\n"
                        "runtime_predicates:\n"
                        "  - \"forge test drains victim\"\n"
                        "---\n\n# Demo with logic\n")
            # File WITHOUT any extracted logic (doc-only prose)
            self._write(csd, "doc_only.md", "# Just prose\n\nNo frontmatter here.\n")

            with patch.object(mod, "CASE_STUDY", csd):
                result = mod.probe_case_studies()

        self.assertEqual(result["corpus"], "case_studies")
        self.assertEqual(result["volume"]["files"], 2)
        self.assertEqual(result["volume"]["logic_extracted"], 1)
        by_name = {i["file"]: i["logic_extracted"] for i in result["files"]}
        self.assertTrue(by_name["with_logic.md"])
        self.assertFalse(by_name["doc_only.md"])
        # Partial-extraction note must be honest about the ratio
        self.assertIn("1/2", result["note"])

    def test_all_extracted_note_and_no_hardcoded_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            csd = Path(tmpdir) / "case_study"
            csd.mkdir()
            self._write(csd, "a.md",
                        "---\nclass: vault\nruntime_predicates:\n  - \"x\"\n---\n# A\n")
            with patch.object(mod, "CASE_STUDY", csd):
                result = mod.probe_case_studies()
        self.assertEqual(result["volume"]["logic_extracted"], 1)
        self.assertIn("Logic extracted", result["note"])

    def test_live_repo_case_studies_are_extracted(self) -> None:
        """On the real repo, every case study should now carry extracted logic
        (closes the case_studies logic_extracted=0 gap)."""
        result = mod.probe_case_studies()
        files = result["volume"]["files"]
        if files == 0:
            self.skipTest("no case studies present in this checkout")
        self.assertEqual(
            result["volume"]["logic_extracted"], files,
            "some case studies lack class-matcher-consumable predicates: "
            + ", ".join(i["file"] for i in result["files"]
                        if not i["logic_extracted"]),
        )


if __name__ == "__main__":
    unittest.main()
