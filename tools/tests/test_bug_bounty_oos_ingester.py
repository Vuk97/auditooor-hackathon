#!/usr/bin/env python3
"""Tests for the M1-4a BUG_BOUNTY.md ingester wrapper."""

from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


_HERE = Path(__file__).resolve().parent
_TOOL_PATH = _HERE.parent / "bug-bounty-oos-ingester.py"
_FIXTURE_PATH = _HERE / "fixtures" / "bug_bounty_oos" / "superearn-BUG_BOUNTY.md"
_spec = importlib.util.spec_from_file_location("bug_bounty_oos_ingester", _TOOL_PATH)
ingester = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(ingester)


class BugBountyOosIngesterTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "workspace"
        self.ws.mkdir(parents=True)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _run_cli(self, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(_TOOL_PATH), "--workspace", str(self.ws), *extra],
            capture_output=True,
            text=True,
            timeout=30,
        )

    def _write_fixture(self, rel: str = "BUG_BOUNTY.md") -> Path:
        path = self.ws / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(_FIXTURE_PATH, path)
        return path

    def test_parses_oos_bullets(self) -> None:
        self._write_fixture()
        result = ingester.ingest_workspace(self.ws)

        oos_rows = [row for row in result["index"]["rows"] if row["section"] == "out_of_scope"]
        self.assertGreaterEqual(len(oos_rows), 2)
        self.assertTrue(any("front-running-public-mempool" in row["semantic_tags"] for row in oos_rows))

    def test_parses_ai_fp_table_rows(self) -> None:
        self._write_fixture()
        result = ingester.ingest_workspace(self.ws)

        ai_fp = [row for row in result["index"]["rows"] if row["section"] == "ai_false_positive"]
        clause_ids = {row["clause_id"] for row in ai_fp}
        self.assertIn("AI-FP-row-42", clause_ids)
        self.assertIn("AI-FP-row-43", clause_ids)

    def test_parses_known_issue_catalog_ids(self) -> None:
        self._write_fixture()
        result = ingester.ingest_workspace(self.ws)

        known_ids = {row["clause_id"] for row in result["index"]["rows"] if row["section"] == "known_issue"}
        self.assertIn("SE-P13", known_ids)
        self.assertIn("SE-P32", known_ids)

    def test_parses_trust_assumption_paragraphs(self) -> None:
        self._write_fixture()
        result = ingester.ingest_workspace(self.ws)

        trust_rows = [row for row in result["index"]["rows"] if row["section"] == "trust_assumption"]
        self.assertEqual(len(trust_rows), 1)
        self.assertIn("stablecoin-trust", trust_rows[0]["semantic_tags"])
        self.assertIn("trusted-issuer", trust_rows[0]["semantic_tags"])

    def test_missing_bug_bounty_is_success_warn_and_writes_empty_index(self) -> None:
        proc = self._run_cli()

        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("SUCCESS_WARN", proc.stdout)
        index_path = self.ws / ".auditooor" / "bug_bounty_oos_index.json"
        self.assertTrue(index_path.is_file())
        index = json.loads(index_path.read_text(encoding="utf-8"))
        self.assertEqual(index["row_count"], 0)
        self.assertEqual(index["source_paths"], [])

    def test_malformed_markdown_degrades_gracefully(self) -> None:
        (self.ws / "BUG_BOUNTY.md").write_text(
            "\n".join(
                [
                    "# Broken",
                    "## AI-Tool False-Positive Patterns",
                    "| Row | Pattern ",
                    "| --- | --- ",
                    "| 42 | Front-running via public mempool",
                    "## Trust Assumptions",
                    "Stablecoin issuers are trusted even if the table above is malformed",
                ]
            ),
            encoding="utf-8",
        )

        result = ingester.ingest_workspace(self.ws)

        self.assertEqual(result["status"], ingester.SUCCESS)
        self.assertGreaterEqual(result["row_count"], 1)
        self.assertTrue(any(row["section"] == "trust_assumption" for row in result["index"]["rows"]))

    def test_fresh_workspace_no_catalog_json_mode_reports_success_warn(self) -> None:
        proc = self._run_cli("--json")

        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["status"], "SUCCESS_WARN")
        self.assertEqual(payload["state"], "missing-bug-bounty-md")
        self.assertEqual(payload["row_count"], 0)

    def test_multiple_repos_are_merged_into_one_index(self) -> None:
        self._write_fixture("BUG_BOUNTY.md")
        self._write_fixture("src/superearn/BUG_BOUNTY.md")

        result = ingester.ingest_workspace(self.ws)

        self.assertEqual(result["status"], ingester.SUCCESS)
        self.assertIn("BUG_BOUNTY.md", result["source_paths"])
        self.assertIn("src/superearn/BUG_BOUNTY.md", result["source_paths"])
        self.assertGreater(result["row_count"], 4)


if __name__ == "__main__":
    unittest.main()
