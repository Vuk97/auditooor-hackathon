#!/usr/bin/env python3
"""Focused contract tests for prior-audit status reconciliation."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "tools" / "prior-audit-resolved-reverify-gate.py"


class PriorAuditGateTests(unittest.TestCase):
    def run_gate(self, workspace, strict=True):
        command = [sys.executable, str(GATE), str(workspace), "--json"]
        if strict:
            command.append("--strict")
        return subprocess.run(command, text=True, capture_output=True)

    def workspace(self, prior_text):
        td = tempfile.TemporaryDirectory()
        ws = Path(td.name)
        (ws / "prior_audits").mkdir()
        (ws / ".auditooor").mkdir()
        (ws / "SCOPE.md").write_text("Target.sol\n")
        (ws / "prior_audits" / "report.md").write_text(prior_text)
        return td, ws

    def test_statuses_are_explicit_and_block_promotion(self):
        text = "\n".join([
            "known Target.sol:1",
            "acknowledged Target.sol:2",
            "risk-accepted Target.sol:3",
            "wont-fix Target.sol:4",
            "TODO planned remediation Target.sol:5",
            "fixed Target.sol:6",
            "resolved Target.sol:7",
            "OOS Target.sol:8",
            "unreviewed Target.sol:9",
        ])
        td, ws = self.workspace(text)
        try:
            result = self.run_gate(ws)
            body = json.loads(result.stdout)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(body["prior_items_in_scope"], 9)
            self.assertEqual(body["dispositions"]["planned-remediation"], 1)
            self.assertEqual(body["dispositions"]["unknown"], 1)
            self.assertEqual(len(body["blocking_items"]), 7)
            self.assertEqual(len(body["unmet"]), 2)
        finally:
            td.cleanup()

    def test_fixed_item_needs_current_code_artifact_and_identity(self):
        td, ws = self.workspace("fixed Target.sol:10\nfixed Target.sol:20\n")
        try:
            first = json.loads(self.run_gate(ws).stdout)
            self.assertEqual(len(first["unmet"]), 2)
            item = first["unmet"][0]
            evidence = ws / ".auditooor" / "prior_resolved_reverify" 
            evidence.mkdir()
            (evidence / "one.json").write_text(json.dumps({
                "finding_id": item["finding_id"], "file": item["file"],
                "verdict": "still-fixed", "cite": "current code Target.sol:10",
            }))
            second = json.loads(self.run_gate(ws).stdout)
            self.assertEqual(len(second["unmet"]), 1)
            self.assertEqual(second["unmet"][0]["line"], "20")
        finally:
            td.cleanup()

    def test_empty_prior_corpus_is_not_applicable(self):
        td = tempfile.TemporaryDirectory()
        ws = Path(td.name)
        (ws / "prior_audits").mkdir()
        try:
            result = self.run_gate(ws)
            body = json.loads(result.stdout)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(body["verdict"], "pass-no-relevant-prior-items")
        finally:
            td.cleanup()

    def test_scope_description_with_file_anchor_is_not_a_finding(self):
        text = (
            "The core functionality is exported using Import.sol and Export.sol.\n"
            "Both contracts use Governance.sol to decide protocol parameters.\n"
        )
        td, ws = self.workspace(text)
        try:
            result = self.run_gate(ws)
            body = json.loads(result.stdout)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(body["prior_items_in_scope"], 0)
        finally:
            td.cleanup()

    def test_explicit_unknown_finding_still_blocks(self):
        td, ws = self.workspace("Finding 7.2 - unknown issue in Target.sol:10\n")
        try:
            result = self.run_gate(ws)
            body = json.loads(result.stdout)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(body["prior_items_in_scope"], 1)
            self.assertEqual(body["dispositions"]["unknown"], 1)
        finally:
            td.cleanup()

    def test_context_review_exports_full_audit_text_and_blocks_until_imported(self):
        text = "Finding 7.2 - known issue in Target.sol:10\nThe team will wire the fix.\n"
        td, ws = self.workspace(text)
        try:
            command = [sys.executable, str(GATE), str(ws), "--context-review", "--json"]
            first = subprocess.run(command, text=True, capture_output=True)
            body = json.loads(first.stdout)
            self.assertEqual(first.returncode, 1)
            self.assertEqual(body["verdict"], "pending-agent-analysis")
            queue = json.loads((ws / ".auditooor" / "prior_audit_context_review_queue.json").read_text())
            self.assertIn("The team will wire the fix.", queue["documents"][0]["content"])
            doc_id = queue["documents"][0]["document_id"]
            (ws / ".auditooor" / "prior_audit_context_analysis.json").write_text(json.dumps({
                "schema_version": "auditooor.prior_audit_context_analysis.v1",
                "documents": [{"document_id": doc_id, "status": "complete", "disposition": "reviewed"}],
            }))
            second = subprocess.run(command, text=True, capture_output=True)
            self.assertEqual(second.returncode, 0)
            self.assertEqual(json.loads(second.stdout)["verdict"], "pass-prior-audit-context-reviewed")
        finally:
            td.cleanup()


if __name__ == "__main__":
    unittest.main()
