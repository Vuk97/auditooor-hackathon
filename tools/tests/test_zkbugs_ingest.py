#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "zkbugs-ingest.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("zkbugs_ingest_test_subject", TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class ZkBugsIngestTest(unittest.TestCase):
    def _fixture_tree(self, root: Path) -> Path:
        bug_dir = root / "dataset" / "circom" / "demo" / "project" / "missing_range"
        bug_dir.mkdir(parents=True)
        (bug_dir / "zkbugs_config.json").write_text(
            json.dumps(
                {
                    "Missing range check": {
                        "Id": "demo/project/missing-range",
                        "Path": "dataset/circom/demo/project/missing_range",
                        "Project": "https://github.com/demo/project",
                        "Commit": "abcdef123456",
                        "Fix Commit": "fedcba654321",
                        "DSL": "Circom",
                        "Vulnerability": "Under-Constrained",
                        "Impact": "Soundness",
                        "Root Cause": "Missing Input Constraints",
                        "Reproduced": True,
                        "Location": {"Path": "circuits/demo.circom", "Function": "Demo", "Line": "10"},
                        "Source": {
                            "Audit Report": {
                                "Source Link": "https://example.com/demo-audit.pdf",
                                "Bug ID": "M-01",
                            }
                        },
                        "Commands": {"Reproduce": "./zkbugs_exploit.sh"},
                        "Short Description of the Vulnerability": "Signal lacks range constraint.",
                        "Short Description of the Exploit": "Malicious witness aliases field value.",
                        "Proposed Mitigation": "Add Num2Bits range constraint.",
                    }
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        reports = root / "reports"
        (reports / "documents").mkdir(parents=True)
        (reports / "documents" / "demo-audit.pdf").write_text("pdf placeholder", encoding="utf-8")
        (reports / "documents" / "demo-audit.txt").write_text("extracted report text", encoding="utf-8")
        (reports / "reports.json").write_text(
            json.dumps(
                [
                    {
                        "ID": "demo-audit",
                        "File": "documents/demo-audit.pdf",
                        "Project": "https://github.com/demo/project",
                        "Commit": "0xabcdef123456",
                        "DSL": "Circom",
                        "processed": True,
                    }
                ]
            ),
            encoding="utf-8",
        )
        return root

    def test_load_records_prioritizes_reproduced_and_reports(self) -> None:
        tool = _load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = self._fixture_tree(Path(tmp))
            records = tool.load_records(root)
            self.assertEqual(len(records), 1)
            rec = records[0]
            self.assertEqual(rec.title, "Missing range check")
            self.assertEqual(rec.dsl, "Circom")
            self.assertTrue(rec.reproduced)
            self.assertIn("reports/documents/demo-audit.pdf", rec.report_files)
            self.assertIn("reports/documents/demo-audit.txt", rec.report_text_files)
            self.assertIn("has-local-report", rec.priority_reasons)
            self.assertIn("has-local-report-text", rec.priority_reasons)
            self.assertGreaterEqual(rec.priority_score, 130)

    def test_cli_writes_index_and_briefs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._fixture_tree(Path(tmp) / "zkbugs")
            out = Path(tmp) / "out"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--zkbugs-root",
                    str(root),
                    "--out-dir",
                    str(out),
                    "--brief-limit",
                    "1",
                    "--index-limit",
                    "1",
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads((out / "zkbugs_index.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["total"], 1)
            self.assertEqual(payload["summary"]["with_local_report"], 1)
            self.assertEqual(payload["summary"]["with_local_report_text"], 1)
            index = (out / "zkbugs_index.md").read_text(encoding="utf-8")
            self.assertIn("zkBugs Farming Index", index)
            self.assertIn("With extracted local report text", index)
            briefs = list((out / "briefs").glob("*.md"))
            self.assertEqual(len(briefs), 1)
            brief = briefs[0].read_text(encoding="utf-8")
            self.assertIn("Local Reports / PDFs", brief)
            self.assertIn("Local Report Text", brief)
            self.assertIn("reports/documents/demo-audit.txt", brief)

    def test_brief_limit_zero_writes_all_briefs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = self._fixture_tree(Path(tmp) / "zkbugs")
            second = root / "dataset" / "circom" / "demo" / "project" / "second"
            second.mkdir(parents=True)
            (second / "zkbugs_config.json").write_text(
                json.dumps({"Second bug": {"Id": "demo/project/second", "DSL": "Circom"}}),
                encoding="utf-8",
            )
            out = Path(tmp) / "out"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--zkbugs-root",
                    str(root),
                    "--out-dir",
                    str(out),
                    "--brief-limit",
                    "0",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            briefs = list((out / "briefs").glob("*.md"))
            self.assertEqual(len(briefs), 2)


if __name__ == "__main__":
    unittest.main()
