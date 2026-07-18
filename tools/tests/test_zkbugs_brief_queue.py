#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "zkbugs-brief-queue.py"


def _write_fixture_root(root: Path) -> None:
    bug_dir = root / "dataset" / "demo"
    bug_dir.mkdir(parents=True)
    (bug_dir / "zkbugs_config.json").write_text(
        json.dumps(
            {
                "Range check missing": {
                    "Id": "ZK-1",
                    "DSL": "Circom",
                    "Vulnerability": "Under-Constrained",
                    "Impact": "Invalid proof accepted",
                    "Root Cause": "Missing range check",
                    "Project": "demo/project",
                    "Commit": "abcdef1234",
                    "Path": "circuits/demo.circom",
                    "Source": {"Report": {"Bug ID": "demo-report", "Source Link": "reports/demo.pdf"}},
                    "Location": {"Path": "circuits/demo.circom", "Function": "Demo", "Line": "7"},
                }
            }
        ),
        encoding="utf-8",
    )
    reports = root / "reports"
    (reports / "documents").mkdir(parents=True)
    (reports / "reports.json").write_text(
        json.dumps([{"ID": "demo-report", "File": "documents/demo.pdf", "Project": "demo/project"}]),
        encoding="utf-8",
    )
    (reports / "documents" / "demo.pdf").write_bytes(b"%PDF demo")
    (reports / "documents" / "demo.txt").write_text("Report text for missing range check.\n", encoding="utf-8")
    (root / "circuits").mkdir()
    (root / "circuits" / "demo.circom").write_text("template Demo() {}\n", encoding="utf-8")


class ZkBugsBriefQueueTest(unittest.TestCase):
    def test_cli_writes_provider_prompts_and_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            briefs = root / "briefs"
            briefs.mkdir()
            (briefs / "demo.md").write_text("# Demo\n\nBug body\n", encoding="utf-8")
            out = root / "queue"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--brief-dir",
                    str(briefs),
                    "--out-dir",
                    str(out),
                    "--limit",
                    "1",
                    "--print-json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            manifest = json.loads((out / "zkbugs_provider_queue.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["count"], 1)
            row = manifest["rows"][0]
            self.assertEqual(row["kimi_command"][:4], ["python3", "tools/llm-dispatch.py", "--provider", "kimi"])
            self.assertEqual(row["minimax_command_template"][:4], ["python3", "tools/llm-dispatch.py", "--provider", "minimax"])
            self.assertIn("smoke-fire", row["promotion_gate"])
            kimi_prompt = Path(row["kimi_prompt"]).read_text(encoding="utf-8")
            minimax_prompt = Path(row["minimax_prompt_template"]).read_text(encoding="utf-8")
            self.assertIn("Return JSON only", kimi_prompt)
            self.assertIn("<PASTE_KIMI_JSON_HERE>", minimax_prompt)
            self.assertIn("zkBugs Provider Queue", (out / "zkbugs_provider_queue.md").read_text(encoding="utf-8"))

    def test_queue_refreshes_readiness_from_indexed_root(self) -> None:
        ingest_tool = ROOT / "tools" / "zkbugs-ingest.py"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "zkbugs"
            out = Path(tmp) / "farming"
            _write_fixture_root(root)
            ingest_proc = subprocess.run(
                [
                    sys.executable,
                    str(ingest_tool),
                    "--zkbugs-root",
                    str(root),
                    "--out-dir",
                    str(out),
                    "--brief-limit",
                    "0",
                    "--index-limit",
                    "0",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(ingest_proc.returncode, 0, ingest_proc.stderr)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--brief-dir",
                    str(out / "briefs"),
                    "--out-dir",
                    str(out / "provider_queue"),
                    "--limit",
                    "0",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            readiness = json.loads((out / "zkbugs_readiness.json").read_text(encoding="utf-8"))
            manifest = json.loads((out / "provider_queue" / "zkbugs_provider_queue.json").read_text(encoding="utf-8"))
            self.assertEqual(readiness["status"], "ready")
            self.assertEqual(manifest["readiness"]["status"], "ready")
            self.assertTrue((out / "zkbugs_readiness.md").is_file())


if __name__ == "__main__":
    unittest.main()
