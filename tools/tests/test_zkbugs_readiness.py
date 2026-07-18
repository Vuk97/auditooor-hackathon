from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "zkbugs-readiness.py"
INGEST = ROOT / "tools" / "zkbugs-ingest.py"
QUEUE = ROOT / "tools" / "zkbugs-brief-queue.py"


def _import(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


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


class ZkbugsReadinessTests(unittest.TestCase):
    def test_reports_missing_root_blocker_and_commands(self) -> None:
        mod = _import(TOOL, "zkbugs_readiness_test_subject")
        with tempfile.TemporaryDirectory() as td:
            payload = mod.build_payload(None, Path(td) / "farming")

        self.assertEqual(payload["status"], "blocked")
        self.assertIn("zkbugs_root_missing", payload["blockers"])
        self.assertIn("make zkbugs-ingest ZKBUGS_ROOT=<zkbugs-root>", "\n".join(payload["next_commands"]))
        self.assertIn("repo-content", payload["proof_boundary"])

    def test_ready_when_repo_content_records_are_indexed_and_queued(self) -> None:
        readiness = _import(TOOL, "zkbugs_readiness_ready_subject")
        ingest = _import(INGEST, "zkbugs_ingest_ready_subject")
        queue = _import(QUEUE, "zkbugs_queue_ready_subject")
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            root = td_path / "zkbugs"
            out = td_path / "farming"
            _write_fixture_root(root)
            ingest.main(["--zkbugs-root", str(root), "--out-dir", str(out), "--brief-limit", "0", "--index-limit", "0"])
            queue.main(["--brief-dir", str(out / "briefs"), "--out-dir", str(out / "provider_queue"), "--limit", "0"])

            payload = readiness.build_payload(root, out)

        self.assertEqual(payload["status"], "ready")
        self.assertEqual(payload["counts"]["repo_content_records"], 1)
        self.assertEqual(payload["counts"]["index_records"], 1)
        self.assertEqual(payload["counts"]["provider_queue_rows"], 1)
        self.assertEqual(payload["artifacts"]["kimi_prompt_count"], 1)
        self.assertEqual(payload["artifacts"]["minimax_prompt_count"], 1)
        self.assertEqual(payload["blockers"], [])

    def test_detects_partial_queue(self) -> None:
        readiness = _import(TOOL, "zkbugs_readiness_partial_subject")
        ingest = _import(INGEST, "zkbugs_ingest_partial_subject")
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            root = td_path / "zkbugs"
            out = td_path / "farming"
            _write_fixture_root(root)
            ingest.main(["--zkbugs-root", str(root), "--out-dir", str(out), "--brief-limit", "0", "--index-limit", "0"])

            payload = readiness.build_payload(root, out)

        self.assertEqual(payload["status"], "blocked")
        self.assertIn("zkbugs_provider_queue_json_missing", payload["blockers"])
        self.assertIn("zkbugs_provider_queue_rows_mismatch", payload["blockers"])


if __name__ == "__main__":
    unittest.main()
