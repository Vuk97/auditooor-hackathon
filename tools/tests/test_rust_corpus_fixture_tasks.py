from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "rust-corpus-fixture-tasks.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("rust_corpus_fixture_tasks", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["rust_corpus_fixture_tasks"] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_tool()


class RustCorpusFixtureTaskTests(unittest.TestCase):
    def test_blocker_only_index_uses_hermetic_fixture_without_proof_claims(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            index_dir = ws / ".audit_logs" / "rust_corpus_mining"
            index_dir.mkdir(parents=True)
            (index_dir / "rust_corpus_index.json").write_text(
                json.dumps({"records": [], "blockers": [{"blocker_id": "missing"}]}),
                encoding="utf-8",
            )
            payload = MOD.build_payload(ws)
            self.assertEqual(payload["summary"]["input_mode"], "hermetic_fixture")
            self.assertEqual(payload["summary"]["task_count"], 3)
            self.assertEqual(payload["summary"]["proof_claims"], 0)
            self.assertEqual(payload["blockers"][0]["blocker_id"], "rust-corpus-index-missing-or-empty")
            self.assertIn("high", payload["summary"]["by_feasibility"])

    def test_real_index_groups_patch_poc_and_writeup_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            index = Path(tmp) / "rust_corpus_index.json"
            index.write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "item_id": "H-001",
                                "title": "unsafe from_raw_parts length overflow",
                                "family": "rust_unsafe_memory_boundary",
                                "route": "detector",
                                "source_kind": "md",
                                "rel_path": "findings/high/H-001.md",
                                "source_pointers": ["findings/high/H-001.md"],
                                "patch_pointers": ["findings/high/H-001.patch"],
                                "poc_pointers": ["findings/high/H-001-poc.rs"],
                                "replay_commands": ["cargo test h001_repro"],
                            },
                            {
                                "item_id": "M-001",
                                "title": "ordinary row without usable evidence",
                                "family": "rust_manual_semantic_review",
                                "route": "invariant",
                                "source_kind": "json",
                                "source_pointers": ["index.json"],
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            payload = MOD.build_payload(ws, index)
            self.assertEqual(payload["summary"]["input_mode"], "rust_corpus_index")
            self.assertEqual(payload["summary"]["source_record_count"], 2)
            self.assertEqual(payload["summary"]["task_count"], 1)
            self.assertEqual(payload["summary"]["excluded_record_count"], 1)
            task = payload["tasks"][0]
            self.assertEqual(task["feasibility"], "high")
            self.assertEqual(task["task_kind"], "replay_task")
            self.assertIn("not_executed_no_proof", task["blockers"])

    def test_cli_writes_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            proc = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws), "--print-json"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            summary = json.loads(proc.stdout)["summary"]
            self.assertEqual(summary["input_mode"], "hermetic_fixture")
            self.assertTrue((ws / ".audit_logs" / "rust_corpus_mining" / "rust_corpus_fixture_tasks.json").is_file())
            self.assertTrue((ws / ".audit_logs" / "rust_corpus_mining" / "rust_corpus_fixture_tasks.md").is_file())


if __name__ == "__main__":
    unittest.main()
