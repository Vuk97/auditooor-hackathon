from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "rust-swival-family-map.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("rust_swival_family_map", TOOL)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["rust_swival_family_map"] = module
    spec.loader.exec_module(module)
    return module


MOD = _load_tool()


def _write_index(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "records": [
                    {
                        "item_id": "001-unsafe-tar-extraction",
                        "title": "Unsafe Tar Extraction",
                        "corpus_severity": "High",
                        "component": "io",
                        "family": "rust_unsafe_memory_boundary",
                        "source_pointers": ["001-unsafe-tar-extraction.md"],
                        "submission_posture": "NOT_SUBMIT_READY",
                    },
                    {
                        "item_id": "151-oversized-uleb128-invalid-shift",
                        "title": "Oversized ULEB128 Invalid Shift",
                        "corpus_severity": "Medium",
                        "component": "alloc",
                        "family": "rust_decode_or_parser_boundary",
                        "source_pointers": ["151-oversized-uleb128-invalid-shift.md"],
                        "submission_posture": "NOT_SUBMIT_READY",
                    },
                    {
                        "item_id": "112-wait-error-leaves-mutex-unlocked",
                        "title": "wait error leaves mutex unlocked",
                        "corpus_severity": "Medium",
                        "component": "sync",
                        "family": "rust_unsafe_memory_boundary",
                        "source_pointers": ["112-wait-error-leaves-mutex-unlocked.md"],
                        "submission_posture": "NOT_SUBMIT_READY",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )


def _write_tasks(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "tasks": [
                    {
                        "source_item_id": "001-unsafe-tar-extraction",
                        "task_id": "rust-fixture-0001-001-unsafe-tar-extraction",
                        "task_kind": "fixture_pair_task",
                        "proof_status": "not_proved",
                        "submission_posture": "NOT_SUBMIT_READY",
                    },
                    {
                        "source_item_id": "151-oversized-uleb128-invalid-shift",
                        "task_id": "rust-fixture-0002-151-oversized-uleb128-invalid-shift",
                        "task_kind": "replay_task",
                        "proof_status": "not_proved",
                        "submission_posture": "NOT_SUBMIT_READY",
                    },
                    {
                        "source_item_id": "112-wait-error-leaves-mutex-unlocked",
                        "task_id": "rust-fixture-0003-112-wait-error-leaves-mutex-unlocked",
                        "task_kind": "fixture_pair_task",
                        "proof_status": "not_proved",
                        "submission_posture": "NOT_SUBMIT_READY",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )


class RustSwivalFamilyMapTests(unittest.TestCase):
    def test_clusters_rows_queues_and_preserves_no_proof_posture(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            index = Path(tmp) / "index.json"
            tasks = Path(tmp) / "tasks.json"
            _write_index(index)
            _write_tasks(tasks)
            payload = MOD.build_payload(ws, index, tasks, expected_total=3)
            self.assertEqual(payload["summary"]["source_item_count"], 3)
            self.assertTrue(payload["summary"]["coverage_complete_for_expected_swival_total"])
            self.assertEqual(payload["summary"]["proof_claims"], 0)
            self.assertFalse(payload["summary"]["base_vulnerability_proof_claimed"])
            self.assertEqual(payload["summary"]["cross_linked_fixture_task_count"], 3)
            by_family = {row["family_id"]: row for row in payload["families"]}
            self.assertIn("path_filesystem_canonicalization", by_family)
            self.assertIn("parser_format_table_bounds", by_family)
            self.assertIn("concurrency_lock_atomic_state", by_family)
            self.assertTrue(by_family["parser_format_table_bounds"]["suitability"]["runtime_semantic_blocker"])
            self.assertEqual(by_family["parser_format_table_bounds"]["task_kind_distribution"]["replay_task"], 1)
            self.assertGreaterEqual(payload["summary"]["queue_counts"]["detector"], 2)
            self.assertGreaterEqual(payload["summary"]["queue_counts"]["runtime_semantic_blocker"], 2)

    def test_incomplete_expected_total_is_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            index = Path(tmp) / "index.json"
            _write_index(index)
            payload = MOD.build_payload(ws, index, None, expected_total=151)
            self.assertFalse(payload["summary"]["coverage_complete_for_expected_swival_total"])
            self.assertEqual(payload["blockers"][0]["blocker_id"], "swival-family-map-incomplete-coverage")

    def test_cli_writes_json_markdown_and_auditooor_mirror(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "ws"
            (ws / ".auditooor").mkdir(parents=True)
            index = Path(tmp) / "index.json"
            tasks = Path(tmp) / "tasks.json"
            out = Path(tmp) / "out"
            _write_index(index)
            _write_tasks(tasks)
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--index",
                    str(index),
                    "--fixture-tasks",
                    str(tasks),
                    "--expected-total",
                    "3",
                    "--out-dir",
                    str(out),
                    "--print-json",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            summary = json.loads(proc.stdout)["summary"]
            self.assertEqual(summary["family_count"], 3)
            self.assertTrue((out / "rust_swival_family_map.json").is_file())
            self.assertTrue((out / "rust_swival_family_map.md").is_file())
            self.assertTrue((ws / ".auditooor" / "rust_swival_family_map.json").is_file())
            md = (out / "rust_swival_family_map.md").read_text(encoding="utf-8")
            self.assertIn("Implementation Queues", md)
            self.assertIn("does not claim Base vulnerability proof", md)


if __name__ == "__main__":
    unittest.main()
