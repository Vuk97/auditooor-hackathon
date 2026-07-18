#!/usr/bin/env python3
"""Tests for tools/deep-counterexample-collect.py."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "deep-counterexample-collect.py"


class DeepCounterexampleCollectTest(unittest.TestCase):
    def test_collects_fuzz_counterexample_as_advisory_without_forge_replay(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            run = ws / "fuzz_runs" / "run-1"
            run.mkdir(parents=True)
            (run / "failing_sequence.txt").write_text("call sequence\n", encoding="utf-8")
            (run / "manifest.json").write_text(
                json.dumps(
                    {
                        "engine": "medusa",
                        "status": "counterexample",
                        "command": "medusa fuzz --target-contracts Demo",
                        "counterexample_path": "failing_sequence.txt",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws), "--print-json"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["counterexample_count"], 1)
            record = payload["records"][0]
            self.assertEqual(record["schema_version"], "auditooor.deep_counterexample.v1")
            self.assertEqual(record["engine"], "medusa")
            self.assertEqual(record["input_sequence"], "call sequence")
            self.assertFalse(record["promotes_to_poc_work"])
            self.assertIn("no generated Forge replay", record["replay_impossible_reason"])
            self.assertEqual(payload["queue_refresh"]["status"], "ok")
            queue_path = ws / "deep_counterexamples" / "execution_queue.json"
            self.assertTrue(queue_path.is_file())
            queue = json.loads(queue_path.read_text(encoding="utf-8"))
            self.assertEqual(queue["record_count"], 1)
            self.assertEqual(queue["items"][0]["status"], "needs_replay_path")

    def test_collects_symbolic_counterexample_with_forge_replay(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            run = ws / "symbolic_runs" / "run-1"
            run.mkdir(parents=True)
            (run / "manifest.json").write_text(
                json.dumps(
                    {
                        "engine": "halmos",
                        "status": "counterexample",
                        "contract": "Vault",
                        "angle": "A-AUTH",
                        "command": "halmos --contract Vault",
                        "counterexample_path": "counterexample.txt",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--generated-forge-test-path",
                    "test/VaultAuthReplay.t.sol",
                    "--print-json",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            record = payload["records"][0]
            self.assertEqual(record["engine"], "halmos")
            self.assertEqual(record["target_function"], "Vault.A-AUTH")
            self.assertTrue(record["promotes_to_poc_work"])
            self.assertEqual(record["generated_forge_test_path"], "test/VaultAuthReplay.t.sol")
            self.assertEqual(payload["queue_refresh"]["status"], "ok")
            queue_path = ws / "deep_counterexamples" / "execution_queue.json"
            queue = json.loads(queue_path.read_text(encoding="utf-8"))
            self.assertEqual(queue["record_count"], 1)
            self.assertEqual(queue["items"][0]["status"], "needs_replay_scaffold")


if __name__ == "__main__":
    unittest.main()
