#!/usr/bin/env python3
"""Tests for tools/deep-counterexample-queue.py."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "deep-counterexample-queue.py"


def write_record(ws: Path, name: str, **overrides: object) -> Path:
    record = {
        "schema_version": "auditooor.deep_counterexample.v1",
        "workspace": str(ws),
        "engine": "halmos",
        "target_function": "Vault.withdraw",
        "expected_invariant": "shares decrease",
        "observed_violation": "shares unchanged",
        "replay_impossible_reason": "runner trace has no Forge replay yet",
        "promotes_to_poc_work": False,
    }
    record.update(overrides)
    path = ws / "deep_counterexamples" / f"{name}.deep_counterexample.v1.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    return path


class DeepCounterexampleQueueTest(unittest.TestCase):
    def run_tool(self, ws: Path) -> dict:
        proc = subprocess.run(
            [sys.executable, str(TOOL), "--workspace", str(ws), "--print-json"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        start = proc.stdout.find("{")
        self.assertGreaterEqual(start, 0, proc.stdout)
        return json.loads(proc.stdout[start:])

    def test_advisory_record_routes_to_kimi_minimax(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            write_record(ws, "halmos-vault")

            payload = self.run_tool(ws)

            self.assertEqual(payload["record_count"], 1)
            item = payload["items"][0]
            self.assertEqual(item["status"], "needs_replay_path")
            self.assertEqual(item["assigned_model"], "kimi+minimax")
            # Item #14: a no-replay record never escapes generated_hypothesis.
            self.assertEqual(item["evidence_class"], "generated_hypothesis")
            self.assertEqual(
                payload["evidence_class_counts"]["generated_hypothesis"], 1
            )
            self.assertEqual(
                payload["evidence_class_counts"]["executed_with_manifest"], 0
            )
            self.assertTrue((ws / "deep_counterexamples" / "execution_queue.md").is_file())

    def test_skipped_scaffold_routes_to_claude(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            scaffold = ws / "poc-tests" / "VaultReplay.t.sol"
            scaffold.parent.mkdir(parents=True)
            scaffold.write_text("function test_replay() public { vm.skip(true); }\n", encoding="utf-8")
            (scaffold.with_name(scaffold.name + ".handoff.json")).write_text(
                json.dumps(
                    {
                        "schema_version": "auditooor.deep_counterexample_replay_handoff.v1",
                        "synthesized_call_count": 2,
                        "remaining_tasks": ["wire setup", "assert exploit impact"],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            write_record(
                ws,
                "halmos-vault",
                replay_command="forge test --match-path poc-tests/VaultReplay.t.sol",
                generated_forge_test_path="poc-tests/VaultReplay.t.sol",
                replay_impossible_reason="",
                promotes_to_poc_work=True,
            )

            item = self.run_tool(ws)["items"][0]

            self.assertEqual(item["status"], "needs_replay_wiring")
            self.assertEqual(item["assigned_model"], "claude")
            self.assertEqual(item["synthesized_call_count"], 2)
            self.assertIn("replay_handoff_manifest", item)
            self.assertEqual(item["remaining_tasks"], ["wire setup", "assert exploit impact"])
            # Item #14: a skipped scaffold is at most ``scaffolded_unverified``.
            self.assertEqual(item["evidence_class"], "scaffolded_unverified")

    def test_execution_manifest_marks_record_executed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            write_record(
                ws,
                "halmos-vault",
                replay_command="forge test --match-test test_replay",
                generated_forge_test_path="poc-tests/VaultReplay.t.sol",
                replay_impossible_reason="",
                promotes_to_poc_work=True,
            )
            manifest = ws / "poc_execution" / "halmos-vault" / "execution_manifest.json"
            manifest.parent.mkdir(parents=True)
            manifest.write_text(
                json.dumps({
                    "candidate_id": "halmos-vault",
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                })
                + "\n",
                encoding="utf-8",
            )

            payload = self.run_tool(ws)
            item = payload["items"][0]

            self.assertEqual(item["status"], "executed")
            self.assertEqual(item["assigned_model"], "codex")
            self.assertEqual(item["final_result"], "proved")
            # Item #14: an executed record (manifest matched) is upgraded to
            # ``executed_with_manifest``; further upgrades happen on Codex
            # sign-off, not in this tool.
            self.assertEqual(item["evidence_class"], "executed_with_manifest")
            self.assertEqual(
                payload["evidence_class_counts"]["executed_with_manifest"], 1
            )
            self.assertEqual(
                payload["evidence_class_counts"]["generated_hypothesis"], 0
            )


if __name__ == "__main__":
    unittest.main()
