from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.control.runner import (
    CLASS_BLOCKED,
    CLASS_NEEDS_OPERATOR,
    CLASS_PROOF_RECORDING,
    CLASS_SAFE_LOCAL,
    SCHEMA,
    build_execution_plan,
    command_hash,
    plan_command,
    write_execution_plan,
)


class ControlRunnerTests(unittest.TestCase):
    def test_safe_local_command_is_dry_run_only(self) -> None:
        row = plan_command(
            "python3 tools/engage.py --workspace /tmp/ws --stage mine-prioritize",
            workspace="/tmp/ws",
            cwd="/repo",
        )

        self.assertEqual(row["classification"], CLASS_SAFE_LOCAL)
        self.assertTrue(row["dry_run"])
        self.assertFalse(row["would_execute"])
        self.assertEqual(row["workspace"], "/tmp/ws")
        self.assertEqual(row["cwd"], "/repo")
        self.assertEqual(row["blockers"], [])
        self.assertEqual(len(row["command_hash"]), 64)

    def test_proof_recording_and_operator_commands_are_classified(self) -> None:
        proof = plan_command(
            "make poc-execution-record WS=/tmp/ws BRIEF=finding.md CMD='forge test'",
            workspace="/tmp/ws",
            cwd="/repo",
        )
        operator = plan_command(
            "python3 tools/operator-oos-import.py /tmp/ws",
            workspace="/tmp/ws",
            cwd="/repo",
        )

        self.assertEqual(proof["classification"], CLASS_PROOF_RECORDING)
        self.assertEqual(proof["blockers"], [])
        self.assertEqual(operator["classification"], CLASS_NEEDS_OPERATOR)
        self.assertEqual(operator["blockers"], [])

    def test_blocked_git_and_github_commands_report_specific_blockers(self) -> None:
        cases = {
            "git push origin HEAD": ["git_push_blocked"],
            "git push --force origin HEAD": ["git_force_push_blocked", "git_push_blocked"],
            "git merge main": ["git_merge_blocked"],
            "git reset --hard HEAD": ["destructive_git_cleanup_blocked"],
            "git clean -fdx": ["destructive_git_cleanup_blocked"],
            "git checkout -- tools/control/runner.py": ["destructive_git_cleanup_blocked"],
            "gh workflow run tests.yml": ["github_actions_blocked"],
            "gh run rerun 123": ["github_actions_blocked"],
            "gh pr create --fill": ["github_pr_blocked"],
            "gh pr merge 12": ["github_pr_blocked"],
        }

        for command, blockers in cases.items():
            with self.subTest(command=command):
                row = plan_command(command, workspace="/tmp/ws", cwd="/repo")
                self.assertEqual(row["classification"], CLASS_BLOCKED)
                self.assertEqual(row["blockers"], blockers)
                self.assertFalse(row["would_execute"])

    def test_command_hash_is_deterministic_and_context_sensitive(self) -> None:
        first = command_hash("make audit WS=/tmp/ws", cwd="/repo", workspace="/tmp/ws")
        second = command_hash(" make   audit   WS=/tmp/ws ", cwd="/repo", workspace="/tmp/ws")
        other_cwd = command_hash("make audit WS=/tmp/ws", cwd="/other", workspace="/tmp/ws")
        other_ws = command_hash("make audit WS=/tmp/ws", cwd="/repo", workspace="/tmp/other")

        self.assertEqual(first, second)
        self.assertNotEqual(first, other_cwd)
        self.assertNotEqual(first, other_ws)

    def test_manifest_is_replayable_dry_run_with_action_context(self) -> None:
        actions = [
            {
                "priority": 30,
                "reason": "semantic graph is missing",
                "command": "make semantic-graph WS=/tmp/ws",
                "artifact": ".auditooor/semantic_graph.json",
                "stop_condition": "semantic graph exists",
                "proof_boundary": "planning only",
            },
            {
                "priority": 60,
                "reason": "candidate is missing executed test output",
                "command": "make poc-execution-record WS=/tmp/ws BRIEF=draft.md CMD='forge test'",
                "artifact": "poc_execution",
                "stop_condition": "execution manifest exists",
                "proof_boundary": "records executed proof",
            },
            {"priority": 99, "reason": "do not do this", "command": "git push origin HEAD"},
        ]

        manifest = build_execution_plan("/tmp/ws", actions, cwd="/repo")

        self.assertEqual(manifest["schema"], SCHEMA)
        self.assertTrue(manifest["dry_run"])
        self.assertFalse(manifest["would_execute"])
        self.assertEqual(manifest["workspace"], "/tmp/ws")
        self.assertEqual(manifest["cwd"], "/repo")
        self.assertEqual(manifest["command_count"], 3)
        self.assertEqual(manifest["counts_by_classification"][CLASS_SAFE_LOCAL], 1)
        self.assertEqual(manifest["counts_by_classification"][CLASS_PROOF_RECORDING], 1)
        self.assertEqual(manifest["counts_by_classification"][CLASS_BLOCKED], 1)
        self.assertEqual(manifest["commands"][0]["action"]["priority"], 30)
        self.assertEqual(manifest["commands"][2]["blockers"], ["git_push_blocked"])

    def test_write_execution_plan_persists_json_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "plan.json"
            payload = write_execution_plan(
                out,
                "/tmp/ws",
                [{"command": "python3 tools/engage.py --workspace /tmp/ws --stage env-check"}],
                cwd="/repo",
            )
            loaded = json.loads(out.read_text(encoding="utf-8"))

        self.assertEqual(loaded, payload)
        self.assertEqual(loaded["schema"], SCHEMA)
        self.assertTrue(loaded["dry_run"])


if __name__ == "__main__":
    unittest.main()
