from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.control.run_manifest import SCHEMA, build_run_manifest, write_run_manifest


class ControlRunManifestTests(unittest.TestCase):
    def test_planned_command_manifest_does_not_claim_execution(self) -> None:
        manifest = build_run_manifest(
            "python3 tools/engage.py --workspace /tmp/ws --stage env-check",
            cwd="/repo",
            workspace="/tmp/ws",
            stdout_path="logs/stdout.txt",
            artifacts=["INTAKE_BASELINE.json"],
        )

        self.assertEqual(manifest["schema"], SCHEMA)
        self.assertEqual(len(manifest["command_hash"]), 64)
        self.assertEqual(
            manifest["argv"],
            ["python3", "tools/engage.py", "--workspace", "/tmp/ws", "--stage", "env-check"],
        )
        self.assertEqual(manifest["cwd"], "/repo")
        self.assertEqual(manifest["workspace"], "/tmp/ws")
        self.assertEqual(manifest["status"], "planned")
        self.assertIsNone(manifest["finished_at"])
        self.assertIsNone(manifest["exit_code"])
        self.assertEqual(manifest["stdout_path"], "logs/stdout.txt")
        self.assertEqual(manifest["stderr_path"], None)
        self.assertEqual(manifest["artifacts"], ["INTAKE_BASELINE.json"])
        self.assertFalse(manifest["proof_counted"])
        self.assertEqual(manifest["blocked_reasons"], [])

    def test_completed_process_metadata_sets_success_status(self) -> None:
        manifest = build_run_manifest(
            ["make", "semantic-graph", "WS=/tmp/ws"],
            cwd="/repo",
            workspace="/tmp/ws",
            completed={
                "returncode": 0,
                "started_at": "2026-05-03T10:00:00Z",
                "finished_at": "2026-05-03T10:00:05Z",
                "stdout_path": ".audit_logs/stdout.log",
                "stderr_path": ".audit_logs/stderr.log",
                "artifacts": [{"path": ".auditooor/semantic_graph.json"}, ".auditooor/semantic_graph.md"],
            },
        )

        self.assertEqual(manifest["status"], "succeeded")
        self.assertEqual(manifest["exit_code"], 0)
        self.assertEqual(manifest["started_at"], "2026-05-03T10:00:00Z")
        self.assertEqual(manifest["finished_at"], "2026-05-03T10:00:05Z")
        self.assertEqual(manifest["stdout_path"], ".audit_logs/stdout.log")
        self.assertEqual(manifest["stderr_path"], ".audit_logs/stderr.log")
        self.assertEqual(
            manifest["artifacts"],
            [".auditooor/semantic_graph.json", ".auditooor/semantic_graph.md"],
        )
        self.assertFalse(manifest["proof_counted"])

    def test_explicit_metadata_overrides_completed_mapping(self) -> None:
        manifest = build_run_manifest(
            "forge test --match-test testExploit",
            cwd="/repo",
            workspace="/tmp/ws",
            completed={"returncode": 1, "status": "failed", "proof_counted": True},
            status="success",
            exit_code=0,
            proof_counted=False,
        )

        self.assertEqual(manifest["status"], "succeeded")
        self.assertEqual(manifest["exit_code"], 0)
        self.assertFalse(manifest["proof_counted"])

    def test_blocked_status_preserves_normalized_reasons(self) -> None:
        manifest = build_run_manifest(
            "git push origin HEAD",
            cwd="/repo",
            workspace="/tmp/ws",
            status="blocked",
            blocked_reasons=[" git_push_blocked ", "git_push_blocked", "github_boundary"],
        )

        self.assertEqual(manifest["status"], "blocked")
        self.assertEqual(manifest["blocked_reasons"], ["git_push_blocked", "github_boundary"])
        self.assertIsNone(manifest["exit_code"])

    def test_write_run_manifest_persists_deterministic_json(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "run_manifest.json"
            manifest = build_run_manifest("make audit WS=/tmp/ws", cwd="/repo", workspace="/tmp/ws")
            write_run_manifest(out, manifest)
            loaded = json.loads(out.read_text(encoding="utf-8"))

        self.assertEqual(loaded, manifest)
        self.assertEqual(loaded["schema"], SCHEMA)


if __name__ == "__main__":
    unittest.main()
