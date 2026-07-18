"""Tests for tools/finalization-manifest.py."""

from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "finalization-manifest.py"


def _run(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["python3", str(TOOL), *args],
        capture_output=True,
        text=True,
        cwd=cwd or REPO_ROOT,
    )


class FinalizationManifestCliTest(unittest.TestCase):
    def test_build_and_read_valid_manifest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finalization-manifest-") as td:
            workspace = Path(td) / "ws"
            workspace.mkdir()
            proc_build = _run(
                "build",
                "--workspace",
                str(workspace),
                "--artifact-path",
                "tools/finalization-manifest.py",
                "--handoff-or-ledger-path",
                "docs/LOOP_FINALIZATION_CHECK.md",
                "--agent-output-path",
                "agent_outputs/finalization_slice.md",
                "--test-command",
                "python3 -m pytest tools/tests/test_finalization_manifest.py -q",
                "--test-log-path",
                "agent_outputs/finalization_slice.md",
                "--mcp-evidence-path",
                ".auditooor/memory_update.json",
                "--task-update-path",
                "reports/finalization_manifest_writer_phase_a_2026-05-17.md",
                "--context-pack-id",
                "auditooor.vault_context_pack.v1:finalization:1234567890abcdef",
                "--context-pack-hash",
                "b2f5ff47436671b6e533d8dc3614845d",
                "--source-ref",
                "obsidian-vault/finalization/current.md",
                "--json",
            )
            self.assertEqual(proc_build.returncode, 0, proc_build.stdout + proc_build.stderr)
            built = json.loads(proc_build.stdout)
            self.assertTrue(built["passed"])
            manifest_path = Path(built["manifest_path"])
            self.assertTrue(manifest_path.is_file())

            proc_read = _run("read", "--manifest", str(manifest_path), "--json")
            self.assertEqual(proc_read.returncode, 0, proc_read.stdout + proc_read.stderr)
            read_payload = json.loads(proc_read.stdout)
            self.assertEqual(read_payload["status"], "pass")

    def test_missing_required_sections_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finalization-manifest-") as td:
            manifest = Path(td) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.finalization_manifest.v1",
                        "schema_version": 1,
                        "workspace_path": "/tmp/workspace",
                        "generated_at_utc": "2026-05-17T10:00:00Z",
                        "artifact_paths": ["tools/finalization-manifest.py"],
                        "agent_output_paths": ["agent_outputs/slice.md"],
                        "tests_or_logs": {"commands": ["pytest -q"], "logs": []},
                        "mcp_task_update_evidence": {"mcp_paths": ["obsidian-vault/tasks/current.md"]},
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            proc = _run("read", "--manifest", str(manifest), "--json")
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["status"], "fail")
            self.assertIn("handoff_or_ledger_paths must be a non-empty string list", payload["errors"])

    def test_read_rejects_tbd_mcp_context_even_with_strict_memory_command(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finalization-manifest-") as td:
            manifest = Path(td) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.finalization_manifest.v1",
                        "schema_version": 1,
                        "workspace_path": "/tmp/workspace",
                        "generated_at_utc": "2026-05-17T10:00:00Z",
                        "artifact_paths": ["tools/finalization-manifest.py"],
                        "handoff_or_ledger_paths": ["docs/LOOP_FINALIZATION_CHECK.md"],
                        "agent_output_paths": ["agent_outputs/slice.md"],
                        "tests_or_logs": {
                            "commands": [
                                "python3 tools/memory-context-load.py --workspace /tmp/workspace --check --strict --require-proof"
                            ],
                            "logs": ["reports/run.log"],
                        },
                        "mcp_task_update_evidence": {"mcp_paths": ["obsidian-vault/tasks/current.md"]},
                        "mcp_context_evidence": {
                            "context_pack_id": "TBD",
                            "context_pack_hash": "TBD",
                            "source_refs": ["obsidian-vault/current.md"],
                        },
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            proc = _run("read", "--manifest", str(manifest), "--json")

            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["status"], "fail")
            self.assertIn(
                "mcp_context_evidence, when present, must include non-placeholder context_pack_id/context_pack_hash/source_refs",
                payload["errors"],
            )

    def test_build_with_source_ref_only_uses_strict_memory_command_without_tbd_context(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finalization-manifest-") as td:
            workspace = Path(td) / "ws"
            workspace.mkdir()
            proc_build = _run(
                "build",
                "--workspace",
                str(workspace),
                "--artifact-path",
                "tools/finalization-manifest.py",
                "--handoff-or-ledger-path",
                "docs/LOOP_FINALIZATION_CHECK.md",
                "--agent-output-path",
                "agent_outputs/finalization_slice.md",
                "--test-command",
                f"python3 tools/memory-context-load.py --workspace {workspace} --check --strict --require-proof",
                "--mcp-evidence-path",
                ".auditooor/memory_update.json",
                "--source-ref",
                "obsidian-vault/finalization/current.md",
                "--json",
            )

            self.assertEqual(proc_build.returncode, 0, proc_build.stdout + proc_build.stderr)
            payload = json.loads(proc_build.stdout)
            self.assertTrue(payload["passed"])
            self.assertNotIn("mcp_context_evidence", payload["manifest"])

    def test_no_artifact_reason_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finalization-manifest-") as td:
            workspace = Path(td) / "ws"
            workspace.mkdir()
            proc_build = _run(
                "build",
                "--workspace",
                str(workspace),
                "--no-artifact-reason",
                "docs-only closeout note sync",
                "--handoff-or-ledger-path",
                "docs/LOOP_FINALIZATION_CHECK.md",
                "--agent-output-path",
                "agent_outputs/docs_sync.md",
                "--test-command",
                "python3 -m pytest tools/tests/test_finalization_manifest.py -q",
                "--mcp-evidence-path",
                ".auditooor/memory_update.json",
                "--context-pack-id",
                "auditooor.vault_context_pack.v1:finalization:1234567890abcdef",
                "--context-pack-hash",
                "b2f5ff47436671b6e533d8dc3614845d",
                "--source-ref",
                "obsidian-vault/finalization/current.md",
                "--json",
            )
            self.assertEqual(proc_build.returncode, 0, proc_build.stdout + proc_build.stderr)
            built = json.loads(proc_build.stdout)
            self.assertTrue(built["passed"])
            manifest = built["manifest"]
            self.assertEqual(manifest["artifact_paths"], [])
            self.assertIn("NO_ARTIFACT", manifest["no_artifact_reason"])

    def test_build_normalizes_paths(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finalization-manifest-") as td:
            workspace = Path(td) / "ws"
            workspace.mkdir()
            proc_build = _run(
                "build",
                "--workspace",
                str(workspace),
                "--artifact-path",
                "./src/../tools\\finalization-manifest.py",
                "--handoff-or-ledger-path",
                str(workspace / "docs/../docs/LOOP_FINALIZATION_CHECK.md"),
                "--agent-output-path",
                "agent_outputs\\slice\\note.md",
                "--test-command",
                "pytest -q",
                "--test-log-path",
                "./logs/../logs/run.log",
                "--mcp-evidence-path",
                "./.auditooor\\memory.json",
                "--task-update-path",
                str(workspace / "reports/../reports/task_update.json"),
                "--context-pack-id",
                "auditooor.vault_context_pack.v1:finalization:1234567890abcdef",
                "--context-pack-hash",
                "b2f5ff47436671b6e533d8dc3614845d",
                "--source-ref",
                "obsidian-vault/finalization/current.md",
                "--json",
            )
            self.assertEqual(proc_build.returncode, 0, proc_build.stdout + proc_build.stderr)
            payload = json.loads(proc_build.stdout)
            manifest = payload["manifest"]
            self.assertEqual(manifest["artifact_paths"], ["tools/finalization-manifest.py"])
            self.assertEqual(manifest["handoff_or_ledger_paths"], ["docs/LOOP_FINALIZATION_CHECK.md"])
            self.assertEqual(manifest["agent_output_paths"], ["agent_outputs/slice/note.md"])
            self.assertEqual(manifest["tests_or_logs"]["logs"], ["logs/run.log"])
            self.assertEqual(
                manifest["mcp_task_update_evidence"]["mcp_paths"],
                [".auditooor/memory.json"],
            )
            self.assertEqual(
                manifest["mcp_task_update_evidence"]["task_update_paths"],
                ["reports/task_update.json"],
            )

    def test_build_includes_agent_cycle_log_summary_when_present(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finalization-manifest-") as td:
            workspace = Path(td) / "ws"
            workspace.mkdir()
            log_path = workspace / ".auditooor" / "agent_cycle_log.jsonl"
            log_path.parent.mkdir(parents=True, exist_ok=True)
            log_path.write_text(
                "\n".join(
                    [
                        json.dumps({"event": "spawn", "ts": "2026-05-17T10:00:00Z"}),
                        "{bad json",
                        json.dumps({"event": "complete", "timestamp": "2026-05-17T10:05:00Z"}),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            proc_build = _run(
                "build",
                "--workspace",
                str(workspace),
                "--artifact-path",
                "tools/finalization-manifest.py",
                "--handoff-or-ledger-path",
                "docs/LOOP_FINALIZATION_CHECK.md",
                "--agent-output-path",
                "agent_outputs/finalization_slice.md",
                "--test-command",
                "pytest -q",
                "--mcp-evidence-path",
                ".auditooor/memory.json",
                "--context-pack-id",
                "auditooor.vault_context_pack.v1:finalization:1234567890abcdef",
                "--context-pack-hash",
                "b2f5ff47436671b6e533d8dc3614845d",
                "--source-ref",
                "obsidian-vault/finalization/current.md",
                "--json",
            )
            self.assertEqual(proc_build.returncode, 0, proc_build.stdout + proc_build.stderr)
            payload = json.loads(proc_build.stdout)
            manifest = payload["manifest"]
            self.assertIn("agent_cycle_log", manifest)
            summary = manifest["agent_cycle_log"]
            self.assertEqual(Path(summary["path"]).resolve(strict=False), log_path.resolve(strict=False))
            self.assertEqual(summary["event_count"], 2)
            self.assertEqual(summary["malformed_rows"], 1)
            self.assertEqual(summary["counts_by_event"], {"complete": 1, "spawn": 1})
            self.assertEqual(summary["last_updated"], "2026-05-17T10:05:00Z")

    def test_build_skips_agent_cycle_log_summary_when_missing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finalization-manifest-") as td:
            workspace = Path(td) / "ws"
            workspace.mkdir()
            log_path = workspace / ".auditooor" / "agent_cycle_log.jsonl"
            proc_build = _run(
                "build",
                "--workspace",
                str(workspace),
                "--artifact-path",
                "tools/finalization-manifest.py",
                "--handoff-or-ledger-path",
                "docs/LOOP_FINALIZATION_CHECK.md",
                "--agent-output-path",
                "agent_outputs/finalization_slice.md",
                "--test-command",
                "pytest -q",
                "--mcp-evidence-path",
                ".auditooor/memory.json",
                "--context-pack-id",
                "auditooor.vault_context_pack.v1:finalization:1234567890abcdef",
                "--context-pack-hash",
                "b2f5ff47436671b6e533d8dc3614845d",
                "--source-ref",
                "obsidian-vault/finalization/current.md",
                "--json",
            )
            self.assertEqual(proc_build.returncode, 0, proc_build.stdout + proc_build.stderr)
            payload = json.loads(proc_build.stdout)
            manifest = payload["manifest"]
            self.assertNotIn("agent_cycle_log", manifest)
            self.assertFalse(log_path.exists())

    def test_missing_mcp_context_proof_fails(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finalization-manifest-") as td:
            workspace = Path(td) / "ws"
            workspace.mkdir()
            proc_build = _run(
                "build",
                "--workspace",
                str(workspace),
                "--artifact-path",
                "tools/finalization-manifest.py",
                "--handoff-or-ledger-path",
                "docs/LOOP_FINALIZATION_CHECK.md",
                "--agent-output-path",
                "agent_outputs/finalization_slice.md",
                "--test-command",
                "pytest -q",
                "--mcp-evidence-path",
                ".auditooor/memory.json",
                "--json",
            )
            self.assertEqual(proc_build.returncode, 1, proc_build.stdout + proc_build.stderr)
            payload = json.loads(proc_build.stdout)
            self.assertFalse(payload["passed"])
            self.assertIn(
                "manifest must include mcp_context_evidence "
                "(context_pack_id/context_pack_hash/source_refs) or a strict "
                "python3 tools/memory-context-load.py --check --strict --require-proof command",
                payload["errors"],
            )

    def test_strict_receipt_command_is_valid_mcp_context_proof(self) -> None:
        with tempfile.TemporaryDirectory(prefix="finalization-manifest-") as td:
            workspace = Path(td) / "ws"
            workspace.mkdir()
            proc_build = _run(
                "build",
                "--workspace",
                str(workspace),
                "--artifact-path",
                "tools/finalization-manifest.py",
                "--handoff-or-ledger-path",
                "docs/LOOP_FINALIZATION_CHECK.md",
                "--agent-output-path",
                "agent_outputs/finalization_slice.md",
                "--test-command",
                "python3 tools/memory-context-load.py --workspace /tmp/ws --from-requirements --check --strict --require-proof --json",
                "--mcp-evidence-path",
                ".auditooor/memory.json",
                "--json",
            )
            self.assertEqual(proc_build.returncode, 0, proc_build.stdout + proc_build.stderr)
            payload = json.loads(proc_build.stdout)
            self.assertTrue(payload["passed"])


if __name__ == "__main__":
    unittest.main()
