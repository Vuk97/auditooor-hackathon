import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "agent-cycle-log.py"


def load_module():
    spec = importlib.util.spec_from_file_location("agent_cycle_log", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


cycle_log = load_module()


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(MODULE_PATH), *args],
        capture_output=True,
        text=True,
        check=False,
    )


class AgentCycleLogTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-agent-cycle-log-test-")
        self.root = Path(self.tmp.name)
        self.workspace = self.root / "ws"
        self.workspace.mkdir(parents=True)
        self.log_path = self.workspace / ".auditooor" / "agent_cycle_log.jsonl"

    def tearDown(self):
        self.tmp.cleanup()

    def read_jsonl(self, path: Path):
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def write_closeout_manifest(
        self,
        *,
        artifact_paths: list[str] | None = None,
        no_artifact_reason: str | None = None,
        include_mcp_context: bool = True,
        include_strict_receipt: bool = False,
        include_handoff: bool = True,
        include_agent_outputs: bool = True,
        mcp_memory_relevant: bool = True,
        mcp_memory_updated: bool = True,
        include_mcp_memory_evidence: bool = True,
    ) -> Path:
        manifest_path = self.workspace / ".auditooor" / "finalization" / "current_manifest.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        commands = ["python3 -m unittest tools.tests.test_agent_cycle_log -v"]
        if include_strict_receipt:
            commands.append(
                "python3 tools/memory-context-load.py --workspace /tmp/ws "
                "--from-requirements --check --strict --require-proof --json"
            )
        payload: dict[str, object] = {
            "schema": "auditooor.finalization_manifest.v1",
            "schema_version": 1,
            "workspace_path": str(self.workspace.resolve()),
            "generated_at_utc": "2026-05-17T00:00:00Z",
            "artifact_paths": artifact_paths or ["reports/finalization_note.md"],
            "tests_or_logs": {"commands": commands, "logs": ["reports/finalization_note.md"]},
            "mcp_task_update_evidence": {"mcp_paths": [".auditooor/memory_context_receipt.json"]},
        }
        if include_handoff:
            payload["handoff_or_ledger_updated"] = {
                "paths": ["reports/task_finalization.jsonl"],
                "note": "Local finalization ledger updated.",
            }
        if include_agent_outputs:
            payload["agent_outputs_collected"] = {
                "paths": ["agent_outputs/finalization_note.md"],
            }
        mcp_memory: dict[str, object] = {
            "relevant": mcp_memory_relevant,
        }
        if mcp_memory_relevant:
            mcp_memory["updated"] = mcp_memory_updated
            if include_mcp_memory_evidence:
                mcp_memory["paths"] = [".auditooor/memory_context_receipt.json"]
        payload["mcp_memory_updated_when_relevant"] = mcp_memory
        if no_artifact_reason is not None:
            payload["no_artifact_reason"] = no_artifact_reason
        if include_mcp_context:
            payload["mcp_context_evidence"] = {
                "context_pack_id": "auditooor.vault_context_pack.v1:finalization:1234567890abcdef",
                "context_pack_hash": "b2f5ff47436671b6e533d8dc3614845d",
                "source_refs": ["obsidian-vault/finalization/current.md"],
            }
        manifest_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return manifest_path

    def test_append_writes_jsonl_row(self):
        row = cycle_log.append_event(
            workspace=self.workspace,
            event="spawn",
            agent="codex",
            task="active-objective-gap",
            note="manual run",
            now_fn=lambda: "2026-05-17T00:00:00Z",
        )

        self.assertTrue(self.log_path.is_file())
        rows = self.read_jsonl(self.log_path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["schema"], cycle_log.SCHEMA)
        self.assertEqual(rows[0]["event"], "spawn")
        self.assertEqual(rows[0]["agent"], "codex")
        self.assertEqual(rows[0]["task"], "active-objective-gap")
        self.assertEqual(rows[0]["workspace"], str(self.workspace.resolve()))
        self.assertEqual(row["ts"], "2026-05-17T00:00:00Z")

    def test_summary_counts_by_event_agent_task(self):
        manifest_path = self.write_closeout_manifest()
        cycle_log.append_event(
            workspace=self.workspace,
            event="spawn",
            agent="codex",
            task="gap-audit",
            now_fn=lambda: "2026-05-17T00:00:00Z",
        )
        cycle_log.append_event(
            workspace=self.workspace,
            event="verify",
            agent="codex",
            task="gap-audit",
            now_fn=lambda: "2026-05-17T00:05:00Z",
        )
        cycle_log.append_event(
            workspace=self.workspace,
            event="close",
            agent="operator",
            task="handoff",
            closeout_manifest=manifest_path,
            now_fn=lambda: "2026-05-17T00:10:00Z",
        )

        summary = cycle_log.summarize_log(self.log_path)

        self.assertEqual(summary["rows"], 3)
        self.assertEqual(summary["malformed_rows"], 0)
        self.assertEqual(summary["last_updated"], "2026-05-17T00:10:00Z")
        self.assertEqual(summary["by_event"], {"close": 1, "spawn": 1, "verify": 1})
        self.assertEqual(summary["by_agent"], {"codex": 2, "operator": 1})
        self.assertEqual(summary["by_task"], {"gap-audit": 2, "handoff": 1})

    def test_summary_tolerates_malformed_rows(self):
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.write_text(
            "\n".join([
                json.dumps({
                    "schema": cycle_log.SCHEMA,
                    "ts": "2026-05-17T00:00:00Z",
                    "event": "verify",
                    "agent": "codex",
                    "task": "gap-audit",
                    "workspace": str(self.workspace.resolve()),
                }),
                "{not-json",
                json.dumps(["not", "an", "object"]),
                "",
            ]),
            encoding="utf-8",
        )

        summary = cycle_log.summarize_log(self.log_path)

        self.assertEqual(summary["rows"], 1)
        self.assertEqual(summary["malformed_rows"], 2)
        self.assertEqual(summary["by_event"], {"verify": 1})
        self.assertEqual(summary["by_agent"], {"codex": 1})
        self.assertEqual(summary["by_task"], {"gap-audit": 1})

    def test_summary_does_not_create_workspace_or_log(self):
        missing = self.root / "missing-workspace"

        self.assertFalse(missing.exists())
        rc = run_cli("summary", "--workspace", str(missing))
        self.assertEqual(rc.returncode, 0, msg=rc.stderr)
        payload = json.loads(rc.stdout)
        self.assertEqual(payload["rows"], 0)
        self.assertEqual(payload["malformed_rows"], 0)
        self.assertFalse(missing.exists())
        self.assertFalse((missing / ".auditooor").exists())

    def test_complete_requires_manifest(self):
        with self.assertRaises(ValueError):
            cycle_log.append_event(
                workspace=self.workspace,
                event="complete",
                agent="codex",
                task="gap-audit",
                now_fn=lambda: "2026-05-17T00:00:00Z",
            )

    def test_close_rejects_manifest_without_mcp_context_proof(self):
        manifest_path = self.write_closeout_manifest(include_mcp_context=False, include_strict_receipt=False)
        with self.assertRaises(ValueError):
            cycle_log.append_event(
                workspace=self.workspace,
                event="close",
                agent="codex",
                task="gap-audit",
                closeout_manifest=manifest_path,
                now_fn=lambda: "2026-05-17T00:00:00Z",
            )

    def test_close_rejects_manifest_without_handoff_or_ledger_evidence(self):
        manifest_path = self.write_closeout_manifest(include_handoff=False)
        with self.assertRaises(ValueError) as ctx:
            cycle_log.append_event(
                workspace=self.workspace,
                event="close",
                agent="codex",
                task="gap-audit",
                closeout_manifest=manifest_path,
                now_fn=lambda: "2026-05-17T00:00:00Z",
            )
        self.assertIn("updated local ledger/handoff evidence", str(ctx.exception))

    def test_close_rejects_manifest_without_agent_output_evidence(self):
        manifest_path = self.write_closeout_manifest(include_agent_outputs=False)
        with self.assertRaises(ValueError) as ctx:
            cycle_log.append_event(
                workspace=self.workspace,
                event="close",
                agent="codex",
                task="gap-audit",
                closeout_manifest=manifest_path,
                now_fn=lambda: "2026-05-17T00:00:00Z",
            )
        self.assertIn("agent output collection evidence", str(ctx.exception))

    def test_close_rejects_manifest_without_relevant_mcp_memory_update(self):
        manifest_path = self.write_closeout_manifest(mcp_memory_updated=False)
        with self.assertRaises(ValueError) as ctx:
            cycle_log.append_event(
                workspace=self.workspace,
                event="close",
                agent="codex",
                task="gap-audit",
                closeout_manifest=manifest_path,
                now_fn=lambda: "2026-05-17T00:00:00Z",
            )
        self.assertIn("MCP memory update when relevant", str(ctx.exception))

    def test_close_rejects_manifest_without_relevant_mcp_memory_evidence(self):
        manifest_path = self.write_closeout_manifest(include_mcp_memory_evidence=False)
        with self.assertRaises(ValueError) as ctx:
            cycle_log.append_event(
                workspace=self.workspace,
                event="close",
                agent="codex",
                task="gap-audit",
                closeout_manifest=manifest_path,
                now_fn=lambda: "2026-05-17T00:00:00Z",
            )
        self.assertIn("MCP memory update evidence when relevant", str(ctx.exception))

    def test_close_accepts_manifest_when_mcp_memory_not_relevant(self):
        manifest_path = self.write_closeout_manifest(mcp_memory_relevant=False)
        row = cycle_log.append_event(
            workspace=self.workspace,
            event="close",
            agent="codex",
            task="gap-audit",
            closeout_manifest=manifest_path,
            now_fn=lambda: "2026-05-17T00:00:00Z",
        )
        self.assertIn("closeout_manifest", row)

    def test_close_accepts_manifest_with_no_artifact_marker(self):
        manifest_path = self.write_closeout_manifest(
            artifact_paths=[],
            no_artifact_reason="NO_ARTIFACT: docs-only finalization cleanup",
        )
        row = cycle_log.append_event(
            workspace=self.workspace,
            event="close",
            agent="codex",
            task="gap-audit",
            closeout_manifest=manifest_path,
            now_fn=lambda: "2026-05-17T00:00:00Z",
        )
        self.assertIn("closeout_manifest", row)
        self.assertEqual(Path(row["closeout_manifest"]).resolve(), manifest_path.resolve())


class AgentCycleLogCliTest(unittest.TestCase):
    def test_append_cli_round_trip(self):
        with tempfile.TemporaryDirectory(prefix="auditooor-agent-cycle-log-cli-") as raw:
            workspace = Path(raw) / "ws"
            workspace.mkdir()
            rc = run_cli(
                "append",
                "--workspace",
                str(workspace),
                "--event",
                "no_artifact",
                "--agent",
                "operator",
                "--task",
                "manual-gap-note",
                "--note",
                "no workspace artifact existed",
            )
            self.assertEqual(rc.returncode, 0, msg=rc.stderr)
            log_path = workspace / ".auditooor" / "agent_cycle_log.jsonl"
            self.assertTrue(log_path.is_file())
            rows = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(rows[0]["event"], "no_artifact")
            self.assertEqual(rows[0]["agent"], "operator")
            self.assertEqual(rows[0]["task"], "manual-gap-note")

    def test_summary_cli_text_format(self):
        with tempfile.TemporaryDirectory(prefix="auditooor-agent-cycle-log-cli-") as raw:
            workspace = Path(raw) / "ws"
            workspace.mkdir()
            cycle_log.append_event(
                workspace=workspace,
                event="spawn",
                agent="codex",
                task="gap-audit",
                now_fn=lambda: "2026-05-17T00:00:00Z",
            )
            rc = run_cli("summary", "--workspace", str(workspace), "--format", "text")
            self.assertEqual(rc.returncode, 0, msg=rc.stderr)
            self.assertIn("rows: 1", rc.stdout)
            self.assertIn("by_event:", rc.stdout)

    def test_complete_cli_requires_manifest(self):
        with tempfile.TemporaryDirectory(prefix="auditooor-agent-cycle-log-cli-") as raw:
            workspace = Path(raw) / "ws"
            workspace.mkdir()
            rc = run_cli(
                "append",
                "--workspace",
                str(workspace),
                "--event",
                "complete",
                "--agent",
                "operator",
            )
            self.assertEqual(rc.returncode, 1)
            self.assertIn("requires --manifest", rc.stderr)
