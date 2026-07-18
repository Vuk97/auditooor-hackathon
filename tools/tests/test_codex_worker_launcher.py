import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "codex-worker-launcher.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("codex_worker_launcher", TOOL)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class CodexWorkerLauncherTest(unittest.TestCase):
    def setUp(self):
        self.tool = load_tool()

    def test_failed_turn_detects_json_error_even_with_shell_success(self):
        stdout = "\n".join(
            [
                json.dumps({"type": "thread.started", "thread_id": "t"}),
                json.dumps({"type": "turn.failed", "error": {"message": "bad model"}}),
            ]
        )
        failed, reason = self.tool.has_failed_turn(stdout, "")
        self.assertTrue(failed)
        self.assertIn("bad model", reason)

    def test_configured_model_reads_user_config(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = Path(td) / "config.toml"
            cfg.write_text('model = "gpt-5.5"\n', encoding="utf-8")
            self.assertEqual(self.tool.configured_model(cfg), "gpt-5.5")

    def test_runtime_falls_back_to_ignore_user_config_after_model_rejection(self):
        with tempfile.TemporaryDirectory() as td:
            workspace = Path(td)
            cfg = workspace / "config.toml"
            cfg.write_text('model = "gpt-5.5"\n', encoding="utf-8")

            def fake_probe(command, exec_options, prompt, timeout, *, cwd=None):
                if "-m" in command:
                    return False, "requires a newer version of Codex", "", "bad"
                return True, "", json.dumps({"type": "turn.completed"}), ""

            with mock.patch.object(self.tool, "run_probe", side_effect=fake_probe):
                runtime = self.tool.resolve_runtime(
                    codex_bin="codex",
                    workspace=workspace,
                    requested_model="auto",
                    config_path=cfg,
                    probe_timeout=1,
                    skip_model_probe=False,
                )
        self.assertEqual(runtime.mode, "ignore_user_config_default_model")
        self.assertTrue(runtime.ignored_user_config)
        self.assertNotIn("-m", runtime.command)
        self.assertIn("--dangerously-bypass-approvals-and-sandbox", runtime.command)
        self.assertIn("--ignore-user-config", runtime.exec_options)

    def test_run_probe_uses_target_workspace_as_cwd(self):
        workspace = Path("/tmp/target-workspace")
        completed = mock.Mock(returncode=0, stdout='{"type":"turn.completed"}\n', stderr="")
        with mock.patch.object(self.tool.subprocess, "run", return_value=completed) as run:
            result = self.tool.run_probe(
                ["codex"], [], "probe", 7, cwd=workspace
            )
        self.assertEqual(result[0], True)
        self.assertEqual(run.call_args.kwargs["cwd"], workspace)

    def test_dry_run_writes_manifest_without_starting_processes(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            prompt = root / "worker_el_test.md"
            prompt.write_text("do work\n", encoding="utf-8")
            manifest = root / "manifest.json"
            runtime = self.tool.CodexRuntime(
                command=["codex", "-a", "never"],
                exec_options=[],
                mode="ignore_user_config_default_model",
                model=None,
                ignored_user_config=True,
                preflight_stdout="",
                preflight_stderr="",
            )
            payload = self.tool.launch_workers(
                runtime,
                [self.tool.WorkerSpec("EL", prompt)],
                root,
                root / "runs",
                manifest,
                startup_grace=0,
                dry_run=True,
            )
            self.assertTrue(manifest.exists())
            self.assertEqual(payload["workers"][0]["status"], "dry_run")
            self.assertEqual(payload["runtime"]["model"], "codex_cli_default")

    def test_prompt_lint_blocks_audit_worker_without_start_packet(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            prompt = root / "worker_ab_test.md"
            prompt.write_text(
                """
task.type: source-extract
## Acceptance
- Review detector hits and produce a proof lane.
- Deliverable: `reports/example.md`
- Self-test mandatory.
""",
                encoding="utf-8",
            )
            with self.assertRaises(SystemExit) as cm:
                self.tool.lint_worker_prompts(
                    [self.tool.WorkerSpec("AB", prompt)],
                    root,
                    root / "runs",
                    strict=True,
                )
            self.assertIn("codex_worker_prompt_lint_failed", str(cm.exception))

    def test_prompt_lint_allows_audit_worker_with_start_packet(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            prompt = root / "worker_cd_test.md"
            prompt.write_text(
                """
task.type: source-extract
## Required Start Packet
Read `docs/MCP_AUDIT_AGENT_START.md` before source work.

## Acceptance
- Review detector hits and produce a proof lane.
- Deliverable: `reports/example.md`
- Self-test mandatory.
""",
                encoding="utf-8",
            )
            rows = self.tool.lint_worker_prompts(
                [self.tool.WorkerSpec("CD", prompt)],
                root,
                root / "runs",
                strict=True,
            )
            self.assertEqual(rows["CD"]["status"], "pass")
            self.assertTrue(Path(rows["CD"]["report"]).is_file())


if __name__ == "__main__":
    unittest.main()
