#!/usr/bin/env python3
"""Tests for tools/batch-boundary-preflight.py."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "batch-boundary-preflight.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("batch_boundary_preflight", TOOL)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def completed(returncode: int = 0, stdout: str = "", stderr: str = ""):
    return subprocess.CompletedProcess(args=["python3"], returncode=returncode, stdout=stdout, stderr=stderr)


class BatchBoundaryPreflightTest(unittest.TestCase):
    def run_main(self, argv: list[str], results: list[subprocess.CompletedProcess]):
        mod = load_tool()
        stdout = io.StringIO()
        with mock.patch.object(mod.subprocess, "run", side_effect=results) as run_mock:
            with contextlib.redirect_stdout(stdout):
                exit_code = mod.main(argv)
        return exit_code, json.loads(stdout.getvalue()), run_mock

    def test_advisory_without_pr_body_runs_memory_checks_and_skips_hygiene(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            exit_code, payload, run_mock = self.run_main(
                ["--repo-root", tmp],
                [completed(stdout="mcp ok"), completed(stdout="parity ok")],
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["schema"], "auditooor.batch_boundary_preflight.v1")
        self.assertEqual(payload["mode"], "advisory")
        self.assertEqual(payload["overall_status"], "ADVISORY")
        self.assertEqual(payload["skipped_optional"], ["pr_hygiene"])
        self.assertEqual([c["key"] for c in payload["checks"]], ["memory_mcp_self_test", "memory_context_parity", "pr_hygiene"])
        self.assertEqual(run_mock.call_count, 2)
        commands = [call.args[0] for call in run_mock.call_args_list]
        self.assertEqual(commands[0], ["python3", "tools/vault-mcp-server.py", "--self-test"])
        self.assertEqual(commands[1], ["python3", "tools/memory-context-parity-check.py", "--strict"])

    def test_pr_body_runs_optional_pr_hygiene(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pr_body = Path(tmp) / "pr.md"
            exit_code, payload, run_mock = self.run_main(
                ["--repo-root", tmp, "--pr-body", str(pr_body)],
                [completed(), completed(), completed(stdout="hygiene ok")],
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["overall_status"], "READY")
        self.assertEqual(payload["skipped_optional"], [])
        self.assertEqual(run_mock.call_count, 3)
        self.assertEqual(run_mock.call_args_list[2].args[0], ["python3", "tools/pr-hygiene-check.py", str(pr_body)])

    def test_advisory_mode_reports_memory_failure_but_exits_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            exit_code, payload, _ = self.run_main(
                ["--repo-root", tmp],
                [completed(returncode=2, stderr="mcp failed"), completed()],
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["overall_status"], "BLOCKED")
        self.assertFalse(payload["exit_would_fail"])
        self.assertEqual(payload["mandatory_failures"], ["memory_mcp_self_test"])
        self.assertEqual(payload["checks"][0]["status"], "FAIL")
        self.assertEqual(payload["checks"][0]["stderr"], "mcp failed")

    def test_strict_mode_fails_when_mandatory_memory_check_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            exit_code, payload, _ = self.run_main(
                ["--repo-root", tmp, "--strict"],
                [completed(), completed(returncode=1, stderr="parity failed")],
            )

        self.assertEqual(exit_code, 1)
        self.assertTrue(payload["exit_would_fail"])
        self.assertEqual(payload["mandatory_failures"], ["memory_context_parity"])

    def test_strict_mode_does_not_fail_on_optional_pr_hygiene_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pr_body = Path(tmp) / "pr.md"
            exit_code, payload, _ = self.run_main(
                ["--repo-root", tmp, "--strict", "--pr-body", str(pr_body)],
                [completed(), completed(), completed(returncode=1, stderr="pr issue")],
            )

        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["overall_status"], "WARN")
        self.assertEqual(payload["optional_failures"], ["pr_hygiene"])
        self.assertEqual(payload["mandatory_failures"], [])

    def test_pr_strict_fails_without_pr_body(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            exit_code, payload, run_mock = self.run_main(
                ["--repo-root", tmp, "--pr-strict"],
                [completed(), completed()],
            )

        self.assertEqual(exit_code, 1)
        self.assertTrue(payload["pr_strict"])
        self.assertTrue(payload["exit_would_fail"])
        self.assertEqual(payload["overall_status"], "BLOCKED")
        self.assertEqual(payload["mandatory_failures"], ["pr_hygiene"])
        self.assertEqual(payload["checks"][2]["status"], "FAIL")
        self.assertIn("--pr-strict", payload["checks"][2]["reason"])
        self.assertEqual(run_mock.call_count, 2)

    def test_pr_strict_runs_hygiene_strict_and_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pr_body = Path(tmp) / "pr.md"
            exit_code, payload, run_mock = self.run_main(
                ["--repo-root", tmp, "--pr-strict", "--pr-body", str(pr_body)],
                [completed(), completed(), completed(returncode=1, stderr="pr issue")],
            )

        self.assertEqual(exit_code, 1)
        self.assertTrue(payload["pr_strict"])
        self.assertTrue(payload["exit_would_fail"])
        self.assertEqual(payload["overall_status"], "BLOCKED")
        self.assertEqual(payload["mandatory_failures"], ["pr_hygiene"])
        self.assertEqual(payload["checks"][2]["status"], "FAIL")
        self.assertEqual(
            run_mock.call_args_list[2].args[0],
            ["python3", "tools/pr-hygiene-check.py", str(pr_body), "--strict"],
        )

    def test_complete_pr_body_pr_strict_is_ready_and_mandatory(self) -> None:
        mod = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            pr_body = Path(tmp) / "complete-pr.md"
            pr_body.write_text(
                "\n".join(
                    [
                        "## Summary",
                        "- Add strict PR body hygiene regression coverage.",
                        "",
                        "## PR Hygiene",
                        "- exact file list: `tools/tests/test_batch_boundary_preflight.py`",
                        "- why these files belong in one slice: regression coverage is isolated to the batch-boundary preflight tests",
                        "- exact commands: `python3 -m unittest tools.tests.test_batch_boundary_preflight.BatchBoundaryPreflightTest.test_complete_pr_body_pr_strict_is_ready_and_mandatory`",
                        "- result: passed",
                        "- context_pack_id: `local-test-pack-20260506`",
                        "- context_pack_hash: `sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`",
                        "- source_refs: `tools/batch-boundary-preflight.py`, `tools/pr-hygiene-check.py`",
                        "- receipt_proof: `not needed; context pack fields present`",
                        "- excluded paths/patterns: `tools/calibration/*.jsonl`",
                        "- confirmation: no generated or local calibration outputs are included in this PR slice",
                    ]
                ),
                encoding="utf-8",
            )

            pass_check = mod.CheckSpec(
                key="stub_memory_gate",
                label="Stub memory gate",
                command=("python3", "-c", "pass"),
                mandatory=True,
            )
            stdout = io.StringIO()
            with mock.patch.object(mod, "MANDATORY_CHECKS", (pass_check,)):
                with contextlib.redirect_stdout(stdout):
                    exit_code = mod.main(["--repo-root", str(ROOT), "--pr-strict", "--pr-body", str(pr_body)])

        payload = json.loads(stdout.getvalue())
        pr_hygiene = next(check for check in payload["checks"] if check["key"] == "pr_hygiene")
        self.assertEqual(exit_code, 0)
        self.assertTrue(payload["pr_strict"])
        self.assertFalse(payload["exit_would_fail"])
        self.assertEqual(payload["overall_status"], "READY")
        self.assertEqual(payload["mandatory_failures"], [])
        self.assertEqual(payload["optional_failures"], [])
        self.assertEqual(payload["skipped_optional"], [])
        self.assertTrue(pr_hygiene["mandatory"])
        self.assertEqual(pr_hygiene["status"], "PASS")
        self.assertEqual(pr_hygiene["command"], ["python3", "tools/pr-hygiene-check.py", str(pr_body), "--strict"])


if __name__ == "__main__":
    unittest.main()
