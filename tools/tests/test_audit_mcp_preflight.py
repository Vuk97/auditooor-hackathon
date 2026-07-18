from __future__ import annotations

import importlib.util
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO / "tools" / "audit-mcp-preflight.py"
TOKEN_SECRET = "audit-mcp-preflight-test-secret"

sys.path.insert(0, str(REPO / "tools"))
from auditooor_mcp_token import BYPASS_LOG_RELATIVE, issue_token


def _load_tool():
    spec = importlib.util.spec_from_file_location("audit_mcp_preflight", TOOL_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


preflight = _load_tool()


def _write_recall(workspace: Path, *, age_s: float = 0.0) -> None:
    out = workspace / ".auditooor" / "last_mcp_recall.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "context_pack_id": "auditooor.vault_context_pack.v1:resume:test",
        "context_pack_hash": "f" * 64,
        "workspace_path": str(workspace),
        "recall_ts": time.time() - age_s,
        "recall_iso": "2026-05-21T00:00:00Z",
        "owner_tool": "TEST",
    }
    out.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class TestAuditMcpPreflight(unittest.TestCase):
    def setUp(self) -> None:
        os.environ["AUDITOOOR_MCP_SECRET"] = TOKEN_SECRET
        self.tmp = tempfile.TemporaryDirectory(prefix="audit-mcp-preflight-")
        self.workspace = Path(self.tmp.name) / "ws"
        self.workspace.mkdir()

    def tearDown(self) -> None:
        os.environ.pop("AUDITOOOR_MCP_SECRET", None)
        os.environ.pop("AUDITOOOR_WS_ROOT", None)
        self.tmp.cleanup()

    def test_missing_token_fails_with_next_commands(self) -> None:
        report = preflight.build_report(self.workspace, token="", required_scope="read")
        self.assertFalse(report["ok"])
        self.assertEqual(report["status"], "fail")
        self.assertIn("AUDITOOOR_MCP_SESSION_TOKEN missing", report["error"])
        self.assertTrue(report["privacy_guards"]["token_redacted"])
        self.assertTrue(any("auditooor_mcp_token.py issue" in cmd for cmd in report["next_commands"]))

    def test_next_commands_quote_workspace_paths(self) -> None:
        workspace = Path(self.tmp.name) / "ws with spaces"
        workspace.mkdir()
        report = preflight.build_report(workspace, token="", required_scope="read")
        workspace_arg = shlex.quote(str(workspace.resolve()))
        self.assertTrue(report["next_commands"])
        for cmd in report["next_commands"]:
            self.assertIn(workspace_arg, cmd)

    def test_valid_workspace_bound_token_passes_without_recall_requirement(self) -> None:
        token, _ = issue_token(str(self.workspace), scope=["read"], log=False)
        report = preflight.build_report(
            self.workspace,
            token=token,
            required_scope="read",
            require_recent_recall=False,
        )
        self.assertTrue(report["ok"], report)
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["payload"]["workspace"], str(self.workspace.resolve()))
        self.assertNotIn(token, json.dumps(report))

    def test_recent_recall_requirement_passes_with_fresh_sentinel(self) -> None:
        token, _ = issue_token(str(self.workspace), scope=["read"], log=False)
        _write_recall(self.workspace, age_s=1)
        report = preflight.build_report(
            self.workspace,
            token=token,
            required_scope="read",
            require_recent_recall=True,
        )
        self.assertTrue(report["ok"], report)

    def test_recent_recall_requirement_fails_closed_and_logs_bypass(self) -> None:
        token, _ = issue_token(str(self.workspace), scope=["read"], log=False)
        _write_recall(self.workspace, age_s=999999)
        report = preflight.build_report(
            self.workspace,
            token=token,
            required_scope="read",
            require_recent_recall=True,
        )
        self.assertFalse(report["ok"])
        self.assertIn("recall freshness", report["error"])
        self.assertTrue((self.workspace / BYPASS_LOG_RELATIVE).is_file())
        self.assertTrue(any("auditooor-session-start.sh" in cmd for cmd in report["next_commands"]))

    def test_wrong_workspace_token_is_rejected(self) -> None:
        other = Path(self.tmp.name) / "other"
        other.mkdir()
        token, _ = issue_token(str(other), scope=["read"], log=False)
        report = preflight.build_report(
            self.workspace,
            token=token,
            required_scope="read",
            require_recent_recall=False,
        )
        self.assertFalse(report["ok"])
        self.assertIn("workspace mismatch", report["error"])

    def test_cli_json_exit_codes(self) -> None:
        token, _ = issue_token(str(self.workspace), scope=["read"], log=False)
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL_PATH),
                "--workspace",
                str(self.workspace),
                "--scope",
                "read",
                "--token",
                token,
                "--json",
            ],
            cwd=REPO,
            capture_output=True,
            text=True,
            env={**os.environ, "AUDITOOOR_MCP_SECRET": TOKEN_SECRET},
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(json.loads(proc.stdout)["ok"])

        missing = subprocess.run(
            [sys.executable, str(TOOL_PATH), "--workspace", str(self.workspace), "--json"],
            cwd=REPO,
            capture_output=True,
            text=True,
            env={**os.environ, "AUDITOOOR_MCP_SECRET": TOKEN_SECRET, "AUDITOOOR_MCP_SESSION_TOKEN": ""},
            check=False,
        )
        self.assertEqual(missing.returncode, 1)
        self.assertFalse(json.loads(missing.stdout)["ok"])


class TestAuditDeepMakefileMcpPreflight(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if not shutil.which("make"):
            raise unittest.SkipTest("make not on PATH")

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="audit-deep-mcp-make-")
        self.workspace = Path(self.tmp.name) / "ws"
        self.workspace.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _make_dry(self, *extra: str, skip_audit: bool = True) -> subprocess.CompletedProcess[str]:
        args = ["make", "-n", "audit-deep", f"WS={self.workspace}"]
        if skip_audit:
            args.append("AUDIT_DEEP_SKIP_AUDIT_PREREQ=1")
        args.extend(extra)
        return subprocess.run(
            args,
            cwd=REPO,
            capture_output=True,
            text=True,
            env={**os.environ, "HOME": self.tmp.name},
            timeout=60,
            check=False,
        )

    def test_audit_deep_does_not_preflight_by_default(self) -> None:
        proc = self._make_dry()
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("audit-mcp-preflight.py", proc.stdout)

    def test_audit_deep_preflight_disabled_by_explicit_zeroes(self) -> None:
        cases = [
            ("AUDIT_DEEP_REQUIRE_MCP_PREFLIGHT=0",),
            ("REQUIRE_MCP_CONTEXT=0",),
            ("AUDIT_DEEP_REQUIRE_MCP_PREFLIGHT=0", "REQUIRE_MCP_CONTEXT=0"),
        ]
        for extra in cases:
            with self.subTest(extra=extra):
                proc = self._make_dry(*extra)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertNotIn("audit-mcp-preflight.py", proc.stdout)

    def test_audit_deep_preflight_is_opt_in_gate(self) -> None:
        proc = self._make_dry("AUDIT_DEEP_REQUIRE_MCP_PREFLIGHT=1")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("tools/audit-mcp-preflight.py", proc.stdout)
        self.assertIn("--require-recent-recall", proc.stdout)
        self.assertLess(
            proc.stdout.index("tools/audit-mcp-preflight.py"),
            proc.stdout.index("bypassing 'audit' prerequisite"),
        )

    def test_audit_deep_preflight_runs_before_audit_when_enabled(self) -> None:
        proc = self._make_dry("REQUIRE_MCP_CONTEXT=yes", "DRY_RUN=1", "FORCE=1", skip_audit=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("tools/audit-mcp-preflight.py", proc.stdout)
        self.assertIn("make --no-print-directory audit", proc.stdout)
        self.assertLess(
            proc.stdout.index("tools/audit-mcp-preflight.py"),
            proc.stdout.index("make --no-print-directory audit"),
        )

    def test_audit_deep_requires_workspace_before_inline_preflight(self) -> None:
        proc = subprocess.run(
            [
                "make",
                "audit-deep",
                "REQUIRE_MCP_CONTEXT=yes",
                "AUDIT_DEEP_SKIP_AUDIT_PREREQ=1",
            ],
            cwd=REPO,
            capture_output=True,
            text=True,
            env={**os.environ, "HOME": self.tmp.name},
            timeout=60,
            check=False,
        )
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("Usage: make audit-deep WS=<workspace>", proc.stdout)
        self.assertNotIn('--workspace ""', proc.stdout)
        self.assertNotIn("audit-mcp-preflight.py", proc.stdout)

    def test_audit_run_full_preflights_before_intake_truth(self) -> None:
        makefile = (REPO / "Makefile").read_text(encoding="utf-8")
        self.assertIn("audit-run-full: export AUDITOOOR_MCP_SESSION_TOKEN", makefile)
        self.assertIn("tools/auditooor_mcp_token.py issue", makefile)
        self.assertIn("tools/audit-mcp-preflight.py", makefile)
        self.assertIn("stage\":\"mcp-preflight", makefile)
        self.assertIn("deep_engine_skip_reason\":\"mcp_preflight_failed", makefile)
        self.assertLess(
            makefile.index("tools/audit-mcp-preflight.py"),
            makefile.index("stage\":\"intake-truth"),
        )


if __name__ == "__main__":
    unittest.main()
