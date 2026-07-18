"""Guard tests for the wave-3 daemon code-revision staleness stamp.

Spec (2026-06-18): the MCP daemon (vault-mcp-server.py) is a long-lived
process. After a `git pull`/merge the on-disk tool code can advance while the
running process keeps serving the OLD code, with no signal to callers.
`serverInfo.version` used to be a frozen literal "0.1.0" decoupled from the
actual revision.

Fix under test:
  1. A code-revision stamp is computed at server start and exposed in
     serverInfo.version and a `vault_daemon_version` callable.
  2. On each call() the start-time stamp is compared to the live on-disk
     stamp; when the on-disk code is NEWER, the response envelope gains
     degraded:true + a daemon_staleness_warning so callers know the result
     may be pre-fix. The daemon does NOT hot-reload code; it only signals.

Implementation note: _compute_code_revision_stamp honours the
AUDITOOOR_MCP_CODE_STAMP env override, which these tests use to deterministically
simulate "a newer on-disk stamp" without mutating git state.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "vault_mcp_server_daemon_version_test", MODULE_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module()


def _vault_dir() -> Path:
    vault_dir = REPO_ROOT / "obsidian-vault"
    if not vault_dir.exists():
        vault_dir = Path.home() / "Documents" / "Codex" / "auditooor" / "obsidian-vault"
    return vault_dir


class DaemonVersionStampTests(unittest.TestCase):
    """The daemon stamps its code revision and exposes it."""

    def setUp(self) -> None:
        os.environ["AUDITOOOR_MCP_TELEMETRY_DISABLE"] = "1"
        # Pin a known start stamp so the process is deterministic.
        os.environ["AUDITOOOR_MCP_CODE_STAMP"] = "git:aaaaaaaaaaaa"
        self.server = vault_mcp_server.VaultQuery(_vault_dir(), REPO_ROOT)

    def tearDown(self) -> None:
        os.environ.pop("AUDITOOOR_MCP_CODE_STAMP", None)

    def test_version_is_not_frozen_literal(self) -> None:
        """serverInfo.version embeds the live stamp, not a bare '0.1.0'."""
        info = self.server.daemon_version_info()
        self.assertNotEqual(info["version"], "0.1.0")
        self.assertIn("0.1.0", info["version"])  # base is preserved
        self.assertIn(self.server.start_code_stamp, info["version"])

    def test_initialize_serverinfo_carries_stamp(self) -> None:
        """The initialize handshake reports the stamped version."""
        resp = vault_mcp_server.handle_request(
            self.server, {"id": 1, "method": "initialize"}
        )
        version = resp["result"]["serverInfo"]["version"]
        self.assertEqual(
            version, vault_mcp_server._daemon_version_string(self.server.start_code_stamp)
        )
        self.assertNotEqual(version, "0.1.0")

    def test_vault_daemon_version_callable(self) -> None:
        """The explicit callable returns the stamp + verdict schema."""
        out = self.server.call("vault_daemon_version", {})
        self.assertEqual(out["schema"], "auditooor.vault_daemon_version.v1")
        self.assertEqual(out["start_code_stamp"], "git:aaaaaaaaaaaa")
        self.assertIn("stale", out)
        self.assertIn("current_code_stamp", out)

    def test_compute_stamp_never_empty(self) -> None:
        """The stamp helper always returns a non-empty string (fail-open)."""
        os.environ.pop("AUDITOOOR_MCP_CODE_STAMP", None)
        stamp = vault_mcp_server._compute_code_revision_stamp(REPO_ROOT)
        self.assertIsInstance(stamp, str)
        self.assertTrue(stamp)


class DaemonStalenessSignalTests(unittest.TestCase):
    """When on-disk code advances past the running process, callers are warned."""

    def setUp(self) -> None:
        os.environ["AUDITOOOR_MCP_TELEMETRY_DISABLE"] = "1"
        # Start the daemon at an OLD stamp.
        os.environ["AUDITOOOR_MCP_CODE_STAMP"] = "git:000000000000"
        self.server = vault_mcp_server.VaultQuery(_vault_dir(), REPO_ROOT)
        self.assertEqual(self.server.start_code_stamp, "git:000000000000")

    def tearDown(self) -> None:
        os.environ.pop("AUDITOOOR_MCP_CODE_STAMP", None)

    def test_fresh_daemon_has_no_staleness_warning(self) -> None:
        """When on-disk == start, no degraded flag is injected."""
        # on-disk stamp still equals the start stamp (env unchanged).
        result = self.server.call("vault_engagement_status", {})
        self.assertIsInstance(result, dict)
        self.assertNotIn("daemon_staleness_warning", result)
        self.assertNotIn("degraded", result)

    def test_newer_on_disk_stamp_triggers_warning(self) -> None:
        """Simulate a newer on-disk stamp -> envelope gains the warning."""
        # The process started at git:000...; now the on-disk code "advances".
        os.environ["AUDITOOOR_MCP_CODE_STAMP"] = "git:ffffffffffff"
        result = self.server.call("vault_engagement_status", {})
        self.assertIsInstance(result, dict)
        self.assertTrue(result.get("degraded"))
        warn = result.get("daemon_staleness_warning")
        self.assertIsInstance(warn, dict)
        self.assertEqual(warn["status"], "daemon-stale-restart-required")
        self.assertEqual(warn["start_code_stamp"], "git:000000000000")
        self.assertEqual(warn["current_code_stamp"], "git:ffffffffffff")
        self.assertIn("restart", warn["detail"].lower())

    def test_vault_daemon_version_reports_stale(self) -> None:
        """The explicit callable also flips stale/degraded when on-disk newer."""
        os.environ["AUDITOOOR_MCP_CODE_STAMP"] = "git:ffffffffffff"
        out = self.server.call("vault_daemon_version", {})
        self.assertTrue(out["stale"])
        self.assertTrue(out["degraded"])
        self.assertEqual(out["warning"], "daemon-stale-restart-required")

    def test_staleness_does_not_clobber_existing_warning(self) -> None:
        """A method-body daemon_staleness_warning is preserved (setdefault)."""
        os.environ["AUDITOOOR_MCP_CODE_STAMP"] = "git:ffffffffffff"
        sentinel = {"status": "from-body"}
        original_dispatch = self.server._dispatch

        def patched_dispatch(name: str, args: dict[str, Any]) -> dict[str, Any]:
            return {"daemon_staleness_warning": sentinel, "ok": True}

        self.server._dispatch = patched_dispatch  # type: ignore[assignment]
        try:
            result = self.server.call("vault_engagement_status", {})
        finally:
            self.server._dispatch = original_dispatch  # type: ignore[assignment]
        self.assertEqual(result["daemon_staleness_warning"], sentinel)
        # degraded is still raised even when the warning body was preserved.
        self.assertTrue(result.get("degraded"))


if __name__ == "__main__":
    unittest.main()
