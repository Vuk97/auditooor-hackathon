"""test_forever_loop_mcp_bridge.py — unit tests for tools/forever-loop-mcp-bridge.py.

PR #658 Lane 7 — Worker-B1 deliverable.

Run:
    python3 -m unittest tools.tests.test_forever_loop_mcp_bridge
"""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest


# ---------------------------------------------------------------------------
# Helpers to load the bridge module under test
# ---------------------------------------------------------------------------

def _load_bridge():
    here = pathlib.Path(__file__).parent.parent  # tools/
    spec = importlib.util.spec_from_file_location(
        "forever_loop_mcp_bridge",
        here / "forever-loop-mcp-bridge.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


BRIDGE = _load_bridge()

BRIDGE_CLI = str(pathlib.Path(__file__).parent.parent / "forever-loop-mcp-bridge.py")
HOOK_SCRIPT = str(pathlib.Path(__file__).parent.parent / "hooks" / "sessionend-forever-loop-packet.sh")


# ---------------------------------------------------------------------------
# Tests: prime subcommand
# ---------------------------------------------------------------------------

class TestPrime(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = pathlib.Path(self._tmp.name)
        # minimal .auditooor dir so auditooor_mcp_token log doesn't fail
        (self.ws / ".auditooor").mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self._tmp.cleanup()

    def _run_prime(self, ttl_hours=1):
        return BRIDGE.cmd_prime(self.ws, ttl_hours=ttl_hours)

    def test_prime_writes_file(self):
        rc = self._run_prime(ttl_hours=1)
        self.assertEqual(rc, 0)
        token_path = BRIDGE._token_path(self.ws)
        self.assertTrue(token_path.exists(), "token file should exist after prime")
        token = token_path.read_text().strip()
        self.assertTrue(len(token) > 20, "token should be non-trivial")

    def test_prime_file_mode_0600(self):
        rc = self._run_prime(ttl_hours=1)
        self.assertEqual(rc, 0)
        token_path = BRIDGE._token_path(self.ws)
        mode = oct(token_path.stat().st_mode & 0o777)
        self.assertEqual(mode, oct(0o600), f"expected mode 0600, got {mode}")

    def test_prime_stdout_does_not_contain_raw_token(self):
        """Capture stdout; verify only the 8-char hash appears, not the full token."""
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = self._run_prime(ttl_hours=1)
        self.assertEqual(rc, 0)
        output = buf.getvalue()

        token_path = BRIDGE._token_path(self.ws)
        raw_token = token_path.read_text().strip()

        self.assertNotIn(raw_token, output, "raw token must not appear in stdout")
        self.assertIn("primed", output, "stdout should contain 'primed'")
        self.assertIn("hash=", output, "stdout should contain hash= label")

    def test_prime_idempotent_skips_reissue(self):
        """Second prime call within TTL should not reissue — same token on disk."""
        rc1 = self._run_prime(ttl_hours=2)
        self.assertEqual(rc1, 0)
        token_path = BRIDGE._token_path(self.ws)
        token_after_first = token_path.read_text().strip()

        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc2 = self._run_prime(ttl_hours=2)
        self.assertEqual(rc2, 0)
        token_after_second = token_path.read_text().strip()

        self.assertEqual(token_after_first, token_after_second,
                         "idempotent prime should not rewrite a fresh token")
        self.assertIn("skipping re-issue", buf.getvalue())


# ---------------------------------------------------------------------------
# Tests: export-env subcommand
# ---------------------------------------------------------------------------

class TestExportEnv(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = pathlib.Path(self._tmp.name)
        (self.ws / ".auditooor").mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        self._tmp.cleanup()

    def test_export_env_round_trip(self):
        """prime then export-env should yield a non-empty token."""
        rc = BRIDGE.cmd_prime(self.ws, ttl_hours=2)
        self.assertEqual(rc, 0)

        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc2 = BRIDGE.cmd_export_env(self.ws)
        self.assertEqual(rc2, 0)

        output = buf.getvalue().strip()
        self.assertTrue(output.startswith("export AUDITOOOR_MCP_SESSION_TOKEN="),
                        f"unexpected output: {output[:80]!r}")
        _, token_val = output.split("=", 1)
        self.assertTrue(len(token_val) > 20, "exported token should be non-empty")

    def test_export_env_refuses_when_file_missing(self):
        """export-env without prior prime should return exit code 1."""
        rc = BRIDGE.cmd_export_env(self.ws)
        self.assertEqual(rc, 1)

    def test_export_env_refuses_when_file_expired(self):
        """Token written with ttl=0 should be refused by export-env."""
        # Issue a token that is already expired (ttl=0 → exp = now)
        mod_token = _load_auditooor_mcp_token_module()
        token, _payload = mod_token.issue_token(
            workspace_path=str(self.ws),
            ttl_seconds=0,
            owner="service-account",
            scope=["read"],
            log=False,
        )
        token_path = BRIDGE._token_path(self.ws)
        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text(token)

        rc = BRIDGE.cmd_export_env(self.ws)
        self.assertEqual(rc, 1, "export-env should refuse an expired token")


# ---------------------------------------------------------------------------
# Tests: sessionend hook
# ---------------------------------------------------------------------------

class TestSessionEndHook(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = pathlib.Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def test_sessionend_emits_parseable_json(self):
        """Hook should write a valid JSON packet to .auditooor/sessionend_packet.json."""
        env = os.environ.copy()
        env["CLAUDE_PROJECT_DIR"] = str(self.ws)

        result = subprocess.run(
            ["bash", HOOK_SCRIPT],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(result.returncode, 0, f"hook exited {result.returncode}: {result.stderr}")

        packet_path = self.ws / ".auditooor" / "sessionend_packet.json"
        self.assertTrue(packet_path.exists(), "packet file should be written")

        packet = json.loads(packet_path.read_text())
        self.assertEqual(packet["schema"], "auditooor.sessionend_packet.v1")
        self.assertIn("session_ended_at", packet)
        self.assertIn("git_head", packet)
        self.assertIn("branch", packet)
        self.assertIn("workspace", packet)
        self.assertIn("next_loop_hint", packet)
        self.assertIsInstance(packet["next_loop_hint"], str)
        self.assertTrue(len(packet["next_loop_hint"]) > 5)


# ---------------------------------------------------------------------------
# Shared helper
# ---------------------------------------------------------------------------

def _load_auditooor_mcp_token_module():
    here = pathlib.Path(__file__).parent.parent
    spec = importlib.util.spec_from_file_location(
        "auditooor_mcp_token", here / "auditooor_mcp_token.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main()
