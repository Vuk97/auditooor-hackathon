"""Tests for auditooor_mcp_token.py (PR #658 commit 2)."""
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools"))

from auditooor_mcp_token import (
    issue_token,
    verify_token,
    refresh_token,
    decode_token,
    DEFAULT_TTL_SECONDS,
    SERVICE_ACCOUNT_TTL_SECONDS,
    TOKEN_VERSION,
)


class TestMcpTokenPrimitive(unittest.TestCase):
    def setUp(self):
        # Use a stable secret for test reproducibility
        os.environ["AUDITOOOR_MCP_SECRET"] = "test-secret-do-not-use-in-prod-32-bytes"
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        # Clear env
        os.environ.pop("AUDITOOOR_MCP_SECRET", None)

    def test_issue_and_verify_round_trip(self):
        token, payload = issue_token(self.tmp, log=False)
        self.assertTrue(token)
        self.assertIn(".", token)
        valid, err, vpayload = verify_token(token)
        self.assertTrue(valid, f"valid expected, error: {err}")
        self.assertEqual(vpayload["sid"], payload["sid"])
        self.assertEqual(vpayload["v"], TOKEN_VERSION)
        self.assertEqual(vpayload["owner"], "claude")

    def test_default_ttl_4h(self):
        token, payload = issue_token(self.tmp, log=False)
        self.assertEqual(payload["exp"] - payload["iat"], DEFAULT_TTL_SECONDS)
        self.assertEqual(DEFAULT_TTL_SECONDS, 4 * 3600)

    def test_service_account_ttl_24h(self):
        token, payload = issue_token(self.tmp, ttl_seconds=SERVICE_ACCOUNT_TTL_SECONDS, owner="service-account", log=False)
        self.assertEqual(payload["exp"] - payload["iat"], 24 * 3600)
        self.assertEqual(payload["owner"], "service-account")

    def test_invalid_owner_raises(self):
        with self.assertRaises(ValueError):
            issue_token(self.tmp, owner="not-an-allowed-owner", log=False)

    def test_signature_mismatch_rejected(self):
        token, _ = issue_token(self.tmp, log=False)
        # Tamper with signature
        head, _ = token.rsplit(".", 1)
        tampered = head + ".dGFtcGVyZWQ"
        valid, err, _ = verify_token(tampered)
        self.assertFalse(valid)
        self.assertIn("signature", err)

    def test_expired_token_rejected(self):
        # Issue with negative TTL (already expired)
        token, payload = issue_token(self.tmp, ttl_seconds=-1, log=False)
        valid, err, _ = verify_token(token)
        self.assertFalse(valid)
        self.assertIn("expired", err)

    def test_secret_change_invalidates_token(self):
        token, _ = issue_token(self.tmp, log=False)
        os.environ["AUDITOOOR_MCP_SECRET"] = "different-secret-now-tokens-invalid"
        valid, err, _ = verify_token(token)
        self.assertFalse(valid)
        self.assertIn("signature", err)

    def test_malformed_token_rejected(self):
        for bad in ["", "no-dot", ".", "abc.def.ghi"]:
            valid, err, _ = verify_token(bad)
            self.assertFalse(valid, f"bad token {bad!r} should fail")

    def test_unsupported_version_rejected(self):
        # Manually craft a v999 token to test
        import json, base64, hmac, hashlib
        bad_payload = {"v": 999, "sid": "abc", "ws": self.tmp, "owner": "claude", "iat": int(time.time()), "exp": int(time.time()) + 3600, "scope": ["read"]}
        pb = json.dumps(bad_payload, sort_keys=True, separators=(",", ":")).encode()
        sig = hmac.new(b"test-secret-do-not-use-in-prod-32-bytes", pb, hashlib.sha256).digest()
        token = base64.urlsafe_b64encode(pb).rstrip(b"=").decode() + "." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
        valid, err, _ = verify_token(token)
        self.assertFalse(valid)
        self.assertIn("version", err)

    def test_scope_check(self):
        token, _ = issue_token(self.tmp, scope=["read"], log=False)
        valid, err, _ = verify_token(token, require_scope="read")
        self.assertTrue(valid)
        valid, err, _ = verify_token(token, require_scope="write")
        self.assertFalse(valid)
        self.assertIn("scope", err)

    def test_workspace_check(self):
        token, _ = issue_token(self.tmp, log=False)
        # Same workspace ok
        valid, err, _ = verify_token(token, require_workspace=self.tmp)
        self.assertTrue(valid, f"err={err}")
        # Different workspace rejected
        with tempfile.TemporaryDirectory() as other_ws:
            valid, err, _ = verify_token(token, require_workspace=other_ws)
            self.assertFalse(valid)
            self.assertIn("workspace mismatch", err)

    def test_refresh_token(self):
        token1, payload1 = issue_token(self.tmp, log=False)
        token2 = refresh_token(token1)
        self.assertIsNotNone(token2)
        self.assertNotEqual(token1, token2)
        valid, err, payload2 = verify_token(token2)
        self.assertTrue(valid)
        self.assertEqual(payload2["ws"], payload1["ws"])
        self.assertEqual(payload2["owner"], payload1["owner"])
        self.assertNotEqual(payload2["sid"], payload1["sid"])

    def test_refresh_invalid_token_returns_none(self):
        result = refresh_token("not-a-valid-token")
        self.assertIsNone(result)

    def test_decode_token_no_verification(self):
        token, payload = issue_token(self.tmp, owner="kimi", log=False)
        decoded = decode_token(token)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded["owner"], "kimi")
        self.assertEqual(decoded["v"], TOKEN_VERSION)

    def test_decode_handles_garbage(self):
        self.assertIsNone(decode_token(""))
        self.assertIsNone(decode_token("garbage"))
        self.assertIsNone(decode_token("a.b"))

    def test_logging_writes_jsonl(self):
        with tempfile.TemporaryDirectory() as tmp:
            token, _ = issue_token(tmp, log=True, owner="kimi")
            log_file = pathlib.Path(tmp) / ".auditooor" / "mcp_session_tokens.jsonl"
            self.assertTrue(log_file.is_file(), "log file should be created")
            content = log_file.read_text()
            import json
            for line in content.strip().split("\n"):
                rec = json.loads(line)
                self.assertEqual(rec["schema"], "auditooor.mcp_session_token.v1")
                self.assertEqual(rec["owner"], "kimi")
                self.assertIn("token_short", rec)
                # Full token should NOT be in log
                self.assertNotIn(token, content)

    def test_no_log_flag_skips_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            issue_token(tmp, log=False)
            log_file = pathlib.Path(tmp) / ".auditooor" / "mcp_session_tokens.jsonl"
            self.assertFalse(log_file.is_file())


class TestMcpTokenCLI(unittest.TestCase):
    def setUp(self):
        os.environ["AUDITOOOR_MCP_SECRET"] = "cli-test-secret-32-bytes-of-content"
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        os.environ.pop("AUDITOOOR_MCP_SECRET", None)

    def _run(self, *args):
        return subprocess.run(
            ["python3", str(REPO / "tools" / "auditooor_mcp_token.py"), *args],
            capture_output=True,
            text=True,
            env={**os.environ},
        )

    def test_cli_issue_and_verify(self):
        proc = self._run("issue", "--workspace", self.tmp, "--no-log")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        token = proc.stdout.strip()
        self.assertIn(".", token)

        proc = self._run("verify", token)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("valid=True", proc.stdout)

    def test_cli_service_account_24h(self):
        proc = self._run("issue", "--workspace", self.tmp, "--service-account", "--no-log", "--json")
        self.assertEqual(proc.returncode, 0)
        import json
        data = json.loads(proc.stdout)
        self.assertEqual(data["payload"]["owner"], "service-account")
        self.assertEqual(data["payload"]["exp"] - data["payload"]["iat"], 24 * 3600)

    def test_cli_info_decodes_without_verify(self):
        proc = self._run("issue", "--workspace", self.tmp, "--no-log")
        token = proc.stdout.strip()
        proc = self._run("info", token)
        self.assertEqual(proc.returncode, 0)
        import json
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["v"], TOKEN_VERSION)


if __name__ == "__main__":
    unittest.main()
