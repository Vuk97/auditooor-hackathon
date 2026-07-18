"""Wave-6 E-2: tests for the freshness gate extension in auditooor_mcp_token.py.

Tests:
1. --verify --token <bad> returns rc=1 (baseline sanity).
2. --verify --token <good> --require-recent-recall returns rc=1 when no recall file.
3. Same but with fresh recall returns rc=0.
4. Stale recall returns rc=1.
5. Python API: verify_token(..., require_recent_recall=True) with no ws resolves via env.
6. Custom AUDITOOOR_RECALL_MAX_AGE_S tightens the window.
7. Bypass log entry written on freshness failure.
"""
import json
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
    DEFAULT_RECALL_MAX_AGE_S,
    MCP_RECALL_SENTINEL,
    BYPASS_LOG_RELATIVE,
)

TOKEN_TOOL = REPO / "tools" / "auditooor_mcp_token.py"

TEST_SECRET = "freshness-test-secret-exactly-32-bytes"


def _issue_cli(workspace: str, ttl: int = 14400) -> str:
    """Issue a token via CLI and return the token string."""
    proc = subprocess.run(
        [
            "python3", str(TOKEN_TOOL), "issue",
            "--workspace", workspace,
            "--no-log",
            "--ttl", str(ttl),
        ],
        capture_output=True, text=True,
        env={**os.environ, "AUDITOOOR_MCP_SECRET": TEST_SECRET},
    )
    assert proc.returncode == 0, f"issue failed: {proc.stderr}"
    return proc.stdout.strip()


def _verify_cli(*extra_args, token: str, env: dict = None) -> subprocess.CompletedProcess:
    """Run the verify subcommand with optional extra args."""
    base_env = {**os.environ, "AUDITOOOR_MCP_SECRET": TEST_SECRET}
    if env:
        base_env.update(env)
    return subprocess.run(
        ["python3", str(TOKEN_TOOL), "verify", token, *extra_args],
        capture_output=True, text=True,
        env=base_env,
    )


def _write_recall(ws: str, age_s: float = 0.0) -> pathlib.Path:
    """Write .auditooor/last_mcp_recall.json with given age (0=fresh)."""
    sentinel_dir = pathlib.Path(ws) / ".auditooor"
    sentinel_dir.mkdir(parents=True, exist_ok=True)
    data = {
        "context_pack_id": "test.pack.v1:resume:freshness_test",
        "context_pack_hash": "deadbeef",
        "workspace_path": ws,
        "recall_ts": time.time() - age_s,
        "recall_iso": "2026-05-11T00:00:00Z",
        "owner_tool": "TEST",
    }
    sentinel = sentinel_dir / "last_mcp_recall.json"
    sentinel.write_text(json.dumps(data, indent=2))
    return sentinel


class TestCLIBaselineSanity(unittest.TestCase):
    """Deliverable 6 assertion 1: bad token returns rc=1."""

    def setUp(self):
        os.environ["AUDITOOOR_MCP_SECRET"] = TEST_SECRET
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        os.environ.pop("AUDITOOOR_MCP_SECRET", None)

    def test_bad_token_returns_rc1(self):
        proc = _verify_cli(token="this.is.not.a.valid.token")
        self.assertEqual(proc.returncode, 1, f"stdout={proc.stdout}")
        self.assertIn("valid=False", proc.stdout)


class TestCLIRequireRecentRecall(unittest.TestCase):
    """Deliverable 6 assertions 2-4: --require-recent-recall CLI flag."""

    def setUp(self):
        os.environ["AUDITOOOR_MCP_SECRET"] = TEST_SECRET
        self.tmp = tempfile.mkdtemp()
        self.token = _issue_cli(self.tmp)

    def tearDown(self):
        os.environ.pop("AUDITOOOR_MCP_SECRET", None)
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_no_recall_file_returns_rc1(self):
        """Assertion 2: --require-recent-recall returns rc=1 when no recall file."""
        # No recall file written
        proc = _verify_cli(
            "--require-recent-recall",
            token=self.token,
            env={"AUDITOOOR_WS_ROOT": self.tmp},
        )
        self.assertEqual(proc.returncode, 1, f"stdout={proc.stdout}\nstderr={proc.stderr}")
        self.assertIn("valid=False", proc.stdout)

    def test_fresh_recall_returns_rc0(self):
        """Assertion 3: fresh recall returns rc=0."""
        _write_recall(self.tmp, age_s=0)
        proc = _verify_cli(
            "--require-recent-recall",
            token=self.token,
            env={"AUDITOOOR_WS_ROOT": self.tmp},
        )
        self.assertEqual(proc.returncode, 0, f"stdout={proc.stdout}\nstderr={proc.stderr}")
        self.assertIn("valid=True", proc.stdout)

    def test_stale_recall_returns_rc1(self):
        """Assertion 4: stale recall (>max_age) returns rc=1."""
        _write_recall(self.tmp, age_s=DEFAULT_RECALL_MAX_AGE_S + 600)
        proc = _verify_cli(
            "--require-recent-recall",
            token=self.token,
            env={"AUDITOOOR_WS_ROOT": self.tmp},
        )
        self.assertEqual(proc.returncode, 1, f"stdout={proc.stdout}\nstderr={proc.stderr}")
        self.assertIn("valid=False", proc.stdout)

    def test_without_flag_ignores_missing_recall(self):
        """Without --require-recent-recall, missing recall file is irrelevant."""
        # No recall file — should still pass (token is valid, no freshness check)
        proc = _verify_cli(token=self.token)
        self.assertEqual(proc.returncode, 0, f"stdout={proc.stdout}")
        self.assertIn("valid=True", proc.stdout)


class TestPythonAPIFreshnessGate(unittest.TestCase):
    """Assertion 5: Python API verify_token with require_recent_recall."""

    def setUp(self):
        os.environ["AUDITOOOR_MCP_SECRET"] = TEST_SECRET
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        os.environ.pop("AUDITOOOR_MCP_SECRET", None)
        os.environ.pop("AUDITOOOR_WS_ROOT", None)
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_api_fresh_recall_passes(self):
        token, _ = issue_token(self.tmp, log=False)
        _write_recall(self.tmp, age_s=0)
        os.environ["AUDITOOOR_WS_ROOT"] = self.tmp
        valid, err, payload = verify_token(token, require_recent_recall=True)
        self.assertTrue(valid, f"err={err}")
        self.assertIsNone(err)

    def test_api_stale_recall_fails(self):
        token, _ = issue_token(self.tmp, log=False)
        _write_recall(self.tmp, age_s=DEFAULT_RECALL_MAX_AGE_S + 300)
        os.environ["AUDITOOOR_WS_ROOT"] = self.tmp
        valid, err, payload = verify_token(token, require_recent_recall=True)
        self.assertFalse(valid, "stale recall should fail")
        self.assertIsNotNone(err)
        self.assertIn("stale", err.lower())

    def test_api_no_recall_file_fails(self):
        token, _ = issue_token(self.tmp, log=False)
        # No sentinel file written
        os.environ["AUDITOOOR_WS_ROOT"] = self.tmp
        valid, err, payload = verify_token(token, require_recent_recall=True)
        self.assertFalse(valid, "missing recall should fail")
        self.assertIsNotNone(err)

    def test_api_without_flag_ignores_missing_recall(self):
        """Default behavior (require_recent_recall=False) is unaffected."""
        token, _ = issue_token(self.tmp, log=False)
        # No recall file, no flag — should pass
        valid, err, payload = verify_token(token)
        self.assertTrue(valid, f"err={err}")


class TestCustomMaxAgeCLI(unittest.TestCase):
    """Assertion 6: AUDITOOOR_RECALL_MAX_AGE_S shortens window correctly."""

    def setUp(self):
        os.environ["AUDITOOOR_MCP_SECRET"] = TEST_SECRET
        self.tmp = tempfile.mkdtemp()
        self.token = _issue_cli(self.tmp)

    def tearDown(self):
        os.environ.pop("AUDITOOOR_MCP_SECRET", None)
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_80s_old_recall_rejected_with_max_age_60(self):
        _write_recall(self.tmp, age_s=80)
        proc = _verify_cli(
            "--require-recent-recall",
            token=self.token,
            env={
                "AUDITOOOR_WS_ROOT": self.tmp,
                "AUDITOOOR_RECALL_MAX_AGE_S": "60",
            },
        )
        self.assertEqual(proc.returncode, 1, f"expected reject with 80s recall and max_age=60")

    def test_40s_old_recall_passes_with_max_age_60(self):
        _write_recall(self.tmp, age_s=40)
        proc = _verify_cli(
            "--require-recent-recall",
            token=self.token,
            env={
                "AUDITOOOR_WS_ROOT": self.tmp,
                "AUDITOOOR_RECALL_MAX_AGE_S": "60",
            },
        )
        self.assertEqual(proc.returncode, 0, f"expected pass with 40s recall and max_age=60\nstdout={proc.stdout}")


class TestBypassLogOnFreshnessFailure(unittest.TestCase):
    """Assertion 7: bypass log entry written on freshness failure (Python API)."""

    def setUp(self):
        os.environ["AUDITOOOR_MCP_SECRET"] = TEST_SECRET
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        os.environ.pop("AUDITOOOR_MCP_SECRET", None)
        os.environ.pop("AUDITOOOR_WS_ROOT", None)
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_bypass_log_written_on_stale_recall(self):
        token, _ = issue_token(self.tmp, log=False)
        _write_recall(self.tmp, age_s=DEFAULT_RECALL_MAX_AGE_S + 600)
        os.environ["AUDITOOOR_WS_ROOT"] = self.tmp
        valid, err, _ = verify_token(token, require_recent_recall=True)
        self.assertFalse(valid)
        bypass_log = pathlib.Path(self.tmp) / BYPASS_LOG_RELATIVE
        self.assertTrue(bypass_log.is_file(), "bypass_log.jsonl should be written on freshness failure")
        entries = [json.loads(line) for line in bypass_log.read_text().strip().split("\n") if line.strip()]
        self.assertTrue(len(entries) > 0)
        reasons = [e.get("reason", "") for e in entries]
        self.assertTrue(
            any("stale" in r or "freshness" in r.lower() for r in reasons),
            f"Expected stale reason in bypass log; got reasons={reasons}",
        )

    def test_bypass_log_written_on_missing_recall_file(self):
        token, _ = issue_token(self.tmp, log=False)
        # No recall file
        os.environ["AUDITOOOR_WS_ROOT"] = self.tmp
        valid, err, _ = verify_token(token, require_recent_recall=True)
        self.assertFalse(valid)
        bypass_log = pathlib.Path(self.tmp) / BYPASS_LOG_RELATIVE
        self.assertTrue(bypass_log.is_file(), "bypass_log.jsonl should be written when recall missing")
        entries = [json.loads(line) for line in bypass_log.read_text().strip().split("\n") if line.strip()]
        reasons = [e.get("reason", "") for e in entries]
        self.assertTrue(
            any("no_recall_file" in r or "freshness" in r.lower() for r in reasons),
            f"Expected no_recall_file reason in bypass log; got reasons={reasons}",
        )


if __name__ == "__main__":
    unittest.main()
