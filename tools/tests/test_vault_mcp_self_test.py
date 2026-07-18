"""Regression test: `vault-mcp-server.py --self-test` exits 0 and the
follow-up `vault_resume_context` call returns a non-empty `context_pack_id`.

This guards CISS-002 / SPARK-FIX-004: the self-test must keep passing as a
first-class regression invariant, AND a real workspace `vault_resume_context`
recall must keep returning a usable pack id (so a fixture-only fix that
silently broke the live recall path would still fail this test).

Stdlib-only, offline-safe, deterministic.
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER = REPO_ROOT / "tools" / "vault-mcp-server.py"


class VaultMcpSelfTestRegressionTest(unittest.TestCase):
    def test_self_test_exits_zero(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(SERVER), "--self-test"],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(
            proc.returncode,
            0,
            msg=(
                "vault-mcp self-test must exit 0 (CISS-002 regression). "
                f"stdout={proc.stdout[-2000:]!r} stderr={proc.stderr[-2000:]!r}"
            ),
        )
        self.assertIn("SELF-TEST PASS", proc.stdout + proc.stderr)

    def test_resume_context_returns_pack_id(self) -> None:
        """A real `vault_resume_context` call must return a non-empty
        `context_pack_id`. The server emits a `[vault-mcp-server] ...`
        banner line on stderr and/or stdout before the JSON payload; we
        tolerate that by stripping any line that begins with the banner
        prefix before parsing JSON."""
        args = json.dumps(
            {
                "workspace_path": str(REPO_ROOT),
                "limit": 2,
            }
        )
        proc = subprocess.run(
            [
                sys.executable,
                str(SERVER),
                "--call",
                "vault_resume_context",
                "--args",
                args,
            ],
            cwd=REPO_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(
            proc.returncode,
            0,
            msg=(
                "vault_resume_context call must exit 0. "
                f"stdout={proc.stdout[-2000:]!r} stderr={proc.stderr[-2000:]!r}"
            ),
        )
        body_lines = [
            line
            for line in proc.stdout.splitlines()
            if not line.startswith("[vault-mcp-server]")
        ]
        body = "\n".join(body_lines).strip()
        self.assertTrue(body, msg=f"empty payload after banner strip; raw stdout={proc.stdout!r}")
        try:
            payload = json.loads(body)
        except json.JSONDecodeError as e:
            self.fail(f"vault_resume_context payload is not valid JSON: {e}; body={body[:2000]!r}")
        self.assertIsInstance(payload, dict)
        pack_id = payload.get("context_pack_id")
        self.assertTrue(
            isinstance(pack_id, str) and pack_id.strip(),
            msg=f"context_pack_id missing or empty; payload keys={list(payload)!r}",
        )
        # Sanity: pack hash should also be non-empty when the id is set.
        pack_hash = payload.get("context_pack_hash")
        self.assertTrue(
            isinstance(pack_hash, str) and pack_hash.strip(),
            msg=f"context_pack_hash missing or empty; pack_id={pack_id!r}",
        )


if __name__ == "__main__":
    unittest.main()
