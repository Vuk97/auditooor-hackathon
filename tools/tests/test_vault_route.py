"""Regression test: ``vault_route`` MCP call picks the right pack.

Covers the 4 routing branches:
  1. explicit ``intent`` passes through
  2. keyword-based routing for each of the 4 pack types
  3. artifact-extension-based routing (.t.sol / _test.go / rust test)
  4. default fallback → vault_resume_context

Stdlib-only, offline-safe, deterministic. Strips the
``[vault-mcp-server] ...`` banner before parsing JSON.
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _call(payload: dict) -> dict:
    proc = subprocess.run(
        [
            sys.executable,
            str(SERVER),
            "--call",
            "vault_route",
            "--args",
            json.dumps(payload),
        ],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"vault_route exited {proc.returncode}; stderr={proc.stderr[-1000:]!r}"
        )
    body_lines = [
        line for line in proc.stdout.splitlines() if not line.startswith("[vault-mcp-server]")
    ]
    body = "\n".join(body_lines).strip()
    return json.loads(body)


class VaultRouteRegressionTest(unittest.TestCase):
    workspace = str(REPO_ROOT)

    def test_explicit_intent_passes_through(self) -> None:
        for intent, expected in (
            ("resume", "vault_resume_context"),
            ("exploit", "vault_exploit_context"),
            ("harness", "vault_harness_context"),
            ("gap", "vault_knowledge_gap_context"),
        ):
            with self.subTest(intent=intent):
                result = _call({"workspace_path": self.workspace, "intent": intent})
                self.assertEqual(result.get("routed_pack"), expected)
                self.assertIn(intent, result.get("reasoning", ""))

    def test_keyword_routing_for_each_pack(self) -> None:
        cases = [
            (["exploit", "submit"], "vault_exploit_context"),
            (["paste-ready"], "vault_exploit_context"),
            (["harness", "replay"], "vault_harness_context"),
            (["blocker", "tool-failure"], "vault_harness_context"),
            (["gap", "missing"], "vault_knowledge_gap_context"),
            (["closeout", "oos"], "vault_knowledge_gap_context"),
        ]
        for kws, expected in cases:
            with self.subTest(task_keywords=kws):
                result = _call({"workspace_path": self.workspace, "task_keywords": kws})
                self.assertEqual(
                    result.get("routed_pack"),
                    expected,
                    msg=f"keywords={kws!r} reasoning={result.get('reasoning')!r}",
                )

    def test_artifact_extension_routing(self) -> None:
        cases = [
            ["foo.t.sol"],
            ["pkg/baz_test.go"],
            ["crates/x/tests/y.rs"],
        ]
        for artifacts in cases:
            with self.subTest(recent_artifacts=artifacts):
                result = _call(
                    {"workspace_path": self.workspace, "recent_artifacts": artifacts}
                )
                self.assertEqual(
                    result.get("routed_pack"),
                    "vault_exploit_context",
                    msg=f"artifacts={artifacts!r} reasoning={result.get('reasoning')!r}",
                )

    def test_default_fallback(self) -> None:
        result = _call({"workspace_path": self.workspace})
        self.assertEqual(result.get("routed_pack"), "vault_resume_context")
        self.assertIn("default", result.get("reasoning", "").lower())


if __name__ == "__main__":
    unittest.main()
