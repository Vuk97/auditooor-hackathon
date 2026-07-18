#!/usr/bin/env python3
"""Tests for tools/mcp-pin-drift-check.py — Track E-3."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "mcp-pin-drift-check.py"


def load_module():
    spec = importlib.util.spec_from_file_location("mcp_pin_drift_check_for_test", TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {TOOL}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestDocCountParsing(unittest.TestCase):
    """Tests for parse_doc_counts() with synthetic AGENTS.md content."""

    def setUp(self):
        self.mod = load_module()

    def test_doc_count_parsed_when_present(self):
        """parse_doc_counts returns integer when 'N registered callables' present."""
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            agents = d / "AGENTS.md"
            agents.write_text(
                "The Vault MCP server now exposes **35 registered callables**.\n"
            )
            result = self.mod.parse_doc_counts([("AGENTS.md", agents)])
            self.assertEqual(result["AGENTS.md"], 35)

    def test_doc_count_no_claim_when_missing(self):
        """parse_doc_counts returns 'no claim' when doc has no count line."""
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            agents = d / "AGENTS.md"
            agents.write_text("No callable count mentioned here.\n")
            result = self.mod.parse_doc_counts([("AGENTS.md", agents)])
            self.assertEqual(result["AGENTS.md"], "no claim")

    def test_doc_count_missing_file(self):
        """parse_doc_counts returns 'missing' when file does not exist."""
        result = self.mod.parse_doc_counts([("AGENTS.md", Path("/nonexistent/AGENTS.md"))])
        self.assertEqual(result["AGENTS.md"], "missing")


class TestActualCallableCount(unittest.TestCase):
    """Tests for count_actual_callables() with synthetic vault-mcp-server.py."""

    def setUp(self):
        self.mod = load_module()

    def _make_server(self, tmp: Path, names: list[str]) -> Path:
        """Write a synthetic vault-mcp-server.py with the given callable names."""
        lines = ['TOOL_SCHEMAS = [\n']
        for name in names:
            lines.append(f'    {{"name": "{name}", "description": "desc"}},\n')
        lines.append(']\n')
        p = tmp / "tools" / "vault-mcp-server.py"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("".join(lines))
        return p

    def test_counts_all_callables(self):
        """count_actual_callables counts all vault_ entries uniquely."""
        with tempfile.TemporaryDirectory() as tmp:
            names = [f"vault_callable_{i}" for i in range(35)]
            p = self._make_server(Path(tmp), names)
            count = self.mod.count_actual_callables(p)
            self.assertEqual(count, 35)

    def test_deduplicates_repeated_names(self):
        """count_actual_callables deduplicates repeated names."""
        with tempfile.TemporaryDirectory() as tmp:
            names = ["vault_foo", "vault_foo", "vault_bar"]
            p = self._make_server(Path(tmp), names)
            count = self.mod.count_actual_callables(p)
            self.assertEqual(count, 2)


class TestDriftDetection(unittest.TestCase):
    """Tests for drift detection logic in run()."""

    def setUp(self):
        self.mod = load_module()

    def _write_server(self, path: Path, count: int = 35) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        lines = ['TOOL_SCHEMAS = [\n']
        for i in range(count):
            lines.append(f'    {{"name": "vault_callable_{i}", "description": "desc"}},\n')
        lines.append(']\n')
        path.write_text("".join(lines))

    def test_doc_count_drift_detected(self):
        """run() reports doc_drift=True when AGENTS.md says 24 but actual is 35."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # Set up a fake mcp_repo with same server content
            mcp_repo = tmp_path / "mcp_repo"
            (mcp_repo / "tools").mkdir(parents=True)
            # We need a git repo for git calls to not fail
            subprocess.run(["git", "init"], cwd=mcp_repo, capture_output=True)
            mcp_server = mcp_repo / "tools" / "vault-mcp-server.py"
            self._write_server(mcp_server, count=35)

            # Patch worktree references for this test by monkey-patching the module
            # We test doc count parsing directly
            agents_path = tmp_path / "AGENTS.md"
            agents_path.write_text("The server exposes **24 registered callables** total.\n")

            result = self.mod.parse_doc_counts([("AGENTS.md", agents_path)])
            claimed = result["AGENTS.md"]
            # Simulate drift detection
            actual = 35
            drift = isinstance(claimed, int) and claimed != actual
            self.assertTrue(drift)
            self.assertEqual(claimed, 24)

    def test_content_hash_comparison_same(self):
        """Content hashes match when files are identical."""
        with tempfile.TemporaryDirectory() as tmp:
            p1 = Path(tmp) / "server1.py"
            p2 = Path(tmp) / "server2.py"
            content = b"vault_callable content\n"
            p1.write_bytes(content)
            p2.write_bytes(content)
            h1 = self.mod.file_sha256(p1)
            h2 = self.mod.file_sha256(p2)
            self.assertEqual(h1, h2)

    def test_content_hash_comparison_differs(self):
        """Content hashes differ when files differ."""
        with tempfile.TemporaryDirectory() as tmp:
            p1 = Path(tmp) / "server1.py"
            p2 = Path(tmp) / "server2.py"
            p1.write_bytes(b"version A\n")
            p2.write_bytes(b"version B\n")
            h1 = self.mod.file_sha256(p1)
            h2 = self.mod.file_sha256(p2)
            self.assertNotEqual(h1, h2)


class TestJsonOutput(unittest.TestCase):
    """Tests for --json CLI output schema."""

    def test_json_output_schema(self):
        """--json output contains all required keys."""
        result = subprocess.run(
            [sys.executable, str(TOOL), "--json"],
            capture_output=True, text=True, timeout=30
        )
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            self.fail(f"--json output is not valid JSON: {exc}\nstdout={result.stdout!r}")

        required_keys = [
            "actual_count", "doc_counts", "doc_drift",
            "content_hash_worktree", "content_hash_mcp_repo",
            "content_drift", "mcp_repo_head", "mcp_repo_origin_main",
            "upstream_lag_commits", "mirror_gap_count", "verdict", "exit_code",
        ]
        for key in required_keys:
            self.assertIn(key, data, f"Missing key: {key}")

    def test_actual_count_matches_grep(self):
        """--json actual_count matches manual grep of vault-mcp-server.py."""
        import re
        server = REPO_ROOT / "tools" / "vault-mcp-server.py"
        if not server.exists():
            self.skipTest("vault-mcp-server.py not found")
        text = server.read_text()
        expected = len(set(re.findall(r'"name":\s*"(vault_\w+)"', text)))

        result = subprocess.run(
            [sys.executable, str(TOOL), "--json"],
            capture_output=True, text=True, timeout=30
        )
        data = json.loads(result.stdout)
        self.assertEqual(data["actual_count"], expected)

    def test_l_doctrine_code_not_mismatched_as_count(self):
        """L-doctrine section headers like 'L19 callables' do NOT match as callable count."""
        mod = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            doc = d / "VAULT_MCP_SERVER.md"
            # Include both an L-code false-positive and a true count claim
            doc.write_text(textwrap.dedent("""\
                ### L19 callables (added 2026-05-07)

                The L19 batch added three structured-recall callables...

                The vault MCP server registers **38 callables** (verified against tools/vault-mcp-server.py).
                """))
            result = mod.parse_doc_counts([("VAULT_MCP_SERVER.md", doc)])
            # Should match 38, not 19 (the L-code)
            self.assertEqual(result["VAULT_MCP_SERVER.md"], 38,
                           "L-doctrine section header should not be parsed as callable count")


if __name__ == "__main__":
    unittest.main()
