#!/usr/bin/env python3
"""Tests for tools/mcp-callable-usage-audit.py — Track E-4."""
from __future__ import annotations

import importlib.util
import re
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "mcp-callable-usage-audit.py"


def load_module():
    spec = importlib.util.spec_from_file_location("mcp_callable_usage_audit_for_test", TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {TOOL}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def make_synthetic_server(tmp: Path, names: list[str]) -> Path:
    """Write a minimal vault-mcp-server.py with TOOL_SCHEMAS entries."""
    p = tmp / "tools" / "vault-mcp-server.py"
    p.parent.mkdir(parents=True, exist_ok=True)
    lines = ['TOOL_SCHEMAS = [\n']
    for name in names:
        lines.append(f'    {{"name": "{name}", "description": "test callable"}},\n')
    lines.append(']\n')
    p.write_text("".join(lines))
    return p


class TestEnumerateCallables(unittest.TestCase):
    """Tests for enumerate_callables()."""

    def setUp(self):
        self.mod = load_module()

    def test_enumerates_all_callables(self):
        """enumerate_callables returns all callables (count compared to grep ground-truth)."""
        import re
        server = REPO_ROOT / "tools" / "vault-mcp-server.py"
        if not server.exists():
            self.skipTest("vault-mcp-server.py not found")
        names = self.mod.enumerate_callables(server)
        ground_truth = len(re.findall(r'^\s+"name":\s*"vault_', server.read_text(), re.MULTILINE))
        self.assertGreaterEqual(len(names), 35,
                         f"Expected at least 35 callables, got {len(names)}: {names}")
        self.assertEqual(len(names), ground_truth,
                         f"Enumerator count {len(names)} mismatch grep ground-truth {ground_truth}")

    def test_enumerates_from_synthetic_server(self):
        """enumerate_callables returns correct count from a synthetic server file."""
        with tempfile.TemporaryDirectory() as tmp:
            expected = [f"vault_callable_{i}" for i in range(10)]
            p = make_synthetic_server(Path(tmp), expected)
            result = self.mod.enumerate_callables(p)
            self.assertEqual(sorted(result), sorted(expected))

    def test_deduplicates_repeated_names(self):
        """enumerate_callables deduplicates when a name appears twice."""
        with tempfile.TemporaryDirectory() as tmp:
            names = ["vault_foo", "vault_foo", "vault_bar"]
            p = make_synthetic_server(Path(tmp), names)
            result = self.mod.enumerate_callables(p)
            self.assertEqual(sorted(result), ["vault_bar", "vault_foo"])


class TestCountCitations(unittest.TestCase):
    """Tests for count_citations()."""

    def setUp(self):
        self.mod = load_module()

    def test_counts_citations_in_doc(self):
        """count_citations returns correct count when callable appears multiple times."""
        with tempfile.TemporaryDirectory() as tmp:
            doc = Path(tmp) / "AGENTS.md"
            doc.write_text(
                "Use vault_resume_context here.\n"
                "Call vault_resume_context again.\n"
                "vault_resume_context is Layer-1.\n"
            )
            counts = self.mod.count_citations("vault_resume_context", [doc])
            total = sum(counts.values())
            self.assertEqual(total, 3)

    def test_zero_citations_for_absent_callable(self):
        """count_citations returns empty dict when callable is not mentioned."""
        with tempfile.TemporaryDirectory() as tmp:
            doc = Path(tmp) / "AGENTS.md"
            doc.write_text("Nothing about vault_nonexistent here.\n")
            counts = self.mod.count_citations("vault_nonexistent_callable", [doc])
            self.assertEqual(sum(counts.values()), 0)

    def test_skips_missing_files_silently(self):
        """count_citations silently skips non-existent paths."""
        missing = Path("/nonexistent/file.md")
        result = self.mod.count_citations("vault_resume_context", [missing])
        self.assertEqual(result, {})


class TestClassification(unittest.TestCase):
    """Tests for classify() tier assignment."""

    def setUp(self):
        self.mod = load_module()

    def test_heavy_at_5_or_more(self):
        self.assertEqual(self.mod.classify(5), "heavy")
        self.assertEqual(self.mod.classify(100), "heavy")

    def test_moderate_at_2_to_4(self):
        self.assertEqual(self.mod.classify(2), "moderate")
        self.assertEqual(self.mod.classify(4), "moderate")

    def test_light_at_1(self):
        self.assertEqual(self.mod.classify(1), "light")

    def test_silent_at_0(self):
        self.assertEqual(self.mod.classify(0), "silent")


class TestAuditOutput(unittest.TestCase):
    """Tests for audit() and render_markdown() end-to-end."""

    def setUp(self):
        self.mod = load_module()

    def test_silent_callable_classified_correctly(self):
        """A callable with zero citations is classified as 'silent'."""
        with tempfile.TemporaryDirectory() as tmp:
            names = ["vault_silent_one", "vault_mentioned"]
            server = make_synthetic_server(Path(tmp), names)
            doc = Path(tmp) / "AGENTS.md"
            doc.write_text("Use vault_mentioned here.\n")
            rows = self.mod.audit(server, [doc])
            silent = [r for r in rows if r["callable"] == "vault_silent_one"]
            self.assertEqual(len(silent), 1)
            self.assertEqual(silent[0]["tier"], "silent")
            self.assertEqual(silent[0]["total_citations"], 0)

    def test_markdown_table_contains_all_callables(self):
        """render_markdown produces a table row for each callable."""
        with tempfile.TemporaryDirectory() as tmp:
            names = ["vault_alpha", "vault_beta", "vault_gamma"]
            server = make_synthetic_server(Path(tmp), names)
            rows = self.mod.audit(server, [])
            md = self.mod.render_markdown(rows, [])
            for name in names:
                self.assertIn(name, md, f"{name} missing from markdown output")

    def test_markdown_contains_summary_section(self):
        """render_markdown output contains the Summary section."""
        with tempfile.TemporaryDirectory() as tmp:
            names = ["vault_x"]
            server = make_synthetic_server(Path(tmp), names)
            rows = self.mod.audit(server, [])
            md = self.mod.render_markdown(rows, [])
            self.assertIn("## Summary", md)
            self.assertIn("PROMOTE_LAYER_1", md)
            self.assertIn("DEPRECATE", md)

    def test_real_server_produces_all_rows(self):
        """audit() on real vault-mcp-server.py produces one row per callable."""
        import re
        server = REPO_ROOT / "tools" / "vault-mcp-server.py"
        if not server.exists():
            self.skipTest("vault-mcp-server.py not found")
        rows = self.mod.audit(server, [])
        ground_truth = len(re.findall(r'^\s+"name":\s*"vault_', server.read_text(), re.MULTILINE))
        self.assertGreaterEqual(len(rows), 35,
                         f"Expected at least 35 rows, got {len(rows)}")
        self.assertEqual(len(rows), ground_truth,
                         f"Audit row count {len(rows)} mismatch grep ground-truth {ground_truth}")


if __name__ == "__main__":
    unittest.main()
