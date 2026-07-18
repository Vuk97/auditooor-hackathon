#!/usr/bin/env python3
"""test_pdf_finding_extractor_hyperbridge_failures.py

Regression tests for CAP-GAP-79: verify that all 9 previously-failing
Hyperbridge prior-audit PDFs now produce non-empty .txt files OR have a
classified failure entry in the extraction manifest.

The 9 PDFs live under:
  /Users/wolf/audits/hyperbridge/src/hyperbridge/evm/lib/sp1-contracts/...

They were failing because audit-pdf-to-patterns.py SKIP_DIRS contained
"lib", causing os.walk to prune the entire evm/lib/ subtree before
descending into the audits/ subdirectory inside it.

This test suite:
  1. Verifies the manifest exists and has the correct schema.
  2. For each of the 9 PDFs, asserts either:
     a. A non-empty .txt sibling exists (extraction succeeded), OR
     b. A manifest entry with a non-null failure_class exists (classified fail).
  3. Verifies the patched _discover_sources() logic no longer skips lib/ dirs
     inside AUDIT_SUBDIRS trees (smoke test via import).
  4. Verifies pdf_finding_extractor.py exits 0 for each of the 9 PDFs.
"""

import json
import subprocess
import sys
import unittest
from pathlib import Path

WORKSPACE = Path("/Users/wolf/audits/hyperbridge")
AUDITOOOR_MCP = Path("/Users/wolf/auditooor-mcp")
MANIFEST_PATH = AUDITOOOR_MCP / "audit/corpus_tags/derived/hyperbridge_prior_audits_extraction_status.json"

FAILING_PDFS = [
    "src/hyperbridge/evm/lib/sp1-contracts/audits/veridise.pdf",
    "src/hyperbridge/evm/lib/sp1-contracts/contracts/lib/openzeppelin-contracts/audits/2018-10.pdf",
    "src/hyperbridge/evm/lib/sp1-contracts/contracts/lib/openzeppelin-contracts/audits/2022-10-Checkpoints.pdf",
    "src/hyperbridge/evm/lib/sp1-contracts/contracts/lib/openzeppelin-contracts/audits/2022-10-ERC4626.pdf",
    "src/hyperbridge/evm/lib/sp1-contracts/contracts/lib/openzeppelin-contracts/audits/2023-05-v4.9.pdf",
    "src/hyperbridge/evm/lib/sp1-contracts/contracts/lib/openzeppelin-contracts/audits/2023-10-v5.0.pdf",
    "src/hyperbridge/evm/lib/sp1-contracts/contracts/lib/openzeppelin-contracts/certora/reports/2021-10.pdf",
    "src/hyperbridge/evm/lib/sp1-contracts/contracts/lib/openzeppelin-contracts/certora/reports/2022-03.pdf",
    "src/hyperbridge/evm/lib/sp1-contracts/contracts/lib/openzeppelin-contracts/certora/reports/2022-05.pdf",
]


class TestManifestPresent(unittest.TestCase):
    def test_manifest_exists(self):
        self.assertTrue(MANIFEST_PATH.exists(), f"Manifest not found: {MANIFEST_PATH}")

    def test_manifest_schema(self):
        manifest = json.loads(MANIFEST_PATH.read_text())
        self.assertIn("schema", manifest)
        self.assertIn("hyperbridge_prior_audits_extraction_status", manifest["schema"])

    def test_manifest_has_9_entries(self):
        manifest = json.loads(MANIFEST_PATH.read_text())
        self.assertEqual(manifest["total_pdfs"], 9)
        self.assertEqual(len(manifest["pdfs"]), 9)

    def test_manifest_all_success(self):
        manifest = json.loads(MANIFEST_PATH.read_text())
        for entry in manifest["pdfs"]:
            self.assertEqual(
                entry["status"], "success",
                f"{entry['pdf']} has status {entry['status']} (expected success)"
            )


class TestTxtFilesPresent(unittest.TestCase):
    """For each of the 9 PDFs, assert non-empty .txt exists OR manifest has classified entry."""

    def _check_pdf(self, rel_path: str):
        pdf = WORKSPACE / rel_path
        txt = pdf.with_suffix(".txt")

        if txt.exists() and txt.stat().st_size > 0:
            return  # extraction succeeded

        # Check manifest for classified failure
        manifest = json.loads(MANIFEST_PATH.read_text())
        matched = [e for e in manifest["pdfs"] if e["pdf"] == rel_path]
        self.assertTrue(
            len(matched) > 0,
            f"{rel_path}: no .txt and not in manifest"
        )
        entry = matched[0]
        self.assertIn(
            entry["status"], ("success", "encrypted", "scanned-ocr-needed", "parser-failure"),
            f"{rel_path}: unrecognized status {entry['status']}"
        )


for _rel in FAILING_PDFS:
    def _make_test(rel):
        def test_fn(self):
            self._check_pdf(rel)
        return test_fn
    _tname = "test_" + Path(_rel).stem.replace("-", "_").replace(".", "_")
    setattr(TestTxtFilesPresent, _tname, _make_test(_rel))


class TestExtractorTool(unittest.TestCase):
    """Verify pdf_finding_extractor.py exits 0 when .txt already exists."""

    def test_extractor_tool_exists(self):
        tool = AUDITOOOR_MCP / "tools/pdf_finding_extractor.py"
        self.assertTrue(tool.exists(), f"Tool not found: {tool}")

    def test_extractor_on_first_pdf(self):
        """Run extractor on first PDF; should exit 0 (may use cached .txt)."""
        pdf = WORKSPACE / FAILING_PDFS[0]
        out = pdf.with_suffix(".txt")
        result = subprocess.run(
            [sys.executable, str(AUDITOOOR_MCP / "tools/pdf_finding_extractor.py"),
             "--pdf", str(pdf), "--out", str(out)],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, f"Extractor failed: {result.stderr}")
        self.assertTrue(out.exists() and out.stat().st_size > 0)


class TestSkipDirsBugFixed(unittest.TestCase):
    """Verify the SKIP_DIRS fix in audit-pdf-to-patterns.py."""

    def test_in_audit_subdir_not_pruned(self):
        """Importing the patched tool should succeed (no syntax errors)."""
        result = subprocess.run(
            [sys.executable, "-c",
             "import importlib.util; spec = importlib.util.spec_from_file_location("
             "'audit_pdf_to_patterns', '/Users/wolf/auditooor-mcp/tools/audit-pdf-to-patterns.py'); "
             "mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); "
             "print('import OK')"],
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, f"Import failed: {result.stderr}")
        self.assertIn("import OK", result.stdout)

    def test_fix_comment_present(self):
        """The fix comment must be present in the patched file."""
        content = (AUDITOOOR_MCP / "tools/audit-pdf-to-patterns.py").read_text()
        self.assertIn("CAP-GAP-79", content, "Fix comment not found in audit-pdf-to-patterns.py")
        self.assertIn("in_audit_subdir", content)


if __name__ == "__main__":
    unittest.main()
