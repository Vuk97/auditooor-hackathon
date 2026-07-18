"""Tests for tools/audit-pdf-to-patterns.py."""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).parent.parent / "audit-pdf-to-patterns.py"


def load_module():
    spec = importlib.util.spec_from_file_location("audit_pdf_to_patterns_mod", str(TOOL))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestDiscoverSources(unittest.TestCase):
    """_discover_sources: skip-filter and audit-subdir discovery."""

    def _make_tree(self, tmp: str, files: dict) -> None:
        for rel, content in files.items():
            fpath = Path(tmp) / rel
            fpath.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                fpath.write_bytes(content)
            else:
                fpath.write_text(content)

    def test_empty_dir_returns_empty(self):
        mod = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            result = mod._discover_sources([tmp])
        self.assertEqual(result, [])

    def test_nonexistent_dir_returns_empty(self):
        mod = load_module()
        result = mod._discover_sources(["/tmp/__nonexistent_audit_dir_xyz__"])
        self.assertEqual(result, [])

    def test_finds_txt_in_prior_audits(self):
        mod = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            self._make_tree(tmp, {
                "myproject/prior_audits/audit1.txt": "Severity: High\nSome finding",
                "myproject/prior_audits/audit2.txt": "Severity: Medium\nAnother finding",
            })
            result = mod._discover_sources([tmp])
        names = [os.path.basename(str(p)) for p in result]
        self.assertIn("audit1.txt", names)
        self.assertIn("audit2.txt", names)

    def test_skips_lib_dir(self):
        mod = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            self._make_tree(tmp, {
                "myproject/lib/prior_audits/shouldskip.txt": "Critical finding",
                "myproject/prior_audits/shouldfind.txt": "High finding",
            })
            result = mod._discover_sources([tmp])
        names = [os.path.basename(str(p)) for p in result]
        self.assertNotIn("shouldskip.txt", names)
        self.assertIn("shouldfind.txt", names)

    def test_skips_external_dir(self):
        mod = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            self._make_tree(tmp, {
                "proj/external/prior_audits/skip.txt": "High",
                "proj/prior_audits/keep.txt": "High",
            })
            result = mod._discover_sources([tmp])
        names = [os.path.basename(str(p)) for p in result]
        self.assertNotIn("skip.txt", names)
        self.assertIn("keep.txt", names)

    def test_skips_src_chimera_dirs(self):
        mod = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            self._make_tree(tmp, {
                "proj/src/prior_audits/skip.txt": "High",
                "proj/chimera_harnesses/prior_audits/skip2.txt": "High",
                "proj/prior_audits/keep.txt": "High",
            })
            result = mod._discover_sources([tmp])
        names = [os.path.basename(str(p)) for p in result]
        self.assertNotIn("skip.txt", names)
        self.assertNotIn("skip2.txt", names)
        self.assertIn("keep.txt", names)

    def test_txt_preferred_over_pdf_sibling(self):
        """When both .txt and .pdf exist for same stem, only .txt is returned."""
        mod = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            self._make_tree(tmp, {
                "proj/prior_audits/report.txt": "High",
            })
            pdf_path = Path(tmp) / "proj/prior_audits/report.pdf"
            pdf_path.write_bytes(b"%PDF-1.4 fake")
            result = mod._discover_sources([tmp])
        stems = [p.stem for p in result]
        self.assertIn("report", stems)
        # Should not have duplicate for same stem
        self.assertEqual(len([p for p in result if p.stem == "report"]), 1)


class TestCandidateSuffix(unittest.TestCase):
    """Output files MUST have .yaml.candidate suffix."""

    def test_candidate_slug_deterministic(self):
        mod = load_module()
        slug1 = mod._candidate_slug("audit.txt", "Some title", 0)
        slug2 = mod._candidate_slug("audit.txt", "Some title", 0)
        self.assertEqual(slug1, slug2)

    def test_candidate_slug_different_index(self):
        mod = load_module()
        slug1 = mod._candidate_slug("audit.txt", "Some title", 0)
        slug2 = mod._candidate_slug("audit.txt", "Some title", 1)
        self.assertNotEqual(slug1, slug2)

    def test_write_candidate_has_correct_suffix(self):
        mod = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            finding = {"title": "Test reentrancy bug", "severity": "High", "summary": "Reentrancy in withdraw"}
            slug = mod._candidate_slug("test.txt", finding["title"], 0)
            out_path = mod._write_candidate(out_dir, slug, finding, "test.txt")
            self.assertTrue(str(out_path).endswith(".yaml.candidate"),
                            f"Expected .yaml.candidate suffix, got: {out_path}")
            self.assertTrue(out_path.exists())

    def test_write_candidate_no_raw_yaml(self):
        """Ensure no .yaml file (without .candidate) is created."""
        mod = load_module()
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp)
            finding = {"title": "Oracle manipulation", "severity": "Critical", "summary": "Price oracle can be manipulated"}
            slug = mod._candidate_slug("test.txt", finding["title"], 0)
            mod._write_candidate(out_dir, slug, finding, "test.txt")
            all_files = list(out_dir.iterdir())
            for f in all_files:
                self.assertFalse(
                    str(f.name).endswith(".yaml") and not str(f.name).endswith(".yaml.candidate"),
                    f"Raw .yaml file found (no .candidate suffix): {f.name}"
                )


class TestExtractFindings(unittest.TestCase):
    """_extract_findings: various finding-marker patterns."""

    def test_bracket_severity_marker(self):
        mod = load_module()
        text = "[H-1] Reentrancy in withdraw\nThis allows an attacker to drain funds.\n"
        findings = mod._extract_findings(text)
        self.assertGreater(len(findings), 0)
        self.assertIn("High", [f["severity"] for f in findings])

    def test_severity_block_pattern(self):
        mod = load_module()
        text = "Finding Title Here\nSeverity\nCritical\nAn attacker can drain the contract.\n"
        findings = mod._extract_findings(text)
        self.assertGreater(len(findings), 0)
        self.assertIn("Critical", [f["severity"] for f in findings])

    def test_no_false_positives_on_empty(self):
        mod = load_module()
        findings = mod._extract_findings("")
        self.assertEqual(findings, [])

    def test_deduplication(self):
        mod = load_module()
        text = (
            "[H-1] Reentrancy in withdraw\nDetails here\n"
            "[H-1] Reentrancy in withdraw\nDetails again\n"
        )
        findings = mod._extract_findings(text)
        titles = [f["title"] for f in findings]
        self.assertEqual(len(titles), len(set(t.lower()[:60] for t in titles)))


class TestMainZeroInput(unittest.TestCase):
    """Tool exits 0 when min thresholds are 0 and input is empty."""

    def test_zero_threshold_empty_dir(self):
        mod = load_module()
        with tempfile.TemporaryDirectory() as tmp_out, tempfile.TemporaryDirectory() as tmp_in:
            rc = mod.main([
                "--input-dir", tmp_in,
                "--out-dir", tmp_out,
                "--min-pdfs", "0",
                "--min-candidates", "0",
                "--quiet",
            ])
        self.assertEqual(rc, 0)

    def test_threshold_violation_exits_1(self):
        mod = load_module()
        with tempfile.TemporaryDirectory() as tmp_out, tempfile.TemporaryDirectory() as tmp_in:
            rc = mod.main([
                "--input-dir", tmp_in,
                "--out-dir", tmp_out,
                "--min-pdfs", "1",
                "--min-candidates", "0",
                "--quiet",
            ])
        self.assertEqual(rc, 1)

    def test_summary_json_written(self):
        mod = load_module()
        with tempfile.TemporaryDirectory() as tmp_out, tempfile.TemporaryDirectory() as tmp_in:
            orig_cwd = os.getcwd()
            try:
                os.chdir(tmp_in)
                mod.main([
                    "--input-dir", tmp_in,
                    "--out-dir", tmp_out,
                    "--min-pdfs", "0",
                    "--min-candidates", "0",
                    "--quiet",
                ])
                summary_path = Path(tmp_in) / ".auditooor/audit_pdf_mining_run.json"
                self.assertTrue(summary_path.exists())
                data = json.loads(summary_path.read_text())
                self.assertIn("total_candidates", data)
                self.assertIn("sources_scanned", data)
            finally:
                os.chdir(orig_cwd)


class TestMainWithRealTxt(unittest.TestCase):
    """Smoke test: tool extracts candidates from a real-looking audit txt."""

    def _make_audit_txt(self, tmp: str) -> Path:
        content = """\
Security Audit Report — DummyProtocol v2

Severity Summary
Finding Severity #
Critical 1
High 2
Medium 3

Findings

[C-1] Reentrancy in withdrawFunds
Severity: Critical
An attacker can call withdrawFunds repeatedly before the balance is updated,
draining the contract of all funds.

[H-1] Price oracle manipulation via flash loan
Severity: High
The protocol uses a single-block TWAP which can be manipulated with a flash loan
to set an arbitrary price and trigger liquidations.

[H-2] Missing access control on setOwner
Severity: High
Any external caller can invoke setOwner and take control of the contract.

[M-1] Integer overflow in calculateReward
Severity: Medium
The reward calculation uses unchecked arithmetic and can overflow, giving users
incorrect reward amounts.
"""
        audit_dir = Path(tmp) / "testproject" / "prior_audits"
        audit_dir.mkdir(parents=True)
        txt_path = audit_dir / "dummy-audit.txt"
        txt_path.write_text(content)
        return txt_path

    def test_extracts_candidates_from_audit_txt(self):
        mod = load_module()
        with tempfile.TemporaryDirectory() as tmp_in, tempfile.TemporaryDirectory() as tmp_out:
            self._make_audit_txt(tmp_in)
            orig_cwd = os.getcwd()
            try:
                os.chdir(tmp_in)
                rc = mod.main([
                    "--input-dir", tmp_in,
                    "--out-dir", tmp_out,
                    "--min-pdfs", "1",
                    "--min-candidates", "1",
                    "--quiet",
                ])
                candidates = list(Path(tmp_out).glob("*.yaml.candidate"))
                self.assertGreater(len(candidates), 0)
                self.assertEqual(rc, 0)
                # Verify content of first candidate
                c = candidates[0]
                text = c.read_text()
                self.assertIn("severity_hint:", text)
                self.assertIn("source_pdf:", text)
                self.assertIn("confidence: low", text)
                self.assertIn("extraction_method: text-pattern", text)
            finally:
                os.chdir(orig_cwd)


if __name__ == "__main__":
    unittest.main()
