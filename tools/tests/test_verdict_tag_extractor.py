"""Tests for tools/verdict-tag-extractor.py — regex layer + applier."""
from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "verdict-tag-extractor.py"
SCHEMA_PATH = REPO_ROOT / "audit" / "corpus_tags" / "auditooor.verdict_tag.v1.schema.json"
SCHEMA_TOOL = REPO_ROOT / "tools" / "verdict-tag-schema.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class ExtractorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.ext = _load(TOOL_PATH, "_vte")
        self.vts = _load(SCHEMA_TOOL, "_vts")
        self.schema = self.vts.load_schema(SCHEMA_PATH)

    def test_detect_verdict_class_filed_filename(self) -> None:
        self.assertEqual(self.ext.detect_verdict_class("", "FILED_cantina-192_dydx-foo-CRITICAL.md"), "FILED")

    def test_detect_verdict_class_amended_filename(self) -> None:
        self.assertEqual(
            self.ext.detect_verdict_class("", "AMENDED-cluster_cantina-018_dydx-bar-HIGH.md"),
            "AMENDED",
        )

    def test_detect_audit_pin_sha_in_backticks(self) -> None:
        text = "audit-pin `5ee9766351ef864856a309a971b13fdd98cae2c5` (2026-04-28)."
        self.assertEqual(self.ext.detect_audit_pin_sha(text), "5ee9766351ef864856a309a971b13fdd98cae2c5")

    def test_detect_sites_extracts_file_line(self) -> None:
        text = "vulnerable at protocol/x/affiliates/keeper/msg_server.go:23 and other.go:99-105"
        sites = self.ext.detect_sites(text)
        # both sites captured
        paths = {s["file_path"] for s in sites}
        self.assertIn("protocol/x/affiliates/keeper/msg_server.go", paths)
        self.assertIn("other.go", paths)
        # line_start populated
        self.assertTrue(any(s.get("line_start") == 23 for s in sites))

    def test_detect_language_from_sites(self) -> None:
        sites = [{"file_path": "x.go"}, {"file_path": "y.go"}]
        self.assertEqual(self.ext.detect_language(sites, ""), "go")

    def test_detect_parity_precedents(self) -> None:
        text = "Parity precedent: cantina-048 and immunefi-77043 confirmed."
        out = self.ext.detect_parity_precedents(text)
        self.assertIn("cantina-048", out)
        self.assertIn("immunefi-77043", out)

    def test_emit_yaml_roundtrip_quotes_sha(self) -> None:
        tag = {
            "verdict_id": "dydx-hunt-iter-1/X-verdict.md",
            "target_repo": "dydxprotocol/v4-chain",
            "audit_pin_sha": "0000000",  # all-numeric edge case
            "language": "go",
            "verdict_class": "DROP",
            "extraction_provenance": "regex",
            "extractor_version": "0.1.0",
            "extracted_at_utc": "2026-05-11T12:00:00Z",
        }
        text = self.ext.emit_yaml(tag)
        # SHA must be quoted so the loader doesn't coerce to int
        self.assertIn('audit_pin_sha: "0000000"', text)
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(text)
            p = Path(f.name)
        try:
            ok, errs = self.vts.validate_file(p, self.schema)
            self.assertTrue(ok, f"validation failed: {errs}")
        finally:
            p.unlink()

    def test_build_tag_end_to_end_minimal(self) -> None:
        body = """# DYDX verdict

audit-pin `5ee9766351ef864856a309a971b13fdd98cae2c5`
target_repo dydxprotocol/v4-chain

Path: x/affiliates/keeper/msg_server.go:23
verdict: DROP
"""
        with tempfile.TemporaryDirectory() as td:
            # Build fake audits root layout so verdict_id_for resolves
            audits = Path(td) / "audits"
            ws = audits / "dydx" / "agent_outputs" / "dydx-hunt-iter-1"
            ws.mkdir(parents=True)
            f = ws / "DYDX-FOO-verdict.md"
            f.write_text(body)
            # monkeypatch AUDITS_ROOT
            self.ext.AUDITS_ROOT = audits
            tag = self.ext.build_tag(f)
            self.assertEqual(tag["target_repo"], "dydxprotocol/v4-chain")
            self.assertEqual(tag["audit_pin_sha"], "5ee9766351ef864856a309a971b13fdd98cae2c5")
            self.assertEqual(tag["language"], "go")
            self.assertEqual(tag["verdict_class"], "DROP")
            self.assertEqual(
                tag["verdict_id"], "dydx-hunt-iter-1/DYDX-FOO-verdict.md"
            )


if __name__ == "__main__":
    unittest.main()
