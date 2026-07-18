"""Tests for tools/verdict-tag-schema.py (JSON-Schema validator subset)."""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "audit" / "corpus_tags" / "auditooor.verdict_tag.v1.schema.json"
TOOL_PATH = REPO_ROOT / "tools" / "verdict-tag-schema.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("_vts", str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class SchemaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()
        self.schema = self.tool.load_schema(SCHEMA_PATH)

    def test_minimal_valid_tag_passes(self) -> None:
        doc = {
            "verdict_id": "dydx-hunt-iter-1/X-verdict.md",
            "target_repo": "dydxprotocol/v4-chain",
            "audit_pin_sha": "5ee9766351ef864856a309a971b13fdd98cae2c5",
            "language": "go",
            "verdict_class": "DROP",
            "extraction_provenance": "regex",
            "extractor_version": "0.1.0",
            "extracted_at_utc": "2026-05-11T12:00:00Z",
        }
        errs = self.tool.validate(doc, self.schema)
        self.assertEqual(errs, [], f"expected clean; got {errs}")

    def test_missing_mandatory_field_fails(self) -> None:
        doc = {
            "verdict_id": "x",
            # missing target_repo
            "audit_pin_sha": "5ee9766",
            "language": "go",
            "verdict_class": "DROP",
            "extraction_provenance": "regex",
            "extractor_version": "0.1.0",
            "extracted_at_utc": "2026-05-11T12:00:00Z",
        }
        errs = self.tool.validate(doc, self.schema)
        self.assertTrue(any("target_repo" in e for e in errs), f"errors={errs}")

    def test_filed_class_requires_sites(self) -> None:
        # Per allOf rule in schema: FILED must have sites with >=1 entry
        doc = {
            "verdict_id": "x",
            "target_repo": "dydxprotocol/v4-chain",
            "audit_pin_sha": "5ee9766",
            "language": "go",
            "verdict_class": "FILED",
            "extraction_provenance": "regex",
            "extractor_version": "0.1.0",
            "extracted_at_utc": "2026-05-11T12:00:00Z",
        }
        errs = self.tool.validate(doc, self.schema)
        self.assertTrue(any("sites" in e for e in errs), f"errors={errs}")

    def test_enum_rejection(self) -> None:
        doc = {
            "verdict_id": "x",
            "target_repo": "a/b",
            "audit_pin_sha": "1234567",
            "language": "klingon",  # invalid
            "verdict_class": "DROP",
            "extraction_provenance": "regex",
            "extractor_version": "0.1.0",
            "extracted_at_utc": "2026-05-11T12:00:00Z",
        }
        errs = self.tool.validate(doc, self.schema)
        self.assertTrue(any("language" in e and "enum" in e for e in errs), f"errors={errs}")

    def test_validate_file_via_cli_path(self) -> None:
        """End-to-end via validate_file()."""
        yaml_content = """
verdict_id: dydx-hunt-iter-1/X-verdict.md
target_repo: dydxprotocol/v4-chain
audit_pin_sha: "5ee9766351ef864856a309a971b13fdd98cae2c5"
language: go
verdict_class: DROP
extraction_provenance: regex
extractor_version: "0.1.0"
extracted_at_utc: "2026-05-11T12:00:00Z"
"""
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            f.flush()
            p = Path(f.name)
        try:
            ok, errs = self.tool.validate_file(p, self.schema)
            self.assertTrue(ok, f"validation failed: {errs}")
        finally:
            p.unlink()

    def test_pattern_rejection_on_repo(self) -> None:
        doc = {
            "verdict_id": "x",
            "target_repo": "not-a-valid-repo-format",
            "audit_pin_sha": "1234567",
            "language": "go",
            "verdict_class": "DROP",
            "extraction_provenance": "regex",
            "extractor_version": "0.1.0",
            "extracted_at_utc": "2026-05-11T12:00:00Z",
        }
        errs = self.tool.validate(doc, self.schema)
        self.assertTrue(any("target_repo" in e and "pattern" in e for e in errs))


class SchemaV2Tests(unittest.TestCase):
    """Tests for v2 schema with ranker integration fields."""

    def setUp(self) -> None:
        self.tool = _load_tool()
        v2_path = REPO_ROOT / "audit" / "corpus_tags" / "auditooor.verdict_tag.v2.schema.json"
        if v2_path.exists():
            self.schema_v2 = self.tool.load_schema(v2_path)
        else:
            self.skipTest("v2 schema not found")

    def test_v2_accepts_predicted_attack_classes(self) -> None:
        """v2 should accept predicted_attack_classes array (optional)."""
        doc = {
            "verdict_id": "dydx-hunt-iter-1/X-verdict.md",
            "target_repo": "dydxprotocol/v4-chain",
            "audit_pin_sha": "5ee9766351ef864856a309a971b13fdd98cae2c5",
            "language": "go",
            "verdict_class": "FILED",
            "extraction_provenance": "regex",
            "extractor_version": "0.1.0",
            "extracted_at_utc": "2026-05-11T12:00:00Z",
            "predicted_attack_classes": ["admin_bypass", "access_control", "fee_redirect"],
            "sites": [{"file_path": "x.go"}],
        }
        errs = self.tool.validate(doc, self.schema_v2)
        self.assertEqual(errs, [], f"v2 should accept predicted_attack_classes; got {errs}")

    def test_v2_accepts_realized_attack_class(self) -> None:
        """v2 should accept realized_attack_class string (optional)."""
        doc = {
            "verdict_id": "dydx-hunt-iter-1/X-verdict.md",
            "target_repo": "dydxprotocol/v4-chain",
            "audit_pin_sha": "5ee9766351ef864856a309a971b13fdd98cae2c5",
            "language": "go",
            "verdict_class": "CONFIRMED",
            "extraction_provenance": "regex",
            "extractor_version": "0.1.0",
            "extracted_at_utc": "2026-05-11T12:00:00Z",
            "realized_attack_class": "admin_bypass",
            "sites": [{"file_path": "x.go"}],
        }
        errs = self.tool.validate(doc, self.schema_v2)
        self.assertEqual(errs, [], f"v2 should accept realized_attack_class; got {errs}")

    def test_v2_backward_compat_with_v1_docs(self) -> None:
        """v2 schema should accept v1 documents (no v2-specific fields)."""
        doc = {
            "verdict_id": "dydx-hunt-iter-1/X-verdict.md",
            "target_repo": "dydxprotocol/v4-chain",
            "audit_pin_sha": "5ee9766351ef864856a309a971b13fdd98cae2c5",
            "language": "go",
            "verdict_class": "DROP",
            "extraction_provenance": "regex",
            "extractor_version": "0.1.0",
            "extracted_at_utc": "2026-05-11T12:00:00Z",
        }
        errs = self.tool.validate(doc, self.schema_v2)
        self.assertEqual(errs, [], f"v2 should be backward-compat with v1 docs; got {errs}")


if __name__ == "__main__":
    unittest.main()
