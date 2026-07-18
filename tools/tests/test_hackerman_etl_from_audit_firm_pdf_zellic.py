"""Tests for the Wave-2 W2.4 Zellic-firm PDF deep-mine ETL.

Hermetic: synthetic Zellic-shaped PDF fixtures are generated on demand
by ``_zellic_fixture_builder.ensure_fixtures()`` (depends on
``reportlab``) and the driver runs against a temporary
``listings_dir`` + ``cache_dir`` + ``out_dir`` trio.

No network IO. No reads of real Wave-1 corpus listings beyond a single
shape-check helper that builds a fake listing record on the fly.
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
LIB_DIR = TOOLS_DIR / "lib"
FIXTURE_PKG = REPO_ROOT / "tools" / "tests" / "fixtures" / "audit_firm_pdf_samples"

sys.path.insert(0, str(LIB_DIR))
sys.path.insert(0, str(FIXTURE_PKG))

import pdf_finding_extractor  # noqa: E402
import _zellic_fixture_builder  # noqa: E402


def _load_driver():
    """Load the hyphenated Zellic driver module by file path."""
    driver_path = TOOLS_DIR / "hackerman-etl-from-audit-firm-pdf-zellic.py"
    spec = importlib.util.spec_from_file_location("w24_zellic_driver", driver_path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules["w24_zellic_driver"] = mod
    spec.loader.exec_module(mod)
    return mod


_DRIVER = _load_driver()


def _write_fake_listing(
    listings_dir: Path,
    pdf_filename: str,
    project_label: str,
    year: int = 2023,
    record_suffix: str = "deadbeefcafe",
) -> Path:
    slug = project_label.lower().replace(" ", "_")
    rec_dir = listings_dir / f"zellic-publications__{slug}-{record_suffix}"
    rec_dir.mkdir(parents=True, exist_ok=True)
    record = {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": f"audit-firm:zellic-publications:{slug}:{record_suffix}",
        "attack_class": "audit-firm-public-report",
        "bug_class": "audit-firm-public-report-index",
        "function_shape": {
            "raw_signature": f"audit-firm-report::zellic-publications/{slug}",
            "shape_tags": [
                "audit-firm-public-report",
                "firm-zellic-publications",
                "ext-pdf",
                f"year-{year}",
                "verification_tier:tier-2-verified-public-archive",
            ],
        },
        "required_preconditions": [
            f"Reference public audit report at https://raw.githubusercontent.com/Zellic/publications/master/{pdf_filename}",
            "Source repo Zellic/publications",
            f"Source path {pdf_filename}",
            "verification_tier=tier-2-verified-public-archive",
            f"Inferred project name {project_label}",
        ],
        "year": year,
    }
    (rec_dir / "record.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    return rec_dir


class ZellicPdfExtractorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures = _zellic_fixture_builder.ensure_fixtures()

    def test_extract_pages_returns_pages_for_two_findings_pdf(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["zellic_two_findings.pdf"]
        )
        self.assertGreater(len(result.pages), 0)
        self.assertEqual(result.backend, "pypdf")
        joined = "\n".join(p.raw_text for p in result.pages)
        self.assertIn("Reentrancy", joined)
        self.assertIn("Integer overflow", joined)

    def test_zellic_extractor_yields_two_findings_with_severities(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["zellic_two_findings.pdf"]
        )
        findings = pdf_finding_extractor.extract_zellic_findings(result)
        self.assertEqual(len(findings), 2)
        sevs = [f.severity for f in findings]
        self.assertIn("high", sevs)
        self.assertIn("medium", sevs)
        titles = [f.title for f in findings]
        self.assertTrue(any("Reentrancy" in t for t in titles))
        self.assertTrue(any("Integer overflow" in t for t in titles))

    def test_zellic_extractor_captures_impact_and_likelihood(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["zellic_two_findings.pdf"]
        )
        findings = pdf_finding_extractor.extract_zellic_findings(result)
        self.assertTrue(findings, "expected at least one Zellic finding")
        # Find the High finding (Reentrancy) - should have Impact=High, Likelihood=Medium.
        high = next(f for f in findings if f.severity == "high")
        self.assertEqual(high.impact, "High")
        self.assertEqual(high.likelihood, "Medium")

    def test_zellic_extractor_captures_recommendation_and_lines_cited(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["zellic_two_findings.pdf"]
        )
        findings = pdf_finding_extractor.extract_zellic_findings(result)
        first = findings[0]
        self.assertIn(
            "checks-effects-interactions",
            first.recommendation.lower().replace("\n", " "),
        )
        files = {entry["file"] for entry in first.lines_cited}
        self.assertTrue(any(f.endswith("Vault.sol") for f in files))

    def test_zellic_extractor_handles_hash_id_variant(self) -> None:
        """``Finding #1:`` heading variant must also be recognised."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["zellic_one_finding_hash_id.pdf"]
        )
        findings = pdf_finding_extractor.extract_zellic_findings(result)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "critical")
        self.assertIn("Missing access control", findings[0].title)
        self.assertTrue(findings[0].recommendation)

    def test_zellic_extractor_returns_empty_for_no_findings_pdf(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["zellic_no_findings.pdf"]
        )
        findings = pdf_finding_extractor.extract_zellic_findings(result)
        self.assertEqual(findings, [])

    def test_zellic_extractor_normalises_informational_severity(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["zellic_informational_severity.pdf"]
        )
        findings = pdf_finding_extractor.extract_zellic_findings(result)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "informational")
        self.assertEqual(findings[0].severity_verbatim, "Informational")
        # Impact=None and Likelihood=None should be captured verbatim.
        self.assertEqual(findings[0].impact, "None")
        self.assertEqual(findings[0].likelihood, "None")

    def test_zellic_extractor_extension_field_visible_in_extracted_finding(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["zellic_two_findings.pdf"]
        )
        findings = pdf_finding_extractor.extract_zellic_findings(result)
        # Each finding's page_range must be a valid 2-tuple of non-negative ints.
        for f in findings:
            self.assertEqual(len(f.page_range), 2)
            self.assertGreaterEqual(f.page_range[0], 0)
            self.assertGreaterEqual(f.page_range[1], f.page_range[0])
            self.assertGreaterEqual(f.parser_confidence, 0.3)
            self.assertLessEqual(f.parser_confidence, 1.0)


class ZellicDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures = _zellic_fixture_builder.ensure_fixtures()

    def _build_workspace(self) -> tuple[Path, Path, Path, Path]:
        tmp = Path(tempfile.mkdtemp(prefix="w24_zellic_test_"))
        listings_dir = tmp / "audit_firm_public_reports"
        cache_dir = tmp / "cache"
        out_dir = tmp / "out"
        listings_dir.mkdir(parents=True)
        cache_dir.mkdir(parents=True)
        return tmp, listings_dir, cache_dir, out_dir

    def _stage_listing(
        self,
        listings_dir: Path,
        cache_dir: Path,
        pdf_filename: str,
        project_label: str,
        fixture_key: str,
    ) -> None:
        _write_fake_listing(listings_dir, pdf_filename, project_label)
        cache_target = cache_dir / "zellic-publications" / pdf_filename
        cache_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(self.fixtures[fixture_key], cache_target)

    def test_iter_zellic_listings_filters_by_firm_prefix(self) -> None:
        tmp, listings_dir, _, _ = self._build_workspace()
        try:
            _write_fake_listing(listings_dir, "sample.pdf", "Sample Project")
            # Non-Zellic sibling should be ignored.
            non_zellic = listings_dir / "trailofbits-publications__sample-123"
            non_zellic.mkdir()
            (non_zellic / "record.json").write_text(json.dumps({
                "function_shape": {"shape_tags": ["firm-trailofbits-publications"]},
            }), encoding="utf-8")
            handles = list(_DRIVER.iter_zellic_listings(listings_dir))
            self.assertEqual(len(handles), 1)
            self.assertEqual(handles[0].firm, "zellic-publications")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_driver_emits_records_for_cached_pdf(self) -> None:
        tmp, listings_dir, cache_dir, out_dir = self._build_workspace()
        try:
            self._stage_listing(
                listings_dir, cache_dir, "sample_two.pdf", "Sample DEX", "zellic_two_findings.pdf"
            )
            self._stage_listing(
                listings_dir, cache_dir, "sample_one.pdf", "Sample Bridge", "zellic_one_finding_hash_id.pdf"
            )
            self._stage_listing(
                listings_dir, cache_dir, "sample_info.pdf", "Sample Lending", "zellic_informational_severity.pdf"
            )
            summary_path = tmp / "summary.json"
            rc = _DRIVER.main([
                "--listings-dir", str(listings_dir),
                "--cache-dir", str(cache_dir),
                "--out-dir", str(out_dir),
                "--no-fetch",
                "--json-summary",
                "--summary-path", str(summary_path),
            ])
            self.assertEqual(rc, 0)
            self.assertTrue(summary_path.is_file())
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            # Two findings from sample_two + 1 from sample_one + 1 from info = 4 records.
            self.assertEqual(summary["listings_seen"], 3)
            self.assertGreaterEqual(summary["records_written"], 4)
            written_dirs = list(out_dir.iterdir())
            self.assertGreaterEqual(len(written_dirs), 4)
            for entry in written_dirs:
                self.assertTrue((entry / "record.json").is_file())
                self.assertTrue((entry / "record.yaml").is_file())
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_driver_skips_unreachable_pdf_with_no_fetch(self) -> None:
        tmp, listings_dir, cache_dir, out_dir = self._build_workspace()
        try:
            _write_fake_listing(listings_dir, "missing.pdf", "Unreachable Project")
            # NO cache seeding; driver runs with --no-fetch so should skip.
            rc = _DRIVER.main([
                "--listings-dir", str(listings_dir),
                "--cache-dir", str(cache_dir),
                "--out-dir", str(out_dir),
                "--no-fetch",
                "--json-summary",
            ])
            self.assertEqual(rc, 0)
            if out_dir.is_dir():
                self.assertFalse(any(out_dir.glob("zellic-publications__*")))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_record_has_expected_extension_fields(self) -> None:
        tmp, listings_dir, cache_dir, out_dir = self._build_workspace()
        try:
            self._stage_listing(
                listings_dir, cache_dir, "ext_sample.pdf", "Ext Sample", "zellic_one_finding_hash_id.pdf"
            )
            _DRIVER.main([
                "--listings-dir", str(listings_dir),
                "--cache-dir", str(cache_dir),
                "--out-dir", str(out_dir),
                "--no-fetch",
            ])
            records = [p / "record.json" for p in out_dir.iterdir() if p.is_dir()]
            self.assertEqual(len(records), 1)
            rec = json.loads(records[0].read_text(encoding="utf-8"))
            self.assertEqual(rec["schema_version"], "auditooor.hackerman_record.v1")
            self.assertEqual(rec["record_tier"], "public-corpus")
            ext = rec["record_extensions"]
            self.assertEqual(ext["pdf_parser_firm_variant"], "zellic")
            self.assertEqual(ext["pdf_parser_version"], pdf_finding_extractor.PARSER_VERSION)
            self.assertEqual(len(ext["pdf_blob_sha256"]), 64)
            self.assertEqual(len(ext["pdf_page_range"]), 2)
            # Zellic-specific extension fields.
            self.assertEqual(ext["impact"], "Critical")
            self.assertEqual(ext["likelihood"], "High")
            self.assertEqual(ext["severity_verbatim"], "Critical")
            self.assertIn("audit-firm-finding:zellic-publications:ext-sample:001-", rec["record_id"])
            self.assertEqual(rec["severity_at_finding"], "critical")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_driver_summary_has_started_and_ended_timestamps(self) -> None:
        tmp, listings_dir, cache_dir, out_dir = self._build_workspace()
        try:
            self._stage_listing(
                listings_dir, cache_dir, "ts_sample.pdf", "TS Sample", "zellic_two_findings.pdf"
            )
            summary_path = tmp / "summary.json"
            rc = _DRIVER.main([
                "--listings-dir", str(listings_dir),
                "--cache-dir", str(cache_dir),
                "--out-dir", str(out_dir),
                "--no-fetch",
                "--summary-path", str(summary_path),
            ])
            self.assertEqual(rc, 0)
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertIn("started_at", summary)
            self.assertIn("ended_at", summary)
            self.assertEqual(summary["firm"], "zellic-publications")
            self.assertGreaterEqual(summary["findings_emitted"], 2)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
