"""Tests for the Wave-2 W2.4 Sherlock PDF deep-mine ETL.

Hermetic: synthetic Sherlock-shaped PDF fixtures are generated on
demand by ``_sherlock_fixture_builder.ensure_fixtures()`` (depends on
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
import _sherlock_fixture_builder  # noqa: E402


def _load_driver():
    """Load the hyphenated driver module by file path."""
    driver_path = TOOLS_DIR / "hackerman-etl-from-audit-firm-pdf-sherlock.py"
    spec = importlib.util.spec_from_file_location("w24_sherlock_driver", driver_path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules["w24_sherlock_driver"] = mod
    spec.loader.exec_module(mod)
    return mod


_DRIVER = _load_driver()


def _write_fake_listing(
    listings_dir: Path,
    pdf_filename: str,
    project_label: str,
    year: int = 2024,
    record_suffix: str = "deadbeefcafe",
) -> Path:
    slug = project_label.lower().replace(" ", "_")
    rec_dir = listings_dir / f"sherlock-reports__{slug}-{record_suffix}"
    rec_dir.mkdir(parents=True, exist_ok=True)
    # Sherlock URLs commonly contain literal spaces; deliberately preserve
    # them here so the URL regex + percent-encoder are exercised.
    record = {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": f"audit-firm:sherlock-reports:{slug}:{record_suffix}",
        "attack_class": "audit-firm-public-report",
        "bug_class": "audit-firm-public-report-index",
        "function_shape": {
            "raw_signature": f"audit-firm-report::sherlock-reports/{slug}",
            "shape_tags": [
                "audit-firm-public-report",
                "firm-sherlock-reports",
                "ext-pdf",
                f"year-{year}",
                "verification_tier:tier-2-verified-public-archive",
            ],
        },
        "required_preconditions": [
            f"Reference public audit report at https://raw.githubusercontent.com/sherlock-protocol/sherlock-reports/main/audits/{pdf_filename}",
            "Source repo sherlock-protocol/sherlock-reports",
            f"Source path audits/{pdf_filename}",
            "verification_tier=tier-2-verified-public-archive",
            f"Inferred project name {project_label}",
        ],
        "year": year,
    }
    (rec_dir / "record.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    return rec_dir


class SherlockExtractorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures = _sherlock_fixture_builder.ensure_fixtures()

    def test_extract_pages_returns_pages_for_two_findings_pdf(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["sherlock_two_findings.pdf"]
        )
        self.assertGreater(len(result.pages), 0)
        self.assertEqual(result.backend, "pypdf")
        joined = "\n".join(p.raw_text for p in result.pages)
        self.assertIn("Reentrancy", joined)
        self.assertIn("Integer overflow", joined)

    def test_sherlock_extractor_yields_two_findings_with_letters(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["sherlock_two_findings.pdf"]
        )
        findings = pdf_finding_extractor.extract_sherlock_findings(result)
        self.assertEqual(len(findings), 2)
        letters = [f.finding_letter for f in findings]
        sevs = [f.severity for f in findings]
        self.assertIn("H", letters)
        self.assertIn("M", letters)
        self.assertIn("high", sevs)
        self.assertIn("medium", sevs)
        titles = [f.title for f in findings]
        self.assertTrue(any("Reentrancy" in t for t in titles))
        self.assertTrue(any("Integer overflow" in t for t in titles))

    def test_sherlock_extractor_captures_recommendation_and_resolution(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["sherlock_two_findings.pdf"]
        )
        findings = pdf_finding_extractor.extract_sherlock_findings(result)
        self.assertTrue(findings)
        h1 = next(f for f in findings if f.finding_letter == "H")
        self.assertIn("checks-effects-interactions", h1.recommendation.lower().replace("\n", " "))
        self.assertIn("Fixed", h1.resolution)
        files = {entry["file"] for entry in h1.lines_cited}
        self.assertTrue(any(f.endswith("Vault.sol") for f in files))

    def test_sherlock_extractor_handles_inline_summary(self) -> None:
        """Inline ``Summary: text`` (no newline before value) must parse."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["sherlock_critical_inline_summary.pdf"]
        )
        findings = pdf_finding_extractor.extract_sherlock_findings(result)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].finding_letter, "C")
        self.assertEqual(findings[0].severity, "critical")
        self.assertTrue(findings[0].summary, "summary should not be empty")
        self.assertIn("setFeeRecipient", findings[0].summary)

    def test_sherlock_extractor_returns_empty_for_no_findings_pdf(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["sherlock_no_findings.pdf"]
        )
        findings = pdf_finding_extractor.extract_sherlock_findings(result)
        self.assertEqual(findings, [])

    def test_sherlock_extractor_letter_only_severity_fallback(self) -> None:
        """No ``Severity:`` body field -> severity inferred from heading letter."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["sherlock_low_letter_only_severity.pdf"]
        )
        findings = pdf_finding_extractor.extract_sherlock_findings(result)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].finding_letter, "L")
        self.assertEqual(findings[0].severity, "low")
        self.assertEqual(findings[0].severity_verbatim, "")
        self.assertIn("severity-from-letter-only", findings[0].parser_warnings)

    def test_sherlock_extractor_captures_source_field(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["sherlock_two_findings.pdf"]
        )
        findings = pdf_finding_extractor.extract_sherlock_findings(result)
        h1 = next(f for f in findings if f.finding_letter == "H")
        self.assertTrue(h1.source, "source field should be captured")
        # H-1 source points at github.com Vault.sol#L42-L60.
        self.assertIn("Vault.sol", h1.source)


class SherlockDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures = _sherlock_fixture_builder.ensure_fixtures()

    def _build_workspace(self) -> tuple[Path, Path, Path, Path]:
        tmp = Path(tempfile.mkdtemp(prefix="w24_sherlock_test_"))
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
        # Seed the cache so --no-fetch is satisfied. Sherlock filenames
        # often contain spaces; the cache layer must accept them verbatim.
        cache_target = cache_dir / "sherlock-reports" / pdf_filename
        cache_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(self.fixtures[fixture_key], cache_target)

    def test_iter_sherlock_listings_filters_by_firm_prefix(self) -> None:
        tmp, listings_dir, _, _ = self._build_workspace()
        try:
            _write_fake_listing(listings_dir, "sample.pdf", "Sample Project")
            # Non-Sherlock sibling should be ignored.
            non_sherlock = listings_dir / "trailofbits-publications__sample-123"
            non_sherlock.mkdir()
            (non_sherlock / "record.json").write_text(json.dumps({
                "function_shape": {"shape_tags": ["firm-trailofbits-publications"]},
            }), encoding="utf-8")
            handles = list(_DRIVER.iter_sherlock_listings(listings_dir))
            self.assertEqual(len(handles), 1)
            self.assertEqual(handles[0].firm, "sherlock-reports")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_driver_emits_records_for_cached_pdfs(self) -> None:
        tmp, listings_dir, cache_dir, out_dir = self._build_workspace()
        try:
            self._stage_listing(
                listings_dir, cache_dir,
                "2024.03.15 - Final - Sample Vault Audit Report.pdf",
                "Sample Vault",
                "sherlock_two_findings.pdf",
            )
            self._stage_listing(
                listings_dir, cache_dir,
                "2024.04.20 - Final - Sample AMM Audit Report.pdf",
                "Sample AMM",
                "sherlock_critical_inline_summary.pdf",
            )
            self._stage_listing(
                listings_dir, cache_dir,
                "2024.05.10 - Final - Sample Bridge Audit Report.pdf",
                "Sample Bridge",
                "sherlock_low_letter_only_severity.pdf",
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
            # 2 from sherlock_two_findings + 1 from inline + 1 from letter-only.
            self.assertEqual(summary["listings_seen"], 3)
            self.assertGreaterEqual(summary["records_written"], 4)
            written_dirs = [p for p in out_dir.iterdir() if p.is_dir()]
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
            rc = _DRIVER.main([
                "--listings-dir", str(listings_dir),
                "--cache-dir", str(cache_dir),
                "--out-dir", str(out_dir),
                "--no-fetch",
                "--json-summary",
            ])
            self.assertEqual(rc, 0)
            if out_dir.is_dir():
                self.assertFalse(any(out_dir.glob("sherlock-reports__*")))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_record_has_expected_extension_fields(self) -> None:
        tmp, listings_dir, cache_dir, out_dir = self._build_workspace()
        try:
            self._stage_listing(
                listings_dir, cache_dir,
                "2024.06.01 - Final - Ext Sample Audit Report.pdf",
                "Ext Sample",
                "sherlock_critical_inline_summary.pdf",
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
            self.assertEqual(ext["pdf_parser_firm_variant"], "sherlock")
            self.assertEqual(ext["pdf_parser_version"], pdf_finding_extractor.PARSER_VERSION)
            self.assertEqual(len(ext["pdf_blob_sha256"]), 64)
            self.assertEqual(len(ext["pdf_page_range"]), 2)
            self.assertEqual(ext["sherlock_finding_letter"], "C")
            self.assertIn("audit-firm-finding:sherlock-reports:ext-sample:C001-", rec["record_id"])
            self.assertEqual(rec["severity_at_finding"], "critical")
            # Sherlock-specific shape tag must appear.
            self.assertIn("sherlock-letter-C", rec["function_shape"]["shape_tags"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_url_path_encoding_preserves_host_and_encodes_path_spaces(self) -> None:
        encoded = _DRIVER._encode_url_path(
            "https://raw.githubusercontent.com/sherlock-protocol/sherlock-reports/main/audits/"
            "2022.06.27 - Final - Lyra Audit Report.pdf"
        )
        # Spaces in the path become %20; host / scheme untouched.
        self.assertTrue(encoded.startswith("https://raw.githubusercontent.com/"))
        self.assertIn("%20", encoded)
        self.assertNotIn(" ", encoded)
        self.assertTrue(encoded.endswith(".pdf"))

    def test_parse_listing_handles_url_with_spaces(self) -> None:
        tmp, listings_dir, _, _ = self._build_workspace()
        try:
            rec_dir = _write_fake_listing(
                listings_dir,
                "2024.07.04 - Final - Spaced Project Audit Report.pdf",
                "Spaced Project",
            )
            handles = list(_DRIVER.iter_sherlock_listings(listings_dir))
            self.assertEqual(len(handles), 1)
            handle = handles[0]
            # The captured URL retains literal spaces (URL-encoding happens
            # at fetch time, not at parse time, so downstream code paths
            # such as records can show the canonical URL).
            self.assertIn("Spaced Project", handle.pdf_url)
            self.assertEqual(handle.firm, "sherlock-reports")
            self.assertTrue(handle.filename.endswith(".pdf"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
