"""Tests for the Wave-2 W2.4 Pashov PDF deep-mine ETL.

The tests are hermetic: synthetic Pashov-shaped PDF fixtures are
generated on demand by ``_pashov_fixture_builder.ensure_fixtures()``
(depends on ``reportlab``) and the driver runs against a temporary
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
import _pashov_fixture_builder  # noqa: E402


def _load_driver():
    """Load the hyphenated driver module by file path."""
    driver_path = TOOLS_DIR / "hackerman-etl-from-audit-firm-pdf-pashov.py"
    spec = importlib.util.spec_from_file_location("w24_pashov_driver", driver_path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    # Register before exec so dataclass decorator can resolve the module via
    # sys.modules (required on Python 3.14+).
    sys.modules["w24_pashov_driver"] = mod
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
    rec_dir = listings_dir / f"pashov-audits__{slug}-{record_suffix}"
    rec_dir.mkdir(parents=True, exist_ok=True)
    record = {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": f"audit-firm:pashov-audits:{slug}:{record_suffix}",
        "attack_class": "audit-firm-public-report",
        "bug_class": "audit-firm-public-report-index",
        "function_shape": {
            "raw_signature": f"audit-firm-report::pashov-audits/{slug}",
            "shape_tags": [
                "audit-firm-public-report",
                "firm-pashov-audits",
                "ext-pdf",
                f"year-{year}",
                "verification_tier:tier-2-verified-public-archive",
            ],
        },
        "required_preconditions": [
            f"Reference public audit report at https://raw.githubusercontent.com/pashov/audits/main/solo/{pdf_filename}",
            "Source repo pashov/audits",
            f"Source path solo/{pdf_filename}",
            "verification_tier=tier-2-verified-public-archive",
            f"Inferred project name {project_label}",
        ],
        "year": year,
    }
    (rec_dir / "record.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    return rec_dir


class PashovExtractorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures = _pashov_fixture_builder.ensure_fixtures()

    def test_extract_pages_returns_pages_for_two_findings_pdf(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["pashov_two_findings.pdf"]
        )
        self.assertGreater(len(result.pages), 0)
        self.assertEqual(result.backend, "pypdf")
        joined = "\n".join(p.raw_text for p in result.pages)
        self.assertIn("Reentrancy", joined)
        self.assertIn("Integer overflow", joined)

    def test_pashov_extractor_yields_two_findings_with_bracketed_severity(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["pashov_two_findings.pdf"]
        )
        findings = pdf_finding_extractor.extract_pashov_findings(result)
        self.assertEqual(len(findings), 2)
        sevs = [f.severity for f in findings]
        codes = [f.severity_code for f in findings]
        self.assertIn("high", sevs)
        self.assertIn("medium", sevs)
        # Codes preserved as the in-PDF letter (H/M).
        self.assertIn("H", codes)
        self.assertIn("M", codes)
        # No fallback warning should appear when bracketed headings exist.
        for f in findings:
            self.assertNotIn("pashov-fallback-numeric-heading", f.parser_warnings)

    def test_pashov_extractor_captures_recommendation_and_lines_cited(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["pashov_two_findings.pdf"]
        )
        findings = pdf_finding_extractor.extract_pashov_findings(result)
        h_findings = [f for f in findings if f.severity_code == "H"]
        self.assertTrue(h_findings, "expected the H-1 finding")
        h1 = h_findings[0]
        self.assertIn("checks-effects-interactions", h1.recommendation.lower().replace("\n", " "))
        files = {entry["file"] for entry in h1.lines_cited}
        self.assertTrue(any(f.endswith("Vault.sol") for f in files))

    def test_pashov_extractor_includes_poc_in_summary_not_recommendation(self) -> None:
        """Spec §5.6(c): PoC subsection content rides in ``summary``."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["pashov_critical_with_poc.pdf"]
        )
        findings = pdf_finding_extractor.extract_pashov_findings(result)
        self.assertEqual(len(findings), 1)
        c1 = findings[0]
        self.assertEqual(c1.severity, "critical")
        # PoC field populated.
        self.assertIn("setFeeRecipient(mallory)", c1.proof_of_concept)
        # Recommendation does NOT carry the PoC text.
        self.assertNotIn("setFeeRecipient(mallory)", c1.recommendation)

    def test_pashov_extractor_maps_low_and_informational_codes(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["pashov_low_informational.pdf"]
        )
        findings = pdf_finding_extractor.extract_pashov_findings(result)
        self.assertEqual(len(findings), 2)
        codes = sorted([f.severity_code for f in findings])
        self.assertEqual(codes, ["I", "L"])
        sev_by_code = {f.severity_code: f.severity for f in findings}
        self.assertEqual(sev_by_code["L"], "low")
        self.assertEqual(sev_by_code["I"], "informational")

    def test_pashov_extractor_falls_back_to_numeric_template_when_brackets_absent(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["pashov_legacy_numeric.pdf"]
        )
        findings = pdf_finding_extractor.extract_pashov_findings(result)
        self.assertEqual(len(findings), 2)
        # Fallback path: severity recovered from body label, code is empty.
        sevs = sorted([f.severity for f in findings])
        self.assertEqual(sevs, ["high", "low"])
        for f in findings:
            self.assertEqual(f.severity_code, "")
            self.assertIn("pashov-fallback-numeric-heading", f.parser_warnings)

    def test_pashov_extractor_returns_empty_for_pdf_with_no_findings_marker(self) -> None:
        """When neither heading regex matches, we return an empty list."""
        # Build a transient PDF with only narrative text.
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import LETTER
        import os

        tmp = Path(tempfile.mkdtemp(prefix="pashov_empty_"))
        try:
            pdf_path = tmp / "empty.pdf"
            c = canvas.Canvas(str(pdf_path), pagesize=LETTER)
            t = c.beginText(72, 700)
            t.textLine("Pashov Audit Group")
            t.textLine("Security Review: No-Findings Project")
            t.textLine("")
            t.textLine("No security issues were identified during this review.")
            c.drawText(t)
            c.showPage()
            c.save()
            result = pdf_finding_extractor.extract_structured_pages(pdf_path)
            findings = pdf_finding_extractor.extract_pashov_findings(result)
            self.assertEqual(findings, [])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_pashov_extractor_confidence_drops_for_missing_recommendation(self) -> None:
        """Confidence scoring: missing recommendation costs 0.2."""
        # Re-parse the legacy template; the recommendation IS present so
        # we instead synthesise a body-only blob via the private helper.
        body = (
            "Description\n"
            "The withdraw function in target/contracts/Vault.sol:L42 has a bug.\n"
            "\n"
        )
        sev, sev_v, desc, rec, poc, summary, warnings = (
            pdf_finding_extractor._pashov_parse_body(body, severity_code="H")
        )
        self.assertEqual(sev, "high")
        self.assertEqual(rec, "")
        # Helper does not add the warning itself; the public extractor
        # appends 'missing-recommendation' in its own pass. Spot-check
        # the description survived the slice.
        self.assertIn("withdraw function", desc)

    def test_pashov_title_cleanup_normalizes_ligatures_and_glued_status(self) -> None:
        title, warnings = pdf_finding_extractor._clean_pashov_title(
            "ETH transfer grieﬁng MediumAcknowledged",
            severity_code="M",
        )
        self.assertEqual(title, "ETH transfer griefing")
        self.assertIn("pashov-ligature-normalized", warnings)
        self.assertIn("pashov-title-cleaned", warnings)

    def test_pashov_title_cleanup_strips_repeated_finding_code(self) -> None:
        title, warnings = pdf_finding_extractor._clean_pashov_title(
            "H-1 Reentrancy in withdraw allows fund theft Status: Resolved",
            severity_code="H",
        )
        self.assertEqual(title, "Reentrancy in withdraw allows fund theft")
        self.assertIn("pashov-title-cleaned", warnings)


class DriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures = _pashov_fixture_builder.ensure_fixtures()

    def _build_workspace(self) -> tuple[Path, Path, Path, Path]:
        tmp = Path(tempfile.mkdtemp(prefix="w24_pashov_test_"))
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
        # Seed the cache so --no-fetch is satisfied.
        cache_target = cache_dir / "pashov-audits" / pdf_filename
        cache_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(self.fixtures[fixture_key], cache_target)

    def test_iter_pashov_listings_filters_by_firm_prefix(self) -> None:
        tmp, listings_dir, _, _ = self._build_workspace()
        try:
            _write_fake_listing(listings_dir, "sample.pdf", "Sample Project")
            # Non-Pashov sibling should be ignored.
            non_pashov = listings_dir / "zellic-publications__sample-123"
            non_pashov.mkdir()
            (non_pashov / "record.json").write_text(json.dumps({
                "function_shape": {"shape_tags": ["firm-zellic-publications"]},
            }), encoding="utf-8")
            handles = list(_DRIVER.iter_pashov_listings(listings_dir))
            self.assertEqual(len(handles), 1)
            self.assertEqual(handles[0].firm, "pashov-audits")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_driver_emits_records_for_cached_pdfs(self) -> None:
        tmp, listings_dir, cache_dir, out_dir = self._build_workspace()
        try:
            self._stage_listing(
                listings_dir, cache_dir, "two.pdf", "Sample Vault", "pashov_two_findings.pdf"
            )
            self._stage_listing(
                listings_dir, cache_dir, "crit.pdf", "Sample AMM", "pashov_critical_with_poc.pdf"
            )
            self._stage_listing(
                listings_dir, cache_dir, "low.pdf", "Sample Bridge", "pashov_low_informational.pdf"
            )
            self._stage_listing(
                listings_dir, cache_dir, "legacy.pdf", "Legacy Project", "pashov_legacy_numeric.pdf"
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
            # Two findings from sample_two + 1 from crit + 2 from low +
            # 2 from legacy = 7 records.
            self.assertEqual(summary["listings_seen"], 4)
            self.assertGreaterEqual(summary["records_written"], 7)
            written_dirs = list(out_dir.iterdir())
            self.assertGreaterEqual(len(written_dirs), 7)
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
                self.assertFalse(any(out_dir.glob("pashov-audits__*")))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_record_has_expected_extension_fields(self) -> None:
        tmp, listings_dir, cache_dir, out_dir = self._build_workspace()
        try:
            self._stage_listing(
                listings_dir, cache_dir, "ext_sample.pdf", "Ext Sample", "pashov_critical_with_poc.pdf"
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
            self.assertEqual(rec["schema_version"], "auditooor.hackerman_record.v1.1")
            self.assertEqual(rec["record_tier"], "public-corpus")
            self.assertEqual(rec["verification_tier"], "tier-2-verified-public-archive")
            self.assertTrue(rec["record_source_url"].endswith("/solo/ext_sample.pdf"))
            self.assertEqual(rec["source_extraction_method"], "corpus-etl")
            self.assertEqual(rec["verification_method"], "none")
            self.assertNotIn("title", rec)
            self.assertNotIn("summary", rec)
            self.assertNotIn("recommendation", rec)
            self.assertNotIn("lines_cited", rec)
            ext = rec["record_extensions"]
            self.assertEqual(ext["title"], "Missing access control on admin setter")
            self.assertIn("setFeeRecipient function", ext["summary"])
            self.assertIn("onlyOwner modifier", ext["recommendation"])
            self.assertEqual(ext["pdf_extraction_status"], "parsed")
            self.assertEqual(ext["pdf_parser_firm_variant"], "pashov")
            self.assertEqual(ext["pdf_parser_version"], pdf_finding_extractor.PARSER_VERSION)
            self.assertEqual(len(ext["pdf_blob_sha256"]), 64)
            self.assertEqual(len(ext["pdf_page_range"]), 2)
            self.assertEqual(ext["severity_code"], "C")
            self.assertIn("setFeeRecipient(mallory)", ext["proof_of_concept"])
            self.assertIn(
                "audit-firm-finding:pashov-audits:ext-sample:C-001-", rec["record_id"]
            )
            self.assertEqual(rec["severity_at_finding"], "critical")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_driver_percent_encodes_url_path_with_spaces(self) -> None:
        """Pashov filenames sometimes carry spaces. The driver's URL
        encoder must quote the path while leaving the scheme/host
        untouched and must not double-encode an already-quoted path."""
        encoded = _DRIVER._percent_encode_path(
            "https://raw.githubusercontent.com/pashov/audits/main/solo/Resolv Security Review (final).pdf"
        )
        self.assertIn("Resolv%20Security%20Review", encoded)
        self.assertIn("%28final%29", encoded)
        self.assertTrue(encoded.startswith("https://raw.githubusercontent.com/"))
        # Idempotent: re-encoding does not double-encode.
        encoded_twice = _DRIVER._percent_encode_path(encoded)
        self.assertEqual(encoded, encoded_twice)

    def test_parse_listing_keeps_full_reference_url_with_spaces(self) -> None:
        tmp, listings_dir, _, _ = self._build_workspace()
        try:
            _write_fake_listing(
                listings_dir,
                "WishWish-security-review_2025-11-04 (1).pdf",
                "WishWish",
                year=2025,
            )
            handle = next(_DRIVER.iter_pashov_listings(listings_dir))
            self.assertEqual(
                handle.filename,
                "WishWish-security-review_2025-11-04 (1).pdf",
            )
            self.assertTrue(handle.pdf_url.endswith(" (1).pdf"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_parse_listing_uses_v1_1_record_source_url(self) -> None:
        tmp, listings_dir, _, _ = self._build_workspace()
        try:
            rec_dir = _write_fake_listing(
                listings_dir,
                "Modern-security-review.pdf",
                "Modern",
                year=2026,
            )
            record_path = rec_dir / "record.json"
            record = json.loads(record_path.read_text(encoding="utf-8"))
            url_line = record["required_preconditions"].pop(0)
            record["record_source_url"] = url_line.split(" at ", 1)[1]
            record["schema_version"] = "auditooor.hackerman_record.v1.1"
            record_path.write_text(json.dumps(record, indent=2), encoding="utf-8")

            handle = next(_DRIVER.iter_pashov_listings(listings_dir))
            self.assertEqual(handle.filename, "Modern-security-review.pdf")
            self.assertEqual(handle.pdf_url, record["record_source_url"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
