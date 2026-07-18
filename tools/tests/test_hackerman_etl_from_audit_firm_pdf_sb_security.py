"""Tests for the SB Security PDF deep-mine extractor and driver.

Hermetic: synthetic SB Security-shaped PDF fixtures are generated on
demand by ``_sb_security_fixture_builder.ensure_fixtures()`` and the
driver runs against temporary listing/cache/output directories.
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
import _sb_security_fixture_builder  # noqa: E402


def _load_driver():
    driver_path = TOOLS_DIR / "hackerman-etl-from-audit-firm-pdf-sb-security.py"
    spec = importlib.util.spec_from_file_location("w24_sb_security_driver", driver_path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules["w24_sb_security_driver"] = mod
    spec.loader.exec_module(mod)
    return mod


_DRIVER = _load_driver()


def _write_fake_listing(
    listings_dir: Path,
    pdf_filename: str,
    project_label: str,
    year: int = 2024,
    record_suffix: str = "deadbeefcafe",
    record_source_url: str | None = None,
) -> Path:
    slug = project_label.lower().replace(" ", "_")
    rec_dir = listings_dir / f"sb-security-audits__{slug}-{record_suffix}"
    rec_dir.mkdir(parents=True, exist_ok=True)
    record = {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": f"audit-firm:sb-security-audits:{slug}:{record_suffix}",
        "attack_class": "audit-firm-public-report",
        "bug_class": "audit-firm-public-report-index",
        "function_shape": {
            "raw_signature": f"audit-firm-report::sb-security-audits/{slug}",
            "shape_tags": [
                "audit-firm-public-report",
                "firm-sb-security-audits",
                "ext-pdf",
                f"year-{year}",
                "verification_tier:tier-2-verified-public-archive",
            ],
        },
        "required_preconditions": [
            f"Reference public audit report at https://raw.githubusercontent.com/sb-security/audits/main/{pdf_filename}",
            "Source repo sb-security/audits",
            f"Source path {pdf_filename}",
            "verification_tier=tier-2-verified-public-archive",
            f"Inferred project name {project_label}",
        ],
        "year": year,
    }
    if record_source_url is not None:
        record["record_source_url"] = record_source_url
    (rec_dir / "record.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    return rec_dir


class SBSecurityExtractorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures = _sb_security_fixture_builder.ensure_fixtures()

    def test_native_report_extracts_two_real_findings_not_toc_rows(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["sb_security_native_two_findings.pdf"]
        )
        findings = pdf_finding_extractor.extract_sb_security_findings(result)

        self.assertEqual(len(findings), 2)
        self.assertEqual([f.finding_id for f in findings], ["5.1.1", "5.2.1"])
        self.assertEqual([f.severity for f in findings], ["critical", "high"])
        self.assertIn("withdrawFunds", findings[0].title)
        self.assertIn("targetVault", findings[0].description)
        self.assertIn("vaultSplit", findings[0].recommendation)
        self.assertEqual(findings[0].resolution_status, "Fixed")
        self.assertIn("sb-security-duplicate-heading-suppressed", findings[0].parser_warnings)

        cited = findings[0].lines_cited
        self.assertEqual(cited[0]["file"], "RouterVaults.sol")
        self.assertEqual(cited[0]["line_start"], 88)
        self.assertEqual(cited[0]["line_end"], 88)

    def test_low_report_uses_severity_section_fallback_and_poc(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["sb_security_low_with_poc.pdf"]
        )
        findings = pdf_finding_extractor.extract_sb_security_findings(result)

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.finding_id, "7.1.1")
        self.assertEqual(finding.severity, "low")
        self.assertEqual(finding.severity_verbatim, "Low")
        self.assertIn("unused input tokens", finding.description)
        self.assertIn("leftovers", finding.proof_of_concept)
        self.assertIn("post-swap cleanup", finding.recommendation)

    def test_bracket_id_report_extracts_body_rows_not_toc_duplicates(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["sb_security_bracket_ids_with_toc_duplicates.pdf"]
        )
        findings = pdf_finding_extractor.extract_sb_security_findings(result)

        self.assertEqual(len(findings), 5)
        self.assertEqual(
            [f.finding_id for f in findings],
            ["C-01", "H-01", "M-01", "L-01", "I-01"],
        )
        self.assertEqual(
            [f.severity for f in findings],
            ["critical", "high", "medium", "low", "informational"],
        )
        self.assertIn("borrower balance", findings[0].description)
        self.assertIn("accounting before external transfers", findings[0].recommendation)
        self.assertIn("sb-security-duplicate-heading-suppressed", findings[0].parser_warnings)
        self.assertIn("sb-security-severity-from-bracket-id", findings[0].parser_warnings)

    def test_bracket_id_report_with_incidental_numbered_section_still_extracts_bracket_findings(self) -> None:
        result = pdf_finding_extractor.ExtractionResult(
            pages=[
                pdf_finding_extractor.StructuredPage(
                    page_index=0,
                    raw_text=(
                        "1.2.3 Architecture Review\n"
                        "Description: This section documents reviewer methodology.\n"
                        "Context: Foo.sol#L1\n"
                        "Recommendation: Keep the diagram current.\n\n"
                        "[H-01] Callback settlement skips pool authentication\n"
                        "Context: Pool.sol#L77\n"
                        "Description: The swap callback accepts arbitrary callers and transfers funds.\n"
                        "Recommendation: Verify the pool caller before settling the callback.\n"
                    ),
                )
            ],
            diagnostics=[],
        )

        findings = pdf_finding_extractor.extract_sb_security_findings(result)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].finding_id, "H-01")
        self.assertEqual(findings[0].severity, "high")
        self.assertIn("arbitrary callers", findings[0].description)

    def test_bracket_id_severity_does_not_inherit_prior_numbered_context(self) -> None:
        result = pdf_finding_extractor.ExtractionResult(
            pages=[
                pdf_finding_extractor.StructuredPage(
                    page_index=0,
                    raw_text=(
                        "5.1 High severity\n"
                        "High-severity section heading from a prior report layout.\n\n"
                        "[M-01] Reward accounting rounds user claims down\n"
                        "Context: Rewards.sol#L91\n"
                        "Description: The reward index floors fractional claims and underpays users.\n"
                        "Recommendation: Carry fractional reward debt before updating the index.\n"
                    ),
                )
            ],
            diagnostics=[],
        )

        findings = pdf_finding_extractor.extract_sb_security_findings(result)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].finding_id, "M-01")
        self.assertEqual(findings[0].severity, "medium")
        self.assertEqual(findings[0].severity_verbatim, "Medium")

    def test_empty_report_yields_no_findings(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["sb_security_no_findings.pdf"]
        )
        self.assertEqual(pdf_finding_extractor.extract_sb_security_findings(result), [])

    def test_methodology_numbered_section_without_severity_is_not_a_finding(self) -> None:
        result = pdf_finding_extractor.ExtractionResult(
            pages=[
                pdf_finding_extractor.StructuredPage(
                    page_index=0,
                    raw_text=(
                        "1.2.3 Architecture Review\n"
                        "Description: This section documents reviewer methodology.\n"
                        "Context: Foo.sol#L1\n"
                        "Recommendation: Keep the diagram current.\n"
                    ),
                )
            ],
            diagnostics=[],
        )

        self.assertEqual(pdf_finding_extractor.extract_sb_security_findings(result), [])

    def test_filtered_toc_heading_does_not_shift_emitted_indices(self) -> None:
        result = pdf_finding_extractor.ExtractionResult(
            pages=[
                pdf_finding_extractor.StructuredPage(
                    page_index=0,
                    raw_text=(
                        "5.1.Critical severity\n"
                        "5.1.1.Ghost finding ........................ 6\n"
                        "5.2.High severity\n"
                        "5.2.1.Real accounting bug\n"
                        "Severity: High Risk\n"
                        "Context: Vault.sol#L44\n"
                        "Description: The vault sends funds before updating accounting.\n"
                        "Recommendation: Update accounting before transfers.\n"
                    ),
                )
            ],
            diagnostics=[],
        )

        findings = pdf_finding_extractor.extract_sb_security_findings(result)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].finding_id, "5.2.1")
        self.assertEqual(findings[0].finding_index, 1)


class SBSecurityDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures = _sb_security_fixture_builder.ensure_fixtures()

    def _build_workspace(self) -> tuple[Path, Path, Path, Path]:
        tmp = Path(tempfile.mkdtemp(prefix="w24_sb_security_test_"))
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
        cache_target = cache_dir / "sb-security-audits" / pdf_filename
        cache_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(self.fixtures[fixture_key], cache_target)

    def test_driver_emits_records_for_cached_pdf(self) -> None:
        tmp, listings_dir, cache_dir, out_dir = self._build_workspace()
        try:
            self._stage_listing(
                listings_dir,
                cache_dir,
                "sample native report.pdf",
                "Sample Vault",
                "sb_security_native_two_findings.pdf",
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
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual(summary["listings_seen"], 1)
            self.assertEqual(summary["findings_emitted"], 2)
            self.assertEqual(summary["records_written"], 2)

            records = sorted(p / "record.json" for p in out_dir.iterdir() if p.is_dir())
            self.assertEqual(len(records), 2)
            rec = json.loads(records[0].read_text(encoding="utf-8"))
            self.assertEqual(rec["schema_version"], "auditooor.hackerman_record.v1.1")
            self.assertEqual(rec["record_tier"], "public-corpus")
            self.assertEqual(rec["verification_tier"], "tier-2-verified-public-archive")
            self.assertEqual(rec["record_extensions"]["pdf_parser_firm_variant"], "sb-security")
            self.assertEqual(
                rec["record_extensions"]["pdf_parser_version"],
                pdf_finding_extractor.PARSER_VERSION,
            )
            self.assertEqual(len(rec["record_extensions"]["pdf_blob_sha256"]), 64)
            self.assertIn("sample%20native%20report.pdf", rec["record_source_url"])
            self.assertNotIn(" ", rec["record_source_url"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_parse_listing_keeps_full_reference_url_with_spaces(self) -> None:
        tmp, listings_dir, _, _ = self._build_workspace()
        try:
            _write_fake_listing(
                listings_dir,
                "Sample Security Review (final).pdf",
                "Sample",
                year=2025,
            )
            handle = next(_DRIVER.iter_sb_security_listings(listings_dir))
            self.assertEqual(handle.filename, "Sample Security Review (final).pdf")
            self.assertTrue(handle.pdf_url.endswith(" (final).pdf"))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_parse_listing_rejects_non_raw_or_non_pdf_record_source_url(self) -> None:
        tmp, listings_dir, _, _ = self._build_workspace()
        try:
            _write_fake_listing(
                listings_dir,
                "Sample Security Review.pdf",
                "Sample",
                record_source_url="https://example.com/not-raw.pdf",
            )
            self.assertEqual(list(_DRIVER.iter_sb_security_listings(listings_dir)), [])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_percent_encode_url_path_is_idempotent(self) -> None:
        encoded = _DRIVER._percent_encode_path(
            "https://raw.githubusercontent.com/sb-security/audits/main/Sample Security Review (final).pdf"
        )
        self.assertIn("Sample%20Security%20Review", encoded)
        self.assertIn("%28final%29", encoded)
        self.assertEqual(encoded, _DRIVER._percent_encode_path(encoded))


if __name__ == "__main__":
    unittest.main()
