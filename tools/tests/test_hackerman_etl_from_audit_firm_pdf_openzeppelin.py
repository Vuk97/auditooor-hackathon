"""Tests for the Wave-2 W2.4 OpenZeppelin-firm PDF deep-mine ETL.

Hermetic: synthetic OZ-shaped PDF fixtures are generated on demand by
``_openzeppelin_fixture_builder.ensure_fixtures()`` (depends on
``reportlab``) and the driver runs against a temporary ``listings_dir``
+ ``cache_dir`` + ``out_dir`` trio.

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
import _openzeppelin_fixture_builder  # noqa: E402


def _load_driver():
    """Load the hyphenated OpenZeppelin driver module by file path."""
    driver_path = TOOLS_DIR / "hackerman-etl-from-audit-firm-pdf-openzeppelin.py"
    spec = importlib.util.spec_from_file_location("w24_openzeppelin_driver", driver_path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules["w24_openzeppelin_driver"] = mod
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
    rec_dir = listings_dir / f"openzeppelin-audits__{slug}-{record_suffix}"
    rec_dir.mkdir(parents=True, exist_ok=True)
    record = {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": f"audit-firm:openzeppelin-audits:{slug}:{record_suffix}",
        "attack_class": "audit-firm-public-report",
        "bug_class": "audit-firm-public-report-index",
        "function_shape": {
            "raw_signature": f"audit-firm-report::openzeppelin-audits/{slug}",
            "shape_tags": [
                "audit-firm-public-report",
                "firm-openzeppelin-audits",
                "ext-pdf",
                f"year-{year}",
                "verification_tier:tier-2-verified-public-archive",
            ],
        },
        "required_preconditions": [
            f"Reference public audit report at https://raw.githubusercontent.com/OpenZeppelin/audits/main/{pdf_filename}",
            "Source repo OpenZeppelin/audits",
            f"Source path {pdf_filename}",
            "verification_tier=tier-2-verified-public-archive",
            f"Inferred project name {project_label}",
        ],
        "year": year,
    }
    (rec_dir / "record.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    return rec_dir


class OpenZeppelinExtractorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures = _openzeppelin_fixture_builder.ensure_fixtures()

    def test_extract_pages_returns_pages_for_single_h01_pdf(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["oz_single_h01.pdf"]
        )
        self.assertGreater(len(result.pages), 0)
        self.assertEqual(result.backend, "pypdf")
        joined = "\n".join(p.raw_text for p in result.pages)
        self.assertIn("Reentrancy", joined)
        self.assertIn("[H-01]", joined)

    def test_openzeppelin_extractor_single_h01(self) -> None:
        """Single-finding PDF (H-01) produces exactly one finding tagged High."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["oz_single_h01.pdf"]
        )
        findings = pdf_finding_extractor.extract_openzeppelin_findings(result)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.severity_code, "H")
        self.assertEqual(f.finding_id, "H-01")
        self.assertEqual(f.finding_index, 1)
        self.assertIn("Reentrancy", f.title)
        self.assertTrue(f.description)
        self.assertTrue(f.recommendation)
        # Lines cited extracted.
        files = {entry["file"] for entry in f.lines_cited}
        self.assertTrue(any(p.endswith("Vault.sol") for p in files))

    def test_openzeppelin_extractor_multi_finding_one_of_each_severity(self) -> None:
        """Multi-finding PDF: C-01, H-01, M-01, L-01, N-01, I-01 (one of each tier)."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["oz_one_of_each_severity.pdf"]
        )
        findings = pdf_finding_extractor.extract_openzeppelin_findings(result)
        self.assertEqual(len(findings), 6)
        codes = sorted([f.severity_code for f in findings])
        self.assertEqual(codes, ["C", "H", "I", "L", "M", "N"])
        sev_by_code = {f.severity_code: f.severity for f in findings}
        self.assertEqual(sev_by_code["C"], "critical")
        self.assertEqual(sev_by_code["H"], "high")
        self.assertEqual(sev_by_code["M"], "medium")
        self.assertEqual(sev_by_code["L"], "low")
        self.assertEqual(sev_by_code["N"], "note")
        self.assertEqual(sev_by_code["I"], "informational")
        # IDs are 2-digit zero-padded (OZ canonical).
        ids = sorted([f.finding_id for f in findings])
        self.assertEqual(ids, ["C-01", "H-01", "I-01", "L-01", "M-01", "N-01"])

    def test_openzeppelin_extractor_resolution_fixed_with_pr_ref(self) -> None:
        """``Resolution: Fixed in PR #1234`` parses both status and ref."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["oz_single_h01.pdf"]
        )
        findings = pdf_finding_extractor.extract_openzeppelin_findings(result)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.resolution_status, "Fixed")
        self.assertIsNotNone(f.resolution_ref)
        self.assertEqual(f.resolution_ref, "PR #1234")

    def test_openzeppelin_extractor_resolution_acknowledged_no_ref(self) -> None:
        """``Resolution: Acknowledged`` (bare, no PR ref) parses cleanly."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["oz_resolution_acknowledged.pdf"]
        )
        findings = pdf_finding_extractor.extract_openzeppelin_findings(result)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.resolution_status, "Acknowledged")
        self.assertIsNone(f.resolution_ref)

    def test_openzeppelin_extractor_resolution_partially_fixed(self) -> None:
        """``Resolution: Partially Fixed in PR #4321`` collapses to PartiallyFixed."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["oz_partially_fixed.pdf"]
        )
        findings = pdf_finding_extractor.extract_openzeppelin_findings(result)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.resolution_status, "PartiallyFixed")
        self.assertEqual(f.resolution_ref, "PR #4321")

    def test_openzeppelin_extractor_multi_digit_ids(self) -> None:
        """H-10 and H-11 parse correctly (validates 2-digit ID handling)."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["oz_multi_digit_ids.pdf"]
        )
        findings = pdf_finding_extractor.extract_openzeppelin_findings(result)
        self.assertEqual(len(findings), 2)
        ids = sorted([f.finding_id for f in findings])
        self.assertEqual(ids, ["H-10", "H-11"])
        indices = sorted([f.finding_index for f in findings])
        self.assertEqual(indices, [10, 11])
        # Status mix across the two findings.
        status_set = {f.resolution_status for f in findings}
        self.assertEqual(status_set, {"Fixed", "Acknowledged"})

    def test_openzeppelin_extractor_mitigation_label_alt_resolution(self) -> None:
        """``Mitigation: Fixed in PR #888`` is treated as the resolution source."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["oz_mitigation_label.pdf"]
        )
        findings = pdf_finding_extractor.extract_openzeppelin_findings(result)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertIsNotNone(f.mitigation)
        self.assertEqual(f.resolution_status, "Fixed")
        self.assertEqual(f.resolution_ref, "PR #888")

    def test_openzeppelin_extractor_note_tier(self) -> None:
        """N-01 finding has severity='note', verbatim='Note', code='N'."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["oz_note_tier.pdf"]
        )
        findings = pdf_finding_extractor.extract_openzeppelin_findings(result)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, "note")
        self.assertEqual(f.severity_verbatim, "Note")
        self.assertEqual(f.severity_code, "N")
        self.assertEqual(f.finding_id, "N-01")

    def test_openzeppelin_extractor_empty_pdf_zero_findings(self) -> None:
        """Empty-PDF zero-findings exit clean, no records emitted."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["oz_empty.pdf"]
        )
        findings = pdf_finding_extractor.extract_openzeppelin_findings(result)
        self.assertEqual(findings, [])

    def test_openzeppelin_extractor_malformed_no_bracketed_prefix(self) -> None:
        """Report-shaped text with no bracketed prefix emits zero findings."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["oz_malformed_no_bracketed_prefix.pdf"]
        )
        findings = pdf_finding_extractor.extract_openzeppelin_findings(result)
        self.assertEqual(findings, [])

    def test_openzeppelin_extractor_truly_malformed_pdf_returns_empty(self) -> None:
        """Garbage-bytes PDF: tool emits 0 records and exit 0."""
        tmp = Path(tempfile.mkdtemp(prefix="oz_malformed_"))
        try:
            bad_path = tmp / "broken.pdf"
            bad_path.write_bytes(b"not a real pdf header garbage payload\n" * 32)
            result = pdf_finding_extractor.extract_structured_pages(bad_path)
            findings = pdf_finding_extractor.extract_openzeppelin_findings(result)
            self.assertEqual(findings, [])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_openzeppelin_extractor_page_range_and_confidence_bounded(self) -> None:
        """Page-range and confidence-score sanity-bounds preserved."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["oz_single_h01.pdf"]
        )
        findings = pdf_finding_extractor.extract_openzeppelin_findings(result)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(len(f.page_range), 2)
        self.assertGreaterEqual(f.page_range[0], 0)
        self.assertGreaterEqual(f.page_range[1], f.page_range[0])
        self.assertGreaterEqual(f.parser_confidence, 0.3)
        self.assertLessEqual(f.parser_confidence, 1.0)

    def test_openzeppelin_extractor_resolution_helper_partially_fixed_no_ref(self) -> None:
        """Direct helper-fn check: 'Partially Fixed' (no PR ref) → ('PartiallyFixed', None)."""
        status, ref = pdf_finding_extractor._parse_openzeppelin_resolution(
            "Partially Fixed"
        )
        self.assertEqual(status, "PartiallyFixed")
        self.assertIsNone(ref)


class OpenZeppelinDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures = _openzeppelin_fixture_builder.ensure_fixtures()

    def _build_workspace(self) -> tuple[Path, Path, Path, Path]:
        tmp = Path(tempfile.mkdtemp(prefix="w24_oz_test_"))
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
        cache_target = cache_dir / "openzeppelin-audits" / pdf_filename
        cache_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(self.fixtures[fixture_key], cache_target)

    def test_iter_openzeppelin_listings_filters_by_firm_prefix(self) -> None:
        tmp, listings_dir, _, _ = self._build_workspace()
        try:
            _write_fake_listing(listings_dir, "sample.pdf", "Sample Project")
            # Non-OZ sibling should be ignored.
            non_oz = listings_dir / "trailofbits-publications__sample-123"
            non_oz.mkdir()
            (non_oz / "record.json").write_text(json.dumps({
                "function_shape": {"shape_tags": ["firm-trailofbits-publications"]},
            }), encoding="utf-8")
            handles = list(_DRIVER.iter_openzeppelin_listings(listings_dir))
            self.assertEqual(len(handles), 1)
            self.assertEqual(handles[0].firm, "openzeppelin-audits")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_driver_emits_records_for_cached_pdfs(self) -> None:
        tmp, listings_dir, cache_dir, out_dir = self._build_workspace()
        try:
            self._stage_listing(
                listings_dir, cache_dir, "single.pdf", "Sample Protocol", "oz_single_h01.pdf"
            )
            self._stage_listing(
                listings_dir, cache_dir, "ack.pdf", "Sample Bridge",
                "oz_resolution_acknowledged.pdf",
            )
            self._stage_listing(
                listings_dir, cache_dir, "partial.pdf", "Sample Lending",
                "oz_partially_fixed.pdf",
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
            # 1 + 1 + 1 = 3 findings/records.
            self.assertEqual(summary["listings_seen"], 3)
            self.assertGreaterEqual(summary["records_written"], 3)
            written_dirs = list(out_dir.iterdir())
            self.assertGreaterEqual(len(written_dirs), 3)
            for entry in written_dirs:
                self.assertTrue((entry / "record.json").is_file())
                self.assertTrue((entry / "record.yaml").is_file())
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_driver_record_has_expected_extension_fields_and_dual_tier_markers(self) -> None:
        """Schema gap workaround: record_tier=public-corpus + sibling
        verification_tier=tier-2-verified-public-archive on each emitted record."""
        tmp, listings_dir, cache_dir, out_dir = self._build_workspace()
        try:
            self._stage_listing(
                listings_dir, cache_dir, "ext_sample.pdf", "Ext Sample",
                "oz_single_h01.pdf",
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
            self.assertEqual(rec["verification_tier"], "tier-2-verified-public-archive")
            ext = rec["record_extensions"]
            self.assertEqual(ext["pdf_parser_firm_variant"], "openzeppelin")
            self.assertEqual(ext["pdf_parser_version"], pdf_finding_extractor.PARSER_VERSION)
            self.assertEqual(len(ext["pdf_blob_sha256"]), 64)
            self.assertEqual(len(ext["pdf_page_range"]), 2)
            self.assertEqual(ext["severity_code"], "H")
            self.assertEqual(ext["finding_id"], "H-01")
            self.assertEqual(ext["resolution_status"], "Fixed")
            self.assertEqual(ext["resolution_ref"], "PR #1234")
            # Synthetic fixture marker propagates.
            self.assertTrue(ext["synthetic_fixture"])
            self.assertEqual(rec["severity_at_finding"], "high")
            # record_source_url is the original https URL (percent-encoded).
            self.assertIn("https://raw.githubusercontent.com/", rec["record_source_url"])
            self.assertIn("audit-firm-finding:openzeppelin-audits:ext-sample:H-01-", rec["record_id"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_synthetic_fixture_marker_propagates_to_all_emitted_records(self) -> None:
        """Every fixture-derived emitted record carries synthetic_fixture: true."""
        tmp, listings_dir, cache_dir, out_dir = self._build_workspace()
        try:
            for fixture_key, filename, label in [
                ("oz_single_h01.pdf", "h01.pdf", "Protocol One"),
                ("oz_resolution_acknowledged.pdf", "ack.pdf", "Bridge Two"),
                ("oz_partially_fixed.pdf", "partial.pdf", "Lending Three"),
                ("oz_multi_digit_ids.pdf", "multidig.pdf", "Large Four"),
            ]:
                self._stage_listing(listings_dir, cache_dir, filename, label, fixture_key)
            _DRIVER.main([
                "--listings-dir", str(listings_dir),
                "--cache-dir", str(cache_dir),
                "--out-dir", str(out_dir),
                "--no-fetch",
            ])
            recs = [
                json.loads((p / "record.json").read_text())
                for p in out_dir.iterdir() if p.is_dir()
            ]
            self.assertGreaterEqual(len(recs), 5)  # 1+1+1+2=5 findings
            for rec in recs:
                self.assertTrue(
                    rec["record_extensions"]["synthetic_fixture"],
                    msg=f"record {rec['record_id']} missing synthetic_fixture marker",
                )
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_source_mode_dry_run_emits_json_summary(self) -> None:
        """--source <fixture-dir> --dry-run emits JSON summary, no on-disk records."""
        tmp = Path(tempfile.mkdtemp(prefix="w24_oz_source_"))
        try:
            source_dir = tmp / "oz_fixtures"
            source_dir.mkdir()
            for filename, src in self.fixtures.items():
                shutil.copy(src, source_dir / filename)
            out_dir = tmp / "emit"
            summary_path = tmp / "summary.json"
            rc = _DRIVER.main([
                "--source", str(source_dir),
                "--cache-dir", str(tmp / "cache"),
                "--out-dir", str(out_dir),
                "--no-fetch",
                "--dry-run",
                "--json-summary",
                "--summary-path", str(summary_path),
            ])
            self.assertEqual(rc, 0)
            self.assertTrue(summary_path.is_file())
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual(summary["firm"], "openzeppelin-audits")
            # 9 fixtures total. Findings: 1+6+1+1+2+1+0+0+1 = 13.
            self.assertGreaterEqual(summary["listings_seen"], 9)
            self.assertGreaterEqual(summary["findings_emitted"], 13)
            # Dry run: no records on disk.
            self.assertFalse(out_dir.is_dir() and any(out_dir.iterdir()))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_driver_skips_unreachable_pdf_with_no_fetch(self) -> None:
        """Unreachable PDF + --no-fetch: driver returns 0 and emits zero records."""
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
                self.assertFalse(any(out_dir.glob("openzeppelin-audits__*")))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_driver_percent_encodes_url_path_with_spaces(self) -> None:
        """OZ filenames can carry spaces; URL encoder must quote path component."""
        encoded = _DRIVER._percent_encode_path(
            "https://raw.githubusercontent.com/OpenZeppelin/audits/main/reports/Sample Audit (final).pdf"
        )
        self.assertIn("Sample%20Audit", encoded)
        self.assertIn("%28final%29", encoded)
        self.assertTrue(encoded.startswith("https://raw.githubusercontent.com/"))
        # Idempotent.
        encoded_twice = _DRIVER._percent_encode_path(encoded)
        self.assertEqual(encoded, encoded_twice)


if __name__ == "__main__":
    unittest.main()
