"""Tests for the Wave-2 W2.4 ChainSecurity-firm PDF deep-mine ETL.

Hermetic: synthetic ChainSecurity-shaped PDF fixtures are generated on
demand by ``_chainsecurity_fixture_builder.ensure_fixtures()`` (depends
on ``reportlab``) and the driver runs against a temporary
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
import _chainsecurity_fixture_builder  # noqa: E402


def _load_driver():
    """Load the hyphenated ChainSecurity driver module by file path."""
    driver_path = TOOLS_DIR / "hackerman-etl-from-audit-firm-pdf-chainsecurity.py"
    spec = importlib.util.spec_from_file_location("w24_chainsec_driver", driver_path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules["w24_chainsec_driver"] = mod
    spec.loader.exec_module(mod)
    return mod


_DRIVER = _load_driver()


def _write_fake_listing(
    listings_dir: Path,
    pdf_filename: str,
    project_label: str,
    year: int = 2024,
    record_suffix: str = "feedfacecafe",
) -> Path:
    slug = project_label.lower().replace(" ", "_")
    rec_dir = listings_dir / f"chainsecurity-audits__{slug}-{record_suffix}"
    rec_dir.mkdir(parents=True, exist_ok=True)
    record = {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": f"audit-firm:chainsecurity-audits:{slug}:{record_suffix}",
        "attack_class": "audit-firm-public-report",
        "bug_class": "audit-firm-public-report-index",
        "function_shape": {
            "raw_signature": f"audit-firm-report::chainsecurity-audits/{slug}",
            "shape_tags": [
                "audit-firm-public-report",
                "firm-chainsecurity-audits",
                "ext-pdf",
                f"year-{year}",
                "verification_tier:tier-2-verified-public-archive",
            ],
        },
        "required_preconditions": [
            f"Reference public audit report at https://raw.githubusercontent.com/ChainSecurity/audits/main/reports/{pdf_filename}",
            "Source repo ChainSecurity/audits",
            f"Source path reports/{pdf_filename}",
            "verification_tier=tier-2-verified-public-archive",
            f"Inferred project name {project_label}",
        ],
        "year": year,
    }
    (rec_dir / "record.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    return rec_dir


class ChainSecurityExtractorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures = _chainsecurity_fixture_builder.ensure_fixtures()

    def test_extract_pages_returns_pages_for_one_high_pdf(self) -> None:
        """Sanity check: pypdf can read the fixture and finds CS-1 text."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["chainsec_one_high.pdf"]
        )
        self.assertGreater(len(result.pages), 0)
        self.assertEqual(result.backend, "pypdf")
        joined = "\n".join(p.raw_text for p in result.pages)
        self.assertIn("Reentrancy", joined)
        self.assertIn("[CS-1]", joined)

    def test_chainsec_extractor_single_finding_high(self) -> None:
        """Single CS-1 High finding parses with correct fields."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["chainsec_one_high.pdf"]
        )
        findings = pdf_finding_extractor.extract_chainsecurity_findings(result)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.severity_verbatim, "High")
        self.assertEqual(f.finding_id, "CS-1")
        self.assertIn("Reentrancy", f.title)
        self.assertIn("withdraw function", f.description)
        # Acceptance criteria captured separately from description.
        self.assertIsNotNone(f.acceptance_criteria)
        self.assertIn("internal balances", f.acceptance_criteria)
        self.assertIn("checks-effects-interactions", f.recommendation)
        # Lines cited extracted.
        files = {entry["file"] for entry in f.lines_cited}
        self.assertTrue(any(p.endswith("Lending.sol") for p in files))

    def test_chainsec_extractor_multi_finding_one_of_each_severity(self) -> None:
        """Multi-finding PDF: CS-1 C, CS-2 H, CS-3 M, CS-4 L, CS-5 I."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["chainsec_multi_severity.pdf"]
        )
        findings = pdf_finding_extractor.extract_chainsecurity_findings(result)
        self.assertEqual(len(findings), 5)
        ids = sorted([f.finding_id for f in findings])
        self.assertEqual(ids, ["CS-1", "CS-2", "CS-3", "CS-4", "CS-5"])
        sev_by_id = {f.finding_id: f.severity for f in findings}
        self.assertEqual(sev_by_id["CS-1"], "critical")
        self.assertEqual(sev_by_id["CS-2"], "high")
        self.assertEqual(sev_by_id["CS-3"], "medium")
        self.assertEqual(sev_by_id["CS-4"], "low")
        self.assertEqual(sev_by_id["CS-5"], "informational")

    def test_chainsec_resolution_code_corrected(self) -> None:
        """``Code Corrected`` verbatim normalises to CodeCorrected."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["chainsec_one_high.pdf"]
        )
        findings = pdf_finding_extractor.extract_chainsecurity_findings(result)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.resolution_status, "CodeCorrected")
        self.assertIsNotNone(f.resolution_note)
        self.assertIn("Code Corrected", f.resolution_note)

    def test_chainsec_resolution_acknowledged(self) -> None:
        """``Acknowledged`` verbatim parses to Acknowledged status."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["chainsec_multi_severity.pdf"]
        )
        findings = pdf_finding_extractor.extract_chainsecurity_findings(result)
        cs3 = next(f for f in findings if f.finding_id == "CS-3")
        self.assertEqual(cs3.resolution_status, "Acknowledged")
        cs5 = next(f for f in findings if f.finding_id == "CS-5")
        self.assertEqual(cs5.resolution_status, "Acknowledged")

    def test_chainsec_resolution_risk_accepted(self) -> None:
        """``Risk Accepted`` verbatim parses to RiskAccepted status."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["chainsec_risk_accepted.pdf"]
        )
        findings = pdf_finding_extractor.extract_chainsecurity_findings(result)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.resolution_status, "RiskAccepted")
        self.assertIsNotNone(f.resolution_note)
        self.assertIn("Risk Accepted", f.resolution_note)
        # Also verify multi-severity CS-4 (Low) carries Risk Accepted.
        multi = pdf_finding_extractor.extract_chainsecurity_findings(
            pdf_finding_extractor.extract_structured_pages(
                self.fixtures["chainsec_multi_severity.pdf"]
            )
        )
        cs4 = next(f for f in multi if f.finding_id == "CS-4")
        self.assertEqual(cs4.resolution_status, "RiskAccepted")

    def test_chainsec_best_practice_normalized_to_informational(self) -> None:
        """``Best Practice`` severity label normalises to informational tier."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["chainsec_best_practice.pdf"]
        )
        findings = pdf_finding_extractor.extract_chainsecurity_findings(result)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, "informational")
        self.assertEqual(f.severity_verbatim, "Best Practice")

    def test_chainsec_acceptance_criteria_captured_separately(self) -> None:
        """Acceptance Criteria subsection captured separately from Description."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["chainsec_one_high.pdf"]
        )
        findings = pdf_finding_extractor.extract_chainsecurity_findings(result)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        # Description should NOT contain the acceptance criteria text.
        self.assertNotIn("must update internal balances strictly", f.description)
        # Acceptance criteria is captured into its own field.
        self.assertIsNotNone(f.acceptance_criteria)
        self.assertIn("must update internal balances strictly", f.acceptance_criteria)

    def test_chainsec_extractor_empty_pdf_zero_findings(self) -> None:
        """Empty-PDF zero-findings exit clean, no records emitted."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["chainsec_no_findings.pdf"]
        )
        findings = pdf_finding_extractor.extract_chainsecurity_findings(result)
        self.assertEqual(findings, [])

    def test_chainsec_extractor_malformed_pdf_returns_empty(self) -> None:
        """Malformed PDF (no CS-N prefix) returns empty without raising."""
        tmp = Path(tempfile.mkdtemp(prefix="chainsec_malformed_"))
        try:
            bad_path = tmp / "broken.pdf"
            bad_path.write_bytes(b"not a real pdf header garbage payload\n" * 32)
            result = pdf_finding_extractor.extract_structured_pages(bad_path)
            findings = pdf_finding_extractor.extract_chainsecurity_findings(result)
            self.assertEqual(findings, [])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_chainsec_resolution_helper_handles_verbatim_variants(self) -> None:
        """``_parse_chainsec_resolution`` handles all three canonical verbatim phrases."""
        s, n = pdf_finding_extractor._parse_chainsec_resolution("Code Corrected")
        self.assertEqual(s, "CodeCorrected")
        self.assertEqual(n, "Code Corrected")
        s, n = pdf_finding_extractor._parse_chainsec_resolution("Risk Accepted")
        self.assertEqual(s, "RiskAccepted")
        self.assertEqual(n, "Risk Accepted")
        s, n = pdf_finding_extractor._parse_chainsec_resolution("Acknowledged")
        self.assertEqual(s, "Acknowledged")
        self.assertEqual(n, "Acknowledged")
        # Unknown phrase: None.
        s, n = pdf_finding_extractor._parse_chainsec_resolution("unrelated text only")
        self.assertIsNone(s)
        self.assertIsNone(n)


class ChainSecurityDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures = _chainsecurity_fixture_builder.ensure_fixtures()

    def _build_workspace(self) -> tuple[Path, Path, Path, Path]:
        tmp = Path(tempfile.mkdtemp(prefix="w24_chainsec_test_"))
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
        cache_target = cache_dir / "chainsecurity-audits" / pdf_filename
        cache_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(self.fixtures[fixture_key], cache_target)

    def test_iter_chainsec_listings_filters_by_firm_prefix(self) -> None:
        tmp, listings_dir, _, _ = self._build_workspace()
        try:
            _write_fake_listing(listings_dir, "sample.pdf", "Sample Project")
            # Non-ChainSecurity sibling should be ignored.
            non_cs = listings_dir / "cyfrin-audits__sample-123"
            non_cs.mkdir()
            (non_cs / "record.json").write_text(json.dumps({
                "function_shape": {"shape_tags": ["firm-cyfrin-audits"]},
            }), encoding="utf-8")
            handles = list(_DRIVER.iter_chainsecurity_listings(listings_dir))
            self.assertEqual(len(handles), 1)
            self.assertEqual(handles[0].firm, "chainsecurity-audits")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_driver_emits_records_for_cached_pdfs(self) -> None:
        tmp, listings_dir, cache_dir, out_dir = self._build_workspace()
        try:
            self._stage_listing(
                listings_dir, cache_dir, "high.pdf", "Sample Lending", "chainsec_one_high.pdf"
            )
            self._stage_listing(
                listings_dir, cache_dir, "risk.pdf", "Sample Bridge", "chainsec_risk_accepted.pdf"
            )
            self._stage_listing(
                listings_dir, cache_dir, "bp.pdf", "Sample Token", "chainsec_best_practice.pdf"
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
            self.assertEqual(summary["listings_seen"], 3)
            # 1 + 1 + 1 = 3 findings/records.
            self.assertGreaterEqual(summary["records_written"], 3)
            written_dirs = list(out_dir.iterdir())
            self.assertGreaterEqual(len(written_dirs), 3)
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
                self.assertFalse(any(out_dir.glob("chainsecurity-audits__*")))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_record_has_expected_extension_fields_and_dual_tier_markers(self) -> None:
        """W2.7.a-precedent schema-enum gap: record_tier=public-corpus AND
        verification_tier=tier-2-verified-public-archive co-exist on each
        emitted record."""
        tmp, listings_dir, cache_dir, out_dir = self._build_workspace()
        try:
            self._stage_listing(
                listings_dir, cache_dir, "ext_sample.pdf", "Ext Sample", "chainsec_one_high.pdf"
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
            self.assertEqual(ext["pdf_parser_firm_variant"], "chainsecurity")
            self.assertEqual(ext["pdf_parser_version"], pdf_finding_extractor.PARSER_VERSION)
            self.assertEqual(len(ext["pdf_blob_sha256"]), 64)
            self.assertEqual(len(ext["pdf_page_range"]), 2)
            self.assertEqual(ext["finding_id"], "CS-1")
            self.assertEqual(ext["resolution_status"], "CodeCorrected")
            self.assertIsNotNone(ext["acceptance_criteria"])
            self.assertIn("internal balances", ext["acceptance_criteria"])
            # Synthetic fixture marker propagates.
            self.assertTrue(ext["synthetic_fixture"])
            self.assertEqual(rec["severity_at_finding"], "high")
            self.assertIn("https://raw.githubusercontent.com/", rec["record_source_url"])
            self.assertIn("audit-firm-finding:chainsecurity-audits:ext-sample:CS-1-", rec["record_id"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_synthetic_fixture_marker_check(self) -> None:
        """Every fixture-derived emitted record carries synthetic_fixture: true.

        Operator brief explicitly calls out a synthetic-fixture-marker test:
        each PDF carries the marker in its Keywords metadata, and the
        driver must propagate that to every emitted record.
        """
        tmp, listings_dir, cache_dir, out_dir = self._build_workspace()
        try:
            for fixture_key, filename, label in [
                ("chainsec_one_high.pdf", "one_high.pdf", "Lending One"),
                ("chainsec_risk_accepted.pdf", "risk.pdf", "Bridge Two"),
                ("chainsec_best_practice.pdf", "bp.pdf", "Token Three"),
                ("chainsec_multi_severity.pdf", "multi.pdf", "DEX Four"),
            ]:
                self._stage_listing(listings_dir, cache_dir, filename, label, fixture_key)
            _DRIVER.main([
                "--listings-dir", str(listings_dir),
                "--cache-dir", str(cache_dir),
                "--out-dir", str(out_dir),
                "--no-fetch",
            ])
            recs = [json.loads((p / "record.json").read_text()) for p in out_dir.iterdir() if p.is_dir()]
            # 1 + 1 + 1 + 5 = 8 records.
            self.assertGreaterEqual(len(recs), 8)
            for rec in recs:
                self.assertTrue(
                    rec["record_extensions"]["synthetic_fixture"],
                    msg=f"record {rec['record_id']} missing synthetic_fixture marker",
                )
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_source_mode_dry_run_emits_json_summary(self) -> None:
        """Operator brief CLI: --source <fixture-dir> --dry-run emits JSON."""
        tmp = Path(tempfile.mkdtemp(prefix="w24_chainsec_source_"))
        try:
            source_dir = tmp / "chainsec_fixtures"
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
            self.assertEqual(summary["firm"], "chainsecurity-audits")
            # 5 fixtures: 1 (high) + 5 (multi) + 1 (risk) + 1 (bp) + 0 (no-findings) = 8 findings.
            self.assertGreaterEqual(summary["listings_seen"], 5)
            self.assertGreaterEqual(summary["findings_emitted"], 8)
            # Dry run: no records on disk.
            self.assertFalse(out_dir.is_dir() and any(out_dir.iterdir()))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_driver_percent_encodes_url_path_with_spaces(self) -> None:
        """ChainSecurity filenames can carry spaces; URL encoder must quote path."""
        encoded = _DRIVER._percent_encode_path(
            "https://raw.githubusercontent.com/ChainSecurity/audits/main/reports/Spark Security Review (final).pdf"
        )
        self.assertIn("Spark%20Security%20Review", encoded)
        self.assertIn("%28final%29", encoded)
        self.assertTrue(encoded.startswith("https://raw.githubusercontent.com/"))
        # Idempotent.
        encoded_twice = _DRIVER._percent_encode_path(encoded)
        self.assertEqual(encoded, encoded_twice)


if __name__ == "__main__":
    unittest.main()
