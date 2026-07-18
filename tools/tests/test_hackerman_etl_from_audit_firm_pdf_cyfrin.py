"""Tests for the Wave-2 W2.4 Cyfrin-firm PDF deep-mine ETL.

Hermetic: synthetic Cyfrin-shaped PDF fixtures are generated on demand
by ``_cyfrin_fixture_builder.ensure_fixtures()`` (depends on
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
import _cyfrin_fixture_builder  # noqa: E402


def _load_driver():
    """Load the hyphenated Cyfrin driver module by file path."""
    driver_path = TOOLS_DIR / "hackerman-etl-from-audit-firm-pdf-cyfrin.py"
    spec = importlib.util.spec_from_file_location("w24_cyfrin_driver", driver_path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules["w24_cyfrin_driver"] = mod
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
    rec_dir = listings_dir / f"cyfrin-audits__{slug}-{record_suffix}"
    rec_dir.mkdir(parents=True, exist_ok=True)
    record = {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": f"audit-firm:cyfrin-audits:{slug}:{record_suffix}",
        "attack_class": "audit-firm-public-report",
        "bug_class": "audit-firm-public-report-index",
        "function_shape": {
            "raw_signature": f"audit-firm-report::cyfrin-audits/{slug}",
            "shape_tags": [
                "audit-firm-public-report",
                "firm-cyfrin-audits",
                "ext-pdf",
                f"year-{year}",
                "verification_tier:tier-2-verified-public-archive",
            ],
        },
        "required_preconditions": [
            f"Reference public audit report at https://raw.githubusercontent.com/Cyfrin/audit-reports/main/reports/{pdf_filename}",
            "Source repo Cyfrin/audit-reports",
            f"Source path reports/{pdf_filename}",
            "verification_tier=tier-2-verified-public-archive",
            f"Inferred project name {project_label}",
        ],
        "year": year,
    }
    (rec_dir / "record.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    return rec_dir


class CyfrinExtractorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures = _cyfrin_fixture_builder.ensure_fixtures()

    def test_extract_pages_returns_pages_for_one_high_pdf(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["cyfrin_one_high.pdf"]
        )
        self.assertGreater(len(result.pages), 0)
        self.assertEqual(result.backend, "pypdf")
        joined = "\n".join(p.raw_text for p in result.pages)
        self.assertIn("Reentrancy", joined)
        self.assertIn("[H-1]", joined)

    def test_cyfrin_extractor_single_finding_high(self) -> None:
        """Single-finding PDF (H-1) produces exactly one finding tagged High."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["cyfrin_one_high.pdf"]
        )
        findings = pdf_finding_extractor.extract_cyfrin_findings(result)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.severity_code, "H")
        self.assertEqual(f.finding_id, "H-1")
        self.assertIn("Reentrancy", f.title)
        # Impact section captured separately from Description.
        self.assertIn("re-entrant", f.impact)
        # PoC section captured.
        self.assertIn("malicious token", f.proof_of_concept)
        # Recommendation captured.
        self.assertIn("checks-effects-interactions", f.recommendation.lower().replace("\n", " "))
        # Lines cited extracted.
        files = {entry["file"] for entry in f.lines_cited}
        self.assertTrue(any(p.endswith("Vault.sol") for p in files))

    def test_cyfrin_extractor_multi_finding_one_of_each_severity(self) -> None:
        """Multi-finding PDF: C-1, H-1, M-1, L-1, I-1, G-1 (one of each)."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["cyfrin_one_of_each_severity.pdf"]
        )
        findings = pdf_finding_extractor.extract_cyfrin_findings(result)
        self.assertEqual(len(findings), 6)
        codes = sorted([f.severity_code for f in findings])
        self.assertEqual(codes, ["C", "G", "H", "I", "L", "M"])
        sev_by_code = {f.severity_code: f.severity for f in findings}
        self.assertEqual(sev_by_code["C"], "critical")
        self.assertEqual(sev_by_code["H"], "high")
        self.assertEqual(sev_by_code["M"], "medium")
        self.assertEqual(sev_by_code["L"], "low")
        self.assertEqual(sev_by_code["I"], "informational")
        self.assertEqual(sev_by_code["G"], "gas")

    def test_cyfrin_extractor_resolution_fixed_with_commit_ref(self) -> None:
        """``Resolution: Fixed in commit <sha>`` is parsed into both fields."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["cyfrin_one_high.pdf"]
        )
        findings = pdf_finding_extractor.extract_cyfrin_findings(result)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.resolution_status, "Fixed")
        self.assertIsNotNone(f.resolution_commit_ref)
        self.assertTrue(f.resolution_commit_ref.startswith("1a2b3c4d"))
        # 40-char SHA preserved.
        self.assertEqual(len(f.resolution_commit_ref), 40)

    def test_cyfrin_extractor_resolution_acknowledged_no_commit(self) -> None:
        """``Status: Acknowledged`` (bare, no commit ref) parses cleanly."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["cyfrin_acknowledged_no_commit.pdf"]
        )
        findings = pdf_finding_extractor.extract_cyfrin_findings(result)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.resolution_status, "Acknowledged")
        self.assertIsNone(f.resolution_commit_ref)

    def test_cyfrin_extractor_critical_with_poc(self) -> None:
        """Critical [C-1] with PoC subsection: severity=critical, PoC captured."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["cyfrin_one_of_each_severity.pdf"]
        )
        findings = pdf_finding_extractor.extract_cyfrin_findings(result)
        crit = [f for f in findings if f.severity_code == "C"]
        self.assertEqual(len(crit), 1)
        c1 = crit[0]
        self.assertEqual(c1.severity, "critical")
        self.assertEqual(c1.finding_id, "C-1")
        # Impact section populated.
        self.assertIn("attacker", c1.impact.lower())

    def test_cyfrin_extractor_gas_finding_no_impact(self) -> None:
        """Gas severity (G-N) with no Impact section: parser does not flag impact-missing as error."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["cyfrin_gas_finding_no_impact.pdf"]
        )
        findings = pdf_finding_extractor.extract_cyfrin_findings(result)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, "gas")
        self.assertEqual(f.severity_code, "G")
        # Gas findings legitimately omit Impact; parser should NOT add
        # the missing-impact warning for severity=G.
        self.assertNotIn("missing-impact", f.parser_warnings)
        self.assertEqual(f.impact, "")

    def test_cyfrin_extractor_informational_singleparagraph(self) -> None:
        """Informational [I-1] with a single-paragraph body."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["cyfrin_informational_singleparagraph.pdf"]
        )
        findings = pdf_finding_extractor.extract_cyfrin_findings(result)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.severity, "informational")
        self.assertEqual(f.severity_code, "I")
        self.assertTrue(f.description)
        self.assertTrue(f.recommendation)

    def test_cyfrin_extractor_empty_pdf_zero_findings(self) -> None:
        """Empty-PDF zero-findings exit clean, no records emitted."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["cyfrin_no_findings.pdf"]
        )
        findings = pdf_finding_extractor.extract_cyfrin_findings(result)
        self.assertEqual(findings, [])

    def test_cyfrin_extractor_malformed_pdf_returns_empty(self) -> None:
        """Malformed PDF (unparseable header): tool emits 0 records and exit 0.

        The extractor returns ``ExtractionResult(pages=[], diagnostics=[...])``
        and the driver translates that into ``skipped: malformed-header``
        with zero records emitted (rc=0).
        """
        tmp = Path(tempfile.mkdtemp(prefix="cyfrin_malformed_"))
        try:
            bad_path = tmp / "broken.pdf"
            # Not a real PDF: header bytes are nonsense.
            bad_path.write_bytes(b"not a real pdf header garbage payload\n" * 32)
            result = pdf_finding_extractor.extract_structured_pages(bad_path)
            # Either: no pages with diagnostics, OR ~empty pages w/ no findings.
            findings = pdf_finding_extractor.extract_cyfrin_findings(result)
            self.assertEqual(findings, [])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_cyfrin_extractor_extension_field_visible_in_extracted_finding(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["cyfrin_one_high.pdf"]
        )
        findings = pdf_finding_extractor.extract_cyfrin_findings(result)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(len(f.page_range), 2)
        self.assertGreaterEqual(f.page_range[0], 0)
        self.assertGreaterEqual(f.page_range[1], f.page_range[0])
        self.assertGreaterEqual(f.parser_confidence, 0.3)
        self.assertLessEqual(f.parser_confidence, 1.0)


class CyfrinDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures = _cyfrin_fixture_builder.ensure_fixtures()

    def _build_workspace(self) -> tuple[Path, Path, Path, Path]:
        tmp = Path(tempfile.mkdtemp(prefix="w24_cyfrin_test_"))
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
        cache_target = cache_dir / "cyfrin-audits" / pdf_filename
        cache_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(self.fixtures[fixture_key], cache_target)

    def test_iter_cyfrin_listings_filters_by_firm_prefix(self) -> None:
        tmp, listings_dir, _, _ = self._build_workspace()
        try:
            _write_fake_listing(listings_dir, "sample.pdf", "Sample Project")
            # Non-Cyfrin sibling should be ignored.
            non_cyfrin = listings_dir / "trailofbits-publications__sample-123"
            non_cyfrin.mkdir()
            (non_cyfrin / "record.json").write_text(json.dumps({
                "function_shape": {"shape_tags": ["firm-trailofbits-publications"]},
            }), encoding="utf-8")
            handles = list(_DRIVER.iter_cyfrin_listings(listings_dir))
            self.assertEqual(len(handles), 1)
            self.assertEqual(handles[0].firm, "cyfrin-audits")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_driver_emits_records_for_cached_pdfs(self) -> None:
        tmp, listings_dir, cache_dir, out_dir = self._build_workspace()
        try:
            self._stage_listing(
                listings_dir, cache_dir, "high.pdf", "Sample Vault", "cyfrin_one_high.pdf"
            )
            self._stage_listing(
                listings_dir, cache_dir, "ack.pdf", "Sample Bridge", "cyfrin_acknowledged_no_commit.pdf"
            )
            self._stage_listing(
                listings_dir, cache_dir, "gas.pdf", "Sample AMM", "cyfrin_gas_finding_no_impact.pdf"
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
                self.assertFalse(any(out_dir.glob("cyfrin-audits__*")))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_record_has_expected_extension_fields_and_dual_tier_markers(self) -> None:
        """W2.7.a-precedent schema-enum gap: record_tier=public-corpus AND
        verification_tier=tier-2-verified-public-archive co-exist on each
        emitted record."""
        tmp, listings_dir, cache_dir, out_dir = self._build_workspace()
        try:
            self._stage_listing(
                listings_dir, cache_dir, "ext_sample.pdf", "Ext Sample", "cyfrin_one_high.pdf"
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
            self.assertEqual(ext["pdf_parser_firm_variant"], "cyfrin")
            self.assertEqual(ext["pdf_parser_version"], pdf_finding_extractor.PARSER_VERSION)
            self.assertEqual(len(ext["pdf_blob_sha256"]), 64)
            self.assertEqual(len(ext["pdf_page_range"]), 2)
            self.assertEqual(ext["severity_code"], "H")
            self.assertEqual(ext["finding_id"], "H-1")
            self.assertEqual(ext["resolution_status"], "Fixed")
            self.assertIsNotNone(ext["resolution_commit_ref"])
            # Synthetic fixture marker propagates.
            self.assertTrue(ext["synthetic_fixture"])
            self.assertEqual(rec["severity_at_finding"], "high")
            # record_source_url is URL-path percent-encoded.
            self.assertIn("https://raw.githubusercontent.com/", rec["record_source_url"])
            self.assertIn("audit-firm-finding:cyfrin-audits:ext-sample:H-1-", rec["record_id"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_synthetic_fixture_marker_check(self) -> None:
        """Every fixture-derived emitted record carries synthetic_fixture: true."""
        tmp, listings_dir, cache_dir, out_dir = self._build_workspace()
        try:
            for fixture_key, filename, label in [
                ("cyfrin_one_high.pdf", "one_high.pdf", "Vault One"),
                ("cyfrin_acknowledged_no_commit.pdf", "ack.pdf", "Bridge Two"),
                ("cyfrin_gas_finding_no_impact.pdf", "gas.pdf", "AMM Three"),
                ("cyfrin_informational_singleparagraph.pdf", "info.pdf", "Token Four"),
            ]:
                self._stage_listing(listings_dir, cache_dir, filename, label, fixture_key)
            _DRIVER.main([
                "--listings-dir", str(listings_dir),
                "--cache-dir", str(cache_dir),
                "--out-dir", str(out_dir),
                "--no-fetch",
            ])
            recs = [json.loads((p / "record.json").read_text()) for p in out_dir.iterdir() if p.is_dir()]
            self.assertGreaterEqual(len(recs), 4)
            for rec in recs:
                self.assertTrue(
                    rec["record_extensions"]["synthetic_fixture"],
                    msg=f"record {rec['record_id']} missing synthetic_fixture marker",
                )
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_source_mode_dry_run_emits_json_summary(self) -> None:
        """Operator brief CLI: --source <fixture-dir> --dry-run emits JSON."""
        tmp = Path(tempfile.mkdtemp(prefix="w24_cyfrin_source_"))
        try:
            # Stage fixture PDFs into a flat dir for --source mode.
            source_dir = tmp / "cyfrin_fixtures"
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
            # 6 fixtures: 1 (high) + 6 (one-of-each) + 1 (ack) + 1 (info)
            # + 1 (gas) + 0 (no-findings) = 10 findings.
            self.assertEqual(summary["firm"], "cyfrin-audits")
            self.assertGreaterEqual(summary["listings_seen"], 6)
            self.assertGreaterEqual(summary["findings_emitted"], 10)
            # Dry run: no records on disk.
            self.assertFalse(out_dir.is_dir() and any(out_dir.iterdir()))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_resolution_helper_handles_short_commit_ref(self) -> None:
        """Lower-bound (6 chars) commit ref still parses."""
        status, ref = pdf_finding_extractor._parse_cyfrin_resolution(
            "Resolution: Fixed in commit abcdef"
        )
        self.assertEqual(status, "Fixed")
        self.assertEqual(ref, "abcdef")

    def test_driver_percent_encodes_url_path_with_spaces(self) -> None:
        """Cyfrin filenames can carry spaces; URL encoder must quote path."""
        encoded = _DRIVER._percent_encode_path(
            "https://raw.githubusercontent.com/Cyfrin/audit-reports/main/reports/Spark Security Review (final).pdf"
        )
        self.assertIn("Spark%20Security%20Review", encoded)
        self.assertIn("%28final%29", encoded)
        self.assertTrue(encoded.startswith("https://raw.githubusercontent.com/"))
        # Idempotent.
        encoded_twice = _DRIVER._percent_encode_path(encoded)
        self.assertEqual(encoded, encoded_twice)


if __name__ == "__main__":
    unittest.main()
