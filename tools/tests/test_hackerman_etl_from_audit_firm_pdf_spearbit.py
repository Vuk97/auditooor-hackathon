"""Tests for the Wave-2 W2.4 Spearbit-firm PDF deep-mine ETL.

Hermetic: synthetic Spearbit-shaped PDF fixtures are generated on demand
by ``_spearbit_fixture_builder.ensure_fixtures()`` (depends on
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

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TOOLS_DIR = REPO_ROOT / "tools"
LIB_DIR = TOOLS_DIR / "lib"
FIXTURE_PKG = REPO_ROOT / "tools" / "tests" / "fixtures" / "audit_firm_pdf_samples"

sys.path.insert(0, str(LIB_DIR))
sys.path.insert(0, str(FIXTURE_PKG))

import pdf_finding_extractor  # noqa: E402
import _spearbit_fixture_builder  # noqa: E402


def _load_driver():
    """Load the hyphenated Spearbit driver module by file path."""
    driver_path = TOOLS_DIR / "hackerman-etl-from-audit-firm-pdf-spearbit.py"
    spec = importlib.util.spec_from_file_location("w24_spearbit_driver", driver_path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules["w24_spearbit_driver"] = mod
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
    rec_dir = listings_dir / f"spearbit-portfolio__{slug}-{record_suffix}"
    rec_dir.mkdir(parents=True, exist_ok=True)
    record = {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": f"audit-firm:spearbit-portfolio:{slug}:{record_suffix}",
        "attack_class": "audit-firm-public-report",
        "bug_class": "audit-firm-public-report-index",
        "function_shape": {
            "raw_signature": f"audit-firm-report::spearbit-portfolio/{slug}",
            "shape_tags": [
                "audit-firm-public-report",
                "firm-spearbit-portfolio",
                "ext-pdf",
                f"year-{year}",
                "verification_tier:tier-2-verified-public-archive",
            ],
        },
        "required_preconditions": [
            f"Reference public audit report at https://raw.githubusercontent.com/spearbit/portfolio/main/pdfs/{pdf_filename}",
            "Source repo spearbit/portfolio",
            f"Source path pdfs/{pdf_filename}",
            "verification_tier=tier-2-verified-public-archive",
            f"Inferred project name {project_label}",
        ],
        "year": year,
    }
    (rec_dir / "record.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    return rec_dir


class SpearbitPdfExtractorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures = _spearbit_fixture_builder.ensure_fixtures()

    def test_single_finding_high_risk_pdf_yields_one_finding(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["spearbit_single_high.pdf"]
        )
        findings = pdf_finding_extractor.extract_spearbit_findings(result)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.section_id, "5.1.1")
        self.assertEqual(f.severity, "high")
        self.assertEqual(f.severity_verbatim, "High Risk")
        self.assertIn("Reentrancy", f.title)

    def test_multi_finding_one_of_each_severity(self) -> None:
        """5.1.1 C, 5.2.1 H, 5.3.1 M, 5.4.1 L, 5.5.1 Info, 5.6.1 Gas."""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["spearbit_one_of_each_severity.pdf"]
        )
        findings = pdf_finding_extractor.extract_spearbit_findings(result)
        self.assertEqual(len(findings), 6)
        sev_by_section = {f.section_id: f.severity for f in findings}
        self.assertEqual(sev_by_section["5.1.1"], "critical")
        self.assertEqual(sev_by_section["5.2.1"], "high")
        self.assertEqual(sev_by_section["5.3.1"], "medium")
        self.assertEqual(sev_by_section["5.4.1"], "low")
        self.assertEqual(sev_by_section["5.5.1"], "informational")
        self.assertEqual(sev_by_section["5.6.1"], "gas")
        # Verbatim phrase preserved for downstream provenance.
        verbatim_by_section = {f.section_id: f.severity_verbatim for f in findings}
        self.assertEqual(verbatim_by_section["5.6.1"], "Gas Optimization")
        self.assertEqual(verbatim_by_section["5.5.1"], "Informational")
        self.assertEqual(verbatim_by_section["5.1.1"], "Critical Risk")

    def test_resolution_fixed_inline_captures_status_and_note(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["spearbit_resolution_fixed_inline.pdf"]
        )
        findings = pdf_finding_extractor.extract_spearbit_findings(result)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual(f.resolution_status, "Fixed")
        self.assertIsNotNone(f.resolution_note)
        self.assertIn("commit deadbeef1234", f.resolution_note or "")

    def test_resolution_acknowledged_captures_status(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["spearbit_one_of_each_severity.pdf"]
        )
        findings = pdf_finding_extractor.extract_spearbit_findings(result)
        critical = next(f for f in findings if f.section_id == "5.1.1")
        self.assertEqual(critical.resolution_status, "Acknowledged")

    def test_resolution_disputed_captures_status_and_note(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["spearbit_resolution_disputed.pdf"]
        )
        findings = pdf_finding_extractor.extract_spearbit_findings(result)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].resolution_status, "Disputed")
        self.assertIn("admin trust", (findings[0].resolution_note or ""))

    def test_severity_row_with_extra_words_still_normalises(self) -> None:
        """``Severity: High Risk - exploitable in current parameter set``"""
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["spearbit_severity_extra_words.pdf"]
        )
        findings = pdf_finding_extractor.extract_spearbit_findings(result)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "high")
        self.assertEqual(findings[0].severity_verbatim, "High Risk")
        self.assertEqual(findings[0].resolution_status, "Acknowledged")

    def test_empty_pdf_yields_zero_findings(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["spearbit_empty.pdf"]
        )
        findings = pdf_finding_extractor.extract_spearbit_findings(result)
        self.assertEqual(findings, [])

    def test_malformed_pdf_no_section_headings_yields_zero_findings(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["spearbit_malformed_no_section_headings.pdf"]
        )
        findings = pdf_finding_extractor.extract_spearbit_findings(result)
        self.assertEqual(findings, [])

    def test_synthetic_fixture_metadata_marker_present(self) -> None:
        """Every fixture PDF must carry the synthetic_fixture marker in
        its Keywords metadata so downstream auditors can confirm the
        input was hermetic and not a real Spearbit blob."""
        import pypdf
        for name, path in self.fixtures.items():
            reader = pypdf.PdfReader(str(path))
            meta = reader.metadata or {}
            keywords = str(meta.get("/Keywords") or "")
            self.assertIn(
                "synthetic_fixture",
                keywords,
                f"{name} missing synthetic_fixture marker in /Keywords",
            )

    def test_mixed_fixture_only_catches_spearbit_shape_not_sherlock(self) -> None:
        """One Spearbit-shape finding + one Sherlock-shape decoy.

        The Spearbit parser must catch ONLY the Spearbit (X.Y.Z) entry;
        the ``## H-1:`` decoy must not match the Spearbit title regex.
        """
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["spearbit_mixed_with_sherlock_shape.pdf"]
        )
        findings = pdf_finding_extractor.extract_spearbit_findings(result)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].section_id, "5.1.1")
        self.assertNotIn("Sherlock", findings[0].title)

    def test_parser_confidence_in_valid_range(self) -> None:
        result = pdf_finding_extractor.extract_structured_pages(
            self.fixtures["spearbit_single_high.pdf"]
        )
        findings = pdf_finding_extractor.extract_spearbit_findings(result)
        for f in findings:
            self.assertGreaterEqual(f.parser_confidence, 0.3)
            self.assertLessEqual(f.parser_confidence, 1.0)
            self.assertEqual(len(f.page_range), 2)
            self.assertGreaterEqual(f.page_range[0], 0)
            self.assertGreaterEqual(f.page_range[1], f.page_range[0])


class SpearbitDriverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixtures = _spearbit_fixture_builder.ensure_fixtures()

    def _build_workspace(self) -> tuple[Path, Path, Path, Path]:
        tmp = Path(tempfile.mkdtemp(prefix="w24_spearbit_test_"))
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
        cache_target = cache_dir / "spearbit-portfolio" / pdf_filename
        cache_target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(self.fixtures[fixture_key], cache_target)

    def test_iter_spearbit_listings_filters_by_firm_prefix(self) -> None:
        tmp, listings_dir, _, _ = self._build_workspace()
        try:
            _write_fake_listing(listings_dir, "sample.pdf", "Sample Project")
            non_spearbit = listings_dir / "zellic-publications__sample-123"
            non_spearbit.mkdir()
            (non_spearbit / "record.json").write_text(json.dumps({
                "function_shape": {"shape_tags": ["firm-zellic-publications"]},
            }), encoding="utf-8")
            handles = list(_DRIVER.iter_spearbit_listings(listings_dir))
            self.assertEqual(len(handles), 1)
            self.assertEqual(handles[0].firm, "spearbit-portfolio")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_driver_emits_records_for_cached_pdf(self) -> None:
        tmp, listings_dir, cache_dir, out_dir = self._build_workspace()
        try:
            self._stage_listing(
                listings_dir, cache_dir, "sample_single.pdf", "Sample DEX",
                "spearbit_single_high.pdf",
            )
            self._stage_listing(
                listings_dir, cache_dir, "sample_multi.pdf", "Sample Lending",
                "spearbit_one_of_each_severity.pdf",
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
            self.assertEqual(summary["listings_seen"], 2)
            # 1 (single) + 6 (one of each severity) = 7 findings
            self.assertEqual(summary["findings_emitted"], 7)
            self.assertEqual(summary["records_written"], 7)
            written_dirs = list(out_dir.iterdir())
            self.assertGreaterEqual(len(written_dirs), 2)
            # Walk every report-slug dir; expect <section>.yaml + .json
            for entry in written_dirs:
                yaml_files = list(entry.glob("*.yaml"))
                json_files = list(entry.glob("*.json"))
                self.assertTrue(yaml_files, f"no .yaml in {entry}")
                self.assertEqual(len(yaml_files), len(json_files))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_record_has_expected_extension_fields(self) -> None:
        tmp, listings_dir, cache_dir, out_dir = self._build_workspace()
        try:
            self._stage_listing(
                listings_dir, cache_dir, "ext_sample.pdf", "Ext Sample",
                "spearbit_resolution_fixed_inline.pdf",
            )
            _DRIVER.main([
                "--listings-dir", str(listings_dir),
                "--cache-dir", str(cache_dir),
                "--out-dir", str(out_dir),
                "--no-fetch",
            ])
            yaml_files: list[Path] = []
            for d in out_dir.iterdir():
                if d.is_dir():
                    yaml_files.extend(d.glob("*.yaml"))
            self.assertEqual(len(yaml_files), 1)
            rec = yaml.safe_load(yaml_files[0].read_text(encoding="utf-8"))
            self.assertEqual(rec["schema_version"], "auditooor.hackerman_record.v1")
            self.assertEqual(rec["record_tier"], "public-corpus")
            self.assertEqual(rec["verification_tier"], "tier-2-verified-public-archive")
            self.assertEqual(rec["severity_at_finding"], "medium")
            ext = rec["record_extensions"]
            self.assertEqual(ext["pdf_parser_firm_variant"], "spearbit")
            self.assertEqual(ext["pdf_parser_version"], pdf_finding_extractor.PARSER_VERSION)
            self.assertEqual(ext["spearbit_section_id"], "5.1.1")
            self.assertEqual(ext["severity_verbatim"], "Medium Risk")
            self.assertEqual(ext["resolution_status"], "Fixed")
            self.assertIn("deadbeef1234", ext["resolution_note"])
            # record_source_url percent-encoding sanity.
            self.assertIn("record_source_url", rec)
            self.assertTrue(rec["record_source_url"].startswith("file:///"))
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
                self.assertFalse(any(out_dir.glob("spearbit-portfolio__*")))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
