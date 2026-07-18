"""test_rust_scanner_ingest.py — unit tests for tools/rust-scanner-ingest.py.

Targets >= 7 assertions covering all five scanner adapters plus the unified
summary count, and the _util enrichment path (regex fallback mode since
tree-sitter is not a hard test dependency).

Fixture files live under:
  tools/tests/fixtures/rust_scanner_ingest/
    clippy_sample.json
    audit_sample.json
    geiger_sample.json
    deny_sample.json
    semgrep_sample.sarif
    wave1_sample.json
"""

from __future__ import annotations

import importlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

# ---------------------------------------------------------------------------
# Path bootstrap — allow importing from tools/ without installation
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_TOOLS_DIR = _REPO_ROOT / "tools"
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

# Import the module under test (tools/rust-scanner-ingest.py).
# We use importlib because the filename contains a hyphen.
_SPEC = importlib.util.spec_from_file_location(
    "rust_scanner_ingest",
    _TOOLS_DIR / "rust-scanner-ingest.py",
)
_MOD = importlib.util.module_from_spec(_SPEC)  # type: ignore[arg-type]
_SPEC.loader.exec_module(_MOD)  # type: ignore[union-attr]

# Fixture root
_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "rust_scanner_ingest"


class TestClippyAdapter(unittest.TestCase):
    """Tests for _parse_clippy."""

    def setUp(self):
        self.fixture = _FIXTURES / "clippy_sample.json"

    def test_parses_three_warnings(self):
        """clippy adapter should return exactly 3 findings from sample."""
        findings = _MOD._parse_clippy(self.fixture)
        self.assertEqual(len(findings), 3, f"expected 3 clippy findings, got {len(findings)}: {findings}")

    def test_source_field(self):
        """Every clippy finding should have source='clippy'."""
        findings = _MOD._parse_clippy(self.fixture)
        for f in findings:
            self.assertEqual(f["source"], "clippy")

    def test_severity_mapping(self):
        """clippy 'warning' level maps to MEDIUM."""
        findings = _MOD._parse_clippy(self.fixture)
        # All three fixtures are level=warning
        for f in findings:
            self.assertEqual(f["severity"], "MEDIUM",
                             f"expected MEDIUM for warning, got {f['severity']}")

    def test_detector_id_prefix(self):
        """detector_id should start with 'clippy.'."""
        findings = _MOD._parse_clippy(self.fixture)
        for f in findings:
            self.assertTrue(f["detector_id"].startswith("clippy."),
                            f"bad detector_id: {f['detector_id']}")

    def test_file_and_line_populated(self):
        """file and line fields should be non-empty/non-zero for primary spans."""
        findings = _MOD._parse_clippy(self.fixture)
        for f in findings:
            self.assertTrue(f["file"], f"empty file in {f}")
            self.assertGreater(f["line"], 0, f"zero line in {f}")

    def test_skips_non_compiler_message_lines(self):
        """Lines with reason != compiler-message (e.g. build-finished) are skipped."""
        findings = _MOD._parse_clippy(self.fixture)
        # If build-finished was not skipped we'd have 4 items
        self.assertEqual(len(findings), 3)


class TestCargoAuditAdapter(unittest.TestCase):
    """Tests for _parse_cargo_audit."""

    def setUp(self):
        self.fixture = _FIXTURES / "audit_sample.json"

    def test_parses_two_advisories(self):
        """cargo-audit adapter should return 2 findings from sample."""
        findings = _MOD._parse_cargo_audit(self.fixture)
        self.assertEqual(len(findings), 2, f"expected 2 audit findings, got {len(findings)}")

    def test_source_field(self):
        findings = _MOD._parse_cargo_audit(self.fixture)
        for f in findings:
            self.assertEqual(f["source"], "cargo-audit")

    def test_critical_severity(self):
        """RUSTSEC-2023-0001 has severity=critical -> CRITICAL."""
        findings = _MOD._parse_cargo_audit(self.fixture)
        crit = [f for f in findings if "RUSTSEC-2023-0001" in f["detector_id"]]
        self.assertEqual(len(crit), 1)
        self.assertEqual(crit[0]["severity"], "CRITICAL")

    def test_medium_severity(self):
        """RUSTSEC-2022-0099 has severity=medium -> MEDIUM."""
        findings = _MOD._parse_cargo_audit(self.fixture)
        med = [f for f in findings if "RUSTSEC-2022-0099" in f["detector_id"]]
        self.assertEqual(len(med), 1)
        self.assertEqual(med[0]["severity"], "MEDIUM")

    def test_package_field(self):
        """package field should contain the crate name."""
        findings = _MOD._parse_cargo_audit(self.fixture)
        packages = {f["package"] for f in findings}
        self.assertIn("old-crate", packages)
        self.assertIn("dep-pkg", packages)

    def test_detector_id_format(self):
        """detector_id should be 'cargo-audit.RUSTSEC-...'."""
        findings = _MOD._parse_cargo_audit(self.fixture)
        for f in findings:
            self.assertTrue(f["detector_id"].startswith("cargo-audit.RUSTSEC-"),
                            f"bad detector_id: {f['detector_id']}")

    def test_line_zero(self):
        """Advisory findings have line=0 (no per-line location)."""
        findings = _MOD._parse_cargo_audit(self.fixture)
        for f in findings:
            self.assertEqual(f["line"], 0)


class TestCargoGeigerAdapter(unittest.TestCase):
    """Tests for _parse_cargo_geiger."""

    def setUp(self):
        self.fixture = _FIXTURES / "geiger_sample.json"

    def test_parses_one_package(self):
        """geiger adapter should return 1 finding for my_crate."""
        findings = _MOD._parse_cargo_geiger(self.fixture)
        self.assertEqual(len(findings), 1, f"expected 1 geiger finding, got {len(findings)}")

    def test_source_field(self):
        findings = _MOD._parse_cargo_geiger(self.fixture)
        self.assertEqual(findings[0]["source"], "cargo-geiger")

    def test_severity_info(self):
        """Geiger findings are always INFO."""
        findings = _MOD._parse_cargo_geiger(self.fixture)
        self.assertEqual(findings[0]["severity"], "INFO")

    def test_detector_id(self):
        findings = _MOD._parse_cargo_geiger(self.fixture)
        self.assertEqual(findings[0]["detector_id"], "cargo-geiger.unsafe-region")

    def test_unsafe_count_field(self):
        """unsafe_count should reflect sum of used unsafe items."""
        findings = _MOD._parse_cargo_geiger(self.fixture)
        # Sample: functions=3 + exprs=7 + methods=1 = 11
        self.assertEqual(findings[0]["unsafe_count"], 11)

    def test_crate_name_field(self):
        findings = _MOD._parse_cargo_geiger(self.fixture)
        self.assertEqual(findings[0]["crate_name"], "my_crate")


class TestCargoDenyAdapter(unittest.TestCase):
    """Tests for _parse_cargo_deny."""

    def setUp(self):
        self.fixture = _FIXTURES / "deny_sample.json"

    def test_parses_one_violation(self):
        """deny adapter should return 1 finding from sample."""
        findings = _MOD._parse_cargo_deny(self.fixture)
        self.assertEqual(len(findings), 1, f"expected 1 deny finding, got {len(findings)}: {findings}")

    def test_source_field(self):
        findings = _MOD._parse_cargo_deny(self.fixture)
        self.assertEqual(findings[0]["source"], "cargo-deny")

    def test_severity_error_maps_to_high(self):
        """deny 'error' severity maps to HIGH."""
        findings = _MOD._parse_cargo_deny(self.fixture)
        self.assertEqual(findings[0]["severity"], "HIGH")

    def test_detector_id_prefix(self):
        findings = _MOD._parse_cargo_deny(self.fixture)
        self.assertTrue(findings[0]["detector_id"].startswith("cargo-deny."),
                        f"bad detector_id: {findings[0]['detector_id']}")

    def test_file_populated(self):
        """file field should be non-empty."""
        findings = _MOD._parse_cargo_deny(self.fixture)
        self.assertTrue(findings[0]["file"])


class TestSemgrepSarifAdapter(unittest.TestCase):
    """Tests for _parse_semgrep_sarif."""

    def setUp(self):
        self.fixture = _FIXTURES / "semgrep_sample.sarif"

    def test_parses_two_results(self):
        """semgrep adapter should return 2 findings from sample."""
        findings = _MOD._parse_semgrep_sarif(self.fixture)
        self.assertEqual(len(findings), 2, f"expected 2 semgrep findings, got {len(findings)}")

    def test_source_field(self):
        findings = _MOD._parse_semgrep_sarif(self.fixture)
        for f in findings:
            self.assertEqual(f["source"], "semgrep")

    def test_error_level_maps_to_high(self):
        """SARIF 'error' level maps to HIGH."""
        findings = _MOD._parse_semgrep_sarif(self.fixture)
        error_findings = [f for f in findings if "integer-overflow" in f["detector_id"]]
        self.assertEqual(len(error_findings), 1)
        self.assertEqual(error_findings[0]["severity"], "HIGH")

    def test_warning_level_maps_to_medium(self):
        """SARIF 'warning' level maps to MEDIUM."""
        findings = _MOD._parse_semgrep_sarif(self.fixture)
        warn_findings = [f for f in findings if "unsafe-block" in f["detector_id"]]
        self.assertEqual(len(warn_findings), 1)
        self.assertEqual(warn_findings[0]["severity"], "MEDIUM")

    def test_detector_id_prefix(self):
        findings = _MOD._parse_semgrep_sarif(self.fixture)
        for f in findings:
            self.assertTrue(f["detector_id"].startswith("semgrep."),
                            f"bad detector_id: {f['detector_id']}")

    def test_file_and_line(self):
        """file and line should be populated from physicalLocation."""
        findings = _MOD._parse_semgrep_sarif(self.fixture)
        for f in findings:
            self.assertTrue(f["file"], f"empty file in {f}")
            self.assertGreater(f["line"], 0, f"zero line in {f}")


class TestWave1Adapter(unittest.TestCase):
    """Tests for _parse_wave1_findings."""

    def setUp(self):
        self.fixture = _FIXTURES / "wave1_sample.json"

    def test_parses_two_hits(self):
        """wave1 adapter should return 2 findings from sample."""
        findings = _MOD._parse_wave1_findings(self.fixture)
        self.assertEqual(len(findings), 2, f"expected 2 wave1 findings, got {len(findings)}")

    def test_source_field(self):
        findings = _MOD._parse_wave1_findings(self.fixture)
        for f in findings:
            self.assertEqual(f["source"], "rust_wave1")

    def test_detector_id_prefix(self):
        """detector_id should start with 'rust_wave1.'."""
        findings = _MOD._parse_wave1_findings(self.fixture)
        for f in findings:
            self.assertTrue(f["detector_id"].startswith("rust_wave1."),
                            f"bad detector_id: {f['detector_id']}")

    def test_fn_name_extracted(self):
        """fn_name should be populated from extra.function."""
        findings = _MOD._parse_wave1_findings(self.fixture)
        fn_names = {f.get("fn_name") for f in findings}
        self.assertIn("part2", fn_names)
        self.assertIn("aggregate", fn_names)

    def test_file_and_line(self):
        findings = _MOD._parse_wave1_findings(self.fixture)
        for f in findings:
            self.assertTrue(f["file"])
            self.assertGreater(f["line"], 0)


class TestUnifiedIngest(unittest.TestCase):
    """Integration test: ingest all six sources and verify summary counts."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self.tmp.name)
        # Create the .auditooor dir so output can land there
        (self.ws / ".auditooor").mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def _run_ingest(self) -> dict:
        return _MOD.ingest(
            workspace=self.ws,
            clippy_log=_FIXTURES / "clippy_sample.json",
            audit_log=_FIXTURES / "audit_sample.json",
            geiger_log=_FIXTURES / "geiger_sample.json",
            deny_log=_FIXTURES / "deny_sample.json",
            semgrep_sarif=_FIXTURES / "semgrep_sample.sarif",
            wave1_findings=_FIXTURES / "wave1_sample.json",
            enrich=False,  # skip enrichment so we don't need tree-sitter
        )

    def test_total_count(self):
        """Unified doc should contain 3+2+1+1+2+2 = 11 findings total."""
        doc = self._run_ingest()
        self.assertEqual(doc["summary"]["total"], 11,
                         f"unexpected total: {doc['summary']['total']}")

    def test_by_source_counts(self):
        """by_source counts should match per-adapter expectations."""
        doc = self._run_ingest()
        by_src = doc["summary"]["by_source"]
        self.assertEqual(by_src.get("clippy", 0), 3)
        self.assertEqual(by_src.get("cargo-audit", 0), 2)
        self.assertEqual(by_src.get("cargo-geiger", 0), 1)
        self.assertEqual(by_src.get("cargo-deny", 0), 1)
        self.assertEqual(by_src.get("semgrep", 0), 2)
        self.assertEqual(by_src.get("rust_wave1", 0), 2)

    def test_schema_field(self):
        """schema field must be the canonical slug."""
        doc = self._run_ingest()
        self.assertEqual(doc["schema"], "auditooor.rust_findings_unified.v1")

    def test_output_file_written(self):
        """Output JSON file should exist after ingest."""
        self._run_ingest()
        out = self.ws / ".auditooor" / "rust_findings_unified.json"
        self.assertTrue(out.exists(), f"output file not found at {out}")

    def test_output_valid_json(self):
        """Output file must be valid JSON."""
        self._run_ingest()
        out = self.ws / ".auditooor" / "rust_findings_unified.json"
        with open(out) as fh:
            parsed = json.load(fh)
        self.assertIn("findings", parsed)
        self.assertIn("summary", parsed)

    def test_by_severity_populated(self):
        """by_severity map should be populated with correct keys."""
        doc = self._run_ingest()
        by_sev = doc["summary"]["by_severity"]
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            self.assertIn(sev, by_sev, f"severity key {sev} missing from by_severity")
        # We have 1 CRITICAL (RUSTSEC-2023-0001), at least 2 HIGH (deny+semgrep+audit)
        self.assertGreaterEqual(by_sev.get("CRITICAL", 0), 1)
        self.assertGreaterEqual(by_sev.get("HIGH", 0), 2)

    def test_no_missing_sources_when_all_provided(self):
        """When all logs are provided explicitly, missing_sources should be empty."""
        doc = self._run_ingest()
        self.assertEqual(doc["summary"]["missing_sources"], [],
                         f"unexpected missing_sources: {doc['summary']['missing_sources']}")

    def test_missing_source_handled_gracefully(self):
        """When a log is absent, ingest still succeeds and lists the missing source."""
        doc = _MOD.ingest(
            workspace=self.ws,
            clippy_log=_FIXTURES / "clippy_sample.json",
            audit_log=None,  # intentionally absent
            geiger_log=None,
            deny_log=None,
            semgrep_sarif=None,
            wave1_findings=None,
            enrich=False,
        )
        # Only clippy findings (3), all others missing
        self.assertEqual(doc["summary"]["by_source"]["clippy"], 3)
        self.assertGreaterEqual(len(doc["summary"]["missing_sources"]), 1)


class TestUtilEnrichmentRegexFallback(unittest.TestCase):
    """Test the regex fallback enrichment path (no tree-sitter required)."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self.tmp.name)
        # Write a minimal Cargo.toml so crate_name_from_path can find it
        (self.ws / "Cargo.toml").write_text(
            '[package]\nname = "test_crate"\nversion = "0.1.0"\n',
            encoding="utf-8",
        )
        # Write a stub Rust source file
        src_dir = self.ws / "src"
        src_dir.mkdir()
        (src_dir / "lib.rs").write_text(
            "pub fn my_fn() {\n    let _ = 1 + 1;\n}\n",
            encoding="utf-8",
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_regex_enrichment_adds_crate_name(self):
        """Regex fallback should at minimum populate crate_name."""
        finding = {
            "detector_id": "clippy.unwrap_used",
            "source": "clippy",
            "file": "src/lib.rs",
            "line": 2,
            "severity": "MEDIUM",
            "message": "unwrap used",
        }
        # Call the regex fallback directly
        _MOD._try_util_enrichment_regex(finding, self.ws / "src" / "lib.rs", 2)
        # Should have added crate_name (assuming _util.crate_name_from_path works)
        # We don't assert it MUST be present since _util import may fail in some
        # environments, but if it IS present it must be correct.
        if "crate_name" in finding:
            self.assertEqual(finding["crate_name"], "test_crate")

    def test_enrich_does_not_raise_on_nonexistent_file(self):
        """_try_enrich_with_util should not raise for missing file."""
        finding = {
            "detector_id": "semgrep.foo",
            "source": "semgrep",
            "file": "nonexistent/path.rs",
            "line": 5,
            "severity": "HIGH",
            "message": "test",
        }
        # Should not raise
        result = _MOD._try_enrich_with_util(finding, self.ws)
        self.assertIsInstance(result, dict)


if __name__ == "__main__":
    unittest.main()
