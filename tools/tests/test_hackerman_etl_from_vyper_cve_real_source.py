"""Tests for tools/hackerman-etl-from-vyper-cve-real-source.py.

This miner is the M14-trap-aware, real-source replacement for the
quarantined Wave-3b Vyper-CVE miner. The tests below pin the verified
facts (advisory ID, GHSA ID, affected versions, fix version, patch PR
URL, absence of all six known-fabricated CVE IDs) so the rebuild can
not silently regress to the Wave-3b fabrication pattern.

Tests are deliberately blunt - one assertion per fact - because the
Wave-3b failure mode was a fabricated static list, and the regression
guard we want is "the verified-real strings are present AND the
fabricated ones are absent".
"""
from __future__ import annotations

import importlib.util
import json
import re
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-vyper-cve-real-source.py"
VALIDATOR_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"


# Six CVE IDs the Wave-3b miner fabricated. None of these may appear in
# any record this tool emits.
FABRICATED_CVE_IDS_SHOULD_NOT_APPEAR = (
    "CVE-2022-37937",
    "CVE-2023-32674",
    "CVE-2023-30547",
    "CVE-2024-22417",
    "CVE-2024-24563",
    "CVE-2023-46247",
)

# Real verified facts (manually checked against NVD + GHSA on 2026-05-16).
REAL_CVE = "CVE-2023-39363"
REAL_GHSA = "GHSA-5824-cm3x-3c38"
REAL_AFFECTED_VERSIONS = ("0.2.15", "0.2.16", "0.3.0")
REAL_FIX_VERSION = "0.3.1"
REAL_NVD_URL = "https://nvd.nist.gov/vuln/detail/CVE-2023-39363"
REAL_GHSA_URL = (
    "https://github.com/vyperlang/vyper/security/advisories/"
    "GHSA-5824-cm3x-3c38"
)
REAL_PATCH_PR_URL = "https://github.com/vyperlang/vyper/pull/2439"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class HackermanEtlFromVyperCveRealSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tool = _load(
            TOOL_PATH, "_hackerman_etl_from_vyper_cve_real_source"
        )
        cls.validator = _load(
            VALIDATOR_PATH, "_validator_for_vyper_cve_real_source"
        )

    # ------------------------------------------------------------------
    # Verified-source constants.
    # ------------------------------------------------------------------
    def test_constants_pin_real_source_urls_verbatim(self) -> None:
        """The tool must hard-code the exact NVD / GHSA / patch-PR URLs the
        brief specifies. If any of these mutate without re-verification
        against the live source, the regression guard fires.
        """
        self.assertEqual(self.tool.CVE_ID, REAL_CVE)
        self.assertEqual(self.tool.GHSA_ID, REAL_GHSA)
        self.assertEqual(self.tool.NVD_SOURCE_URL, REAL_NVD_URL)
        self.assertEqual(self.tool.GHSA_SOURCE_URL, REAL_GHSA_URL)
        self.assertEqual(self.tool.PATCH_PR_URL, REAL_PATCH_PR_URL)
        self.assertEqual(
            tuple(self.tool.AFFECTED_VERSIONS), REAL_AFFECTED_VERSIONS
        )
        self.assertEqual(self.tool.FIX_VERSION, REAL_FIX_VERSION)

    def test_source_urls_match_documented_pattern(self) -> None:
        """Each source URL must match the per-source pattern the brief
        specifies: nvd.nist.gov for the CVE, github.com/vyperlang for
        the GHSA, github.com/vyperlang/vyper/pull/<n> for the patch PR.
        """
        self.assertRegex(
            self.tool.NVD_SOURCE_URL,
            r"^https://nvd\.nist\.gov/vuln/detail/CVE-\d{4}-\d{4,}$",
        )
        self.assertRegex(
            self.tool.GHSA_SOURCE_URL,
            r"^https://github\.com/vyperlang/vyper/security/advisories/GHSA-",
        )
        self.assertRegex(
            self.tool.PATCH_PR_URL,
            r"^https://github\.com/vyperlang/vyper/pull/\d+$",
        )

    # ------------------------------------------------------------------
    # Record-set shape.
    # ------------------------------------------------------------------
    def test_default_build_emits_three_version_records_plus_incident(
        self,
    ) -> None:
        records = self.tool.build_all_records(include_incident=True)
        self.assertEqual(len(records), 4)
        version_ids = {
            f"vyper-cve-2023-39363-v{v}" for v in REAL_AFFECTED_VERSIONS
        }
        actual_ids = {r["record_id"] for r in records}
        self.assertTrue(version_ids.issubset(actual_ids))
        self.assertIn(
            "vyper-cve-2023-39363-incident-curve-2023-07-30", actual_ids
        )

    def test_no_incident_build_emits_three_records_only(self) -> None:
        records = self.tool.build_all_records(include_incident=False)
        self.assertEqual(len(records), 3)
        for r in records:
            self.assertNotIn("incident", r["record_id"])

    # ------------------------------------------------------------------
    # Per-record required fields.
    # ------------------------------------------------------------------
    def test_every_record_has_cve_ghsa_source_url_and_extensions(
        self,
    ) -> None:
        """Each record must carry cve_id, ghsa_id, record_source_url,
        verification_tier, and the brief-required record_extensions
        block with ghsa_source_url, patch_pr_url, cve_provenance,
        verification_label.
        """
        records = self.tool.build_all_records(include_incident=True)
        for r in records:
            with self.subTest(record_id=r["record_id"]):
                self.assertEqual(r["cve_id"], REAL_CVE)
                self.assertEqual(r["ghsa_id"], REAL_GHSA)
                self.assertEqual(r["record_source_url"], REAL_NVD_URL)
                self.assertEqual(
                    r["verification_tier"],
                    "tier-2-verified-public-archive",
                )
                ext = r["record_extensions"]
                self.assertEqual(ext["ghsa_source_url"], REAL_GHSA_URL)
                self.assertEqual(ext["patch_pr_url"], REAL_PATCH_PR_URL)
                self.assertIn(
                    "manually-verified", ext["cve_provenance"]
                )
                self.assertEqual(
                    ext["verification_label"],
                    "tier-1-officially-disclosed",
                )

    def test_records_carry_critical_severity_per_ghsa(self) -> None:
        """GHSA-5824-cm3x-3c38 carries `severity=critical` and CVSS 9.3;
        the records must reflect this verbatim. NVD lists CVSS Base 9.3.
        """
        records = self.tool.build_all_records(include_incident=True)
        for r in records:
            self.assertEqual(r["severity_at_finding"], "critical")
            self.assertEqual(
                r["record_extensions"]["cvss_base_score"], 9.3
            )

    # ------------------------------------------------------------------
    # No fabricated CVE references.
    # ------------------------------------------------------------------
    def test_no_record_references_any_fabricated_cve_id(self) -> None:
        records = self.tool.build_all_records(include_incident=True)
        serialised = json.dumps(records)
        for fab in FABRICATED_CVE_IDS_SHOULD_NOT_APPEAR:
            self.assertNotIn(
                fab,
                serialised,
                f"forbidden fabricated CVE id {fab} leaked into a record",
            )

    def test_no_real_record_carries_synthetic_fixture_marker(self) -> None:
        """The brief explicitly mandates that real records must NOT carry
        `record_extensions.synthetic_fixture: true`. Synthetic test
        fixtures (none exist in this tool today) would carry it; real
        records must not.
        """
        records = self.tool.build_all_records(include_incident=True)
        for r in records:
            with self.subTest(record_id=r["record_id"]):
                self.assertNotIn(
                    "synthetic_fixture", r["record_extensions"]
                )

    # ------------------------------------------------------------------
    # Schema validation.
    # ------------------------------------------------------------------
    def test_every_record_validates_against_v1_1_schema(self) -> None:
        records = self.tool.build_all_records(include_incident=True)
        for r in records:
            with self.subTest(record_id=r["record_id"]):
                errors = self.validator.validate_doc(dict(r))
                self.assertEqual(errors, [])

    # ------------------------------------------------------------------
    # Dry-run + write flow.
    # ------------------------------------------------------------------
    def test_dry_run_emits_no_files_but_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rc = self.tool.main([
                "--out", tmp, "--dry-run", "--json-summary"
            ])
            self.assertEqual(rc, 0)
            # Directory should not have been populated.
            self.assertEqual(list(Path(tmp).glob("*.yaml")), [])

    def test_write_flow_emits_exactly_4_yaml_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rc = self.tool.main(["--out", tmp])
            self.assertEqual(rc, 0)
            files = sorted(Path(tmp).glob("*.yaml"))
            self.assertEqual(len(files), 4)
            stems = {f.stem for f in files}
            for version in REAL_AFFECTED_VERSIONS:
                self.assertIn(f"vyper-cve-2023-39363-v{version}", stems)
            self.assertIn(
                "vyper-cve-2023-39363-incident-curve-2023-07-30", stems
            )


if __name__ == "__main__":
    unittest.main()
