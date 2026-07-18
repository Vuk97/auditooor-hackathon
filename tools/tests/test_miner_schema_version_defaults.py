#!/usr/bin/env python3
# r36-rebuttal: registered to lane227-schema-v12-default-2026-05-26 in .auditooor/agent_pathspec.json
"""
Regression test: verify each miner emits the correct schema_version default.

Classification (lane227-schema-v12-default-2026-05-26):
  - Incident-mining shape (incident_date / amount_usd / source_url blocks) -> v1.2
  - Enrichment sidecar shape (own namespace: incident_corpus_tx_enrichment,
    defimon_tg_tx_enrichment) -> own namespace, no change
  - Per-finding hackerman shape (real audit findings from platforms) -> v1.1

Rule 37: every miner MUST carry a docstring citing 'Rule 37: this miner emits
at tier-<N>' OR a VERIFICATION_TIER constant. This test asserts the
schema_version constant only (not tier presence, which is checked by Check #72).
"""
import importlib.util
import re
import sys
import unittest
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = TOOLS_DIR.parent

V1 = "auditooor.hackerman_record.v1"
V1_1 = "auditooor.hackerman_record.v1.1"
V1_2 = "auditooor.hackerman_record.v1.2"


def _read_schema_const(miner_rel: str) -> str:
    """Extract the SCHEMA_VERSION constant value from a miner file via regex.
    Does NOT import the module (avoids side-effects and heavy deps).
    """
    path = TOOLS_DIR / miner_rel
    content = path.read_text(encoding="utf-8")
    # Match top-level constant assignment, e.g.:
    #   SCHEMA_VERSION = "auditooor.hackerman_record.v1.2"  # ...
    m = re.search(
        r'^SCHEMA_VERSION\s*=\s*["\']([^"\']+)["\']',
        content,
        re.MULTILINE,
    )
    if m:
        return m.group(1)
    return ""


def _read_inline_yaml_schema(miner_rel: str, pattern: str = r"schema_version:\s+(\S+)") -> str:
    """Extract inline YAML schema_version string from a miner that builds YAML
    by concatenating string lines (no SCHEMA_VERSION constant).
    """
    path = TOOLS_DIR / miner_rel
    content = path.read_text(encoding="utf-8")
    # The defimon miner writes lines like:
    #   "schema_version: auditooor.hackerman_record.v1.2",
    m = re.search(r'"schema_version:\s+([^"\'\\]+)"', content)
    if m:
        return m.group(1).strip()
    return ""


class TestIncidentMiningSchemaDefaults(unittest.TestCase):
    """Incident-mining miners MUST use v1.2."""

    def test_bridge_incidents(self):
        self.assertEqual(
            _read_schema_const("hackerman-etl-from-bridge-incidents.py"),
            V1_2,
            "bridge-incidents is an incident-mining miner and must default to v1.2",
        )

    def test_bridge_attacks(self):
        self.assertEqual(
            _read_schema_const("hackerman-etl-from-bridge-attacks.py"),
            V1_2,
            "bridge-attacks is an incident-mining miner and must default to v1.2",
        )

    def test_mev_exploits(self):
        self.assertEqual(
            _read_schema_const("hackerman-etl-from-mev-exploits.py"),
            V1_2,
            "mev-exploits is an incident-mining miner and must default to v1.2",
        )

    def test_mev_flashloan(self):
        self.assertEqual(
            _read_schema_const("hackerman-etl-from-mev-flashloan.py"),
            V1_2,
            "mev-flashloan is an incident-mining miner and must default to v1.2",
        )

    def test_onchain_traces(self):
        self.assertEqual(
            _read_schema_const("hackerman-etl-from-onchain-traces.py"),
            V1_2,
            "onchain-traces is an incident-mining miner and must default to v1.2",
        )

    def test_major_defi_fix_history(self):
        self.assertEqual(
            _read_schema_const("hackerman-etl-from-major-defi-fix-history.py"),
            V1_2,
            "major-defi-fix-history is an incident-mining miner and must default to v1.2",
        )

    def test_defimon_telegram_archive_miner_inline(self):
        """defimon archive miner builds YAML directly; check inline string."""
        schema = _read_inline_yaml_schema("defimon-telegram-archive-miner.py")
        self.assertEqual(
            schema,
            V1_2,
            "defimon-telegram-archive-miner emits YAML inline; must use v1.2",
        )


class TestPerFindingSchemaDefaults(unittest.TestCase):
    """Per-finding hackerman miners MUST keep v1.1 (not promoted to v1.2)."""

    V1_1_MINERS = [
        "hackerman-etl-from-cantina-reports.py",
        "hackerman-etl-from-audit-firm-pdf-pashov.py",
        "hackerman-etl-from-audit-firm-pdf-sb-security.py",
        "hackerman-etl-from-audit-firm-public-reports.py",
        "hackerman-etl-from-go-vuln-db.py",
        "hackerman-etl-from-graph-protocol-sources.py",
        "hackerman-etl-from-public-poc-harnesses.py",
        "hackerman-etl-from-rust-cargo-advisories.py",
        "hackerman-etl-from-swc-registry.py",
        "hackerman-etl-from-vyper-cve-real-source.py",
    ]

    def _check_keeps_v1_1(self, miner_rel: str) -> None:
        schema = _read_schema_const(miner_rel)
        self.assertEqual(
            schema,
            V1_1,
            f"{miner_rel} is a per-finding miner and must keep v1.1 (not promoted to v1.2)",
        )

    def test_cantina_reports(self):
        self._check_keeps_v1_1("hackerman-etl-from-cantina-reports.py")

    def test_audit_pdf_pashov(self):
        self._check_keeps_v1_1("hackerman-etl-from-audit-firm-pdf-pashov.py")

    def test_audit_pdf_sb_security(self):
        self._check_keeps_v1_1("hackerman-etl-from-audit-firm-pdf-sb-security.py")

    def test_audit_firm_public_reports(self):
        self._check_keeps_v1_1("hackerman-etl-from-audit-firm-public-reports.py")

    def test_go_vuln_db(self):
        self._check_keeps_v1_1("hackerman-etl-from-go-vuln-db.py")

    def test_graph_protocol_sources(self):
        self._check_keeps_v1_1("hackerman-etl-from-graph-protocol-sources.py")

    def test_public_poc_harnesses(self):
        self._check_keeps_v1_1("hackerman-etl-from-public-poc-harnesses.py")

    def test_rust_cargo_advisories(self):
        self._check_keeps_v1_1("hackerman-etl-from-rust-cargo-advisories.py")

    def test_swc_registry(self):
        self._check_keeps_v1_1("hackerman-etl-from-swc-registry.py")

    def test_vyper_cve_real_source(self):
        self._check_keeps_v1_1("hackerman-etl-from-vyper-cve-real-source.py")


class TestEnrichmentSidecarOwnNamespaces(unittest.TestCase):
    """Enrichment sidecars use their own schema namespaces (not hackerman_record).
    These should NOT be touched by the v1.2 promotion.
    """

    def test_incident_corpus_tx_enrichment_uses_own_namespace(self):
        path = TOOLS_DIR / "incident-corpus-tx-enrichment.py"
        content = path.read_text(encoding="utf-8")
        # Must NOT use any hackerman_record schema (uses its own namespace)
        self.assertNotIn(
            "auditooor.hackerman_record",
            content,
            "incident-corpus-tx-enrichment must not use hackerman_record schema",
        )
        # Must use its own namespace
        self.assertIn(
            "auditooor.incident_corpus_tx_enrichment",
            content,
            "incident-corpus-tx-enrichment must use its own schema namespace",
        )

    def test_defimon_tg_tx_enrichment_uses_own_namespace(self):
        path = TOOLS_DIR / "defimon-tg-tx-enrichment.py"
        content = path.read_text(encoding="utf-8")
        # This miner uses defimon_tg_tx_enrichment namespace, not hackerman_record
        # It may or may not have a SCHEMA_VERSION const; either way must not use hackerman_record
        self.assertNotIn(
            "auditooor.hackerman_record",
            content,
            "defimon-tg-tx-enrichment must not use hackerman_record schema",
        )


class TestValidatorRecognisesV1_2(unittest.TestCase):
    """hackerman-record-validate.py must list v1.2 in RECOGNISED_SCHEMA_VERSIONS."""

    def test_v1_2_in_recognised_versions(self):
        path = TOOLS_DIR / "hackerman-record-validate.py"
        content = path.read_text(encoding="utf-8")
        self.assertIn(
            "auditooor.hackerman_record.v1.2",
            content,
            "hackerman-record-validate.py must recognise v1.2",
        )
        # Also verify the doc comment cites v1.2 as canonical for incident-mining
        self.assertIn(
            "incident-mining",
            content.lower(),
            "hackerman-record-validate.py docstring must cite incident-mining as v1.2 use-case",
        )


if __name__ == "__main__":
    unittest.main()
