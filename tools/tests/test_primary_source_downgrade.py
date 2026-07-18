#!/usr/bin/env python3
"""Tests for tools/primary-source-downgrade.py (I3a).

Covers:
1. official_postmortem classification
2. tx_contract_trace classification
3. audit_report classification
4. contest_judgment classification
5. blog_analysis classification + strict-mode BLOCK on secondary-only proof_grade row
6. provider_summary classification + cap at detector_seed
7. unknown type cap at hunt_context
8. blog_analysis with primary tx binding - allowed proof_grade
9. JSON schema fields validation
10. Missing subtree defensive handling (no crash, missing info emitted)
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "primary_source_downgrade",
    ROOT / "tools" / "primary-source-downgrade.py",
)
psd = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(psd)  # type: ignore[union-attr]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_tags_dir(tmp: Path, subtree: str, records: list[dict]) -> Path:
    """Write records as JSON files under tmp/<subtree>/record_N.json."""
    d = tmp / subtree
    d.mkdir(parents=True, exist_ok=True)
    for i, rec in enumerate(records):
        (d / f"record_{i}.json").write_text(json.dumps(rec), encoding="utf-8")
    return tmp


def _run(argv: list[str]) -> tuple[int, str]:
    """Run main() capturing stdout; return (exit_code, stdout_text)."""
    import io
    from contextlib import redirect_stdout
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = psd.main(argv)
    return code, buf.getvalue()


# ---------------------------------------------------------------------------
# Unit tests for _classify_source_type
# ---------------------------------------------------------------------------

class TestClassifySourceType(unittest.TestCase):

    def test_official_postmortem_via_cve_in_record_id(self):
        rec = {
            "record_id": "cve-2023-12345:some-project",
            "record_source_url": "https://example.com/advisory",
        }
        st, reason = psd._classify_source_type(rec)
        self.assertEqual(st, psd.SOURCE_TYPE_OFFICIAL_POSTMORTEM)

    def test_tx_contract_trace_via_url(self):
        rec = {
            "record_source_url": "https://etherscan.io/tx/0xabc123",
        }
        st, reason = psd._classify_source_type(rec)
        self.assertEqual(st, psd.SOURCE_TYPE_TX_CONTRACT_TRACE)

    def test_audit_report_via_spearbit_url(self):
        rec = {
            "record_source_url": "https://raw.githubusercontent.com/spearbit/portfolio/master/pdfs/Foo-Security-Review.pdf",
            "source_extraction_method": "human-curated",
        }
        st, reason = psd._classify_source_type(rec)
        self.assertEqual(st, psd.SOURCE_TYPE_AUDIT_REPORT)

    def test_contest_judgment_via_record_id_prefix(self):
        rec = {
            "record_id": "code4rena:2024-10-foo:37:abc123",
        }
        st, reason = psd._classify_source_type(rec)
        self.assertEqual(st, psd.SOURCE_TYPE_CONTEST_JUDGMENT)

    def test_contest_judgment_via_immunefi_prefix(self):
        rec = {
            "record_id": "immunefi-public:33444:6506336afd6c",
            "verification_tier": "tier-1-verified-realtime-api",
        }
        st, reason = psd._classify_source_type(rec)
        self.assertEqual(st, psd.SOURCE_TYPE_CONTEST_JUDGMENT)

    def test_blog_analysis_via_rekt_url(self):
        rec = {
            "record_source_url": "https://rekt.news/qubit-rekt",
        }
        st, reason = psd._classify_source_type(rec)
        self.assertEqual(st, psd.SOURCE_TYPE_BLOG_ANALYSIS)

    def test_blog_analysis_via_darknavy_schema(self):
        rec = {
            "schema": "auditooor.darknavy_web3_record.v1",
            "record_id": "darknavy-web3:foo:abc123",
        }
        st, reason = psd._classify_source_type(rec)
        self.assertEqual(st, psd.SOURCE_TYPE_BLOG_ANALYSIS)

    def test_provider_summary_via_defillama(self):
        rec = {
            "record_source_url": "https://defillama.com/hacks",
        }
        st, reason = psd._classify_source_type(rec)
        self.assertEqual(st, psd.SOURCE_TYPE_PROVIDER_SUMMARY)

    def test_provider_summary_via_peckshield(self):
        rec = {
            "record_source_url": "https://peckshield.com/2023/foo-hack",
        }
        st, reason = psd._classify_source_type(rec)
        self.assertEqual(st, psd.SOURCE_TYPE_PROVIDER_SUMMARY)

    def test_unknown_no_signals(self):
        rec = {
            "record_id": "some-obscure-record:abc123",
            "record_source_url": "https://totally-unknown-domain.io/article",
            "source_extraction_method": "human-curated",
        }
        st, reason = psd._classify_source_type(rec)
        self.assertEqual(st, psd.SOURCE_TYPE_UNKNOWN)

    def test_explicit_source_type_field_passthrough(self):
        rec = {
            "source_type": "tx_contract_trace",
            "record_source_url": "https://rekt.news/foo",  # would normally -> blog
        }
        st, reason = psd._classify_source_type(rec)
        self.assertEqual(st, psd.SOURCE_TYPE_TX_CONTRACT_TRACE)
        self.assertIn("explicit", reason)

    def test_defimon_blog_via_record_id_prefix(self):
        rec = {
            "record_id": "defimon-blog:yearn-yeth-hack-november-2025:solver-collapse",
        }
        st, reason = psd._classify_source_type(rec)
        self.assertEqual(st, psd.SOURCE_TYPE_BLOG_ANALYSIS)


# ---------------------------------------------------------------------------
# Unit tests for _has_primary_binding
# ---------------------------------------------------------------------------

class TestPrimaryBinding(unittest.TestCase):

    def test_tx_hash_in_required_preconditions(self):
        rec = {
            "required_preconditions": [
                "Public-exploit-tx 0xae0670e64db402a878faf09f6c5b1d9b08f0fef85788c2a51812c14a35f49ad9"
            ],
        }
        has, note = psd._has_primary_binding(rec)
        self.assertTrue(has)
        self.assertIn("tx hash", note)

    def test_cve_in_required_preconditions(self):
        rec = {
            "required_preconditions": ["CVE-2023-12345 advisory"],
        }
        has, note = psd._has_primary_binding(rec)
        self.assertTrue(has)
        self.assertIn("CVE", note)

    def test_explicit_exploit_tx_hash_field(self):
        rec = {
            "exploit_tx_hash": "0xae0670e64db402a878faf09f6c5b1d9b08f0fef85788c2a51812c14a35f49ad9",
        }
        has, note = psd._has_primary_binding(rec)
        self.assertTrue(has)

    def test_no_binding_blog_only(self):
        rec = {
            "record_source_url": "https://rekt.news/qubit-rekt",
            "notes": "tier-2 rekt post-mortem",
        }
        has, note = psd._has_primary_binding(rec)
        self.assertFalse(has)

    def test_source_audit_ref_contest_url_is_binding(self):
        rec = {
            "source_audit_ref": "https://github.com/code-423n4/2024-10-loopfi-findings/issues/37",
        }
        has, note = psd._has_primary_binding(rec)
        self.assertTrue(has)


# ---------------------------------------------------------------------------
# Unit tests for _current_evidence_grade
# ---------------------------------------------------------------------------

class TestCurrentEvidenceGrade(unittest.TestCase):

    def test_tier1_with_proof_shape_is_proof_grade(self):
        rec = {
            "verification_tier": "tier-1-verified-realtime-api",
            "required_preconditions": ["Impact listed verbatim by Immunefi disclosure: Compiler bug"],
        }
        g = psd._current_evidence_grade(rec)
        self.assertEqual(g, psd.EVIDENCE_GRADE_PROOF_GRADE)

    def test_tier2_with_proof_shape_is_proof_grade(self):
        rec = {
            "verification_tier": "tier-2-verified-public-archive",
            "attacker_action_sequence": "Attacker called QBridge.deposit() with token=0 and minted 77k qXETH",
        }
        g = psd._current_evidence_grade(rec)
        self.assertEqual(g, psd.EVIDENCE_GRADE_PROOF_GRADE)

    def test_tier3_is_detector_seed(self):
        rec = {
            "verification_tier": "tier-3-synthetic-taxonomy-anchored",
        }
        g = psd._current_evidence_grade(rec)
        self.assertEqual(g, psd.EVIDENCE_GRADE_DETECTOR_SEED)

    def test_high_quality_score_is_proof_grade(self):
        rec = {
            "record_quality_score": 4.5,
        }
        g = psd._current_evidence_grade(rec)
        self.assertEqual(g, psd.EVIDENCE_GRADE_PROOF_GRADE)

    def test_no_signals_is_hunt_context(self):
        rec = {}
        g = psd._current_evidence_grade(rec)
        self.assertEqual(g, psd.EVIDENCE_GRADE_HUNT_CONTEXT)

    def test_explicit_evidence_grade_passthrough(self):
        rec = {"evidence_grade": "detector_seed"}
        g = psd._current_evidence_grade(rec)
        self.assertEqual(g, psd.EVIDENCE_GRADE_DETECTOR_SEED)


# ---------------------------------------------------------------------------
# Integration tests: _scan over temp dirs
# ---------------------------------------------------------------------------

class TestScanViolations(unittest.TestCase):

    def _blog_proof_grade_record(self) -> dict:
        """A rekt.news (blog) record that appears proof_grade but has no primary binding."""
        return {
            "schema_version": "auditooor.hackerman_record.v1.1",
            "record_id": "post-mortem-rekt:beanstalk-rekt:f68de33cee77",
            "record_source_url": "https://rekt.news/beanstalk-rekt/",
            "source_extraction_method": "web-scrape-rekt",
            "verification_tier": "tier-2-verified-public-archive",
            "required_preconditions": ["Incident-date April 18 2022", "flash loan attack"],
            "attacker_action_sequence": "Attacker used flash loan to execute governance takeover for $181M loss",
            "record_quality_score": 3.0,
            "notes": "tier-2 rekt post-mortem; regex-extracted body",
        }

    def _blog_with_primary_binding(self) -> dict:
        """A rekt.news record that also has a tx hash binding."""
        return {
            "schema_version": "auditooor.hackerman_record.v1.1",
            "record_id": "post-mortem-rekt:qubit-rekt:334a7960215e",
            "record_source_url": "https://rekt.news/qubit-rekt",
            "source_extraction_method": "web-scrape-rekt",
            "verification_tier": "tier-2-verified-public-archive",
            "required_preconditions": [
                "Public-exploit-tx 0xae0670e64db402a878faf09f6c5b1d9b08f0fef85788c2a51812c14a35f49ad9",
                "Incident-date 2022-01-27",
            ],
            "attacker_action_sequence": "Attacker exploited QBridge deposit zero-token bypass",
            "record_quality_score": 4.0,
        }

    def _provider_summary_record(self) -> dict:
        """A defillama provider summary record."""
        return {
            "schema_version": "auditooor.hackerman_record.v1.1",
            "record_id": "defillama:hacks:foo-protocol-2023",
            "record_source_url": "https://defillama.com/hacks?project=foo",
            "source_extraction_method": "defillama-hacks-api",
            "verification_tier": "tier-3-synthetic-taxonomy-anchored",
            "notes": "provider summary only",
        }

    def _audit_report_record(self) -> dict:
        """A spearbit audit report record."""
        return {
            "schema_version": "auditooor.hackerman_record.v1.1",
            "record_id": "audit-firm:spearbit-portfolio:centrifuge-review-2024:e10c22b2e4a5",
            "record_source_url": "https://raw.githubusercontent.com/spearbit/portfolio/master/pdfs/Centrifuge-2024.pdf",
            "source_extraction_method": "corpus-etl-audit-firm",
            "verification_tier": "tier-2-verified-public-archive",
            "required_preconditions": ["audit-firm report spearbit/portfolio"],
            "attacker_action_sequence": "Audit finding: reentrancy in Centrifuge withdraw path",
            "record_quality_score": 4.2,
        }

    def test_blog_only_proof_grade_is_violation(self):
        """Blog-only record with proof_grade signals but no tx binding -> violation."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_tags_dir(tmp_path, "rekt_news_incidents", [self._blog_proof_grade_record()])
            report = psd._scan(tmp_path, ["rekt_news_incidents"], False)
        self.assertGreaterEqual(report["violations_count"], 1)
        viol = report["violations"][0]
        self.assertEqual(viol["detected_source_type"], psd.SOURCE_TYPE_BLOG_ANALYSIS)
        self.assertTrue(viol["violation"])

    def test_blog_with_primary_binding_no_violation(self):
        """Blog record WITH a tx hash binding -> permitted_grade=proof_grade -> no violation."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_tags_dir(tmp_path, "rekt_news_incidents", [self._blog_with_primary_binding()])
            report = psd._scan(tmp_path, ["rekt_news_incidents"], False)
        self.assertEqual(report["violations_count"], 0)

    def test_provider_summary_not_proof_grade_no_violation(self):
        """Provider summary with tier-3 is detector_seed, not proof_grade -> no violation."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_tags_dir(tmp_path, "defillama_hacks_delta", [self._provider_summary_record()])
            report = psd._scan(tmp_path, ["defillama_hacks_delta"], False)
        # No violation because current grade (detector_seed) <= permitted (detector_seed).
        self.assertEqual(report["violations_count"], 0)
        # Confirm source type classified correctly.
        row = None
        for sub, count in report["source_type_counts"].items():
            if sub == psd.SOURCE_TYPE_PROVIDER_SUMMARY and count > 0:
                row = True
        self.assertTrue(row, "expected provider_summary in source_type_counts")

    def test_audit_report_proof_grade_no_violation(self):
        """Audit report (primary source type) at proof_grade -> no violation."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_tags_dir(tmp_path, "audit_firm_public_reports", [self._audit_report_record()])
            report = psd._scan(tmp_path, ["audit_firm_public_reports"], False)
        self.assertEqual(report["violations_count"], 0)

    def test_unknown_type_cap(self):
        """Unknown source type with proof_grade signal -> violation (capped at hunt_context)."""
        rec = {
            "schema_version": "auditooor.hackerman_record.v1.1",
            "record_id": "some-obscure:unknown:abc123",
            "record_source_url": "https://totally-unknown-domain.io/article/foo",
            "verification_tier": "tier-2-verified-public-archive",
            "required_preconditions": ["some proof-shape content that is long enough"],
            "attacker_action_sequence": "Attacker exploited unknown path for large loss in protocol X",
        }
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_tags_dir(tmp_path, "corpus_mined", [rec])
            report = psd._scan(tmp_path, ["corpus_mined"], False)
        # Unknown source at proof_grade signals -> should be capped at hunt_context -> violation.
        self.assertGreaterEqual(report["violations_count"], 1)
        viol = report["violations"][0]
        self.assertEqual(viol["detected_source_type"], psd.SOURCE_TYPE_UNKNOWN)
        self.assertEqual(viol["permitted_grade"], psd.EVIDENCE_GRADE_HUNT_CONTEXT)

    def test_missing_subtree_no_crash(self):
        """Scanning a non-existent subtree emits it in missing_dirs without crashing."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # Add one real subtree so we get some scanned_dirs.
            _make_tags_dir(tmp_path, "rekt_news_incidents", [self._blog_with_primary_binding()])
            report = psd._scan(tmp_path, ["rekt_news_incidents", "totally_missing_subtree"], False)
        self.assertIn("totally_missing_subtree", report["missing_dirs"])
        self.assertIn("rekt_news_incidents", report["scanned_dirs"])
        self.assertGreaterEqual(report["records_scanned"], 1)

    def test_strict_mode_exits_nonzero_on_violation(self):
        """--strict flag causes exit code 1 when violations present."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_tags_dir(tmp_path, "rekt_news_incidents", [self._blog_proof_grade_record()])
            code, _ = _run([
                "--tags-dir", str(tmp_path),
                "--subtrees", "rekt_news_incidents",
                "--strict",
            ])
        self.assertEqual(code, 1)

    def test_strict_mode_exits_zero_no_violations(self):
        """--strict flag exits 0 when no violations."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_tags_dir(tmp_path, "rekt_news_incidents", [self._blog_with_primary_binding()])
            code, _ = _run([
                "--tags-dir", str(tmp_path),
                "--subtrees", "rekt_news_incidents",
                "--strict",
            ])
        self.assertEqual(code, 0)

    def test_json_output_schema_fields(self):
        """JSON output must contain all required schema fields."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_tags_dir(tmp_path, "rekt_news_incidents", [self._blog_proof_grade_record()])
            code, out = _run([
                "--tags-dir", str(tmp_path),
                "--subtrees", "rekt_news_incidents",
                "--json",
            ])
        doc = json.loads(out)
        required_keys = [
            "schema_id",
            "gate",
            "tags_dir",
            "scanned_dirs",
            "missing_dirs",
            "records_scanned",
            "violations_count",
            "source_type_counts",
            "violations",
        ]
        for k in required_keys:
            self.assertIn(k, doc, f"Missing key: {k}")
        self.assertEqual(doc["schema_id"], psd.SCHEMA_ID)
        self.assertEqual(doc["gate"], psd.GATE_NAME)
        # Violations must include required per-record keys.
        if doc["violations"]:
            v = doc["violations"][0]
            for k in ["record_path", "detected_source_type", "current_grade", "permitted_grade", "reason"]:
                self.assertIn(k, v, f"Violation row missing key: {k}")

    def test_json_violation_row_structure(self):
        """Each violation row has record_path, detected_source_type, current_grade, etc."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_tags_dir(tmp_path, "rekt_news_incidents", [self._blog_proof_grade_record()])
            _, out = _run([
                "--tags-dir", str(tmp_path),
                "--subtrees", "rekt_news_incidents",
                "--json",
            ])
        doc = json.loads(out)
        self.assertGreater(len(doc["violations"]), 0)
        v = doc["violations"][0]
        self.assertIn("record_path", v)
        self.assertIn("detected_source_type", v)
        self.assertIn("current_grade", v)
        self.assertIn("permitted_grade", v)
        self.assertIn("reason", v)
        self.assertIn("has_primary_binding", v)

    def test_empty_tags_dir_no_crash(self):
        """Empty tags dir with missing default subtrees returns gracefully."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            # Don't create any subdirs.
            report = psd._scan(tmp_path, ["nonexistent_subtree"], False)
        self.assertIn("nonexistent_subtree", report["missing_dirs"])
        self.assertEqual(report["records_scanned"], 0)
        self.assertEqual(report["violations_count"], 0)


if __name__ == "__main__":
    unittest.main()
