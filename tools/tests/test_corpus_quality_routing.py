#!/usr/bin/env python3
"""Tests for tools/corpus-quality-routing.py (J3 full-corpus quality routing).

Covers:
  - empty corpus
  - usable_for_hunting bucket
  - advisory_context_only bucket
  - blocked bucket (multiple blocked_class values)
  - work-queue routing and naming
  - bounded-row cap (MAX_ROWS_PER_QUEUE)
  - JSON schema field presence
  - malformed record handling
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "corpus-quality-routing.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("_corpus_quality_routing", str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()

# ---------------------------------------------------------------------------
# Helpers to build synthetic record YAML in tempdir
# ---------------------------------------------------------------------------

BASE_RECORD = """\
schema_version: auditooor.hackerman_record.v1.1
record_id: {record_id}
source_audit_ref: {source_ref}
target_domain: lending
target_language: solidity
target_repo: {target_repo}
target_component: SomeComponent
function_shape:
  raw_signature: "function foo()"
  shape_tags:
    - access-control
    {extra_tags}
bug_class: {bug_class}
attack_class: {attack_class}
attacker_role: unprivileged
attacker_action_sequence: attacker calls foo
required_preconditions:
  - funded protocol
impact_class: theft
impact_actor: arbitrary-user
impact_dollar_class: "$100K-$1M"
fix_pattern: enforce signer
fix_anti_pattern_avoided: trusting caller
severity_at_finding: high
year: {year}
record_tier: {record_tier}
source_extraction_confidence: {confidence}
source_extraction_method: corpus-etl
cross_language_analogues: []
related_records: []
verification_tier: {verification_tier}
"""


def make_record(
    tmpdir: Path,
    record_id: str,
    *,
    source_ref: str = "sherlock:2024-foo:001",
    target_repo: str = "example/repo",
    bug_class: str = "access-control",
    attack_class: str = "admin-bypass",
    year: int = 2024,
    record_tier: str = "public-corpus",
    confidence: float = 0.85,
    verification_tier: str = "tier-2-verified-public-archive",
    extra_tags: str = "",
    extra_fields: str = "",
) -> Path:
    """Write a synthetic hackerman record YAML to tmpdir."""
    text = BASE_RECORD.format(
        record_id=record_id,
        source_ref=source_ref,
        target_repo=target_repo,
        bug_class=bug_class,
        attack_class=attack_class,
        year=year,
        record_tier=record_tier,
        confidence=confidence,
        verification_tier=verification_tier,
        extra_tags=extra_tags,
    )
    if extra_fields:
        text += extra_fields + "\n"
    slug = record_id.replace(":", "-").replace("/", "-")[:60]
    out = tmpdir / f"{slug}.yaml"
    out.write_text(text, encoding="utf-8")
    return out


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestEmptyCorpus(unittest.TestCase):
    """Empty tags dir produces zero-count report with correct schema."""

    def test_empty_dir(self):
        with tempfile.TemporaryDirectory() as td:
            report = MOD.run_scan(Path(td))
        self.assertEqual(report["schema"], MOD.SCHEMA_ID)
        self.assertEqual(report["summary"]["total_records_scanned"], 0)
        self.assertEqual(report["bucket_counts"][MOD.BUCKET_USABLE], 0)
        self.assertEqual(report["bucket_counts"][MOD.BUCKET_ADVISORY], 0)
        self.assertEqual(report["bucket_counts"][MOD.BUCKET_BLOCKED], 0)
        self.assertEqual(report["work_queues"], [])


class TestUsableForHunting(unittest.TestCase):
    """tier-2 records with real repo, known year, non-dark class -> usable."""

    def test_tier2_record_is_usable(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            make_record(tdp, "test:usable:001",
                        verification_tier="tier-2-verified-public-archive",
                        year=2024,
                        bug_class="access-control",
                        attack_class="admin-bypass")
            report = MOD.run_scan(tdp)
        self.assertEqual(report["bucket_counts"][MOD.BUCKET_USABLE], 1)
        self.assertEqual(report["bucket_counts"][MOD.BUCKET_BLOCKED], 0)

    def test_tier1_api_record_is_usable(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            make_record(tdp, "immunefi:12345:aabbccdd",
                        source_ref="immunefi:12345:aabbccdd",
                        verification_tier="tier-1-verified-realtime-api",
                        year=2023,
                        bug_class="reentrancy",
                        attack_class="reentrancy-classic")
            report = MOD.run_scan(tdp)
        self.assertEqual(report["bucket_counts"][MOD.BUCKET_USABLE], 1)
        self.assertEqual(report["bucket_counts"][MOD.BUCKET_BLOCKED], 0)


class TestAdvisoryContextOnly(unittest.TestCase):
    """tier-3 records route to advisory_context_only."""

    def test_tier3_record_is_advisory(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            make_record(tdp, "test:advisory:001",
                        verification_tier="tier-3-synthetic-taxonomy-anchored",
                        year=2024,
                        attack_class="admin-bypass")
            report = MOD.run_scan(tdp)
        self.assertEqual(report["bucket_counts"][MOD.BUCKET_ADVISORY], 1)
        self.assertEqual(report["bucket_counts"][MOD.BUCKET_BLOCKED], 0)


class TestBlockedDarkAuditFirm(unittest.TestCase):
    """Audit-firm-public-report-index records -> dark_audit_firm_report_no_extraction."""

    def test_dark_audit_firm_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            make_record(tdp, "audit-firm:pashov:report:abc123",
                        source_ref="audit-firm:pashov:some-report.pdf",
                        bug_class="audit-firm-public-report-index",
                        attack_class="audit-firm-public-report",
                        verification_tier="tier-2-verified-public-archive")
            report = MOD.run_scan(tdp)
        self.assertEqual(report["bucket_counts"][MOD.BUCKET_BLOCKED], 1)
        self.assertIn(MOD.BC_DARK_AUDIT_FIRM, report["blocked_class_counts"])
        # Check work queue appears
        wq_names = [q["work_queue"] for q in report["work_queues"]]
        self.assertIn(MOD.WORK_QUEUES[MOD.BC_DARK_AUDIT_FIRM], wq_names)


class TestBlockedSyntheticFixture(unittest.TestCase):
    """tier-4 bundled fixture records -> synthetic_fixture_only."""

    def test_tier4_fixture_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            make_record(tdp, "fixture:test:001",
                        verification_tier="tier-4-bundled-fixture",
                        year=2024,
                        attack_class="admin-bypass")
            report = MOD.run_scan(tdp)
        self.assertEqual(report["bucket_counts"][MOD.BUCKET_BLOCKED], 1)
        self.assertIn(MOD.BC_SYNTHETIC_FIXTURE, report["blocked_class_counts"])

    def test_dsl_pattern_synthetic_provenance_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            text = """\
schema_version: auditooor.hackerman_record.v1.1
record_id: dsl:pattern:foo
source_audit_ref: dsl:pattern:foo
target_domain: lending
target_language: solidity
target_repo: unknown/dsl-synthetic
function_shape:
  raw_signature: "function foo()"
  shape_tags: []
bug_class: storage-collision
attack_class: proxy-storage-collision
attacker_role: unprivileged
attacker_action_sequence: call foo
required_preconditions: []
impact_class: theft
impact_actor: arbitrary-user
impact_dollar_class: ">=$1M"
fix_pattern: fix it
fix_anti_pattern_avoided: bad thing
severity_at_finding: critical
year: 2024
record_tier: public-corpus
source_extraction_confidence: 0.9
source_extraction_method: corpus-etl
extraction_provenance: dsl_pattern_synthesis
cross_language_analogues: []
related_records: []
verification_tier: tier-2-verified-public-archive
"""
            (Path(td) / "dsl_pattern_foo.yaml").write_text(text, encoding="utf-8")
            report = MOD.run_scan(Path(td))
        self.assertEqual(report["bucket_counts"][MOD.BUCKET_BLOCKED], 1)
        self.assertIn(MOD.BC_SYNTHETIC_FIXTURE, report["blocked_class_counts"])


class TestBlockedTemplateAnalogue(unittest.TestCase):
    """corpus-mined records with unknown target_repo -> template_analogue_no_provenance."""

    def test_corpus_mined_unknown_repo_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            make_record(tdp, "corpus-mined:slice_ah.md:L37:S16:d6715fca62fc",
                        source_ref="corpus-mined:slice_ah.md:L37:S16",
                        target_repo="unknown",
                        verification_tier="tier-3-synthetic-taxonomy-anchored",
                        year=2000,
                        attack_class="state-accounting-drift")
            report = MOD.run_scan(tdp)
        self.assertEqual(report["bucket_counts"][MOD.BUCKET_BLOCKED], 1)
        self.assertIn(MOD.BC_TEMPLATE_ANALOGUE, report["blocked_class_counts"])


class TestBlockedLowConfidence(unittest.TestCase):
    """Records with extraction confidence < 0.5 -> low_confidence_prose_draft."""

    def test_low_confidence_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            make_record(tdp, "test:lowconf:001",
                        verification_tier="tier-2-verified-public-archive",
                        confidence=0.3,
                        year=2024,
                        attack_class="admin-bypass")
            report = MOD.run_scan(tdp)
        self.assertEqual(report["bucket_counts"][MOD.BUCKET_BLOCKED], 1)
        self.assertIn(MOD.BC_LOW_CONFIDENCE_PROSE, report["blocked_class_counts"])
        wq_names = [q["work_queue"] for q in report["work_queues"]]
        self.assertIn(MOD.WORK_QUEUES[MOD.BC_LOW_CONFIDENCE_PROSE], wq_names)


class TestBlockedUnknownYear(unittest.TestCase):
    """Records with year=2000 sentinel and no source URL -> unknown_year_no_source_date."""

    def test_unknown_year_no_url_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            make_record(tdp, "test:unknownyear:001",
                        verification_tier="tier-2-verified-public-archive",
                        year=2000,
                        attack_class="admin-bypass")
            # No record_source_url in default record
            report = MOD.run_scan(tdp)
        self.assertEqual(report["bucket_counts"][MOD.BUCKET_BLOCKED], 1)
        self.assertIn(MOD.BC_UNKNOWN_YEAR, report["blocked_class_counts"])
        wq_names = [q["work_queue"] for q in report["work_queues"]]
        self.assertIn(MOD.WORK_QUEUES[MOD.BC_UNKNOWN_YEAR], wq_names)

    def test_unknown_year_with_source_url_not_blocked(self):
        """year=2000 but has record_source_url - should not be blocked for unknown year."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            make_record(tdp, "test:unknownyear:002",
                        verification_tier="tier-2-verified-public-archive",
                        year=2000,
                        attack_class="admin-bypass",
                        extra_fields="record_source_url: https://example.com/audit.pdf")
            report = MOD.run_scan(tdp)
        # Should NOT be blocked for unknown_year
        bc_counts = report["blocked_class_counts"]
        self.assertNotIn(MOD.BC_UNKNOWN_YEAR, bc_counts)


class TestBlockedWeakTier(unittest.TestCase):
    """tier-5 quarantine and missing tier -> missing_or_weak_verification_tier."""

    def test_tier5_quarantine_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            make_record(tdp, "quarantine:test:001",
                        verification_tier="tier-5-quarantine",
                        year=2024,
                        attack_class="admin-bypass")
            report = MOD.run_scan(tdp)
        self.assertEqual(report["bucket_counts"][MOD.BUCKET_BLOCKED], 1)
        self.assertIn(MOD.BC_WEAK_TIER, report["blocked_class_counts"])

    def test_missing_tier_blocked(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            make_record(tdp, "test:notier:001",
                        verification_tier="",
                        year=2024,
                        attack_class="admin-bypass")
            report = MOD.run_scan(tdp)
        self.assertEqual(report["bucket_counts"][MOD.BUCKET_BLOCKED], 1)
        self.assertIn(MOD.BC_WEAK_TIER, report["blocked_class_counts"])


class TestWorkQueueBoundedCap(unittest.TestCase):
    """Work queue example_rows list is capped at MAX_ROWS_PER_QUEUE."""

    def test_bounded_row_cap(self):
        cap = MOD.MAX_ROWS_PER_QUEUE
        n = cap + 5  # write more records than the cap
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            for i in range(n):
                make_record(tdp, f"audit-firm:pashov:report:{i:04d}",
                            source_ref=f"audit-firm:pashov:report-{i}.pdf",
                            bug_class="audit-firm-public-report-index",
                            attack_class="audit-firm-public-report",
                            verification_tier="tier-2-verified-public-archive")
            report = MOD.run_scan(tdp)

        blocked_count = report["bucket_counts"][MOD.BUCKET_BLOCKED]
        self.assertEqual(blocked_count, n)

        # Find the matching queue entry
        target_queue = MOD.WORK_QUEUES[MOD.BC_DARK_AUDIT_FIRM]
        queue_entry = next(
            (q for q in report["work_queues"] if q["work_queue"] == target_queue),
            None,
        )
        self.assertIsNotNone(queue_entry)
        self.assertEqual(queue_entry["total_rows"], n)
        self.assertLessEqual(len(queue_entry["example_rows"]), cap)
        self.assertEqual(queue_entry["example_rows_capped_at"], cap)


class TestJsonSchemaFields(unittest.TestCase):
    """JSON output contains required schema fields."""

    def test_json_schema_presence(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            make_record(tdp, "test:schema:001",
                        verification_tier="tier-2-verified-public-archive",
                        year=2024)
            report = MOD.run_scan(tdp)

        self.assertIn("schema", report)
        self.assertEqual(report["schema"], MOD.SCHEMA_ID)
        self.assertIn("summary", report)
        self.assertIn("bucket_counts", report)
        self.assertIn("blocked_class_counts", report)
        self.assertIn("work_queues", report)

        # summary sub-fields
        summary = report["summary"]
        self.assertIn("total_records_scanned", summary)
        self.assertIn("malformed_routed_to_blocked", summary)
        self.assertIn("taxonomy_orphan_classes_loaded", summary)

        # bucket_counts keys
        bc = report["bucket_counts"]
        self.assertIn(MOD.BUCKET_USABLE, bc)
        self.assertIn(MOD.BUCKET_ADVISORY, bc)
        self.assertIn(MOD.BUCKET_BLOCKED, bc)

    def test_work_queue_entry_fields(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            make_record(tdp, "audit-firm:zellic:report:deadbeef",
                        source_ref="audit-firm:zellic:report.pdf",
                        bug_class="audit-firm-public-report-index",
                        attack_class="audit-firm-public-report",
                        verification_tier="tier-2-verified-public-archive")
            report = MOD.run_scan(tdp)

        self.assertEqual(len(report["work_queues"]), 1)
        entry = report["work_queues"][0]
        self.assertIn("work_queue", entry)
        self.assertIn("blocked_class", entry)
        self.assertIn("total_rows", entry)
        self.assertIn("example_rows_capped_at", entry)
        self.assertIn("example_rows", entry)


class TestMalformedRecordHandling(unittest.TestCase):
    """Malformed/non-hackerman records do not crash the scan."""

    def test_non_hackerman_yaml_ignored(self):
        """A YAML file that is NOT a hackerman record is silently skipped."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            # Write a non-hackerman YAML (wrong schema_version)
            (tdp / "not_hackerman.yaml").write_text(
                "verdict_id: foo\nbug_class: storage-collision\n",
                encoding="utf-8"
            )
            # Also write a valid record
            make_record(tdp, "test:valid:001",
                        verification_tier="tier-2-verified-public-archive",
                        year=2024)
            report = MOD.run_scan(tdp)

        # Only the valid hackerman record is counted
        self.assertEqual(report["summary"]["total_records_scanned"], 1)

    def test_completely_invalid_yaml_skipped(self):
        """An unreadable YAML file is silently skipped."""
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            (tdp / "invalid.yaml").write_text(
                "{{{{not valid yaml: [[[",
                encoding="utf-8"
            )
            make_record(tdp, "test:valid:002",
                        verification_tier="tier-2-verified-public-archive",
                        year=2024)
            report = MOD.run_scan(tdp)

        self.assertEqual(report["summary"]["total_records_scanned"], 1)


class TestSubtreesFilter(unittest.TestCase):
    """--subtrees filter limits scan to specified subdirectories."""

    def test_subtrees_filter(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            # Create two subtree dirs
            sub_a = tdp / "subA"
            sub_a.mkdir()
            sub_b = tdp / "subB"
            sub_b.mkdir()
            make_record(sub_a, "test:subtree-a:001",
                        verification_tier="tier-2-verified-public-archive",
                        year=2024)
            make_record(sub_b, "test:subtree-b:001",
                        verification_tier="tier-3-synthetic-taxonomy-anchored",
                        year=2024)
            # Scan only subA
            report = MOD.run_scan(tdp, subtrees=["subA"])

        self.assertEqual(report["summary"]["total_records_scanned"], 1)
        self.assertEqual(report["bucket_counts"][MOD.BUCKET_USABLE], 1)
        self.assertEqual(report["bucket_counts"][MOD.BUCKET_ADVISORY], 0)


class TestLimitFlag(unittest.TestCase):
    """--limit caps records scanned."""

    def test_limit_caps_scan(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            for i in range(10):
                make_record(tdp, f"test:limit:{i:02d}",
                            verification_tier="tier-2-verified-public-archive",
                            year=2024)
            report = MOD.run_scan(tdp, limit=3)

        self.assertLessEqual(report["summary"]["total_records_scanned"], 3)


class TestMultipleBuckets(unittest.TestCase):
    """Mixed corpus produces counts in all three buckets."""

    def test_mixed_corpus(self):
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            # usable
            make_record(tdp, "test:usable:001",
                        verification_tier="tier-2-verified-public-archive",
                        year=2024)
            # advisory
            make_record(tdp, "test:advisory:001",
                        verification_tier="tier-3-synthetic-taxonomy-anchored",
                        year=2024)
            # blocked - dark audit firm
            make_record(tdp, "audit-firm:pashov:report:abc123",
                        bug_class="audit-firm-public-report-index",
                        attack_class="audit-firm-public-report",
                        verification_tier="tier-2-verified-public-archive")
            # blocked - low confidence
            make_record(tdp, "test:lowconf:001",
                        verification_tier="tier-2-verified-public-archive",
                        confidence=0.2,
                        year=2024)
            report = MOD.run_scan(tdp)

        self.assertGreaterEqual(report["bucket_counts"][MOD.BUCKET_USABLE], 1)
        self.assertGreaterEqual(report["bucket_counts"][MOD.BUCKET_ADVISORY], 1)
        self.assertGreaterEqual(report["bucket_counts"][MOD.BUCKET_BLOCKED], 2)
        total = sum(report["bucket_counts"].values())
        self.assertEqual(total, report["summary"]["total_records_scanned"])


class TestWorkQueueVocabulary(unittest.TestCase):
    """All blocked classes map to exactly one named work queue."""

    def test_all_blocked_classes_have_queue(self):
        for bc in [
            MOD.BC_DARK_AUDIT_FIRM,
            MOD.BC_LOW_CONFIDENCE_PROSE,
            MOD.BC_MISSING_PROOF,
            MOD.BC_WEAK_TIER,
            MOD.BC_ORPHAN_ATTACK,
            MOD.BC_UNKNOWN_YEAR,
            MOD.BC_STALE_SOURCE,
            MOD.BC_SYNTHETIC_FIXTURE,
            MOD.BC_TEMPLATE_ANALOGUE,
        ]:
            self.assertIn(bc, MOD.WORK_QUEUES, f"{bc} missing from WORK_QUEUES")
            self.assertTrue(MOD.WORK_QUEUES[bc], f"{bc} maps to empty queue name")


if __name__ == "__main__":
    unittest.main()
