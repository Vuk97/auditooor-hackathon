"""Tests for tools/hackerman-schema-migration-dry-run.py (Wave-2 W2.1).

Covers >=8 cases:

 1. ``dry_run_record`` reports a verification_tier gain when the source v1
    record smuggles the tier through ``function_shape.shape_tags``.
 2. ``dry_run_record`` reports a record_source_url gain (and a precondition
    prune) when a URL is hoisted out of ``required_preconditions``.
 3. ``dry_run_record`` reports cve_id + ghsa_id gains when those tokens
    appear in scanned fields.
 4. ``dry_run_record`` reports schema_version_bumped=True for v1 input.
 5. Idempotency: ``dry_run_record`` on a v1.1 record (already populated) is
    a no-op -- would_migrate=False, gained=[] and no validation errors.
 6. ``validate_v11_additive`` flags an invalid CVE format (and the failing
    record bubbles up through ``aggregate_counts.records_failing_v11_validation``).
 7. ``aggregate_counts`` sums per-field gains, schema bumps, prune counts,
    and validation failures across many entries.
 8. ``discover_records`` returns a sorted list and ignores non-.json/.yaml
    files; ``walk_and_preview`` skips non-v1 records and unparseable files.
 9. ``render_report`` is deterministic for a fixed generated_at and includes
    the headline metrics, per-field table, and risk assessment section.
10. End-to-end ``main()`` writes the preview JSONL + report file and
    exits 0; the JSONL is line-delimited valid JSON.
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict


_HERE = Path(__file__).resolve()
_REPO = _HERE.parents[2]
_TOOL_PATH = _REPO / "tools" / "hackerman-schema-migration-dry-run.py"


def _load_tool() -> Any:
    name = "_hackerman_schema_migration_dry_run_test_mod"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, str(_TOOL_PATH))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


T = _load_tool()


def _base_v1_record() -> Dict[str, Any]:
    return {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": "audit:example:001",
        "source_audit_ref": "cantina:example-2025:1.2.3",
        "target_domain": "lending",
        "target_language": "solidity",
        "target_repo": "example/example",
        "target_component": "src/Pool.sol::deposit",
        "function_shape": {
            "raw_signature": "function deposit(uint256 amount)",
            "shape_tags": ["state-mutating", "external-callable"],
        },
        "bug_class": "missing-access-control",
        "attack_class": "unauth-state-write",
        "attacker_role": "unprivileged",
        "attacker_action_sequence": "Call deposit with any amount.",
        "required_preconditions": ["Pool deployed and not paused."],
        "impact_class": "theft",
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": ">=$1M",
        "fix_pattern": "Add onlyOwner modifier.",
        "fix_anti_pattern_avoided": "Public state writer.",
        "severity_at_finding": "high",
        "year": 2025,
        "cross_language_analogues": [],
        "related_records": [],
    }


class TestDryRunRecord(unittest.TestCase):
    def test_verification_tier_lift_reported_as_gain(self) -> None:
        rec = _base_v1_record()
        rec["function_shape"]["shape_tags"].append(
            "verification_tier:tier-2-verified-public-archive"
        )
        out = T.dry_run_record(rec)
        self.assertTrue(out["would_migrate"])
        self.assertIn("verification_tier", out["gained"])
        self.assertEqual(out["validation_errors"], [])
        self.assertEqual(
            out["diff"]["verification_tier"]["after"],
            "tier-2-verified-public-archive",
        )

    def test_record_source_url_hoist_and_precondition_prune(self) -> None:
        rec = _base_v1_record()
        rec["required_preconditions"] = [
            "See https://example.com/cve-report",
            "Pool deployed and not paused.",
        ]
        out = T.dry_run_record(rec)
        self.assertTrue(out["would_migrate"])
        self.assertIn("record_source_url", out["gained"])
        self.assertTrue(out["diff"].get("required_preconditions_pruned"))
        self.assertEqual(
            out["diff"]["required_preconditions_len_before"], 2
        )
        self.assertEqual(
            out["diff"]["required_preconditions_len_after"], 1
        )

    def test_cve_and_ghsa_extraction(self) -> None:
        rec = _base_v1_record()
        rec["source_audit_ref"] = (
            "cantina:example-2025:1.2.3 CVE-2024-12345 GHSA-abcd-1234-wxyz"
        )
        out = T.dry_run_record(rec)
        self.assertIn("cve_id", out["gained"])
        self.assertIn("ghsa_id", out["gained"])
        self.assertEqual(
            out["diff"]["cve_id"]["after"], "CVE-2024-12345"
        )
        self.assertEqual(
            out["diff"]["ghsa_id"]["after"], "GHSA-abcd-1234-wxyz"
        )
        self.assertEqual(out["validation_errors"], [])

    def test_schema_version_bumped_for_v1_input(self) -> None:
        rec = _base_v1_record()
        rec["function_shape"]["shape_tags"].append(
            "verification_tier:tier-3-synthetic-taxonomy-anchored"
        )
        out = T.dry_run_record(rec)
        self.assertTrue(out["diff"]["schema_version_bumped"])
        self.assertEqual(
            out["diff"]["schema_version_before"],
            "auditooor.hackerman_record.v1",
        )
        self.assertEqual(
            out["diff"]["schema_version_after"],
            "auditooor.hackerman_record.v1.1",
        )

    def test_idempotency_on_v11_record_is_noop(self) -> None:
        rec = _base_v1_record()
        rec["schema_version"] = "auditooor.hackerman_record.v1.1"
        rec["verification_tier"] = "tier-2-verified-public-archive"
        rec["record_source_url"] = "https://example.com/x"
        rec["cve_id"] = "CVE-2024-12345"
        rec["ghsa_id"] = "GHSA-abcd-1234-wxyz"
        out = T.dry_run_record(rec)
        self.assertFalse(out["would_migrate"])
        self.assertEqual(out["gained"], [])
        self.assertEqual(out["validation_errors"], [])


class TestValidationGate(unittest.TestCase):
    def test_invalid_cve_format_flagged(self) -> None:
        record = {
            "schema_version": "auditooor.hackerman_record.v1.1",
            "cve_id": "CVE-XX-1",  # invalid
        }
        errs = T.validate_v11_additive(record)
        self.assertTrue(any("cve_id" in e for e in errs))

    def test_invalid_ghsa_format_flagged(self) -> None:
        record = {
            "schema_version": "auditooor.hackerman_record.v1.1",
            "ghsa_id": "GHSA-too-short",
        }
        errs = T.validate_v11_additive(record)
        self.assertTrue(any("ghsa_id" in e for e in errs))

    def test_invalid_record_source_url_flagged(self) -> None:
        record = {
            "schema_version": "auditooor.hackerman_record.v1.1",
            "record_source_url": "ftp://nope.example.com/x",
        }
        errs = T.validate_v11_additive(record)
        self.assertTrue(any("record_source_url" in e for e in errs))

    def test_invalid_verification_tier_flagged(self) -> None:
        record = {
            "schema_version": "auditooor.hackerman_record.v1.1",
            "verification_tier": "tier-99-bogus",
        }
        errs = T.validate_v11_additive(record)
        self.assertTrue(any("verification_tier" in e for e in errs))

    def test_clean_record_passes(self) -> None:
        record = {
            "schema_version": "auditooor.hackerman_record.v1.1",
            "verification_tier": "tier-2-verified-public-archive",
            "record_source_url": "https://example.com/x",
            "cve_id": "CVE-2024-12345",
            "ghsa_id": "GHSA-abcd-1234-wxyz",
            "record_extensions": {"foo": "bar"},
        }
        self.assertEqual(T.validate_v11_additive(record), [])


class TestAggregateCounts(unittest.TestCase):
    def test_aggregate_sums_gains_and_failures(self) -> None:
        entries = [
            {
                "would_migrate": True,
                "gained": ["verification_tier"],
                "diff": {
                    "schema_version_bumped": True,
                    "verification_tier": {
                        "before": None,
                        "after": "tier-2-verified-public-archive",
                    },
                },
                "validation_errors": [],
            },
            {
                "would_migrate": True,
                "gained": ["verification_tier", "cve_id"],
                "diff": {
                    "schema_version_bumped": True,
                    "required_preconditions_pruned": True,
                },
                "validation_errors": [],
            },
            {
                "would_migrate": True,
                "gained": ["cve_id"],
                "diff": {"schema_version_bumped": True},
                "validation_errors": ["cve_id bad format"],
            },
            {
                "would_migrate": False,
                "gained": [],
                "diff": {},
                "validation_errors": [],
            },
        ]
        counts = T.aggregate_counts(entries)
        self.assertEqual(counts["total_records_scanned"], 4)
        self.assertEqual(counts["records_that_would_migrate"], 3)
        self.assertEqual(counts["schema_version_bumps"], 3)
        self.assertEqual(counts["required_preconditions_prunes"], 1)
        self.assertEqual(counts["per_field_gained"]["verification_tier"], 2)
        self.assertEqual(counts["per_field_gained"]["cve_id"], 2)
        self.assertEqual(counts["per_field_gained"]["ghsa_id"], 0)
        self.assertEqual(counts["records_failing_v11_validation"], 1)


class TestWalkAndPreview(unittest.TestCase):
    def test_discover_records_sorted_and_filters_extensions(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            dp = Path(d)
            (dp / "a.json").write_text("{}")
            (dp / "b.yaml").write_text("schema_version: x")
            (dp / "c.txt").write_text("not a record")
            sub = dp / "sub"
            sub.mkdir()
            (sub / "d.json").write_text("{}")
            paths = T.discover_records(dp)
            names = sorted(p.name for p in paths)
            self.assertEqual(names, ["a.json", "b.yaml", "d.json"])
            self.assertEqual(paths, sorted(paths))

    def test_walk_skips_non_v1_and_unparseable(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            dp = Path(d)
            # v1 record
            v1 = _base_v1_record()
            v1["function_shape"]["shape_tags"].append(
                "verification_tier:tier-4-bundled-fixture"
            )
            (dp / "v1.json").write_text(json.dumps(v1))
            # non-v1
            (dp / "other.json").write_text(json.dumps({
                "schema_version": "something.else.v1"
            }))
            # unparseable
            (dp / "broken.json").write_text("{not json")
            entries, file_stats = T.walk_and_preview(dp)
            self.assertEqual(file_stats["files_scanned"], 1)
            self.assertEqual(file_stats["files_skipped_not_v1"], 1)
            self.assertEqual(file_stats["files_unparseable"], 1)
            self.assertEqual(file_stats["total_candidate_files"], 3)
            self.assertEqual(len(entries), 1)
            self.assertIn("verification_tier", entries[0]["gained"])
            self.assertEqual(
                entries[0]["record_id"], v1["record_id"]
            )

    def test_walk_respects_limit(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            dp = Path(d)
            for i in range(5):
                rec = _base_v1_record()
                rec["record_id"] = f"audit:example:{i:03d}"
                rec["function_shape"]["shape_tags"].append(
                    "verification_tier:tier-2-verified-public-archive"
                )
                (dp / f"r{i}.json").write_text(json.dumps(rec))
            entries, file_stats = T.walk_and_preview(dp, limit=2)
            self.assertEqual(file_stats["files_scanned"], 2)
            self.assertEqual(len(entries), 2)


class TestRenderReport(unittest.TestCase):
    def test_render_report_deterministic_and_has_sections(self) -> None:
        counts = {
            "total_records_scanned": 10,
            "records_that_would_migrate": 8,
            "schema_version_bumps": 8,
            "required_preconditions_prunes": 1,
            "per_field_gained": {
                "verification_tier": 7,
                "record_source_url": 1,
                "cve_id": 2,
                "ghsa_id": 0,
                "record_extensions": 0,
            },
            "records_failing_v11_validation": 0,
            "validation_error_classes": {},
        }
        file_stats = {
            "files_scanned": 10,
            "files_skipped_not_v1": 2,
            "files_unparseable": 0,
            "total_candidate_files": 12,
        }
        samples = [
            {
                "path": "audit/corpus_tags/tags/x.json",
                "record_id": "audit:x:1",
                "gained": ["verification_tier"],
                "diff": {
                    "verification_tier": {
                        "before": None,
                        "after": "tier-2-verified-public-archive",
                    },
                    "schema_version_bumped": True,
                    "schema_version_before": "auditooor.hackerman_record.v1",
                    "schema_version_after": "auditooor.hackerman_record.v1.1",
                },
            }
        ]
        a = T.render_report(
            counts,
            file_stats,
            samples,
            [],
            generated_at="2026-05-16T00:00:00Z",
        )
        b = T.render_report(
            counts,
            file_stats,
            samples,
            [],
            generated_at="2026-05-16T00:00:00Z",
        )
        self.assertEqual(a, b)
        self.assertIn("# Hackerman schema v1 -> v1.1 migration", a)
        self.assertIn("## Headline counts", a)
        self.assertIn("## Per-field promotion counts", a)
        self.assertIn("## Risk assessment", a)
        self.assertIn("## Sample diffs", a)
        self.assertIn("`verification_tier`", a)


class TestMainCli(unittest.TestCase):
    def test_main_writes_jsonl_and_report_and_exits_zero(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            dp = Path(d)
            tags = dp / "tags"
            tags.mkdir()
            for i in range(3):
                rec = _base_v1_record()
                rec["record_id"] = f"audit:example:{i:03d}"
                rec["function_shape"]["shape_tags"].append(
                    "verification_tier:tier-2-verified-public-archive"
                )
                (tags / f"r{i}.json").write_text(json.dumps(rec))

            preview = dp / "preview.jsonl"
            report = dp / "report.md"
            rc = T.main([
                "--tags-dir", str(tags),
                "--preview-out", str(preview),
                "--report-out", str(report),
                "--generated-at", "2026-05-16T00:00:00Z",
                "--quiet",
            ])
            self.assertEqual(rc, 0)
            self.assertTrue(preview.exists())
            self.assertTrue(report.exists())
            lines = preview.read_text().splitlines()
            self.assertEqual(len(lines), 3)
            for line in lines:
                obj = json.loads(line)
                self.assertIn("would_migrate", obj)
                self.assertIn("diff", obj)
                self.assertIn("path", obj)
            rep = report.read_text()
            self.assertIn("Wave-2 W2.1", rep)
            self.assertIn("`verification_tier`", rep)


if __name__ == "__main__":
    unittest.main()
