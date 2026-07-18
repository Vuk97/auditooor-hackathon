"""
tools/tests/test_invariant_candidate_schema.py

Test suite for auditooor.invariant_candidate.v1 schema + lane-integrator-validate.py.

Coverage:
  - All 404 ground-truth records pass the schema (CODEX-2 acceptance criterion)
  - Required field missing -> fails
  - Wrong type -> fails
  - Bad enum value -> fails
  - Bad invariant_id pattern -> fails
  - Bad extracted_at_utc pattern -> fails
  - source_count < minimum -> fails
  - source_finding_ids empty array -> fails
  - Optional fields absent -> still passes
  - additionalProperties allowed (schema uses additionalProperties: true)

Lane: lane234-codex2-schema-2026-05-26
R36: declared in .auditooor/agent_pathspec.json
R37: reads records, does NOT modify them.
L34: workspace-ledger bucket; auto-executable.
"""

import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent.parent

# Load lane-integrator-validate.py via importlib (filename contains hyphens)
_spec = importlib.util.spec_from_file_location(
    "lane_integrator_validate",
    _REPO_ROOT / "tools" / "lane-integrator-validate.py",
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)  # type: ignore[union-attr]

load_schema = _mod.load_schema
validate_record = _mod.validate_record

_SCHEMA_PATH = _REPO_ROOT / "audit/corpus_tags/schemas/auditooor.invariant_candidate.v1.schema.json"
_JSONL_PATH = _REPO_ROOT / "audit/corpus_tags/derived/invariants_extracted.jsonl"

# Minimal valid record matching all required fields from the ground-truth corpus
_VALID_RECORD = {
    "schema_version": "auditooor.invariant_extraction.v1",
    "invariant_id": "INV-ATM-TEST-0001",
    "category": "atomicity",
    "statement": "External calls that hand control back to the caller MUST NOT occur before all relevant state writes have committed.",
    "target_lang": "solidity",
    "source_finding_ids": ["prior-audit:test:file.txt:L1:S1:abc123"],
    "abstraction_level": "cross-domain",
    "commit_point_pattern": "nonReentrant",
    "defense_layer": "checks-effects-interactions",
    "verification_tier": "tier-2-verified-public-archive",
    "source_count": 3,
    "extracted_at_utc": "2026-05-26T00:00:00Z",
    "extractor": "hand-extract",
}


class TestSchemaFile(unittest.TestCase):
    """Verify the schema file is well-formed and has expected structure."""

    def setUp(self):
        self.schema = load_schema(_SCHEMA_PATH)

    def test_schema_file_exists(self):
        self.assertTrue(_SCHEMA_PATH.exists(), f"Schema not found: {_SCHEMA_PATH}")

    def test_schema_has_required_meta(self):
        self.assertIn("$schema", self.schema)
        self.assertIn("$id", self.schema)
        self.assertEqual(self.schema["$id"], "auditooor.invariant_candidate.v1")

    def test_schema_required_fields_present(self):
        required = set(self.schema.get("required", []))
        expected_required = {
            "schema_version", "invariant_id", "category", "statement",
            "target_lang", "source_finding_ids", "abstraction_level",
            "commit_point_pattern", "defense_layer", "verification_tier",
            "source_count", "extracted_at_utc", "extractor",
        }
        self.assertTrue(
            expected_required.issubset(required),
            f"Missing required fields: {expected_required - required}"
        )

    def test_schema_r37_verification_tier_field(self):
        """R37: verification_tier MUST be a first-class field with enum values."""
        props = self.schema.get("properties", {})
        self.assertIn("verification_tier", props)
        tier_spec = props["verification_tier"]
        self.assertIn("enum", tier_spec)
        self.assertIn("tier-2-verified-public-archive", tier_spec["enum"])
        self.assertIn("tier-1-verified-realtime-api", tier_spec["enum"])

    def test_schema_additional_properties_true(self):
        """Ground-truth corpus has outlier fields; schema must allow additionalProperties."""
        # Either explicit true or absence (defaults to true)
        ap = self.schema.get("additionalProperties", True)
        self.assertTrue(ap is True or ap == {}, f"additionalProperties={ap!r} is too restrictive")


class TestValidRecordPasses(unittest.TestCase):

    def setUp(self):
        self.schema = load_schema(_SCHEMA_PATH)

    def test_minimal_valid_record(self):
        errors = validate_record(_VALID_RECORD, self.schema, lineno=1)
        self.assertEqual(errors, [], f"Unexpected errors: {errors}")

    def test_optional_attack_signature_present(self):
        record = dict(_VALID_RECORD, attack_signature="reentrancy|callback-reentrancy")
        errors = validate_record(record, self.schema, lineno=1)
        self.assertEqual(errors, [])

    def test_optional_singleton_true(self):
        record = dict(_VALID_RECORD, singleton=True)
        errors = validate_record(record, self.schema, lineno=1)
        self.assertEqual(errors, [])

    def test_optional_singleton_false(self):
        record = dict(_VALID_RECORD, singleton=False)
        errors = validate_record(record, self.schema, lineno=1)
        self.assertEqual(errors, [])

    def test_optional_fields_absent_still_passes(self):
        """attack_signature and singleton are optional (400/404 in ground truth)."""
        record = {k: v for k, v in _VALID_RECORD.items()
                  if k not in ("attack_signature", "singleton")}
        errors = validate_record(record, self.schema, lineno=1)
        self.assertEqual(errors, [])

    def test_schema_version_alternate_value(self):
        record = dict(_VALID_RECORD, schema_version="auditooor.invariant_candidate.v1")
        errors = validate_record(record, self.schema, lineno=1)
        self.assertEqual(errors, [])

    def test_all_abstraction_level_values(self):
        for level in ("cross-domain", "protocol-invariant", "per-protocol-family", "cross-language"):
            record = dict(_VALID_RECORD, abstraction_level=level)
            errors = validate_record(record, self.schema, lineno=1)
            self.assertEqual(errors, [], f"Level '{level}' failed: {errors}")

    def test_all_verification_tier_values(self):
        tiers = [
            "tier-1-verified-realtime-api",
            "tier-1-officially-disclosed",
            "tier-2-verified-public-archive",
            "tier-3-synthetic-taxonomy-anchored",
            "tier-4-bundled-fixture",
            "tier-5-quarantine",
        ]
        for tier in tiers:
            record = dict(_VALID_RECORD, verification_tier=tier)
            errors = validate_record(record, self.schema, lineno=1)
            self.assertEqual(errors, [], f"Tier '{tier}' failed: {errors}")

    def test_target_lang_go(self):
        record = dict(_VALID_RECORD, target_lang="go")
        errors = validate_record(record, self.schema, lineno=1)
        self.assertEqual(errors, [])

    def test_additional_property_allowed(self):
        """Schema uses additionalProperties: true - extra fields must NOT cause errors."""
        record = dict(_VALID_RECORD, novel_future_field="some_value")
        errors = validate_record(record, self.schema, lineno=1)
        self.assertEqual(errors, [])

    def test_source_count_max_20(self):
        record = dict(_VALID_RECORD, source_count=20)
        errors = validate_record(record, self.schema, lineno=1)
        self.assertEqual(errors, [])


class TestInvalidRecordFails(unittest.TestCase):

    def setUp(self):
        self.schema = load_schema(_SCHEMA_PATH)

    def _validate(self, record, lineno=99):
        return validate_record(record, self.schema, lineno=lineno)

    def test_missing_required_invariant_id(self):
        record = {k: v for k, v in _VALID_RECORD.items() if k != "invariant_id"}
        errors = self._validate(record)
        self.assertTrue(any("invariant_id" in e for e in errors), errors)

    def test_missing_required_statement(self):
        record = {k: v for k, v in _VALID_RECORD.items() if k != "statement"}
        errors = self._validate(record)
        self.assertTrue(any("statement" in e for e in errors), errors)

    def test_missing_required_verification_tier(self):
        record = {k: v for k, v in _VALID_RECORD.items() if k != "verification_tier"}
        errors = self._validate(record)
        self.assertTrue(any("verification_tier" in e for e in errors), errors)

    def test_missing_required_extracted_at_utc(self):
        record = {k: v for k, v in _VALID_RECORD.items() if k != "extracted_at_utc"}
        errors = self._validate(record)
        self.assertTrue(any("extracted_at_utc" in e for e in errors), errors)

    def test_bad_schema_version_enum(self):
        record = dict(_VALID_RECORD, schema_version="auditooor.invariant.v99")
        errors = self._validate(record)
        self.assertTrue(any("schema_version" in e and "enum" in e for e in errors), errors)

    def test_bad_abstraction_level_enum(self):
        record = dict(_VALID_RECORD, abstraction_level="galaxy-brain")
        errors = self._validate(record)
        self.assertTrue(any("abstraction_level" in e for e in errors), errors)

    def test_bad_verification_tier_enum(self):
        record = dict(_VALID_RECORD, verification_tier="tier-99-made-up")
        errors = self._validate(record)
        self.assertTrue(any("verification_tier" in e for e in errors), errors)

    def test_bad_invariant_id_pattern(self):
        record = dict(_VALID_RECORD, invariant_id="not-an-inv-id")
        errors = self._validate(record)
        self.assertTrue(any("invariant_id" in e and "pattern" in e for e in errors), errors)

    def test_bad_extracted_at_utc_pattern(self):
        record = dict(_VALID_RECORD, extracted_at_utc="2026-05-26 00:00:00")
        errors = self._validate(record)
        self.assertTrue(any("extracted_at_utc" in e for e in errors), errors)

    def test_source_count_below_minimum(self):
        record = dict(_VALID_RECORD, source_count=0)
        errors = self._validate(record)
        self.assertTrue(any("source_count" in e and "minimum" in e for e in errors), errors)

    def test_source_finding_ids_empty_array(self):
        record = dict(_VALID_RECORD, source_finding_ids=[])
        errors = self._validate(record)
        self.assertTrue(any("source_finding_ids" in e and "minItems" in e for e in errors), errors)

    def test_statement_wrong_type(self):
        record = dict(_VALID_RECORD, statement=12345)
        errors = self._validate(record)
        self.assertTrue(any("statement" in e and "type" in e for e in errors), errors)

    def test_source_count_string_type(self):
        record = dict(_VALID_RECORD, source_count="three")
        errors = self._validate(record)
        self.assertTrue(any("source_count" in e and "type" in e for e in errors), errors)

    def test_source_finding_ids_wrong_type(self):
        record = dict(_VALID_RECORD, source_finding_ids="not-a-list")
        errors = self._validate(record)
        self.assertTrue(any("source_finding_ids" in e and "type" in e for e in errors), errors)

    def test_singleton_string_instead_of_bool(self):
        record = dict(_VALID_RECORD, singleton="true")
        errors = self._validate(record)
        self.assertTrue(any("singleton" in e and "type" in e for e in errors), errors)


class TestGroundTruth404Records(unittest.TestCase):
    """
    CODEX-2 acceptance criterion: all 404 records in invariants_extracted.jsonl
    must pass the schema. This is the canonical gate.
    """

    @classmethod
    def setUpClass(cls):
        if not _JSONL_PATH.exists():
            raise unittest.SkipTest(f"JSONL not found: {_JSONL_PATH}")
        if not _SCHEMA_PATH.exists():
            raise unittest.SkipTest(f"Schema not found: {_SCHEMA_PATH}")

        cls.schema = load_schema(_SCHEMA_PATH)

        with open(_JSONL_PATH, "r", encoding="utf-8") as f:
            cls.records = []
            for lineno, line in enumerate(f, 1):
                line = line.strip()
                if line:
                    cls.records.append((lineno, json.loads(line)))

    def test_record_count_is_404(self):
        self.assertEqual(
            len(self.records), 404,
            f"Expected 404 records, got {len(self.records)}"
        )

    def test_all_404_records_pass(self):
        all_errors = []
        for lineno, record in self.records:
            errs = validate_record(record, self.schema, lineno)
            all_errors.extend(errs)
        self.assertEqual(
            all_errors, [],
            f"Schema validation failures ({len(all_errors)} errors):\n"
            + "\n".join(all_errors[:20])
        )

    def test_all_records_have_invariant_id(self):
        missing = [lineno for lineno, r in self.records if "invariant_id" not in r]
        self.assertEqual(missing, [], f"Records missing invariant_id at lines: {missing}")

    def test_all_records_have_verification_tier(self):
        """R37: verification_tier must be present in every record."""
        missing = [lineno for lineno, r in self.records if "verification_tier" not in r]
        self.assertEqual(missing, [], f"Records missing verification_tier at lines: {missing}")

    def test_verification_tier_values_are_valid(self):
        valid_tiers = {
            "tier-1-verified-realtime-api",
            "tier-1-officially-disclosed",
            "tier-2-verified-public-archive",
            "tier-3-synthetic-taxonomy-anchored",
            "tier-4-bundled-fixture",
            "tier-5-quarantine",
        }
        bad = [
            (lineno, r.get("verification_tier"))
            for lineno, r in self.records
            if r.get("verification_tier") not in valid_tiers
        ]
        self.assertEqual(bad, [], f"Invalid verification_tier values: {bad[:5]}")

    def test_invariant_id_pattern(self):
        import re
        pattern = re.compile(r"^INV-[A-Za-z0-9_.-]{1,80}$")
        bad = [
            (lineno, r.get("invariant_id"))
            for lineno, r in self.records
            if not pattern.match(r.get("invariant_id", ""))
        ]
        self.assertEqual(bad, [], f"Bad invariant_id patterns: {bad[:5]}")

    def test_abstraction_level_values(self):
        valid = {"cross-domain", "protocol-invariant", "per-protocol-family", "cross-language"}
        bad = [
            (lineno, r.get("abstraction_level"))
            for lineno, r in self.records
            if r.get("abstraction_level") not in valid
        ]
        self.assertEqual(bad, [], f"Invalid abstraction_level: {bad[:5]}")

    def test_source_count_positive_integer(self):
        bad = [
            (lineno, r.get("source_count"))
            for lineno, r in self.records
            if not (isinstance(r.get("source_count"), int)
                    and not isinstance(r.get("source_count"), bool)
                    and r.get("source_count", 0) >= 1)
        ]
        self.assertEqual(bad, [], f"Invalid source_count: {bad[:5]}")

    def test_source_finding_ids_non_empty_list(self):
        bad = [
            lineno for lineno, r in self.records
            if not isinstance(r.get("source_finding_ids"), list)
            or len(r.get("source_finding_ids", [])) == 0
        ]
        self.assertEqual(bad, [], f"Empty/missing source_finding_ids at lines: {bad[:5]}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
