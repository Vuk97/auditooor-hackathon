"""Tests for tools/hackerman-schema-v1-to-v1.1-migrator.py.

Loads the migrator via importlib because the canonical filename contains
hyphens and dots (not importable as a normal Python module).
"""
from __future__ import annotations

import copy
import importlib.util
import os
import unittest
from pathlib import Path
from typing import Any, Dict

_HERE = Path(__file__).resolve()
_REPO = _HERE.parents[2]
_MIGRATOR_PATH = _REPO / "tools" / "hackerman-schema-v1-to-v1.1-migrator.py"

_spec = importlib.util.spec_from_file_location(
    "hackerman_schema_v1_to_v1_1_migrator", str(_MIGRATOR_PATH)
)
assert _spec is not None and _spec.loader is not None
M = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(M)  # type: ignore[union-attr]


def _base_v1_record() -> Dict[str, Any]:
    """A minimally-populated v1 record used as a template for tests."""
    return {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": "audit:example:001",
        "source_audit_ref": "cantina:example-2025:1.2.3",
        "target_domain": "lending",
        "target_language": "solidity",
        "target_repo": "example/example",
        "target_component": "src/Pool.sol::depositCollateral",
        "function_shape": {
            "raw_signature": "function depositCollateral(uint256 amount)",
            "shape_tags": ["state-mutating", "external-callable"],
        },
        "bug_class": "missing-access-control",
        "attack_class": "unauth-state-write",
        "attacker_role": "unprivileged",
        "attacker_action_sequence": "Call depositCollateral with any amount.",
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


class TestVerificationTierLift(unittest.TestCase):
    def test_extracts_tier_2_from_shape_tags(self) -> None:
        rec = _base_v1_record()
        rec["function_shape"]["shape_tags"].append(
            "verification_tier:tier-2-verified-public-archive"
        )
        out = M.migrate_record(rec)
        self.assertEqual(
            out["verification_tier"], "tier-2-verified-public-archive"
        )

    def test_extracts_tier_1_from_shape_tags(self) -> None:
        rec = _base_v1_record()
        rec["function_shape"]["shape_tags"] = [
            "verification_tier:tier-1-verified-realtime-api",
            "state-mutating",
        ]
        out = M.migrate_record(rec)
        self.assertEqual(
            out["verification_tier"], "tier-1-verified-realtime-api"
        )

    def test_no_tier_smuggled_returns_record_without_tier(self) -> None:
        rec = _base_v1_record()
        out = M.migrate_record(rec)
        self.assertNotIn("verification_tier", out)

    def test_unknown_tier_value_in_shape_tag_is_ignored(self) -> None:
        rec = _base_v1_record()
        rec["function_shape"]["shape_tags"].append(
            "verification_tier:tier-99-fictional"
        )
        out = M.migrate_record(rec)
        self.assertNotIn("verification_tier", out)


class TestRecordSourceUrlLift(unittest.TestCase):
    def test_extracts_url_and_drops_precondition_when_safe(self) -> None:
        rec = _base_v1_record()
        rec["required_preconditions"] = [
            "Pool deployed and not paused.",
            "https://github.com/example/example/security/advisories/GHSA-aaaa-bbbb-cccc",
        ]
        out = M.migrate_record(rec)
        self.assertTrue(out["record_source_url"].startswith("https://"))
        self.assertEqual(len(out["required_preconditions"]), 1)
        self.assertNotIn(
            out["record_source_url"], out["required_preconditions"]
        )

    def test_preserves_single_url_precondition_to_avoid_min_items_violation(
        self,
    ) -> None:
        rec = _base_v1_record()
        rec["required_preconditions"] = [
            "https://example.com/advisory/X"
        ]
        out = M.migrate_record(rec)
        self.assertEqual(out["record_source_url"], "https://example.com/advisory/X")
        # Cannot empty the array; the URL entry stays.
        self.assertEqual(out["required_preconditions"], rec["required_preconditions"])

    def test_no_url_in_preconditions_no_field(self) -> None:
        rec = _base_v1_record()
        out = M.migrate_record(rec)
        self.assertNotIn("record_source_url", out)

    def test_existing_record_source_url_is_preserved(self) -> None:
        rec = _base_v1_record()
        rec["record_source_url"] = "https://pre-existing.example/path"
        rec["required_preconditions"] = [
            "Pool deployed and not paused.",
            "https://different-url.example/X",
        ]
        out = M.migrate_record(rec)
        self.assertEqual(
            out["record_source_url"], "https://pre-existing.example/path"
        )
        # Pre-existing field protects the preconditions array from mutation.
        self.assertEqual(out["required_preconditions"], rec["required_preconditions"])


class TestCveAndGhsaExtraction(unittest.TestCase):
    def test_extracts_cve_from_source_audit_ref(self) -> None:
        rec = _base_v1_record()
        rec["source_audit_ref"] = "nvd:CVE-2024-12345"
        out = M.migrate_record(rec)
        self.assertEqual(out["cve_id"], "CVE-2024-12345")

    def test_extracts_ghsa_from_record_id(self) -> None:
        rec = _base_v1_record()
        rec["record_id"] = "ghsa:GHSA-aaaa-bbbb-cccc:001"
        out = M.migrate_record(rec)
        self.assertEqual(out["ghsa_id"], "GHSA-aaaa-bbbb-cccc")

    def test_extracts_cve_from_attacker_action_sequence(self) -> None:
        rec = _base_v1_record()
        rec["attacker_action_sequence"] = (
            "Reproduce per CVE-2023-9999 PoC against the deployed pool."
        )
        out = M.migrate_record(rec)
        self.assertEqual(out["cve_id"], "CVE-2023-9999")

    def test_extracts_ghsa_with_mixed_case(self) -> None:
        rec = _base_v1_record()
        rec["fix_pattern"] = "Per GHSA-AbCd-1234-EfGh patch notes."
        out = M.migrate_record(rec)
        self.assertEqual(out["ghsa_id"], "GHSA-AbCd-1234-EfGh")

    def test_no_cve_no_ghsa_no_fields(self) -> None:
        rec = _base_v1_record()
        out = M.migrate_record(rec)
        self.assertNotIn("cve_id", out)
        self.assertNotIn("ghsa_id", out)


class TestSchemaVersionBump(unittest.TestCase):
    def test_v1_bumps_to_v1_1(self) -> None:
        rec = _base_v1_record()
        out = M.migrate_record(rec)
        self.assertEqual(
            out["schema_version"], "auditooor.hackerman_record.v1.1"
        )

    def test_already_v1_1_is_unchanged(self) -> None:
        rec = _base_v1_record()
        rec["schema_version"] = "auditooor.hackerman_record.v1.1"
        out = M.migrate_record(rec)
        self.assertEqual(
            out["schema_version"], "auditooor.hackerman_record.v1.1"
        )


class TestIdempotency(unittest.TestCase):
    def test_double_migrate_is_stable(self) -> None:
        rec = _base_v1_record()
        rec["function_shape"]["shape_tags"].append(
            "verification_tier:tier-2-verified-public-archive"
        )
        rec["required_preconditions"] = [
            "Pool deployed and not paused.",
            "https://example.com/advisory/CVE-2024-99999",
        ]
        once = M.migrate_record(rec)
        twice = M.migrate_record(once)
        self.assertEqual(once, twice)

    def test_does_not_mutate_input(self) -> None:
        rec = _base_v1_record()
        rec["function_shape"]["shape_tags"].append(
            "verification_tier:tier-3-synthetic-taxonomy-anchored"
        )
        snapshot = copy.deepcopy(rec)
        _ = M.migrate_record(rec)
        self.assertEqual(rec, snapshot)


class TestEndToEndCombined(unittest.TestCase):
    def test_all_four_fields_lift_together(self) -> None:
        rec = _base_v1_record()
        rec["function_shape"]["shape_tags"].append(
            "verification_tier:tier-4-bundled-fixture"
        )
        rec["required_preconditions"] = [
            "Pool deployed and not paused.",
            "https://github.com/advisories/GHSA-1111-2222-3333",
        ]
        rec["source_audit_ref"] = "nvd:CVE-2020-1234:upstream"
        out = M.migrate_record(rec)
        self.assertEqual(out["verification_tier"], "tier-4-bundled-fixture")
        self.assertEqual(
            out["record_source_url"],
            "https://github.com/advisories/GHSA-1111-2222-3333",
        )
        self.assertEqual(out["cve_id"], "CVE-2020-1234")
        self.assertEqual(out["ghsa_id"], "GHSA-1111-2222-3333")
        self.assertEqual(
            out["schema_version"], "auditooor.hackerman_record.v1.1"
        )


class TestExistingFieldsPreserved(unittest.TestCase):
    def test_pre_set_verification_tier_not_overwritten(self) -> None:
        rec = _base_v1_record()
        rec["verification_tier"] = "tier-1-verified-realtime-api"
        rec["function_shape"]["shape_tags"].append(
            "verification_tier:tier-5-quarantine"
        )
        out = M.migrate_record(rec)
        self.assertEqual(out["verification_tier"], "tier-1-verified-realtime-api")

    def test_pre_set_cve_id_not_overwritten(self) -> None:
        rec = _base_v1_record()
        rec["cve_id"] = "CVE-1999-0001"
        rec["source_audit_ref"] = "nvd:CVE-2024-99999"
        out = M.migrate_record(rec)
        self.assertEqual(out["cve_id"], "CVE-1999-0001")


class TestTypeContract(unittest.TestCase):
    def test_non_dict_raises_typeerror(self) -> None:
        with self.assertRaises(TypeError):
            M.migrate_record(["not", "a", "record"])  # type: ignore[arg-type]


class TestPublicConstants(unittest.TestCase):
    def test_tier_values_match_schema_enum(self) -> None:
        # Mirrors the v1.1 schema enum for verification_tier; if either side
        # changes both must move in lockstep.
        self.assertEqual(
            set(M.VERIFICATION_TIER_VALUES),
            {
                "tier-1-verified-realtime-api",
                "tier-2-verified-public-archive",
                "tier-3-synthetic-taxonomy-anchored",
                "tier-4-bundled-fixture",
                "tier-5-quarantine",
            },
        )


if __name__ == "__main__":
    unittest.main()
