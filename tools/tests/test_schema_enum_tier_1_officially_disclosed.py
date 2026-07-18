"""Tests for the Wave-2 PR-A (2026-05-16) tier-1-officially-disclosed
enum extension.

Adds ``tier-1-officially-disclosed`` to:

1. The ``record_tier`` enum of both
   ``auditooor.hackerman_record.v1`` and
   ``auditooor.hackerman_record.v1.1`` schemas (mirrors the sibling
   ``tier-2-verified-public-archive`` extension landed in commit
   ``ad3cc4bda7``).

2. The ``verification_tier`` enum of the
   ``auditooor.hackerman_record.v1.1`` schema (v1 has no
   ``verification_tier`` property, so only v1.1 is touched on that axis).

Empirical anchor: the Wave-2 PR-B Vyper-CVE real-source rebuilder
(commit ``a428d287c4`` on the wave-2-corpus-migration branch) flagged
that the schema's ``verification_tier`` enum did not include the
brief-requested label ``tier-1-officially-disclosed``; that rebuilder
worked around the gap by emitting
``verification_tier=tier-2-verified-public-archive`` plus a sibling
``record_extensions.verification_label=tier-1-officially-disclosed``.
This PR closes the workaround so the next rebuilder revision can drop
the ``record_extensions.verification_label`` field and emit a single
canonical value.

Synthetic fixtures only - no live corpus is mutated.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from pathlib import Path
from typing import Any, Dict

_HERE = Path(__file__).resolve()
_REPO = _HERE.parents[2]
_SCHEMA_V1 = (
    _REPO
    / "audit"
    / "corpus_tags"
    / "schemas"
    / "auditooor.hackerman_record.v1.schema.json"
)
_SCHEMA_V1_1 = (
    _REPO
    / "audit"
    / "corpus_tags"
    / "schemas"
    / "auditooor.hackerman_record.v1.1.schema.json"
)

_VTS_SPEC = importlib.util.spec_from_file_location(
    "_verdict_tag_schema_test_tier1_officially_disclosed",
    str(_REPO / "tools" / "verdict-tag-schema.py"),
)
assert _VTS_SPEC is not None and _VTS_SPEC.loader is not None
_VTS = importlib.util.module_from_spec(_VTS_SPEC)
_VTS_SPEC.loader.exec_module(_VTS)  # type: ignore[union-attr]

_MIGRATOR_SPEC = importlib.util.spec_from_file_location(
    "_hackerman_schema_v1_to_v1_1_migrator_test_tier1_officially_disclosed",
    str(_REPO / "tools" / "hackerman-schema-v1-to-v1.1-migrator.py"),
)
assert _MIGRATOR_SPEC is not None and _MIGRATOR_SPEC.loader is not None
_MIGRATOR = importlib.util.module_from_spec(_MIGRATOR_SPEC)
_MIGRATOR_SPEC.loader.exec_module(_MIGRATOR)  # type: ignore[union-attr]


_NEW_ENUM_VALUE = "tier-1-officially-disclosed"
_LEGACY_RECORD_TIER_VALUES = (
    "public-corpus",
    "local-workspace",
    "submission-derived",
    "dydx-filed",
    "mezo-filed",
    "tier-2-verified-public-archive",
)
_LEGACY_VERIFICATION_TIER_VALUES = (
    "tier-1-verified-realtime-api",
    "tier-2-verified-public-archive",
    "tier-3-synthetic-taxonomy-anchored",
    "tier-4-bundled-fixture",
    "tier-5-quarantine",
)


def _base_v1_record() -> Dict[str, Any]:
    """A minimally-populated v1 record used as a template for tests.

    Marked ``synthetic_fixture`` via the ``synthetic-fixture:`` record_id
    prefix and ``synthetic:test:`` source_audit_ref prefix.
    """
    return {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": "synthetic-fixture:tier1-officially-disclosed:0001",
        "source_audit_ref": "synthetic:test:tier1-officially-disclosed",
        "target_domain": "lending",
        "target_language": "vyper",
        "target_repo": "synthetic/fixture",
        "target_component": "src/Pool.vy::synthetic",
        "function_shape": {
            "raw_signature": "def synthetic()",
            "shape_tags": ["state-mutating"],
        },
        "bug_class": "reentrancy-lock-slot-drift",
        "attack_class": "reentrancy",
        "attacker_role": "unprivileged",
        "attacker_action_sequence": "Synthetic fixture only - not a real exploit.",
        "required_preconditions": ["Synthetic precondition."],
        "impact_class": "theft",
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": ">=$1M",
        "fix_pattern": "Synthetic fix.",
        "fix_anti_pattern_avoided": "Synthetic anti-pattern.",
        "severity_at_finding": "high",
        "year": 2023,
        "cross_language_analogues": [],
        "related_records": [],
    }


def _base_v1_1_record() -> Dict[str, Any]:
    rec = _base_v1_record()
    rec["schema_version"] = "auditooor.hackerman_record.v1.1"
    return rec


def _load_schema(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


class TestSchemaLoadsCleanly(unittest.TestCase):
    def test_v1_loads(self) -> None:
        schema = _load_schema(_SCHEMA_V1)
        self.assertEqual(schema.get("$id"), "auditooor.hackerman_record.v1")
        self.assertIn("record_tier", schema["properties"])

    def test_v1_1_loads(self) -> None:
        schema = _load_schema(_SCHEMA_V1_1)
        self.assertIn("record_tier", schema["properties"])
        self.assertIn("verification_tier", schema["properties"])


class TestNewEnumValuePresent(unittest.TestCase):
    def test_v1_record_tier_enum_contains_new_value(self) -> None:
        schema = _load_schema(_SCHEMA_V1)
        enum_values = schema["properties"]["record_tier"]["enum"]
        self.assertIn(_NEW_ENUM_VALUE, enum_values)

    def test_v1_1_record_tier_enum_contains_new_value(self) -> None:
        schema = _load_schema(_SCHEMA_V1_1)
        enum_values = schema["properties"]["record_tier"]["enum"]
        self.assertIn(_NEW_ENUM_VALUE, enum_values)

    def test_v1_1_verification_tier_enum_contains_new_value(self) -> None:
        schema = _load_schema(_SCHEMA_V1_1)
        enum_values = schema["properties"]["verification_tier"]["enum"]
        self.assertIn(_NEW_ENUM_VALUE, enum_values)

    def test_v1_record_tier_description_mentions_pra_followup(self) -> None:
        schema = _load_schema(_SCHEMA_V1)
        record_tier_prop = schema["properties"]["record_tier"]
        desc = record_tier_prop.get("description", "")
        self.assertIn("tier-1-officially-disclosed", desc)
        self.assertIn("a428d287c4", desc)

    def test_v1_1_verification_tier_description_mentions_pra_followup(self) -> None:
        schema = _load_schema(_SCHEMA_V1_1)
        verification_tier_prop = schema["properties"]["verification_tier"]
        desc = verification_tier_prop.get("description", "")
        self.assertIn("tier-1-officially-disclosed", desc)


class TestRecordEmitterAcceptsNewTier(unittest.TestCase):
    def test_v1_record_with_new_record_tier_validates(self) -> None:
        schema = _load_schema(_SCHEMA_V1)
        rec = _base_v1_record()
        rec["record_tier"] = _NEW_ENUM_VALUE
        errors = _VTS.validate(rec, schema)
        self.assertEqual(errors, [], msg=f"unexpected errors: {errors}")

    def test_v1_1_record_with_new_record_tier_validates(self) -> None:
        schema = _load_schema(_SCHEMA_V1_1)
        rec = _base_v1_1_record()
        rec["record_tier"] = _NEW_ENUM_VALUE
        errors = _VTS.validate(rec, schema)
        self.assertEqual(errors, [], msg=f"unexpected errors: {errors}")

    def test_v1_1_record_with_new_verification_tier_validates(self) -> None:
        schema = _load_schema(_SCHEMA_V1_1)
        rec = _base_v1_1_record()
        rec["verification_tier"] = _NEW_ENUM_VALUE
        errors = _VTS.validate(rec, schema)
        self.assertEqual(errors, [], msg=f"unexpected errors: {errors}")

    def test_v1_1_record_with_both_tiers_set_validates(self) -> None:
        schema = _load_schema(_SCHEMA_V1_1)
        rec = _base_v1_1_record()
        rec["record_tier"] = _NEW_ENUM_VALUE
        rec["verification_tier"] = _NEW_ENUM_VALUE
        errors = _VTS.validate(rec, schema)
        self.assertEqual(errors, [], msg=f"unexpected errors: {errors}")


class TestExistingTierValuesStillValid(unittest.TestCase):
    def test_v1_each_legacy_record_tier_validates(self) -> None:
        schema = _load_schema(_SCHEMA_V1)
        for legacy in _LEGACY_RECORD_TIER_VALUES:
            with self.subTest(record_tier=legacy):
                rec = _base_v1_record()
                rec["record_tier"] = legacy
                errors = _VTS.validate(rec, schema)
                self.assertEqual(errors, [], msg=f"legacy {legacy!r}: {errors}")

    def test_v1_1_each_legacy_record_tier_validates(self) -> None:
        schema = _load_schema(_SCHEMA_V1_1)
        for legacy in _LEGACY_RECORD_TIER_VALUES:
            with self.subTest(record_tier=legacy):
                rec = _base_v1_1_record()
                rec["record_tier"] = legacy
                errors = _VTS.validate(rec, schema)
                self.assertEqual(errors, [], msg=f"legacy {legacy!r}: {errors}")

    def test_v1_1_each_legacy_verification_tier_validates(self) -> None:
        schema = _load_schema(_SCHEMA_V1_1)
        for legacy in _LEGACY_VERIFICATION_TIER_VALUES:
            with self.subTest(verification_tier=legacy):
                rec = _base_v1_1_record()
                rec["verification_tier"] = legacy
                errors = _VTS.validate(rec, schema)
                self.assertEqual(errors, [], msg=f"legacy {legacy!r}: {errors}")

    def test_v1_unknown_record_tier_still_rejected(self) -> None:
        schema = _load_schema(_SCHEMA_V1)
        rec = _base_v1_record()
        rec["record_tier"] = "tier-99-fake-bogus"
        errors = _VTS.validate(rec, schema)
        self.assertTrue(errors)

    def test_v1_1_unknown_verification_tier_still_rejected(self) -> None:
        schema = _load_schema(_SCHEMA_V1_1)
        rec = _base_v1_1_record()
        rec["verification_tier"] = "tier-99-fake-bogus"
        errors = _VTS.validate(rec, schema)
        self.assertTrue(errors)


class TestMigratorHonorsNewTier(unittest.TestCase):
    def test_migrator_preserves_new_record_tier(self) -> None:
        rec = _base_v1_record()
        rec["record_tier"] = _NEW_ENUM_VALUE
        upgraded = _MIGRATOR.migrate_record(copy.deepcopy(rec))
        self.assertEqual(upgraded.get("record_tier"), _NEW_ENUM_VALUE)
        self.assertEqual(
            upgraded.get("schema_version"),
            "auditooor.hackerman_record.v1.1",
        )


class TestStratifierHonorsExplicitTier(unittest.TestCase):
    """The stratifier returns the new tier when emitter asserts it."""

    def _load_stratifier(self):
        spec = importlib.util.spec_from_file_location(
            "_hackerman_stratify_test_tier1_officially_disclosed",
            str(_REPO / "tools" / "hackerman-stratify-verification-tier.py"),
        )
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
        return mod

    def test_stratifier_passthrough_on_record_tier(self) -> None:
        mod = self._load_stratifier()
        rec = _base_v1_1_record()
        rec["record_tier"] = _NEW_ENUM_VALUE
        tier, reason = mod.classify(rec)
        self.assertEqual(tier, _NEW_ENUM_VALUE)
        self.assertIn("record-tier", reason)

    def test_stratifier_passthrough_on_shape_tag(self) -> None:
        mod = self._load_stratifier()
        rec = _base_v1_1_record()
        rec["function_shape"]["shape_tags"].append(
            f"verification_tier:{_NEW_ENUM_VALUE}"
        )
        tier, reason = mod.classify(rec)
        self.assertEqual(tier, _NEW_ENUM_VALUE)
        self.assertIn("shape-tag", reason)

    def test_stratifier_lists_new_tier_in_taxonomy(self) -> None:
        mod = self._load_stratifier()
        self.assertIn(_NEW_ENUM_VALUE, mod.VERIFICATION_TIERS)


class TestQueryCommonEnumMirror(unittest.TestCase):
    def test_query_common_lists_new_tier(self) -> None:
        import sys
        mod_name = "_hackerman_query_common_test_tier1_officially_disclosed"
        spec = importlib.util.spec_from_file_location(
            mod_name,
            str(_REPO / "tools" / "hackerman_query_common.py"),
        )
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = mod
        try:
            spec.loader.exec_module(mod)  # type: ignore[union-attr]
            weights = getattr(mod, "RECORD_TIER_WEIGHTS")
        finally:
            sys.modules.pop(mod_name, None)
        self.assertIn(_NEW_ENUM_VALUE, weights)
        self.assertGreater(weights[_NEW_ENUM_VALUE], 0.0)
        self.assertGreater(
            weights[_NEW_ENUM_VALUE],
            weights["tier-2-verified-public-archive"],
        )
        self.assertGreater(
            weights[_NEW_ENUM_VALUE],
            weights["public-corpus"],
        )


if __name__ == "__main__":
    unittest.main()
