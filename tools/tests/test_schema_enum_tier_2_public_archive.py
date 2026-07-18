"""Tests for the W2.7.a (2026-05-16) record_tier enum extension.

Adds ``tier-2-verified-public-archive`` to the ``record_tier`` enum of
both ``auditooor.hackerman_record.v1`` and
``auditooor.hackerman_record.v1.1`` schemas so off-GitHub miners (the
W2.7.a Immunefi-dashboard / Medium / public-archive miners and the
W2.7.b/c follow-ups) can emit a single canonical provenance value
instead of the legacy ``public-corpus`` + sibling-``verification_tier``
two-field workaround.

These tests do not import the W2.7.a / b / c miners themselves because
those tools live on a separate branch (PR #730, wave-2-offgithub-mining);
the schema is the only contract this PR-A branch owns and the only
contract whose enum must accept the new value.

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

# Load the project-local JSON-schema validator used by
# tools/hackerman-record-validate.py.
_VTS_SPEC = importlib.util.spec_from_file_location(
    "_verdict_tag_schema_test", str(_REPO / "tools" / "verdict-tag-schema.py")
)
assert _VTS_SPEC is not None and _VTS_SPEC.loader is not None
_VTS = importlib.util.module_from_spec(_VTS_SPEC)
_VTS_SPEC.loader.exec_module(_VTS)  # type: ignore[union-attr]

# Load the schema-v1-to-v1.1 migrator (no record_tier enum mirror lives
# inside it, but we exercise it on the new value to confirm passthrough).
_MIGRATOR_SPEC = importlib.util.spec_from_file_location(
    "_hackerman_schema_v1_to_v1_1_migrator_test",
    str(_REPO / "tools" / "hackerman-schema-v1-to-v1.1-migrator.py"),
)
assert _MIGRATOR_SPEC is not None and _MIGRATOR_SPEC.loader is not None
_MIGRATOR = importlib.util.module_from_spec(_MIGRATOR_SPEC)
_MIGRATOR_SPEC.loader.exec_module(_MIGRATOR)  # type: ignore[union-attr]


_NEW_ENUM_VALUE = "tier-2-verified-public-archive"
_LEGACY_ENUM_VALUES = (
    "public-corpus",
    "local-workspace",
    "submission-derived",
    "dydx-filed",
    "mezo-filed",
)


def _base_v1_record() -> Dict[str, Any]:
    """A minimally-populated v1 record used as a template for tests.

    Marked ``synthetic_fixture`` so any downstream telemetry sweep can
    distinguish test fixtures from real corpus records. (The schema's
    ``additionalProperties: false`` rejects unknown top-level fields, so
    the marker lives inside the test rather than the record body.)
    """
    return {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": "synthetic-fixture:tier2-enum:0001",
        "source_audit_ref": "synthetic:test:w27a-enum",
        "target_domain": "lending",
        "target_language": "solidity",
        "target_repo": "synthetic/fixture",
        "target_component": "src/Pool.sol::synthetic",
        "function_shape": {
            "raw_signature": "function synthetic()",
            "shape_tags": ["state-mutating"],
        },
        "bug_class": "missing-access-control",
        "attack_class": "unauth-state-write",
        "attacker_role": "unprivileged",
        "attacker_action_sequence": "Synthetic fixture only - not a real exploit.",
        "required_preconditions": ["Synthetic precondition."],
        "impact_class": "theft",
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": ">=$1M",
        "fix_pattern": "Synthetic fix.",
        "fix_anti_pattern_avoided": "Synthetic anti-pattern.",
        "severity_at_finding": "high",
        "year": 2025,
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
    """Each schema parses as JSON without errors."""

    def test_v1_loads(self) -> None:
        schema = _load_schema(_SCHEMA_V1)
        self.assertEqual(schema.get("$id"), "auditooor.hackerman_record.v1")
        self.assertIn("record_tier", schema["properties"])

    def test_v1_1_loads(self) -> None:
        schema = _load_schema(_SCHEMA_V1_1)
        # v1.1 keeps the same $id is NOT required; only confirm structure.
        self.assertIn("record_tier", schema["properties"])


class TestNewEnumValuePresent(unittest.TestCase):
    """The new tier-2 enum value is declared in both schemas."""

    def test_v1_enum_contains_new_value(self) -> None:
        schema = _load_schema(_SCHEMA_V1)
        enum_values = schema["properties"]["record_tier"]["enum"]
        self.assertIn(_NEW_ENUM_VALUE, enum_values)

    def test_v1_1_enum_contains_new_value(self) -> None:
        schema = _load_schema(_SCHEMA_V1_1)
        enum_values = schema["properties"]["record_tier"]["enum"]
        self.assertIn(_NEW_ENUM_VALUE, enum_values)

    def test_v1_enum_has_description_mentioning_w27a(self) -> None:
        schema = _load_schema(_SCHEMA_V1)
        record_tier_prop = schema["properties"]["record_tier"]
        # Confirm the W2.7.a / 2026-05-16 marker landed in the property
        # description (matches the empirical-anchor convention used
        # elsewhere in the schema for `verdict_artefact` etc.).
        self.assertIn("W2.7.a", record_tier_prop.get("description", ""))


class TestRecordEmitterAcceptsNewTier(unittest.TestCase):
    """A synthetic record carrying record_tier=tier-2-... validates cleanly."""

    def test_v1_record_with_new_tier_validates(self) -> None:
        schema = _load_schema(_SCHEMA_V1)
        rec = _base_v1_record()
        rec["record_tier"] = _NEW_ENUM_VALUE
        errors = _VTS.validate(rec, schema)
        self.assertEqual(errors, [], msg=f"unexpected errors: {errors}")

    def test_v1_1_record_with_new_tier_validates(self) -> None:
        schema = _load_schema(_SCHEMA_V1_1)
        rec = _base_v1_1_record()
        rec["record_tier"] = _NEW_ENUM_VALUE
        errors = _VTS.validate(rec, schema)
        self.assertEqual(errors, [], msg=f"unexpected errors: {errors}")


class TestExistingTierValuesStillValid(unittest.TestCase):
    """Regression: every pre-W2.7.a enum value still passes validation."""

    def test_v1_each_legacy_tier_validates(self) -> None:
        schema = _load_schema(_SCHEMA_V1)
        for legacy in _LEGACY_ENUM_VALUES:
            with self.subTest(record_tier=legacy):
                rec = _base_v1_record()
                rec["record_tier"] = legacy
                errors = _VTS.validate(rec, schema)
                self.assertEqual(
                    errors,
                    [],
                    msg=f"legacy value {legacy!r} regressed: {errors}",
                )

    def test_v1_1_each_legacy_tier_validates(self) -> None:
        schema = _load_schema(_SCHEMA_V1_1)
        for legacy in _LEGACY_ENUM_VALUES:
            with self.subTest(record_tier=legacy):
                rec = _base_v1_1_record()
                rec["record_tier"] = legacy
                errors = _VTS.validate(rec, schema)
                self.assertEqual(
                    errors,
                    [],
                    msg=f"legacy value {legacy!r} regressed: {errors}",
                )

    def test_v1_unknown_tier_still_rejected(self) -> None:
        """Negative-control: a non-enum string is still rejected."""
        schema = _load_schema(_SCHEMA_V1)
        rec = _base_v1_record()
        rec["record_tier"] = "tier-99-fake-bogus"
        errors = _VTS.validate(rec, schema)
        self.assertTrue(errors, msg="unknown record_tier should not validate")


class TestMigratorHonorsNewTier(unittest.TestCase):
    """The v1->v1.1 migrator does not silently drop the new enum value.

    The migrator does not own a record_tier-enum mirror; it copies the
    field through verbatim. This test guards against a future refactor
    that would accidentally enumerate / whitelist values and drop the
    new one.
    """

    def test_migrator_preserves_new_tier(self) -> None:
        rec = _base_v1_record()
        rec["record_tier"] = _NEW_ENUM_VALUE
        upgraded = _MIGRATOR.migrate_record(copy.deepcopy(rec))
        self.assertEqual(upgraded.get("record_tier"), _NEW_ENUM_VALUE)
        # Schema version is bumped; record_tier survives.
        self.assertEqual(
            upgraded.get("schema_version"),
            "auditooor.hackerman_record.v1.1",
        )


class TestQueryCommonEnumMirror(unittest.TestCase):
    """The RECORD_TIER_WEIGHTS dict in tools/hackerman_query_common.py is
    the only hard-coded enum mirror in the repository. It must carry the
    new value with a sensible weight.
    """

    def test_query_common_lists_new_tier(self) -> None:
        import sys
        mod_name = "_hackerman_query_common_test_w27a"
        spec = importlib.util.spec_from_file_location(
            mod_name,
            str(_REPO / "tools" / "hackerman_query_common.py"),
        )
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        # Register in sys.modules BEFORE exec_module so dataclasses
        # (which look up the defining module via sys.modules) can
        # resolve type names declared at class-body scope. Required on
        # Python 3.14+ where dataclasses _is_type does
        # `sys.modules.get(cls.__module__).__dict__`.
        sys.modules[mod_name] = mod
        try:
            spec.loader.exec_module(mod)  # type: ignore[union-attr]
            weights = getattr(mod, "RECORD_TIER_WEIGHTS")
        finally:
            sys.modules.pop(mod_name, None)
        self.assertIn(_NEW_ENUM_VALUE, weights)
        # Sanity: a real positive numeric weight.
        self.assertGreater(weights[_NEW_ENUM_VALUE], 0.0)
        # The new tier ranks above raw public-corpus (verified provenance).
        self.assertGreater(weights[_NEW_ENUM_VALUE], weights["public-corpus"])


if __name__ == "__main__":
    unittest.main()
