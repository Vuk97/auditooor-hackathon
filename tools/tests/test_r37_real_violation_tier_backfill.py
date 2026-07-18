"""Tests for tools/r37-real-violation-tier-backfill.py.

Synthetic fixtures only. Each YAML carries ``synthetic_fixture: true`` so
the records cannot be mistaken for live corpus material.
"""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "r37-real-violation-tier-backfill.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "r37_real_violation_tier_backfill", str(TOOL_PATH)
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


BF = _load_module()


def _write(tags_dir: Path, name: str, body: str) -> Path:
    p = tags_dir / name
    p.write_text(body, encoding="utf-8")
    return p


class TestClassifyTier(unittest.TestCase):
    def test_manual_provenance_maps_to_public_archive(self):
        tier, pending = BF.classify_tier({"extraction_provenance": "manual"})
        self.assertEqual(tier, BF.TIER_PUBLIC_ARCHIVE)
        self.assertFalse(pending)

    def test_hybrid_provenance_maps_to_bundled_fixture(self):
        tier, pending = BF.classify_tier({"extraction_provenance": "hybrid"})
        self.assertEqual(tier, BF.TIER_BUNDLED_FIXTURE)
        self.assertFalse(pending)

    def test_regex_provenance_maps_to_bundled_fixture(self):
        tier, pending = BF.classify_tier({"extraction_provenance": "regex"})
        self.assertEqual(tier, BF.TIER_BUNDLED_FIXTURE)
        self.assertFalse(pending)

    def test_missing_provenance_is_pending_m14_trap(self):
        tier, pending = BF.classify_tier({"verdict_id": "x"})
        self.assertEqual(tier, BF.TIER_PENDING)
        self.assertTrue(pending)

    def test_unrecognised_provenance_is_pending(self):
        tier, pending = BF.classify_tier({"extraction_provenance": "wat"})
        self.assertEqual(tier, BF.TIER_PENDING)
        self.assertTrue(pending)

    def test_smuggled_tier_in_shape_tags_is_lifted(self):
        payload = {
            "function_shape": {
                "shape_tags": [
                    "some-tag",
                    "verification_tier:tier-2-verified-public-archive",
                ]
            }
        }
        tier, pending = BF.classify_tier(payload)
        self.assertEqual(tier, BF.TIER_PUBLIC_ARCHIVE)
        self.assertFalse(pending)

    def test_smuggled_tier_takes_precedence_over_provenance(self):
        payload = {
            "extraction_provenance": "hybrid",
            "function_shape": {
                "shape_tags": [
                    "verification_tier:tier-2-verified-public-archive",
                ]
            },
        }
        tier, _ = BF.classify_tier(payload)
        self.assertEqual(tier, BF.TIER_PUBLIC_ARCHIVE)

    def test_invalid_smuggled_tier_falls_through_to_provenance(self):
        payload = {
            "extraction_provenance": "manual",
            "function_shape": {
                "shape_tags": ["verification_tier:bogus-tier"]
            },
        }
        tier, _ = BF.classify_tier(payload)
        self.assertEqual(tier, BF.TIER_PUBLIC_ARCHIVE)


class TestExemption(unittest.TestCase):
    def test_dsl_pattern_synthetic_family_is_exempt(self):
        # synthetic-pattern family: has verdict_id + extraction_provenance
        payload = {
            "verdict_id": "dsl_pattern/x",
            "extraction_provenance": "dsl_pattern_synthesis",
        }
        self.assertTrue(BF.is_exempt("dsl_pattern_foo.yaml", payload))

    def test_dsl_pattern_universal_fp_is_not_exempt(self):
        # real hackerman_record.v1 file moved into the dsl_pattern prefix:
        # lacks verdict_id + extraction_provenance -> NOT exempt.
        payload = {
            "schema_version": "auditooor.hackerman_record.v1",
            "record_id": "fp-001",
        }
        self.assertFalse(
            BF.is_exempt("dsl_pattern_universal_fp_001_x.yaml", payload)
        )

    def test_non_dsl_record_is_not_exempt(self):
        self.assertFalse(
            BF.is_exempt("solodit_123_h01-thing.yaml", {"verdict_id": "x"})
        )
        self.assertFalse(
            BF.is_exempt("FN1-IMMUNEFI-SUBMISSION.md.yaml", {})
        )


class TestFindAndBackfill(unittest.TestCase):
    def _setup(self) -> Path:
        d = Path(self._tmp.name)
        # manual -> tier-2
        _write(
            d,
            "solodit_999_h01-example.yaml",
            "verdict_id: solodit/999/h01\n"
            "extraction_provenance: manual\n"
            "bug_class: example\n"
            "synthetic_fixture: true\n",
        )
        # hybrid -> tier-4
        _write(
            d,
            "dydx-hunt_VERDICT.md.yaml",
            "verdict_id: dydx-hunt/VERDICT.md\n"
            "extraction_provenance: hybrid\n"
            "synthetic_fixture: true\n",
        )
        # missing provenance -> pending
        _write(
            d,
            "weird_record.yaml",
            "verdict_id: weird/record\n"
            "synthetic_fixture: true\n",
        )
        # already compliant -> not a violation
        _write(
            d,
            "already_tiered.yaml",
            "verdict_id: already/tiered\n"
            "extraction_provenance: manual\n"
            "verification_tier: tier-2-verified-public-archive\n"
            "synthetic_fixture: true\n",
        )
        # exempt dsl_pattern (synthetic family) -> must be untouched
        _write(
            d,
            "dsl_pattern_synthetic_thing.yaml",
            "verdict_id: dsl_pattern/thing\n"
            "extraction_provenance: dsl_pattern_synthesis\n"
            "synthetic_fixture: true\n",
        )
        # dsl_pattern_universal_fp: real hackerman_record, NOT exempt,
        # tier smuggled into shape_tags -> must be lifted to tier-2.
        _write(
            d,
            "dsl_pattern_universal_fp_001_thing.yaml",
            "schema_version: auditooor.hackerman_record.v1\n"
            "record_id: fp-001-thing\n"
            "function_shape:\n"
            "  raw_signature: F\n"
            "  shape_tags:\n"
            "    - some-tag\n"
            "    - verification_tier:tier-2-verified-public-archive\n"
            "synthetic_fixture: true\n",
        )
        return d

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self._tmp.cleanup()

    def test_find_violations_excludes_exempt_and_compliant(self):
        d = self._setup()
        viol = {p.name for p in BF.find_violations(d)}
        self.assertEqual(
            viol,
            {
                "solodit_999_h01-example.yaml",
                "dydx-hunt_VERDICT.md.yaml",
                "weird_record.yaml",
                "dsl_pattern_universal_fp_001_thing.yaml",
            },
        )

    def test_universal_fp_smuggled_tier_lifted_to_first_class(self):
        d = self._setup()
        BF.run(d, apply=True)
        fp = (d / "dsl_pattern_universal_fp_001_thing.yaml").read_text()
        self.assertIn(
            "verification_tier: tier-2-verified-public-archive", fp
        )

    def test_v1_schema_record_is_bumped_to_v11(self):
        d = self._setup()
        before = (d / "dsl_pattern_universal_fp_001_thing.yaml").read_text()
        self.assertIn("schema_version: auditooor.hackerman_record.v1\n", before)
        BF.run(d, apply=True)
        after = (d / "dsl_pattern_universal_fp_001_thing.yaml").read_text()
        self.assertIn(
            "schema_version: auditooor.hackerman_record.v1.1\n", after
        )
        self.assertNotIn(
            "schema_version: auditooor.hackerman_record.v1\n", after
        )

    def test_non_v1_schema_record_keeps_schema_version(self):
        # the verdict_id-style records have no schema_version - the bump
        # must not invent one.
        d = self._setup()
        BF.run(d, apply=True)
        dydx = (d / "dydx-hunt_VERDICT.md.yaml").read_text()
        self.assertNotIn("schema_version", dydx)

    def test_apply_backfills_first_class_field(self):
        d = self._setup()
        rc = BF.run(d, apply=True)
        self.assertEqual(rc, 0)
        sol = (d / "solodit_999_h01-example.yaml").read_text()
        self.assertIn(
            "verification_tier: tier-2-verified-public-archive", sol
        )
        dydx = (d / "dydx-hunt_VERDICT.md.yaml").read_text()
        self.assertIn("verification_tier: tier-4-bundled-fixture", dydx)

    def test_apply_pending_record_gets_rebuttal_marker(self):
        d = self._setup()
        BF.run(d, apply=True)
        weird = (d / "weird_record.yaml").read_text()
        self.assertIn(
            "verification_tier: tier-pending-operator-classify", weird
        )
        self.assertIn("r37_rebuttal:", weird)

    def test_apply_does_not_touch_exempt_dsl_pattern(self):
        d = self._setup()
        before = (d / "dsl_pattern_synthetic_thing.yaml").read_text()
        BF.run(d, apply=True)
        after = (d / "dsl_pattern_synthetic_thing.yaml").read_text()
        self.assertEqual(before, after)
        self.assertNotIn("verification_tier", after)

    def test_idempotent_second_apply_is_noop(self):
        d = self._setup()
        BF.run(d, apply=True)
        first = {
            p.name: p.read_text() for p in d.glob("*.yaml")
        }
        BF.run(d, apply=True)
        second = {
            p.name: p.read_text() for p in d.glob("*.yaml")
        }
        self.assertEqual(first, second)

    def test_check_mode_does_not_modify_files(self):
        d = self._setup()
        before = {p.name: p.read_text() for p in d.glob("*.yaml")}
        rc = BF.run(d, apply=False)
        after = {p.name: p.read_text() for p in d.glob("*.yaml")}
        self.assertEqual(before, after)
        self.assertEqual(rc, 1)  # violations remain

    def test_check_after_apply_is_clean(self):
        d = self._setup()
        BF.run(d, apply=True)
        rc = BF.run(d, apply=False)
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
