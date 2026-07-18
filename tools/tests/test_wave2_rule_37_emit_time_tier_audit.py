"""Tests for tools/wave2-rule-37-emit-time-tier-audit.py.

Synthetic fixtures only. Each YAML carries ``synthetic_fixture: true`` so
the records cannot be mistaken for live corpus material.
"""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "wave2-rule-37-emit-time-tier-audit.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "wave2_rule_37_emit_time_tier_audit", str(TOOL_PATH)
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


AUDIT = _load_module()


def _write_record(
    tags_dir: Path,
    name: str,
    *,
    verification_tier: str = "tier-2-verified-public-archive",
    schema_version: str = "auditooor.hackerman_record.v1.1",
    omit_tier: bool = False,
) -> Path:
    rel = Path(name)
    target = tags_dir / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"schema_version: {schema_version}",
        f"record_id: {rel.stem}",
        "synthetic_fixture: true",
        "target_repo: synthetic/repo",
        "bug_class: reentrancy",
        "attack_class: reentrancy-attack",
    ]
    if not omit_tier:
        lines.append(f"verification_tier: {verification_tier}")
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return target


def _make_workspace(tmpdir: Path) -> Path:
    ws = tmpdir / "workspace"
    (ws / "audit" / "corpus_tags" / "tags").mkdir(parents=True, exist_ok=True)
    return ws


class Rule37AuditTests(unittest.TestCase):
    def test_pass_all_canonical_tiers_set(self):
        """PASS: every record carries a canonical verification_tier value."""
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            tags = ws / "audit" / "corpus_tags" / "tags"
            for i, tier in enumerate(AUDIT.CANONICAL_TIERS):
                _write_record(
                    tags,
                    f"bucket_a/rec_{i}.yaml",
                    verification_tier=tier,
                )
            rc, payload = AUDIT.audit(ws)
            self.assertEqual(rc, 0)
            self.assertEqual(payload["overall_status"], "PASS")
            self.assertEqual(payload["compliant_count"], len(AUDIT.CANONICAL_TIERS))
            self.assertEqual(payload["violation_count"], 0)
            # All canonical -> taxonomy_variant_distribution canonical=N.
            self.assertEqual(
                payload["taxonomy_variant_distribution"].get("canonical"),
                len(AUDIT.CANONICAL_TIERS),
            )

    def test_fail_missing_field(self):
        """A record with no verification_tier triggers a missing-field violation."""
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            tags = ws / "audit" / "corpus_tags" / "tags"
            _write_record(tags, "bucket_b/good.yaml")
            _write_record(tags, "bucket_b/missing.yaml", omit_tier=True)
            rc, payload = AUDIT.audit(ws)
            self.assertEqual(payload["violation_count"], 1)
            self.assertEqual(payload["missing_field_count"], 1)
            self.assertEqual(payload["overall_status"], "WARNING")
            v = payload["violations"][0]
            self.assertEqual(v["kind"], "missing_field")
            self.assertEqual(v["prefix"], "bucket_b")
            # Strict mode propagates non-zero rc.
            self.assertEqual(rc, 1)

    def test_fail_invalid_value(self):
        """An invented verification_tier value triggers invalid-value."""
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            tags = ws / "audit" / "corpus_tags" / "tags"
            _write_record(
                tags,
                "bucket_c/bad.yaml",
                verification_tier="tier-99-invented",
            )
            rc, payload = AUDIT.audit(ws)
            self.assertEqual(payload["violation_count"], 1)
            self.assertEqual(payload["invalid_value_count"], 1)
            self.assertEqual(payload["overall_status"], "WARNING")
            v = payload["violations"][0]
            self.assertEqual(v["kind"], "invalid_value")
            self.assertEqual(v["tier_value"], "tier-99-invented")

    def test_quarantine_and_deprecated_excluded(self):
        """Records under _QUARANTINE_*/ and _deprecated/ are not audited."""
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            tags = ws / "audit" / "corpus_tags" / "tags"
            _write_record(tags, "active/good.yaml")
            # Quarantine record with no tier (would otherwise be a violation).
            _write_record(
                tags,
                "_QUARANTINE_FABRICATED_CVE/bad.yaml",
                omit_tier=True,
            )
            # Deprecated record with invalid tier (would otherwise be a violation).
            _write_record(
                tags,
                "_deprecated/old.yaml",
                verification_tier="tier-99-invented",
            )
            rc, payload = AUDIT.audit(ws)
            self.assertEqual(payload["total_records_scanned"], 1)
            self.assertEqual(payload["compliant_count"], 1)
            self.assertEqual(payload["violation_count"], 0)
            self.assertEqual(payload["skipped_quarantine"], 1)
            self.assertEqual(payload["skipped_deprecated"], 1)
            self.assertEqual(payload["overall_status"], "PASS")
            self.assertEqual(rc, 0)

    def test_mixed_prefix_breakdown(self):
        """prefix_breakdown reports per-prefix compliant/violation counts."""
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            tags = ws / "audit" / "corpus_tags" / "tags"
            # bucket_x: 2 compliant
            _write_record(tags, "bucket_x/a.yaml")
            _write_record(tags, "bucket_x/b.yaml")
            # bucket_y: 1 compliant + 1 missing
            _write_record(tags, "bucket_y/a.yaml")
            _write_record(tags, "bucket_y/b.yaml", omit_tier=True)
            # bucket_z: 1 invalid value
            _write_record(
                tags, "bucket_z/a.yaml", verification_tier="tier-7-fake"
            )
            rc, payload = AUDIT.audit(ws)
            self.assertEqual(payload["total_records_scanned"], 5)
            self.assertEqual(payload["compliant_count"], 3)
            self.assertEqual(payload["violation_count"], 2)
            pb = payload["prefix_breakdown"]
            # Wave-3 W3.2 lane: prefix_breakdown gained an `exempt` field
            # (always 0 here - no exemption registry written to this
            # synthetic workspace).
            self.assertEqual(
                pb["bucket_x"], {"compliant": 2, "violations": 0, "exempt": 0}
            )
            self.assertEqual(
                pb["bucket_y"], {"compliant": 1, "violations": 1, "exempt": 0}
            )
            self.assertEqual(
                pb["bucket_z"], {"compliant": 0, "violations": 1, "exempt": 0}
            )

    def test_brief_variant_tiers_accepted(self):
        """Brief-variant taxonomy values (e.g. tier-1-officially-disclosed)
        are accepted as compliant and tagged taxonomy_variant=brief-variant.
        """
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            tags = ws / "audit" / "corpus_tags" / "tags"
            _write_record(
                tags,
                "bucket_d/brief.yaml",
                verification_tier="tier-1-officially-disclosed",
            )
            rc, payload = AUDIT.audit(ws)
            self.assertEqual(payload["violation_count"], 0)
            self.assertEqual(payload["compliant_count"], 1)
            self.assertEqual(
                payload["taxonomy_variant_distribution"].get("brief-variant"), 1
            )

    def test_no_tier_sentinel_accepted(self):
        """``no_tier`` sentinel value is compliant."""
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            tags = ws / "audit" / "corpus_tags" / "tags"
            _write_record(
                tags, "bucket_e/no_tier.yaml", verification_tier="no_tier"
            )
            rc, payload = AUDIT.audit(ws)
            self.assertEqual(payload["compliant_count"], 1)
            self.assertEqual(payload["violation_count"], 0)
            self.assertEqual(
                payload["taxonomy_variant_distribution"].get("no-tier"), 1
            )

    def test_limit_records_caps_scan(self):
        """--limit-records caps the audited record count."""
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            tags = ws / "audit" / "corpus_tags" / "tags"
            for i in range(10):
                _write_record(tags, f"bucket_lim/rec_{i:02d}.yaml")
            rc, payload = AUDIT.audit(ws, limit=4)
            self.assertEqual(payload["total_records_scanned"], 4)


# ---------------------------------------------------------------------------
# Wave-3 W3.2 lane: R37 exemption registry tests
# ---------------------------------------------------------------------------


def _write_dsl_pattern_record(
    tags_dir: Path,
    name: str,
    *,
    include_tier: bool = False,
) -> Path:
    """Write a dsl_pattern_* style record (verdict_id schema, no tier)."""
    target = tags_dir / name
    target.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f'verdict_id: "dsl_pattern/{target.stem.replace("dsl_pattern_", "")}"',
        'target_repo: "unknown/dsl-synthetic"',
        'audit_pin_sha: "0000000"',
        "language: solidity",
        "verdict_class: CANDIDATE",
        "extraction_provenance: dsl_pattern_synthesis",
        "extractor_version: 0.1.0",
        "synthetic_fixture: true",
        'bug_class: "storage-collision"',
    ]
    if include_tier:
        lines.append("verification_tier: tier-3-synthetic-taxonomy-anchored")
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return target


def _write_registry(workspace: Path, body: str) -> Path:
    """Write the R37 exemption registry to its canonical location."""
    schemas_dir = workspace / "audit" / "corpus_tags" / "schemas"
    schemas_dir.mkdir(parents=True, exist_ok=True)
    target = schemas_dir / "r37_exemption_registry.yaml"
    target.write_text(body, encoding="utf-8")
    return target


REGISTRY_DSL_GLOB_BODY = """\
schema_version: auditooor.r37_exemption_registry.v1
exempt_prefixes:
  - prefix: dsl_pattern_*
    schema_family: dsl_pattern.synthetic
    rationale: synthesized pattern fixtures - no verification axis
exemption_gates:
  dsl_pattern_*:
    require_field_present:
      - verdict_id
      - extraction_provenance
    require_field_absent:
      - verification_tier
"""


REGISTRY_EXACT_PREFIX_BODY = """\
schema_version: auditooor.r37_exemption_registry.v1
exempt_prefixes:
  - prefix: bucket_b
    schema_family: test.exact_prefix
"""


class Rule37ExemptionRegistryTests(unittest.TestCase):
    """Wave-3 W3.2 lane: R37 exemption registry behavior."""

    def test_dsl_pattern_glob_exempts_missing_tier(self):
        """dsl_pattern_* glob registers as exempt instead of violation."""
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            tags = ws / "audit" / "corpus_tags" / "tags"
            _write_dsl_pattern_record(
                tags, "dsl_pattern_bucket-cache-missing.yaml"
            )
            _write_dsl_pattern_record(
                tags, "dsl_pattern_aave-borrow-bug.yaml"
            )
            _write_record(tags, "real_bucket/good.yaml")
            _write_registry(ws, REGISTRY_DSL_GLOB_BODY)
            rc, payload = AUDIT.audit(ws)
            self.assertEqual(payload["total_records_scanned"], 3)
            self.assertEqual(payload["compliant_count"], 1)
            self.assertEqual(payload["exempt_count"], 2)
            self.assertEqual(payload["violation_count"], 0)
            self.assertEqual(payload["overall_status"], "PASS")
            self.assertEqual(rc, 0)
            self.assertEqual(
                payload["exempt_reason_counts"].get("prefix-match-gate-ok"), 2
            )
            self.assertTrue(payload["exemption_registry"]["loaded"])
            self.assertIn(
                "dsl_pattern_*",
                payload["exemption_registry"]["exempt_prefixes"],
            )

    def test_dsl_pattern_with_tier_remains_compliant_not_exempt(self):
        """A dsl_pattern record that DOES carry verification_tier is
        compliant - the exemption is gated by require_field_absent.
        """
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            tags = ws / "audit" / "corpus_tags" / "tags"
            # Compliant: schema_v1.1-style dsl_pattern with tier set.
            _write_record(
                tags,
                "dsl_pattern_a/with_tier.yaml",
                verification_tier="tier-3-synthetic-taxonomy-anchored",
            )
            _write_registry(ws, REGISTRY_DSL_GLOB_BODY)
            rc, payload = AUDIT.audit(ws)
            self.assertEqual(payload["compliant_count"], 1)
            self.assertEqual(payload["exempt_count"], 0)
            self.assertEqual(payload["violation_count"], 0)

    def test_ignore_exemption_registry_reproduces_baseline(self):
        """ignore_exemption_registry=True reproduces the pre-W3.2 view."""
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            tags = ws / "audit" / "corpus_tags" / "tags"
            _write_dsl_pattern_record(
                tags, "dsl_pattern_bucket-cache-missing.yaml"
            )
            _write_registry(ws, REGISTRY_DSL_GLOB_BODY)
            rc, payload = AUDIT.audit(ws, ignore_exemption_registry=True)
            self.assertEqual(payload["violation_count"], 1)
            self.assertEqual(payload["exempt_count"], 0)
            self.assertEqual(payload["overall_status"], "WARNING")
            self.assertEqual(rc, 1)
            self.assertFalse(payload["exemption_registry"]["loaded"])

    def test_missing_registry_emits_zero_exempt(self):
        """No registry file - tool still works, zero exemptions."""
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            tags = ws / "audit" / "corpus_tags" / "tags"
            _write_dsl_pattern_record(
                tags, "dsl_pattern_bucket-cache-missing.yaml"
            )
            # NO registry written - load_exemption_registry returns empty.
            rc, payload = AUDIT.audit(ws)
            self.assertEqual(payload["exempt_count"], 0)
            self.assertEqual(payload["violation_count"], 1)
            self.assertFalse(payload["exemption_registry"]["loaded"])
            self.assertIsNone(payload["exemption_registry"]["error"])

    def test_exact_prefix_match(self):
        """Exact-equality (no trailing ``*``) prefix match also works."""
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            tags = ws / "audit" / "corpus_tags" / "tags"
            _write_record(tags, "bucket_b/no_tier.yaml", omit_tier=True)
            _write_registry(ws, REGISTRY_EXACT_PREFIX_BODY)
            rc, payload = AUDIT.audit(ws)
            self.assertEqual(payload["exempt_count"], 1)
            self.assertEqual(payload["violation_count"], 0)
            self.assertEqual(payload["overall_status"], "PASS")
            self.assertEqual(rc, 0)

    def test_record_outside_exempt_prefix_still_violates(self):
        """A non-dsl_pattern record without tier still counts as violation
        even when the registry is loaded.
        """
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            tags = ws / "audit" / "corpus_tags" / "tags"
            _write_dsl_pattern_record(
                tags, "dsl_pattern_bucket-cache-missing.yaml"
            )
            _write_record(tags, "real_bucket/no_tier.yaml", omit_tier=True)
            _write_registry(ws, REGISTRY_DSL_GLOB_BODY)
            rc, payload = AUDIT.audit(ws)
            self.assertEqual(payload["exempt_count"], 1)
            self.assertEqual(payload["violation_count"], 1)
            v = payload["violations"][0]
            self.assertEqual(v["prefix"], "real_bucket")
            self.assertEqual(v["kind"], "missing_field")

    def test_match_registry_prefix_helper(self):
        """_match_registry_prefix supports exact + trailing-wildcard."""
        ep = {"dsl_pattern_*": {}, "bucket_a": {}}
        self.assertEqual(
            AUDIT._match_registry_prefix("dsl_pattern_aave", ep),
            "dsl_pattern_*",
        )
        self.assertEqual(
            AUDIT._match_registry_prefix("bucket_a", ep),
            "bucket_a",
        )
        self.assertIsNone(AUDIT._match_registry_prefix("real_bucket", ep))

    def test_malformed_registry_yields_error_note(self):
        """A malformed registry file does not crash; error is reported."""
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            tags = ws / "audit" / "corpus_tags" / "tags"
            _write_record(tags, "real_bucket/good.yaml")
            _write_registry(ws, "this: is: not: valid: yaml\n[broken")
            rc, payload = AUDIT.audit(ws)
            self.assertEqual(payload["compliant_count"], 1)
            # Error path: registry_loaded=False, error string populated.
            reg = payload["exemption_registry"]
            self.assertFalse(reg["loaded"])
            self.assertIsNotNone(reg["error"])


if __name__ == "__main__":
    unittest.main()
