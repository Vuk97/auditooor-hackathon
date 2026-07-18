"""Tests for tools/hackerman-record-verification-tier-check.py.

The check tool audits the hackerman corpus tree for verification_tier
provenance and refuses to PASS a submission that cites a tier-5
quarantine record. These tests build small synthetic tag trees and call
the loaded module directly so they stay fast and deterministic.
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-record-verification-tier-check.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_verification_tier_check", str(TOOL_PATH)
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


def _v1_yaml(*, record_id: str, tier_tag: str | None = "tier-1-verified-realtime-api",
             extra_tags: list[str] | None = None) -> str:
    extra_tags = list(extra_tags or ["bug-class-foo", "pkg-example"])
    if tier_tag:
        extra_tags.append(f"verification_tier:{tier_tag}")
    tags_block = "\n".join(f"    - {t}" for t in extra_tags)
    return (
        "schema_version: auditooor.hackerman_record.v1\n"
        f"record_id: {record_id}\n"
        "source_audit_ref: example\n"
        "target_domain: dlt\n"
        "target_language: go\n"
        "target_repo: example/repo\n"
        "target_component: example\n"
        "function_shape:\n"
        "  raw_signature: example\n"
        "  shape_tags:\n"
        f"{tags_block}\n"
        "bug_class: example\n"
        "attack_class: example\n"
        "attacker_role: unprivileged\n"
        'attacker_action_sequence: "example"\n'
        "required_preconditions:\n"
        '  - "example"\n'
        "impact_class: dos\n"
        "impact_actor: arbitrary-user\n"
        'impact_dollar_class: "<$10K"\n'
        'fix_pattern: "example"\n'
        'fix_anti_pattern_avoided: "example"\n'
        "severity_at_finding: low\n"
        "year: 2025\n"
        "cross_language_analogues: []\n"
        "related_records: []\n"
    )


def _v1_1_first_class_yaml(
    *,
    record_id: str,
    first_class_tier: str | None = "tier-2-verified-public-archive",
    shape_tags: list[str] | None = None,
) -> str:
    """A schema v1.1 record carrying `verification_tier` as a first-class
    top-level field (Rule 37). `shape_tags` does NOT carry the tier - this
    is the canonical post-migration shape that the Check #72 9128-record
    backlog was made of.
    """
    shape_tags = list(shape_tags or ["bug-class-foo", "pkg-example"])
    tags_block = "\n".join(f"    - {t}" for t in shape_tags)
    fc_line = f"verification_tier: {first_class_tier}\n" if first_class_tier else ""
    return (
        "schema_version: auditooor.hackerman_record.v1.1\n"
        f"record_id: {record_id}\n"
        "source_audit_ref: example\n"
        f"{fc_line}"
        "target_domain: dlt\n"
        "target_language: go\n"
        "target_repo: example/repo\n"
        "target_component: example\n"
        "function_shape:\n"
        "  raw_signature: example\n"
        "  shape_tags:\n"
        f"{tags_block}\n"
        "bug_class: example\n"
        "attack_class: example\n"
        "attacker_role: unprivileged\n"
        'attacker_action_sequence: "example"\n'
        "required_preconditions:\n"
        '  - "example"\n'
        "impact_class: dos\n"
        "impact_actor: arbitrary-user\n"
        'impact_dollar_class: "<$10K"\n'
        'fix_pattern: "example"\n'
        'fix_anti_pattern_avoided: "example"\n'
        "severity_at_finding: low\n"
        "year: 2025\n"
        "cross_language_analogues: []\n"
        "related_records: []\n"
    )


def _v1_json(*, record_id: str, tier_tag: str | None = "tier-2-verified-public-archive") -> str:
    shape_tags = ["bug-class-foo", "pkg-example"]
    if tier_tag:
        shape_tags.append(f"verification_tier:{tier_tag}")
    payload = {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": record_id,
        "function_shape": {
            "raw_signature": "example",
            "shape_tags": shape_tags,
        },
    }
    return json.dumps(payload, indent=2)


def _v2_verdict_tag_yaml(*, verdict_id: str) -> str:
    """A non-hackerman-v1 record that shares the directory; must be skipped."""
    return (
        f"verdict_id: {verdict_id}\n"
        "target_repo: example/repo\n"
        'audit_pin_sha: "0000000"\n'
        "language: solidity\n"
        "verdict_class: CANDIDATE\n"
        "sites:\n"
        "- file_path: foo.sol\n"
    )


class AuditRecordTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()
        self.tmp = Path(tempfile.mkdtemp(prefix="hkrm_vtier_"))
        self.tags = self.tmp / "audit" / "corpus_tags" / "tags"
        self.tags.mkdir(parents=True)

    def _write(self, relpath: str, content: str) -> Path:
        p = self.tags / relpath
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    # ------------------------------------------------------------------ #
    # 1. happy path — hackerman v1 record with a valid tier tag
    # ------------------------------------------------------------------ #
    def test_pass_record_with_tier_tag(self) -> None:
        p = self._write("ok-record.yaml", _v1_yaml(record_id="example:ok"))
        verdict = self.tool.audit_record(p, self.tags)
        self.assertEqual(verdict["verdict"], "pass")
        self.assertEqual(verdict["verification_tier"], "tier-1-verified-realtime-api")
        self.assertEqual(verdict["schema_version"], "auditooor.hackerman_record.v1")

    # ------------------------------------------------------------------ #
    # 2. record missing verification_tier:tier-N-* fails
    # ------------------------------------------------------------------ #
    def test_fail_missing_tier_tag(self) -> None:
        p = self._write("missing.yaml", _v1_yaml(record_id="example:missing", tier_tag=None))
        verdict = self.tool.audit_record(p, self.tags)
        self.assertEqual(verdict["verdict"], "missing-tier")
        self.assertIsNone(verdict["verification_tier"])

    # ------------------------------------------------------------------ #
    # 3. malformed verification_tier (bad value) → malformed-tier
    # ------------------------------------------------------------------ #
    def test_fail_malformed_tier_value(self) -> None:
        p = self._write(
            "malformed.yaml",
            _v1_yaml(
                record_id="example:malformed",
                tier_tag=None,
                extra_tags=["bug-class-foo", "verification_tier:not-a-tier"],
            ),
        )
        verdict = self.tool.audit_record(p, self.tags)
        self.assertEqual(verdict["verdict"], "malformed-tier")

    # ------------------------------------------------------------------ #
    # 4. duplicate verification_tier tags → duplicate-tier
    # ------------------------------------------------------------------ #
    def test_fail_duplicate_tier_tags(self) -> None:
        p = self._write(
            "dup.yaml",
            _v1_yaml(
                record_id="example:dup",
                tier_tag=None,
                extra_tags=[
                    "verification_tier:tier-1-verified-realtime-api",
                    "verification_tier:tier-2-verified-public-archive",
                ],
            ),
        )
        verdict = self.tool.audit_record(p, self.tags)
        self.assertEqual(verdict["verdict"], "duplicate-tier")

    # ------------------------------------------------------------------ #
    # 5. record under _QUARANTINE_* tagged tier-5 passes as `quarantine`
    # ------------------------------------------------------------------ #
    def test_pass_quarantine_record_tier5(self) -> None:
        p = self._write(
            "_QUARANTINE_FABRICATED_CVE/vyper/fab-1.yaml",
            _v1_yaml(record_id="vyper-fab-1", tier_tag="tier-5-quarantine"),
        )
        verdict = self.tool.audit_record(p, self.tags)
        self.assertEqual(verdict["verdict"], "quarantine")
        self.assertTrue(verdict["quarantine"])
        self.assertEqual(verdict["verification_tier"], "tier-5-quarantine")

    # ------------------------------------------------------------------ #
    # 6. quarantined record WITHOUT tier-5 tag → quarantine-missing-tier
    # ------------------------------------------------------------------ #
    def test_fail_quarantine_record_missing_tier(self) -> None:
        p = self._write(
            "_QUARANTINE_FABRICATED_CVE/vyper/fab-2.yaml",
            _v1_yaml(record_id="vyper-fab-2", tier_tag=None),
        )
        verdict = self.tool.audit_record(p, self.tags)
        self.assertEqual(verdict["verdict"], "quarantine-missing-tier")
        self.assertTrue(verdict["quarantine"])

    # ------------------------------------------------------------------ #
    # 7. quarantined record tagged with a non-tier-5 tier → mismatch
    # ------------------------------------------------------------------ #
    def test_fail_quarantine_record_wrong_tier(self) -> None:
        p = self._write(
            "_QUARANTINE_FABRICATED_CVE/vyper/fab-3.yaml",
            _v1_yaml(record_id="vyper-fab-3", tier_tag="tier-2-verified-public-archive"),
        )
        verdict = self.tool.audit_record(p, self.tags)
        self.assertEqual(verdict["verdict"], "quarantine-tier-mismatch")

    # ------------------------------------------------------------------ #
    # 8. non-hackerman-v1 records (verdict_tag.v2 siblings) are skipped
    # ------------------------------------------------------------------ #
    def test_skip_non_hackerman_v1_record(self) -> None:
        p = self._write("legacy.yaml", _v2_verdict_tag_yaml(verdict_id="legacy-1"))
        verdict = self.tool.audit_record(p, self.tags)
        self.assertEqual(verdict["verdict"], "skipped-non-hackerman-v1")

    # ------------------------------------------------------------------ #
    # 8b. Wave-2 Phase-3 schema migration: v1.1 records must be recognised
    #     (NOT skipped). Regression-guard for the exact-match → prefix-match
    #     migration on the schema_version check.
    # ------------------------------------------------------------------ #
    def test_accept_hackerman_v1_1_record(self) -> None:
        body = _v1_yaml(record_id="example:v1_1").replace(
            "schema_version: auditooor.hackerman_record.v1",
            "schema_version: auditooor.hackerman_record.v1.1",
        )
        p = self._write("v1_1.yaml", body)
        verdict = self.tool.audit_record(p, self.tags)
        self.assertNotEqual(verdict["verdict"], "skipped-non-hackerman-v1")
        self.assertEqual(verdict["verdict"], "pass")
        self.assertEqual(verdict["schema_version"], "auditooor.hackerman_record.v1.1")

    # ------------------------------------------------------------------ #
    # 8c. Rule 37 first-class field: a v1.1 record whose tier lives in the
    #     top-level `verification_tier:` field (NOT in shape_tags) passes.
    #     Regression-guard for the Check #72 9128-record missing-tier
    #     backlog - the worker previously only scanned shape_tags.
    # ------------------------------------------------------------------ #
    def test_pass_v1_1_first_class_tier_no_shape_tag(self) -> None:
        p = self._write(
            "first-class.yaml",
            _v1_1_first_class_yaml(
                record_id="example:first-class",
                first_class_tier="tier-2-verified-public-archive",
            ),
        )
        verdict = self.tool.audit_record(p, self.tags)
        self.assertEqual(verdict["verdict"], "pass")
        self.assertEqual(verdict["verification_tier"], "tier-2-verified-public-archive")
        self.assertEqual(verdict["verification_tier_source"], "first-class-field")
        self.assertEqual(verdict["schema_version"], "auditooor.hackerman_record.v1.1")

    # ------------------------------------------------------------------ #
    # 8d. First-class field is preferred even when shape_tags ALSO carries
    #     a (different) tier tag - the first-class field wins.
    # ------------------------------------------------------------------ #
    def test_first_class_tier_preferred_over_shape_tag(self) -> None:
        body = _v1_1_first_class_yaml(
            record_id="example:both",
            first_class_tier="tier-2-verified-public-archive",
            shape_tags=["bug-class-foo", "verification_tier:tier-1-verified-realtime-api"],
        )
        p = self._write("both.yaml", body)
        verdict = self.tool.audit_record(p, self.tags)
        self.assertEqual(verdict["verdict"], "pass")
        self.assertEqual(verdict["verification_tier"], "tier-2-verified-public-archive")
        self.assertEqual(verdict["verification_tier_source"], "first-class-field")

    # ------------------------------------------------------------------ #
    # 8e. Legacy v1 record with NO first-class field still passes via the
    #     shape_tags fallback scan.
    # ------------------------------------------------------------------ #
    def test_legacy_v1_shape_tags_fallback_passes(self) -> None:
        p = self._write("legacy-ok.yaml", _v1_yaml(record_id="example:legacy-ok"))
        verdict = self.tool.audit_record(p, self.tags)
        self.assertEqual(verdict["verdict"], "pass")
        self.assertEqual(verdict["verification_tier_source"], "shape_tags")
        self.assertEqual(verdict["verification_tier"], "tier-1-verified-realtime-api")

    # ------------------------------------------------------------------ #
    # 8f. A record with NEITHER a first-class tier NOR a shape_tags tier
    #     still fails - the gate is not weakened.
    # ------------------------------------------------------------------ #
    def test_fail_neither_first_class_nor_shape_tag(self) -> None:
        body = _v1_1_first_class_yaml(
            record_id="example:no-tier",
            first_class_tier=None,
            shape_tags=["bug-class-foo", "pkg-example"],
        )
        p = self._write("no-tier.yaml", body)
        verdict = self.tool.audit_record(p, self.tags)
        self.assertEqual(verdict["verdict"], "missing-tier")
        self.assertIsNone(verdict["verification_tier"])

    # ------------------------------------------------------------------ #
    # 8g. A first-class field whose value is NOT in the taxonomy fails as
    #     malformed-tier (the gate does not silently accept junk values).
    # ------------------------------------------------------------------ #
    def test_fail_first_class_tier_malformed_value(self) -> None:
        body = _v1_1_first_class_yaml(
            record_id="example:bad-fc",
            first_class_tier="tier-9-mystery",
            shape_tags=["bug-class-foo"],
        )
        p = self._write("bad-fc.yaml", body)
        verdict = self.tool.audit_record(p, self.tags)
        self.assertEqual(verdict["verdict"], "malformed-tier")

    # ------------------------------------------------------------------ #
    # 8h. A quarantined record with a tier-5 FIRST-CLASS field behaves
    #     exactly as the existing tier-5 shape_tags case (verdict=quarantine).
    # ------------------------------------------------------------------ #
    def test_quarantine_record_first_class_tier5(self) -> None:
        body = _v1_1_first_class_yaml(
            record_id="vyper-fab-fc",
            first_class_tier="tier-5-quarantine",
            shape_tags=["bug-class-foo"],
        )
        p = self._write("_QUARANTINE_FABRICATED_CVE/vyper/fab-fc.yaml", body)
        verdict = self.tool.audit_record(p, self.tags)
        self.assertEqual(verdict["verdict"], "quarantine")
        self.assertTrue(verdict["quarantine"])
        self.assertEqual(verdict["verification_tier"], "tier-5-quarantine")

    # ------------------------------------------------------------------ #
    # 8i. A quarantined record whose first-class tier is NOT tier-5 still
    #     surfaces as quarantine-tier-mismatch.
    # ------------------------------------------------------------------ #
    def test_quarantine_record_first_class_non_tier5_mismatch(self) -> None:
        body = _v1_1_first_class_yaml(
            record_id="vyper-fab-fc2",
            first_class_tier="tier-2-verified-public-archive",
            shape_tags=["bug-class-foo"],
        )
        p = self._write("_QUARANTINE_FABRICATED_CVE/vyper/fab-fc2.yaml", body)
        verdict = self.tool.audit_record(p, self.tags)
        self.assertEqual(verdict["verdict"], "quarantine-tier-mismatch")

    # ------------------------------------------------------------------ #
    # 9. record.json bundle is recognised and audited
    # ------------------------------------------------------------------ #
    def test_pass_record_json_bundle(self) -> None:
        p = self._write(
            "cosmos_sdk_ibc/example-bundle/record.json",
            _v1_json(record_id="cosmos:example", tier_tag="tier-2-verified-public-archive"),
        )
        verdict = self.tool.audit_record(p, self.tags)
        self.assertEqual(verdict["verdict"], "pass")
        self.assertEqual(verdict["verification_tier"], "tier-2-verified-public-archive")

    # ------------------------------------------------------------------ #
    # 10. unknown tier values surface as `unknown-tier`
    # ------------------------------------------------------------------ #
    def test_fail_unknown_tier_value(self) -> None:
        p = self._write(
            "unknown.yaml",
            _v1_yaml(
                record_id="example:unknown",
                tier_tag=None,
                extra_tags=[
                    "bug-class-foo",
                    "verification_tier:tier-9-mystery-source",
                ],
            ),
        )
        verdict = self.tool.audit_record(p, self.tags)
        # tier-9 doesn't match the strict regex (only 1-5) so this becomes
        # malformed-tier, not unknown-tier. Test the contract: the verdict is
        # in FAIL_VERDICTS.
        self.assertIn(verdict["verdict"], {"malformed-tier", "unknown-tier"})


class RunEndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()
        self.tmp = Path(tempfile.mkdtemp(prefix="hkrm_vtier_e2e_"))
        self.tags = self.tmp / "audit" / "corpus_tags" / "tags"
        self.tags.mkdir(parents=True)

    def _write(self, relpath: str, content: str) -> Path:
        p = self.tags / relpath
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    # ------------------------------------------------------------------ #
    # 11. clean tree with two tagged records + one verdict.v2 → PASS rc=0
    # ------------------------------------------------------------------ #
    def test_run_clean_tree_passes(self) -> None:
        self._write("a.yaml", _v1_yaml(record_id="a"))
        self._write("b.yaml", _v1_yaml(record_id="b", tier_tag="tier-3-synthetic-taxonomy-anchored"))
        self._write("c.yaml", _v2_verdict_tag_yaml(verdict_id="legacy"))
        rc, payload = self.tool.run(self.tags)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass")
        self.assertEqual(payload["audited_hackerman_v1"], 2)
        self.assertEqual(payload["skipped_non_hackerman_v1"], 1)
        self.assertEqual(payload["verdict_counts"].get("pass", 0), 2)

    # ------------------------------------------------------------------ #
    # 12. tree with a missing-tier record → FAIL rc=1
    # ------------------------------------------------------------------ #
    def test_run_missing_tier_fails(self) -> None:
        self._write("a.yaml", _v1_yaml(record_id="a"))
        self._write("b.yaml", _v1_yaml(record_id="b", tier_tag=None))
        rc, payload = self.tool.run(self.tags)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail")
        self.assertIn("missing-tier", payload["verdict_counts"])
        self.assertGreaterEqual(len(payload["failed_records"]), 1)

    # ------------------------------------------------------------------ #
    # 13. submission citing tier-5 record_id → FAIL with quarantine_refs
    # ------------------------------------------------------------------ #
    def test_run_submission_cites_quarantine_record(self) -> None:
        self._write("a.yaml", _v1_yaml(record_id="a"))
        self._write(
            "_QUARANTINE_FABRICATED_CVE/vyper/fab-X.yaml",
            _v1_yaml(record_id="vyper-fab-X", tier_tag="tier-5-quarantine"),
        )
        sub_path = self.tmp / "submission.md"
        sub_path.write_text(
            "## Originality\nPrior art: vyper-fab-X is a similar finding.\n",
            encoding="utf-8",
        )
        rc, payload = self.tool.run(self.tags, sub_path)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail")
        self.assertEqual(len(payload["submission_quarantine_refs"]), 1)
        ref = payload["submission_quarantine_refs"][0]
        self.assertEqual(ref["record_id"], "vyper-fab-X")
        self.assertIn("record_id", ref["matched_via"])

    # ------------------------------------------------------------------ #
    # 14. submission that does NOT cite quarantine records → PASS
    # ------------------------------------------------------------------ #
    def test_run_submission_clean_passes(self) -> None:
        self._write("a.yaml", _v1_yaml(record_id="a"))
        self._write(
            "_QUARANTINE_FABRICATED_CVE/vyper/fab-Y.yaml",
            _v1_yaml(record_id="vyper-fab-Y", tier_tag="tier-5-quarantine"),
        )
        sub_path = self.tmp / "submission.md"
        sub_path.write_text(
            "## Originality\nNo fabricated CVE references here.\n",
            encoding="utf-8",
        )
        rc, payload = self.tool.run(self.tags, sub_path)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass")
        self.assertEqual(payload["submission_quarantine_refs"], [])

    # ------------------------------------------------------------------ #
    # 15. missing tags dir → rc=2 unless allow-missing-tags-dir is set
    # ------------------------------------------------------------------ #
    def test_run_missing_tags_dir_errors(self) -> None:
        bogus = self.tmp / "does-not-exist"
        rc, payload = self.tool.run(bogus)
        self.assertEqual(rc, 2)
        self.assertEqual(payload["verdict"], "error")
        rc, payload = self.tool.run(bogus, fail_on_missing_dir=False)
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
