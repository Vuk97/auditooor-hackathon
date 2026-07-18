"""Tests for tools/hackerman-record-provenance-audit.py.

The tool audits hackerman corpus records across four provenance axes:

  1. source_audit_ref non-empty + well-formed
  2. required_preconditions has >=1 URL citation
  3. verification_tier:tier-N-* tag present
  4. tier-1 records must use an externally-refetchable scheme

Tests build small synthetic tag trees and call the loaded module directly so
they stay fast and dependency-free (no PyYAML required).
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-record-provenance-audit.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "_hackerman_record_provenance_audit", str(TOOL_PATH)
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


def _v1_yaml(
    *,
    record_id: str,
    source_audit_ref: str = "https://github.com/example/repo/security/advisories/GHSA-aaaa-bbbb-cccc",
    tier_tag: str | None = "tier-2-verified-public-archive",
    preconds: list[str] | None = None,
    extra_shape_tags: list[str] | None = None,
) -> str:
    if preconds is None:
        preconds = [
            "Reference advisory at https://github.com/example/repo/security/advisories/GHSA-aaaa-bbbb-cccc",
            "Affected repo example/repo",
        ]
    shape_tags = list(extra_shape_tags or ["bug-class-example", "lang-solidity"])
    if tier_tag:
        shape_tags.append(f"verification_tier:{tier_tag}")
    tags_block = "\n".join(f"    - {t}" for t in shape_tags)
    pre_block = "\n".join(f"  - {p!r}" for p in preconds)
    return (
        "schema_version: auditooor.hackerman_record.v1\n"
        f"record_id: {record_id}\n"
        f"source_audit_ref: {source_audit_ref!r}\n"
        "target_domain: dlt\n"
        "target_language: solidity\n"
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
        f"{pre_block}\n"
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


def _v1_json_text(
    *,
    record_id: str,
    source_audit_ref: str,
    tier_tag: str | None = "tier-1-verified-realtime-api",
    preconds: list[str] | None = None,
) -> str:
    if preconds is None:
        preconds = [
            "Reference at https://example.com/x",
            "Other condition without url",
        ]
    shape_tags = ["bug-class-example", "lang-solidity"]
    if tier_tag:
        shape_tags.append(f"verification_tier:{tier_tag}")
    payload = {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": record_id,
        "source_audit_ref": source_audit_ref,
        "function_shape": {
            "raw_signature": "example",
            "shape_tags": shape_tags,
        },
        "required_preconditions": preconds,
    }
    return json.dumps(payload, indent=2)


class ClassifySourceRefTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()

    def test_url_scheme_https(self) -> None:
        s, ok = self.tool.classify_source_ref("https://github.com/foo/bar/security/advisories/GHSA-x")
        self.assertEqual(s, "url-https")
        self.assertTrue(ok)

    def test_git_mining_scheme(self) -> None:
        s, ok = self.tool.classify_source_ref("git-mining:foo/bar@abcdef1234567890abcdef")
        self.assertEqual(s, "git-mining")
        self.assertTrue(ok)

    def test_cve_id(self) -> None:
        s, ok = self.tool.classify_source_ref("CVE-2023-12345")
        self.assertEqual(s, "cve-id")
        self.assertTrue(ok)

    def test_ghsa_id_lowercase(self) -> None:
        s, ok = self.tool.classify_source_ref("GHSA-fjpv-hq67-rcgh")
        self.assertEqual(s, "ghsa-id")
        self.assertTrue(ok)

    def test_asa_id(self) -> None:
        s, ok = self.tool.classify_source_ref("ASA-2024-0012")
        self.assertEqual(s, "asa-id")
        self.assertTrue(ok)

    def test_contest_finding_ids(self) -> None:
        s, ok = self.tool.classify_source_ref("code4rena:2023-04-foo-findings:42")
        self.assertEqual(s, "code4rena")
        self.assertTrue(ok)
        s, ok = self.tool.classify_source_ref("sherlock:2024-08-foo-judging:007")
        self.assertEqual(s, "sherlock")
        self.assertTrue(ok)

    def test_audit_firm_with_spaces_in_path(self) -> None:
        s, ok = self.tool.classify_source_ref(
            "audit-firm:pashov-audits:team/pdf/WishWish-security-review_2025-11-04 (1).pdf"
        )
        self.assertEqual(s, "audit-firm")
        self.assertTrue(ok)

    def test_internal_scheme_solodit_spec(self) -> None:
        s, ok = self.tool.classify_source_ref(
            "solodit-spec:reference/solodit/some-finding-slug"
        )
        self.assertEqual(s, "internal-scheme")
        self.assertTrue(ok)

    def test_bare_path_is_malformed(self) -> None:
        s, ok = self.tool.classify_source_ref("dsl_pattern/a-flashloan-will-be-broken")
        self.assertIsNone(s)
        self.assertFalse(ok)

    def test_empty_is_not_well_formed(self) -> None:
        s, ok = self.tool.classify_source_ref("")
        self.assertIsNone(s)
        self.assertFalse(ok)
        s, ok = self.tool.classify_source_ref(None)
        self.assertIsNone(s)
        self.assertFalse(ok)


class AuditRecordTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()
        self.tmp = Path(tempfile.mkdtemp(prefix="hkrm_prov_"))
        self.tags = self.tmp / "audit" / "corpus_tags" / "tags"
        self.tags.mkdir(parents=True)

    def _write(self, relpath: str, content: str) -> Path:
        p = self.tags / relpath
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def test_pass_full_provenance(self) -> None:
        p = self._write(
            "amm_yield_lst_protocols/ok/record.yaml",
            _v1_yaml(record_id="example:ok"),
        )
        v = self.tool.audit_record(p, self.tags)
        self.assertEqual(v["verdict"], "pass")
        self.assertEqual(v["gaps"], [])
        self.assertEqual(v["source_ref_scheme"], "url-https")
        self.assertEqual(v["preconds_url_count"], 1)

    def test_empty_source_audit_ref_gap(self) -> None:
        p = self._write(
            "bridge_incidents/empty/record.yaml",
            _v1_yaml(record_id="example:empty-ref", source_audit_ref=""),
        )
        v = self.tool.audit_record(p, self.tags)
        self.assertEqual(v["verdict"], "gaps")
        self.assertIn("empty-source-audit-ref", v["gaps"])

    def test_malformed_source_audit_ref_gap(self) -> None:
        p = self._write(
            "bridge_incidents/malformed/record.yaml",
            _v1_yaml(
                record_id="example:malformed-ref",
                source_audit_ref="just-a-bare-string-with-no-colon",
            ),
        )
        v = self.tool.audit_record(p, self.tags)
        self.assertEqual(v["verdict"], "gaps")
        self.assertIn("malformed-source-audit-ref", v["gaps"])
        self.assertIsNone(v["source_ref_scheme"])

    def test_missing_verification_tier_gap(self) -> None:
        p = self._write(
            "cve_db/notier/record.yaml",
            _v1_yaml(record_id="example:no-tier", tier_tag=None),
        )
        v = self.tool.audit_record(p, self.tags)
        self.assertEqual(v["verdict"], "gaps")
        self.assertIn("missing-verification-tier", v["gaps"])

    def test_no_url_in_preconditions_gap(self) -> None:
        p = self._write(
            "git_mining/no-url/record.yaml",
            _v1_yaml(
                record_id="example:no-url",
                preconds=[
                    "Compiled with solc 0.8.10 or earlier",
                    "Affected subsystem: yul-optimizer",
                ],
            ),
        )
        v = self.tool.audit_record(p, self.tags)
        self.assertEqual(v["verdict"], "gaps")
        self.assertIn("no-url-citation-in-preconditions", v["gaps"])
        self.assertEqual(v["preconds_url_count"], 0)

    def test_empty_preconditions_gap(self) -> None:
        p = self._write(
            "cve_db/empty-pre/record.yaml",
            _v1_yaml(record_id="example:empty-pre", preconds=[]),
        )
        v = self.tool.audit_record(p, self.tags)
        self.assertEqual(v["verdict"], "gaps")
        self.assertIn("empty-required-preconditions", v["gaps"])

    def test_tier1_audit_firm_pdf_not_refetchable_gap(self) -> None:
        p = self._write(
            "audit_firm_public_reports/firm/record.yaml",
            _v1_yaml(
                record_id="audit-firm:foo:bar",
                source_audit_ref="audit-firm:pashov-audits:team/pdf/Foo.pdf",
                tier_tag="tier-1-verified-realtime-api",
                preconds=["Reference at https://example.com/foo.pdf"],
            ),
        )
        v = self.tool.audit_record(p, self.tags)
        self.assertEqual(v["verdict"], "gaps")
        self.assertIn("tier1-not-refetchable", v["gaps"])
        self.assertFalse(v["tier1_refetchable"])

    def test_tier1_url_passes_refetchability(self) -> None:
        p = self._write(
            "amm_yield_lst_protocols/tier1ok/record.json",
            _v1_json_text(
                record_id="example:tier1ok",
                source_audit_ref="https://github.com/foo/bar/security/advisories/GHSA-x",
                tier_tag="tier-1-verified-realtime-api",
                preconds=["Reference at https://github.com/foo/bar"],
            ),
        )
        v = self.tool.audit_record(p, self.tags)
        self.assertEqual(v["verdict"], "pass")
        self.assertTrue(v["tier1_refetchable"])

    def test_quarantine_record_short_circuits(self) -> None:
        p = self._write(
            "_QUARANTINE_FABRICATED_CVE/vyper/record.yaml",
            _v1_yaml(
                record_id="quarantine:x",
                source_audit_ref="",  # would be a gap if audited
                tier_tag=None,
                preconds=[],
            ),
        )
        v = self.tool.audit_record(p, self.tags)
        self.assertEqual(v["verdict"], "pass-quarantine")
        self.assertTrue(v["quarantine"])

    def test_non_hackerman_v1_record_skipped(self) -> None:
        text = (
            "verdict_id: legacy-1\n"
            "target_repo: example/repo\n"
            "language: solidity\n"
            "verdict_class: CANDIDATE\n"
        )
        p = self._write("legacy.yaml", text)
        v = self.tool.audit_record(p, self.tags)
        self.assertEqual(v["verdict"], "skipped-non-v1")


class RunEndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()
        self.tmp = Path(tempfile.mkdtemp(prefix="hkrm_prov_e2e_"))
        self.tags = self.tmp / "audit" / "corpus_tags" / "tags"
        self.tags.mkdir(parents=True)

    def _write(self, relpath: str, content: str) -> Path:
        p = self.tags / relpath
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def test_run_clean_tree_passes(self) -> None:
        self._write("amm/a/record.yaml", _v1_yaml(record_id="a"))
        self._write(
            "bridge/b/record.json",
            _v1_json_text(
                record_id="b",
                source_audit_ref="https://github.com/foo/bar",
                tier_tag="tier-2-verified-public-archive",
                preconds=["See https://github.com/foo/bar"],
            ),
        )
        out = self.tmp / ".auditooor" / "provenance_audit.jsonl"
        rc, payload = self.tool.run(self.tags, out_jsonl=out)
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass")
        self.assertEqual(payload["verdict_counts"].get("gaps", 0), 0)
        self.assertTrue(out.exists())
        lines = out.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 2)

    def test_run_mixed_tree_passes_with_gaps_by_default(self) -> None:
        self._write("amm/a/record.yaml", _v1_yaml(record_id="a"))
        self._write(
            "bridge/b/record.yaml",
            _v1_yaml(record_id="b", source_audit_ref="", preconds=[], tier_tag=None),
        )
        out = self.tmp / ".auditooor" / "provenance_audit.jsonl"
        rc, payload = self.tool.run(self.tags, out_jsonl=out)
        # Default mode (non-strict) returns 0 but verdict is pass-with-gaps.
        self.assertEqual(rc, 0)
        self.assertEqual(payload["verdict"], "pass-with-gaps")
        self.assertEqual(payload["verdict_counts"].get("gaps"), 1)
        gap_counts = payload["gap_counts"]
        self.assertIn("empty-source-audit-ref", gap_counts)
        self.assertIn("empty-required-preconditions", gap_counts)
        self.assertIn("missing-verification-tier", gap_counts)

    def test_run_strict_fails_on_gaps(self) -> None:
        self._write(
            "bridge/b/record.yaml",
            _v1_yaml(record_id="b", source_audit_ref="bare-string", preconds=[]),
        )
        out = self.tmp / ".auditooor" / "provenance_audit.jsonl"
        rc, payload = self.tool.run(self.tags, out_jsonl=out, strict=True)
        self.assertEqual(rc, 1)
        self.assertEqual(payload["verdict"], "fail")

    def test_run_missing_tags_dir_errors(self) -> None:
        rc, payload = self.tool.run(self.tmp / "does-not-exist")
        self.assertEqual(rc, 2)
        self.assertEqual(payload["verdict"], "error")

    def test_run_per_subtree_counts_populated(self) -> None:
        self._write("amm_yield_lst_protocols/a/record.yaml", _v1_yaml(record_id="a"))
        self._write("bridge_incidents/b/record.yaml", _v1_yaml(record_id="b"))
        out = self.tmp / ".auditooor" / "provenance_audit.jsonl"
        rc, payload = self.tool.run(self.tags, out_jsonl=out)
        self.assertEqual(rc, 0)
        self.assertIn("amm_yield_lst_protocols", payload["subtree_counts"])
        self.assertIn("bridge_incidents", payload["subtree_counts"])
        self.assertEqual(
            payload["subtree_counts"]["amm_yield_lst_protocols"].get("pass", 0), 1
        )


if __name__ == "__main__":
    unittest.main()
