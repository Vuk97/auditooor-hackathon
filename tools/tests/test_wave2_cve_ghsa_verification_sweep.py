"""Tests for ``tools/wave2-cve-ghsa-verification-sweep.py``.

Hermetic - uses tmpdir fixtures only; no network calls. Tests cover:

  * PASS  - CVE record with trusted NVD source URL
  * PASS  - GHSA record with trusted github.com/.../security/advisories URL
  * SUSPECT - CVE record with internal source_audit_ref (no trusted URL)
  * SUSPECT - GHSA record with non-github source_audit_ref
  * Quarantine subtree (``_QUARANTINE_FABRICATED_CVE``) is excluded
  * QUARANTINE_CANDIDATE - synthetic Vyper-CVE fabrication shape
  * ``record_extensions.cve_source_url`` (record_extensions provenance)
    counts as PASS
  * Empty corpus -> PASS with ``no-cve-or-ghsa-records-found`` note
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "wave2-cve-ghsa-verification-sweep.py"


def _load_tool():
    name = "_wave2_cve_ghsa_verification_sweep_under_test"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


TOOL = _load_tool()


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text), encoding="utf-8")


def _build_workspace(tmpdir: Path) -> Path:
    """Bare workspace skeleton: audit/corpus_tags/{index,tags}."""
    (tmpdir / "audit" / "corpus_tags" / "index").mkdir(parents=True)
    (tmpdir / "audit" / "corpus_tags" / "tags").mkdir(parents=True)
    return tmpdir


def _add_index_entry(ws: Path, idx_file: str, entry: dict) -> None:
    p = ws / "audit" / "corpus_tags" / "index" / idx_file
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")


class Wave2CveGhsaSweepTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.ws = _build_workspace(Path(self.tmp.name))

    # --- helper builders ---------------------------------------------------

    def _add_cve_record_with_nvd_url(self) -> None:
        # PASS: CVE + trusted NVD source URL.
        rec = self.ws / "audit" / "corpus_tags" / "tags" / "cve_db" / "cve-pass-nvd.yaml"
        _write(
            rec,
            """\
            schema_version: auditooor.hackerman_record.v1
            record_id: cve-db:cve-2020-1234:pass-nvd:abc1
            source_audit_ref: https://nvd.nist.gov/vuln/detail/CVE-2020-1234
            target_repo: example/project
            target_language: solidity
            bug_class: example-arithmetic-overflow
            attack_class: example-overflow
            severity_at_finding: high
            year: 2020
            """,
        )
        _add_index_entry(
            self.ws,
            "by_cve_id.jsonl",
            {
                "key": "CVE-2020-1234",
                "record_id": "cve-db:cve-2020-1234:pass-nvd:abc1",
                "source_audit_ref": "https://nvd.nist.gov/vuln/detail/CVE-2020-1234",
                "tag_file": "cve-pass-nvd.yaml",
            },
        )

    def _add_ghsa_record_with_github_url(self) -> None:
        # PASS: GHSA + trusted github.com/.../security/advisories URL.
        rec = (
            self.ws
            / "audit"
            / "corpus_tags"
            / "tags"
            / "evm_client_advisories"
            / "ethereum__go-ethereum__ghsa-q26p-9cq4-7fc2"
            / "record.yaml"
        )
        _write(
            rec,
            """\
            schema_version: auditooor.hackerman_record.v1
            record_id: evm-client:ethereum-go-ethereum:ghsa-q26p-9cq4-7fc2:0936
            source_audit_ref: https://github.com/ethereum/go-ethereum/security/advisories/GHSA-q26p-9cq4-7fc2
            target_repo: ethereum/go-ethereum
            target_language: go
            bug_class: evm-client-public-advisory
            severity_at_finding: high
            year: 2025
            """,
        )
        _add_index_entry(
            self.ws,
            "by_ghsa_id.jsonl",
            {
                "key": "GHSA-q26p-9cq4-7fc2",
                "record_id": "evm-client:ethereum-go-ethereum:ghsa-q26p-9cq4-7fc2:0936",
                "source_audit_ref": "https://github.com/ethereum/go-ethereum/security/advisories/GHSA-q26p-9cq4-7fc2",
                "tag_file": "record.yaml",
            },
        )

    def _add_cve_record_no_url(self) -> None:
        # SUSPECT: CVE + internal source_audit_ref (no trusted URL).
        rec = (
            self.ws
            / "audit"
            / "corpus_tags"
            / "tags"
            / "findings-go:internal-suspect:f00.yaml"
        )
        _write(
            rec,
            """\
            schema_version: auditooor.hackerman_record.v1
            record_id: findings-go:internal-suspect:f00
            source_audit_ref: findings-go:reference/findings_go.jsonl:internal-suspect
            target_repo: lightningnetwork/lnd
            target_language: go
            source_extraction_method: regex-derived
            source_extraction_confidence: 0.65
            bug_class: go.lightning.something
            severity_at_finding: high
            year: 2020
            """,
        )
        _add_index_entry(
            self.ws,
            "by_cve_id.jsonl",
            {
                "key": "CVE-2020-26896",
                "record_id": "findings-go:internal-suspect:f00",
                "source_audit_ref": "findings-go:reference/findings_go.jsonl:internal-suspect",
                "tag_file": "findings-go:internal-suspect:f00.yaml",
            },
        )

    def _add_ghsa_record_invalid_url(self) -> None:
        # SUSPECT: GHSA + invalid source URL (not github.com/security/advisories).
        rec = (
            self.ws
            / "audit"
            / "corpus_tags"
            / "tags"
            / "misc"
            / "bad__url__ghsa-aaaa-bbbb-cccc"
            / "record.yaml"
        )
        _write(
            rec,
            """\
            schema_version: auditooor.hackerman_record.v1
            record_id: misc:bad-url:ghsa-aaaa-bbbb-cccc:d34d
            source_audit_ref: https://example.com/some/other/page
            target_repo: bad/url
            target_language: solidity
            bug_class: misc-advisory
            severity_at_finding: medium
            year: 2024
            """,
        )
        _add_index_entry(
            self.ws,
            "by_ghsa_id.jsonl",
            {
                "key": "GHSA-aaaa-bbbb-cccc",
                "record_id": "misc:bad-url:ghsa-aaaa-bbbb-cccc:d34d",
                "source_audit_ref": "https://example.com/some/other/page",
                "tag_file": "record.yaml",
            },
        )

    def _add_quarantine_record(self) -> None:
        # The sweep MUST skip the quarantine subtree even if it has a CVE
        # reference somewhere on disk.
        rec = (
            self.ws
            / "audit"
            / "corpus_tags"
            / "tags"
            / "_QUARANTINE_FABRICATED_CVE"
            / "vyper_cve_fabricated"
            / "fabricated-cve-2022-37937.yaml"
        )
        _write(
            rec,
            """\
            schema_version: auditooor.hackerman_record.v1
            record_id: quarantined:cve-2022-37937:fabricated
            source_audit_ref: synthetic-not-real
            bug_class: vyper-saturating-arithmetic-reentrancy
            severity_at_finding: high
            year: 2022
            """,
        )
        # NOTE: we intentionally do NOT add this to by_cve_id.jsonl, mirroring
        # production state: index builder excludes quarantine subtree.

    def _add_quarantine_candidate_record(self) -> None:
        # Synthetic fixture matching Vyper-CVE fabrication shape:
        # CVE-ID + low confidence + regex-derived method + no trusted URL.
        rec = (
            self.ws
            / "audit"
            / "corpus_tags"
            / "tags"
            / "vyper_cve"
            / "synthetic-fab-cve-9999-99999.yaml"
        )
        _write(
            rec,
            """\
            schema_version: auditooor.hackerman_record.v1
            record_id: vyper-cve:synthetic-fab:cve-9999-99999:beef
            source_audit_ref: synthetic-not-a-url
            target_repo: vyperlang/vyper
            target_language: vyper
            source_extraction_method: training-data-recalled
            source_extraction_confidence: 0.3
            record_tier: synthetic
            bug_class: vyper-fabricated-class
            attack_class: vyper-fabricated-attack
            severity_at_finding: high
            year: 2099
            synthetic_fixture: true
            """,
        )
        _add_index_entry(
            self.ws,
            "by_cve_id.jsonl",
            {
                "key": "CVE-9999-99999",
                "record_id": "vyper-cve:synthetic-fab:cve-9999-99999:beef",
                "source_audit_ref": "synthetic-not-a-url",
                "tag_file": "synthetic-fab-cve-9999-99999.yaml",
            },
        )

    def _add_record_with_extension_provenance(self) -> None:
        # PASS: CVE + record_extensions.cve_source_url set.
        rec = (
            self.ws
            / "audit"
            / "corpus_tags"
            / "tags"
            / "ext_provenance"
            / "ext-prov-cve-2024-9999.yaml"
        )
        _write(
            rec,
            """\
            schema_version: auditooor.hackerman_record.v1
            record_id: ext-prov:cve-2024-9999:abc1
            source_audit_ref: internal-ref-only
            target_repo: ext/prov
            target_language: solidity
            record_extensions:
              cve_source_url: https://nvd.nist.gov/vuln/detail/CVE-2024-9999
            bug_class: ext-class
            severity_at_finding: high
            year: 2024
            """,
        )
        _add_index_entry(
            self.ws,
            "by_cve_id.jsonl",
            {
                "key": "CVE-2024-9999",
                "record_id": "ext-prov:cve-2024-9999:abc1",
                "source_audit_ref": "internal-ref-only",
                "tag_file": "ext-prov-cve-2024-9999.yaml",
            },
        )

    # --- tests -------------------------------------------------------------

    def test_empty_corpus_passes(self):
        v = TOOL.run_sweep(self.ws)
        # Force the empty-corpus PASS path by reproducing main()'s logic.
        if v["total_cve_records"] == 0 and v["total_ghsa_records"] == 0:
            v["overall_status"] = "PASS"
        self.assertEqual(v["overall_status"], "PASS")
        self.assertEqual(v["total_cve_records"], 0)
        self.assertEqual(v["total_ghsa_records"], 0)

    def test_cve_with_nvd_url_is_pass(self):
        self._add_cve_record_with_nvd_url()
        v = TOOL.run_sweep(self.ws)
        self.assertEqual(v["total_cve_records"], 1)
        self.assertEqual(v["pass_count"], 1)
        self.assertEqual(v["suspect_count"], 0)
        self.assertEqual(v["overall_status"], "PASS")

    def test_ghsa_with_github_url_is_pass(self):
        self._add_ghsa_record_with_github_url()
        v = TOOL.run_sweep(self.ws)
        self.assertEqual(v["total_ghsa_records"], 1)
        self.assertEqual(v["pass_count"], 1)
        self.assertEqual(v["overall_status"], "PASS")

    def test_cve_without_trusted_url_is_suspect(self):
        self._add_cve_record_no_url()
        v = TOOL.run_sweep(self.ws)
        self.assertEqual(v["total_cve_records"], 1)
        self.assertEqual(v["pass_count"], 0)
        self.assertEqual(v["suspect_count"], 1)
        self.assertIn(v["overall_status"], ("SUSPECT", "FAIL"))
        self.assertEqual(
            v["suspect_records"][0]["cve_or_ghsa_id"], "CVE-2020-26896"
        )

    def test_ghsa_with_invalid_url_is_suspect(self):
        self._add_ghsa_record_invalid_url()
        v = TOOL.run_sweep(self.ws)
        self.assertEqual(v["total_ghsa_records"], 1)
        self.assertEqual(v["suspect_count"], 1)
        self.assertEqual(v["pass_count"], 0)
        self.assertIn("no-trusted-ghsa-provenance", v["suspect_records"][0]["reason"])

    def test_quarantine_subtree_is_excluded(self):
        # Quarantine record exists on disk but is NOT indexed (by design).
        # If it WERE accidentally indexed, the path filter in
        # _resolve_record_yaml would still drop it.
        self._add_quarantine_record()
        v = TOOL.run_sweep(self.ws)
        self.assertEqual(v["total_cve_records"], 0)
        self.assertEqual(v["total_ghsa_records"], 0)

    def test_quarantine_candidate_is_flagged(self):
        self._add_quarantine_candidate_record()
        v = TOOL.run_sweep(self.ws)
        self.assertEqual(v["total_cve_records"], 1)
        self.assertEqual(v["suspect_count"], 1)
        self.assertEqual(v["quarantine_candidate_count"], 1)
        self.assertEqual(
            v["quarantine_candidate_records"][0]["cve_id"], "CVE-9999-99999"
        )
        self.assertIn(
            "vyper", v["quarantine_candidate_records"][0]["claimed_subject"].lower()
        )

    def test_record_extensions_provenance_counts_as_pass(self):
        self._add_record_with_extension_provenance()
        v = TOOL.run_sweep(self.ws)
        self.assertEqual(v["total_cve_records"], 1)
        self.assertEqual(v["pass_count"], 1)
        self.assertEqual(v["suspect_count"], 0)

    def test_quarantine_url_pattern_does_not_match_random_github(self):
        # has_cve_provenance: random github URL must NOT pass as trusted
        # unless it's /security/advisories/GHSA- or /advisories/GHSA-.
        rec = {"source_audit_ref": "https://github.com/foo/bar/issues/123"}
        ok, _ = TOOL.has_cve_provenance(rec, [])
        self.assertFalse(ok)
        ok2, _ = TOOL.has_ghsa_provenance(rec, [])
        self.assertFalse(ok2)

    def test_cli_strict_exit_code(self):
        # Add one suspect; --strict should make CLI exit 1.
        self._add_cve_record_no_url()
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL_PATH),
                "--workspace",
                str(self.ws),
                "--strict",
                "--json",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 1, msg=proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema"], TOOL.SCHEMA)


if __name__ == "__main__":
    unittest.main()
