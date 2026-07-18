#!/usr/bin/env python3
"""Tests for the Phase 1 trusted-corpus index build + check tools.

Covers:
  - trusted (tier-1/tier-2 real-repo) record -> active
  - prose-only (solodit-spec draft / prefix_ref) record -> prose_memory
  - fabricated (_QUARANTINE_FABRICATED_CVE subtree) record -> quarantine
  - tier-5 / missing-tier -> quarantine
  - tier-3 / tier-4 -> advisory
  - schema-version counts surfaced in corpus-quality-routing output
  - check tool: clean index -> pass-trusted-corpus-clean
  - check tool: empty index -> pass-empty-index
  - ledgers + report are written
  - corpus-quality-routing v1.2 schema accepted
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BUILD_TOOL = REPO_ROOT / "tools" / "trusted-corpus-index-build.py"
CHECK_TOOL = REPO_ROOT / "tools" / "trusted-corpus-index-check.py"
ROUTING_TOOL = REPO_ROOT / "tools" / "corpus-quality-routing.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


BUILD = _load("_tci_build", BUILD_TOOL)
CHECK = _load("_tci_check", CHECK_TOOL)
ROUTING = _load("_tci_routing", ROUTING_TOOL)


TRUSTED = """\
schema_version: auditooor.hackerman_record.v1.1
record_id: real-repo:reentrancy-001
source_audit_ref: cantina:report-x:finding-3
record_tier: public-corpus
target_domain: lending
target_language: solidity
target_repo: aave/aave-v3-core
target_component: Pool.withdraw
function_shape:
  raw_signature: "function withdraw()"
  shape_tags:
    - reentrancy
bug_class: reentrancy
attack_class: reentrancy
impact_class: theft
year: 2025
verification_tier: tier-2-verified-public-archive
"""

PROSE = """\
schema_version: auditooor.hackerman_record.v1.1
record_id: solodit-spec:drafts_rust_soroban:misnamed-views:abcd
source_audit_ref: solodit-spec:detectors/_specs/drafts_rust_soroban/misnamed-views.yaml:draft
record_tier: public-corpus
target_domain: lending
target_language: rust
target_repo: unknown/solodit
target_component: Misnamed debt-token views
function_shape:
  raw_signature: "function foo()"
  shape_tags:
    - error-handling
bug_class: error-handling
attack_class: error-handling
impact_class: griefing
year: 2025
verification_tier: tier-2-verified-public-archive
"""

TIER3 = """\
schema_version: auditooor.hackerman_record.v1.1
record_id: synth:taxonomy-001
source_audit_ref: corpus-etl-synthetic:taxonomy
record_tier: public-corpus
target_domain: amm
target_language: solidity
target_repo: example/dex
target_component: Swap
function_shape:
  raw_signature: "function swap()"
  shape_tags:
    - slippage
bug_class: slippage
attack_class: slippage
impact_class: griefing
year: 2024
verification_tier: tier-3-synthetic-taxonomy-anchored
"""

TIER4 = """\
schema_version: auditooor.hackerman_record.v1.1
record_id: fixture:bundled-001
source_audit_ref: in-tree-fixture
record_tier: public-corpus
target_language: solidity
target_repo: example/fixtures
target_component: Fixture
function_shape:
  raw_signature: "function f()"
  shape_tags: []
bug_class: misc
attack_class: misc
impact_class: griefing
year: 2024
verification_tier: tier-4-bundled-fixture
"""

TIER5 = """\
schema_version: auditooor.hackerman_record.v1.1
record_id: quarantine:tier5-001
source_audit_ref: deprecated
record_tier: public-corpus
target_language: solidity
target_repo: example/old
target_component: Old
function_shape:
  raw_signature: "function f()"
  shape_tags: []
bug_class: misc
attack_class: misc
impact_class: griefing
year: 2024
verification_tier: tier-5-quarantine
"""

MISSING_TIER = """\
schema_version: auditooor.hackerman_record.v1.1
record_id: missing:tier-001
source_audit_ref: somewhere
record_tier: public-corpus
target_language: solidity
target_repo: example/x
target_component: X
function_shape:
  raw_signature: "function f()"
  shape_tags: []
bug_class: misc
attack_class: misc
impact_class: griefing
year: 2024
"""

FABRICATED = """\
schema_version: auditooor.hackerman_record.v1.1
record_id: fab:cve-001
source_audit_ref: fabricated corpus case
record_tier: public-corpus
target_language: solidity
target_repo: fake/repo
target_component: Fake
function_shape:
  raw_signature: "function f()"
  shape_tags: []
bug_class: misc
attack_class: misc
impact_class: theft
year: 2025
verification_tier: tier-2-verified-public-archive
"""

V12_RECORD = """\
schema_version: auditooor.hackerman_record.v1.2
record_id: wide:incident-001
source_url: https://example.com/postmortem
target_repo: real/protocol
attack_class: oracle-manipulation
bug_class: oracle-manipulation
verification_tier: tier-1-officially-disclosed
"""


def _write_corpus(base: Path) -> None:
    (base / "amm_yield").mkdir(parents=True, exist_ok=True)
    (base / "amm_yield" / "trusted.yaml").write_text(TRUSTED)
    (base / "amm_yield" / "prose.yaml").write_text(PROSE)
    (base / "amm_yield" / "tier3.yaml").write_text(TIER3)
    (base / "amm_yield" / "tier4.yaml").write_text(TIER4)
    (base / "amm_yield" / "tier5.yaml").write_text(TIER5)
    (base / "amm_yield" / "missing.yaml").write_text(MISSING_TIER)
    # Fabricated record lives in a NORMAL subtree (not _QUARANTINE_, which the
    # corpus iterator skips). Its source_audit_ref carries the fabricated marker.
    (base / "amm_yield" / "fab.yaml").write_text(FABRICATED)


class TrustClassificationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tags = Path(self.tmp.name) / "tags"
        self.out = Path(self.tmp.name) / "out"
        self.report = Path(self.tmp.name) / "report" / "latest.md"
        _write_corpus(self.tags)

    def tearDown(self):
        self.tmp.cleanup()

    def _build(self):
        return BUILD.build(
            tags_dir=self.tags, out_dir=self.out, report_path=self.report,
            subtrees=None, limit=None, replay_manifest=None, dry_run=False,
        )

    def _index_by_id(self):
        rows = [
            json.loads(l)
            for l in (self.out / "TRUSTED_CORPUS_INDEX.jsonl").read_text().splitlines()
            if l.strip()
        ]
        return {r["record_id"]: r for r in rows}

    def test_trusted_record_is_active(self):
        self._build()
        idx = self._index_by_id()
        self.assertEqual(idx["real-repo:reentrancy-001"]["trust_state"], "active")
        self.assertEqual(idx["real-repo:reentrancy-001"]["admission_blockers"], [])

    def test_prose_record_is_prose_memory(self):
        self._build()
        idx = self._index_by_id()
        self.assertEqual(idx["solodit-spec:drafts_rust_soroban:misnamed-views:abcd"]["trust_state"], "prose_memory")

    def test_fabricated_record_is_quarantine(self):
        self._build()
        idx = self._index_by_id()
        rec = idx["fab:cve-001"]
        self.assertEqual(rec["trust_state"], "quarantine")
        self.assertTrue(rec["is_fabricated"])

    def test_tier5_and_missing_tier_quarantine(self):
        self._build()
        idx = self._index_by_id()
        self.assertEqual(idx["quarantine:tier5-001"]["trust_state"], "quarantine")
        self.assertEqual(idx["missing:tier-001"]["trust_state"], "quarantine")

    def test_tier3_tier4_advisory(self):
        self._build()
        idx = self._index_by_id()
        self.assertEqual(idx["synth:taxonomy-001"]["trust_state"], "advisory")
        self.assertEqual(idx["fixture:bundled-001"]["trust_state"], "advisory")

    def test_ledgers_and_report_written(self):
        self._build()
        self.assertTrue((self.out / "CORPUS_TRUST_LEDGER.jsonl").exists())
        self.assertTrue((self.out / "CORPUS_QUARANTINE_LEDGER.jsonl").exists())
        self.assertTrue((self.out / "PROSE_MEMORY_INDEX.jsonl").exists())
        self.assertTrue(self.report.exists())
        # quarantine ledger has the fabricated row, restorable=false
        q = [json.loads(l) for l in (self.out / "CORPUS_QUARANTINE_LEDGER.jsonl").read_text().splitlines() if l.strip()]
        fab = [e for e in q if e["record_id"] == "fab:cve-001"]
        self.assertEqual(len(fab), 1)
        self.assertEqual(fab[0]["quarantine_class"], "fabricated")
        self.assertFalse(fab[0]["restorable"])

    def test_dod_no_active_unstated_tier(self):
        summary = self._build()
        self.assertEqual(summary["dod"]["active_with_unstated_tier"], 0)
        self.assertEqual(summary["dod"]["active_fabricated"], 0)


class CheckToolTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.tags = Path(self.tmp.name) / "tags"
        self.out = Path(self.tmp.name) / "out"
        self.report = Path(self.tmp.name) / "report" / "latest.md"
        _write_corpus(self.tags)

    def tearDown(self):
        self.tmp.cleanup()

    def test_clean_index_passes(self):
        BUILD.build(tags_dir=self.tags, out_dir=self.out, report_path=self.report,
                    subtrees=None, limit=None, replay_manifest=None, dry_run=False)
        report = CHECK.check(self.out)
        self.assertEqual(report["verdict"], "pass-trusted-corpus-clean")

    def test_empty_index(self):
        report = CHECK.check(self.out)
        self.assertEqual(report["verdict"], "pass-empty-index")

    def test_check_detects_active_fabricated(self):
        BUILD.build(tags_dir=self.tags, out_dir=self.out, report_path=self.report,
                    subtrees=None, limit=None, replay_manifest=None, dry_run=False)
        # hand-corrupt an index row to mark fabricated active (simulating a
        # forbidden manual edit), then confirm the check fails closed.
        idx_path = self.out / "TRUSTED_CORPUS_INDEX.jsonl"
        rows = [json.loads(l) for l in idx_path.read_text().splitlines() if l.strip()]
        for r in rows:
            if r["record_id"] == "fab:cve-001":
                r["trust_state"] = "active"
                r["admission_blockers"] = []
        idx_path.write_text("".join(json.dumps(r) + "\n" for r in rows))
        report = CHECK.check(self.out)
        self.assertEqual(report["verdict"], "fail-active-fabricated-or-prose")


class RoutingV12Test(unittest.TestCase):
    def test_v12_schema_accepted_and_counted(self):
        with tempfile.TemporaryDirectory() as d:
            tags = Path(d) / "tags" / "wide"
            tags.mkdir(parents=True)
            (tags / "v12.yaml").write_text(V12_RECORD)
            (tags / "v11.yaml").write_text(TRUSTED)
            report = ROUTING.run_scan(Path(d) / "tags")
            self.assertEqual(report["summary"]["total_records_scanned"], 2)
            svc = report["schema_version_counts"]
            self.assertEqual(svc.get("auditooor.hackerman_record.v1.2"), 1)
            self.assertEqual(svc.get("auditooor.hackerman_record.v1.1"), 1)


if __name__ == "__main__":
    unittest.main()
