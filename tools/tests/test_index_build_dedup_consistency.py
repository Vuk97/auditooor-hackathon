"""Wave-2 PR-A W2.6: regression tests for identifier-index record_id dedup.

Background
----------
The Wave-2 dual-form audit (``tools/wave2-index-dual-form-audit.py``,
commit ``2a4fffda8f``) caught a 7-row inflation in
``audit/corpus_tags/index/by_ghsa_id.jsonl`` (200 raw vs 193 unique
``record_id``\\ s). Root cause: a record's
``attacker_action_sequence`` prose can cite a *cross-referenced*
sibling advisory ID (e.g. a Vyper record whose primary GHSA is
``GHSA-22wc-c9wj-6q2v`` and whose prose narrative cites
``GHSA-2r3x-4mrv-mcxf`` as the related fix). The regex fallback in
``_extract_ghsa_ids`` / ``_extract_cve_ids`` surfaced every such
cross-reference and the index emitter produced one row per match,
inflating the index above the unique-record-id count.

The fix (``hackerman-index-build.py`` lines 244-273): for the two
identifier indexes ``by_cve_id`` and ``by_ghsa_id``, emit only ONE
row per record - keyed by the record's *primary* identifier (top-level
field has precedence over regex fallback per ``_extract_*_ids``
ordering).

Test fixtures are marked ``synthetic_fixture: true`` per Wave-2 spec.

Cases
-----
1. ``test_by_ghsa_id_dedup_when_record_has_cross_referenced_ghsa`` -
   the exact shape that caused the live inflation: a record with a
   primary GHSA in ``record_id`` plus a sibling GHSA cited in
   ``attacker_action_sequence`` produces exactly ONE
   ``by_ghsa_id`` row.

2. ``test_by_cve_id_dedup_when_record_has_cross_referenced_cve`` -
   parallel regression for ``by_cve_id`` (same fix shape).

3. ``test_dual_form_corpus_yaml_only_walker_no_inflation`` - synthetic
   3 dual-form + 2 single-form fixture, confirms walker only counts
   yaml siblings (not json) so dedup is observed and the canonical
   row count is 5 unique records.

4. ``test_other_indexes_still_multi_key_per_record`` - regression
   guard: ``by_firm`` / ``by_verification_tier`` keep multi-row-per-
   record semantics (legitimately multi-valued fields).
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-index-build.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("_hackerman_index_build_dedup", str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


_RECORD_TEMPLATE = """# synthetic_fixture: true
schema_version: auditooor.hackerman_record.v1.1
record_id: {record_id}
source_audit_ref: {source_audit_ref}
target_domain: lending
target_language: solidity
target_repo: example/vault
target_component: Example.deposit
function_shape:
  raw_signature: "function deposit(uint256 amount) external"
  shape_tags:
    - simple
bug_class: logic-error
attack_class: first-deposit-share-inflation
attacker_role: unprivileged
attacker_action_sequence: "{action}"
required_preconditions:
  - empty vault
impact_class: theft
impact_actor: arbitrary-user
impact_dollar_class: "$10K-$100K"
fix_pattern: validate
fix_anti_pattern_avoided: trust
severity_at_finding: high
year: 2024
cross_language_analogues: []
related_records: []
{extras}
"""


def _render(record_id, source_audit_ref, action="exploit", extras=""):
    return _RECORD_TEMPLATE.format(
        record_id=record_id,
        source_audit_ref=source_audit_ref,
        action=action,
        extras=extras,
    )


class IndexBuildDedupConsistencyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.tag_dir = self.tmp_path / "tags"
        self.index_dir = self.tmp_path / "index"
        self.tag_dir.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _read_rows(self, name: str):
        path = self.index_dir / f"{name}.jsonl"
        if path.exists():
            return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        return []

    def test_by_ghsa_id_dedup_when_record_has_cross_referenced_ghsa(self) -> None:
        """Reproduce the live-corpus shape: primary GHSA + cross-referenced GHSA in prose."""
        # synthetic_fixture: true
        # Models the live Vyper GHSA-22wc-c9wj-6q2v record (1 of 7 inflated rows).
        # NOTE: GHSA IDs must match ^GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}$
        (self.tag_dir / "vyper_dual_ghsa.yaml").write_text(
            _render(
                "evm-tooling:vyperlang-vyper:ghsa-syn1-aaaa-bbbb:1234567890ab",
                "https://github.com/vyperlang/vyper/security/advisories/GHSA-syn1-aaaa-bbbb",
                action=(
                    "VVE-2021-9999: Memory corruption. ### Patches partially fixed in "
                    "[VVE-2020-9998](https://github.com/vyperlang/vyper/security/advisories/"
                    "GHSA-syn2-cccc-dddd)"
                ),
                extras="ghsa_id: GHSA-syn1-aaaa-bbbb",
            ),
            encoding="utf-8",
        )
        self.tool.build_indices(self.tag_dir, self.index_dir, preserve_existing=False)
        rows = self._read_rows("by_ghsa_id")
        # PRE-FIX behavior: 2 rows (one per GHSA reference).
        # POST-FIX behavior: 1 row keyed by the primary (top-level) ghsa_id.
        self.assertEqual(len(rows), 1, f"expected 1 row, got {len(rows)}: {rows}")
        self.assertEqual(rows[0]["key"], "GHSA-syn1-aaaa-bbbb")
        self.assertEqual(
            rows[0]["record_id"],
            "evm-tooling:vyperlang-vyper:ghsa-syn1-aaaa-bbbb:1234567890ab",
        )

    def test_by_cve_id_dedup_when_record_has_cross_referenced_cve(self) -> None:
        """Parallel regression: by_cve_id must also emit exactly one row per record."""
        # synthetic_fixture: true
        (self.tag_dir / "kernel_dual_cve.yaml").write_text(
            _render(
                "evm-client:example-client:cve-synth-2024-11111:fedcba987654",
                "https://example.com/cve-feed/CVE-2024-11111",
                action=(
                    "CVE-2024-11111: integer overflow. Related: CVE-2024-22222 "
                    "(same vendor, different module) and CVE-2023-33333 (predecessor)."
                ),
                extras="cve_id: CVE-2024-11111",
            ),
            encoding="utf-8",
        )
        self.tool.build_indices(self.tag_dir, self.index_dir, preserve_existing=False)
        rows = self._read_rows("by_cve_id")
        # Three CVE refs in the record (primary + 2 cross-references in prose);
        # the fix dedupes to one row keyed by the primary.
        self.assertEqual(len(rows), 1, f"expected 1 row, got {len(rows)}: {rows}")
        self.assertEqual(rows[0]["key"], "CVE-2024-11111")

    def test_dual_form_corpus_yaml_only_walker_no_inflation(self) -> None:
        """3 dual-form (yaml+json) + 2 single-form -> 5 unique by_ghsa_id rows.

        Walker reads only ``*.yaml`` / ``record.yaml`` (verified at
        ``hackerman-index-build.py`` lines 320-325) so a json sibling does
        NOT trigger a second walk of the same record.
        """
        # synthetic_fixture: true
        # GHSA pattern: ^GHSA-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}$
        # 3 records that exist as BOTH record.yaml and record.json siblings.
        dual_ghsas = ["aaaa-1111-2222", "bbbb-3333-4444", "cccc-5555-6666"]
        for i, ghsa_body in enumerate(dual_ghsas):
            ghsa = f"GHSA-{ghsa_body}"
            subdir = self.tag_dir / f"dual_form_{i}"
            subdir.mkdir()
            yaml_body = _render(
                f"example:dual-form-{i}:{ghsa.lower()}:00000000abc{i}",
                f"https://example.test/advisories/{ghsa}",
                extras=f"ghsa_id: {ghsa}",
            )
            (subdir / "record.yaml").write_text(yaml_body, encoding="utf-8")
            # The json sibling carries the same record_id (the live-corpus
            # invariant verified by the dual-form audit). It is NOT consumed
            # by the index walker (yaml-only walk at lines 320-325).
            (subdir / "record.json").write_text(
                json.dumps(
                    {
                        "record_id": f"example:dual-form-{i}:{ghsa.lower()}:00000000abc{i}",
                        "_synthetic_fixture": True,
                    }
                ),
                encoding="utf-8",
            )
        # 2 records that exist only as record.yaml.
        single_ghsas = ["dddd-7777-8888", "eeee-9999-0000"]
        for i, ghsa_body in enumerate(single_ghsas):
            ghsa = f"GHSA-{ghsa_body}"
            subdir = self.tag_dir / f"single_form_{i}"
            subdir.mkdir()
            (subdir / "record.yaml").write_text(
                _render(
                    f"example:single-form-{i}:{ghsa.lower()}:11111111def{i}",
                    f"https://example.test/advisories/{ghsa}",
                    extras=f"ghsa_id: {ghsa}",
                ),
                encoding="utf-8",
            )

        self.tool.build_indices(self.tag_dir, self.index_dir, preserve_existing=False)
        rows = self._read_rows("by_ghsa_id")
        # Expect exactly 5 rows (3 dual-form + 2 single-form, each emitting once).
        self.assertEqual(len(rows), 5, f"expected 5 unique rows, got {len(rows)}")
        record_ids = sorted(r["record_id"] for r in rows)
        self.assertEqual(len(set(record_ids)), 5, "record_ids must all be unique")

    def test_other_indexes_still_multi_key_per_record(self) -> None:
        """Regression guard: by_firm / by_verification_tier remain multi-valued.

        A record can legitimately belong to multiple firms or carry multiple
        verification tiers - the dedup fix MUST NOT collapse those.
        """
        # synthetic_fixture: true
        (self.tag_dir / "multi_firm.yaml").write_text(
            _render(
                "example:multi-firm:fffffffffff1",
                "audit-firm:pashov-audits:Example.pdf",
                extras=(
                    "function_shape:\n"
                    "  raw_signature: \"function withdraw(uint256) external\"\n"
                    "  shape_tags:\n"
                    "    - simple\n"
                    "    - firm-pashov-audits\n"
                    "    - firm-zellic-publications\n"
                    "    - verification_tier:tier-1-ghsa-rest-api\n"
                    "    - verification_tier:tier-2-verified-public-archive\n"
                ),
            ),
            encoding="utf-8",
        )
        # NOTE: the second function_shape block in `extras` overrides the
        # default one in the template; pyyaml takes the last-defined key.
        self.tool.build_indices(self.tag_dir, self.index_dir, preserve_existing=False)
        firm_rows = self._read_rows("by_firm")
        tier_rows = self._read_rows("by_verification_tier")
        firm_keys = sorted(r["key"] for r in firm_rows)
        tier_keys = sorted(r["key"] for r in tier_rows)
        # Both firms (regex + shape-tag) surface; both tier tags surface.
        self.assertIn("pashov-audits", firm_keys)
        self.assertIn("zellic-publications", firm_keys)
        self.assertGreaterEqual(len(tier_rows), 2, f"tier_rows={tier_rows}")
        self.assertIn("tier-1-ghsa-rest-api", tier_keys)
        self.assertIn("tier-2-verified-public-archive", tier_keys)


if __name__ == "__main__":
    unittest.main()
