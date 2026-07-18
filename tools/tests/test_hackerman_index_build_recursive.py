"""Tests for the Wave-2 recursive walker extension of hackerman-index-build.

Spec: docs/WAVE2_INDEX_COVERAGE_EXTENSION_SPEC_2026-05-16.md (§4 + §6.4).

Pre-extension the index walker used non-recursive ``Path.glob("*.yaml")`` which
silently dropped 6,278 records under 21 nested subtrees (per spec §3 table).
Post-extension the walker uses ``rglob`` with a ``record.yaml`` skip-guard
plus exclusion of ``_QUARANTINE_*`` / ``_deprecated`` subtrees (spec §4.1+§4.2).

These tests pin the post-extension behavior end-to-end via synthetic tag
directories so a regression to the non-recursive form is caught immediately.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-index-build.py"
FIXTURE_DIR = REPO_ROOT / "tools" / "tests" / "fixtures" / "hackerman_records"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "_hackerman_index_build_recursive", str(TOOL_PATH)
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


# Minimal hackerman.v1 record body parametrised by record_id so each synthetic
# fixture is unique (the writer halts on duplicate record_id; see spec §7.3).
_RECORD_TEMPLATE = """schema_version: auditooor.hackerman_record.v1
record_id: {record_id}
source_audit_ref: {record_id}
target_domain: lending
target_language: solidity
target_repo: synthetic/{repo_slug}
target_component: SyntheticComponent.{repo_slug}
function_shape:
  raw_signature: "function action_{repo_slug}(uint256 amount) external"
  shape_tags:
    - external-nonpayable-token-transfer
bug_class: logic-error
attack_class: {attack_class}
attacker_role: unprivileged
attacker_action_sequence: "Step 1: setup. Step 2: trigger. Step 3: profit."
required_preconditions:
  - synthetic precondition
impact_class: theft
impact_actor: arbitrary-user
impact_dollar_class: "$10K-$100K"
fix_pattern: validate inputs before mutation
fix_anti_pattern_avoided: missing validation
severity_at_finding: medium
year: 2025
cross_language_analogues: []
related_records: []
"""


def _write_record(
    path: Path,
    record_id: str,
    repo_slug: str = "rec",
    attack_class: str = "reentrancy",
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        _RECORD_TEMPLATE.format(
            record_id=record_id,
            repo_slug=repo_slug,
            attack_class=attack_class,
        ),
        encoding="utf-8",
    )


class RecursiveWalkerTests(unittest.TestCase):
    """Wave-2 spec §6.4 acceptance: recursive walker + exclusion semantics."""

    def setUp(self) -> None:
        self.tool = _load_tool()
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.tag_dir = self.tmp_path / "tags"
        self.index_dir = self.tmp_path / "index"
        self.tag_dir.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _read_rows(self, name: str) -> list[dict]:
        path = self.index_dir / f"{name}.jsonl"
        if not path.exists():
            return []
        return [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    # ---- §6.4 mandated cases -----------------------------------------------

    def test_rglob_walker_picks_up_nested_record_yaml(self) -> None:
        """Flat YAML + nested ``<slug>/record.yaml`` are BOTH indexed."""
        _write_record(self.tag_dir / "flat_record.yaml", "synth:flat:001")
        _write_record(
            self.tag_dir / "contest_platform_findings" / "synth-nested-001" / "record.yaml",
            "synth:nested:001",
        )
        counts = self.tool.build_indices(self.tag_dir, self.index_dir)
        self.assertEqual(counts["records_indexed"], 2, counts)
        rows = self._read_rows("by_attack_class")
        record_ids = {row["record_id"] for row in rows}
        self.assertIn("synth:flat:001", record_ids)
        self.assertIn("synth:nested:001", record_ids)

    def test_rglob_walker_skips_quarantine(self) -> None:
        """Records under ``_QUARANTINE_FABRICATED_CVE/`` are NOT indexed."""
        _write_record(self.tag_dir / "kept.yaml", "synth:kept:001")
        _write_record(
            self.tag_dir
            / "_QUARANTINE_FABRICATED_CVE"
            / "vyper_cve_fabricated"
            / "bad.yaml",
            "synth:quarantined:001",
        )
        _write_record(
            self.tag_dir
            / "_QUARANTINE_FABRICATED_CVE"
            / "other_fabricated"
            / "nested"
            / "record.yaml",
            "synth:quarantined:nested:002",
        )
        counts = self.tool.build_indices(self.tag_dir, self.index_dir)
        self.assertEqual(counts["records_indexed"], 1, counts)
        record_ids = {row["record_id"] for row in self._read_rows("by_attack_class")}
        self.assertEqual(record_ids, {"synth:kept:001"})

    def test_rglob_walker_skips_deprecated(self) -> None:
        """Records under ``_deprecated/`` are NOT indexed."""
        _write_record(self.tag_dir / "kept.yaml", "synth:kept:002")
        _write_record(
            self.tag_dir / "_deprecated" / "old_format" / "record.yaml",
            "synth:deprecated:001",
        )
        counts = self.tool.build_indices(self.tag_dir, self.index_dir)
        self.assertEqual(counts["records_indexed"], 1, counts)
        record_ids = {row["record_id"] for row in self._read_rows("by_attack_class")}
        self.assertEqual(record_ids, {"synth:kept:002"})

    def test_no_preserve_existing_clean_rebuild(self) -> None:
        """Pre-populated stale index rows are dropped under ``--no-preserve-existing``."""
        # Seed the index dir with a fake stale row.
        self.index_dir.mkdir()
        (self.index_dir / "by_attack_class.jsonl").write_text(
            json.dumps(
                {
                    "key": "stale-attack-class",
                    "record_id": "synth:stale:legacy:001",
                    "tag_file": "ghost.yaml",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        _write_record(self.tag_dir / "fresh.yaml", "synth:fresh:001")
        self.tool.build_indices(self.tag_dir, self.index_dir, preserve_existing=False)
        rows = self._read_rows("by_attack_class")
        record_ids = {row["record_id"] for row in rows}
        self.assertEqual(record_ids, {"synth:fresh:001"})
        # Stale row must be gone.
        self.assertNotIn("synth:stale:legacy:001", record_ids)

    # ---- additional walker shape coverage ----------------------------------

    def test_deeply_nested_three_level_record_yaml_is_indexed(self) -> None:
        """``<subtree>/<year>/<slug>/record.yaml`` (3-level deep) is reachable."""
        _write_record(
            self.tag_dir
            / "audit_firm_public_reports"
            / "2025"
            / "trail-of-bits-deep-slug"
            / "record.yaml",
            "synth:deep:001",
        )
        counts = self.tool.build_indices(self.tag_dir, self.index_dir)
        self.assertEqual(counts["records_indexed"], 1, counts)
        record_ids = {row["record_id"] for row in self._read_rows("by_attack_class")}
        self.assertEqual(record_ids, {"synth:deep:001"})

    def test_yml_extension_also_picked_up_recursively(self) -> None:
        """``.yml`` (not just ``.yaml``) is walked recursively too."""
        _write_record(self.tag_dir / "mev_exploits" / "alpha.yml", "synth:yml:001")
        _write_record(self.tag_dir / "mev_exploits" / "beta" / "record.yaml", "synth:yml:002")
        counts = self.tool.build_indices(self.tag_dir, self.index_dir)
        self.assertEqual(counts["records_indexed"], 2, counts)
        record_ids = {row["record_id"] for row in self._read_rows("by_attack_class")}
        self.assertEqual(record_ids, {"synth:yml:001", "synth:yml:002"})

    def test_record_yaml_skip_guard_prevents_double_count(self) -> None:
        """A nested ``record.yaml`` must not be counted twice via the rglob *.yaml pass."""
        _write_record(
            self.tag_dir / "dex_fix_history" / "curve_dup" / "record.yaml",
            "synth:dedupe:001",
        )
        counts = self.tool.build_indices(self.tag_dir, self.index_dir)
        self.assertEqual(counts["records_indexed"], 1, counts)
        rows = self._read_rows("by_attack_class")
        # If the record.yaml was visited twice, the writer halts on duplicate
        # record_id (line ~240). Reaching here at all proves the skip-guard works.
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["record_id"], "synth:dedupe:001")

    def test_root_level_record_wins_over_nested_mirror_duplicate(self) -> None:
        """Flat canonical records suppress historical nested mirror copies."""
        _write_record(self.tag_dir / "canonical.yaml", "synth:mirror:001")
        _write_record(
            self.tag_dir / "corpus_mined" / "canonical-copy" / "record.yaml",
            "synth:mirror:001",
            repo_slug="mirror-copy",
        )

        counts = self.tool.build_indices(self.tag_dir, self.index_dir)

        self.assertEqual(counts["records_indexed"], 1, counts)
        self.assertEqual(counts["records_skipped"], 1, counts)
        rows = self._read_rows("by_attack_class")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["record_id"], "synth:mirror:001")
        self.assertEqual(rows[0]["tag_file"], "canonical.yaml")

    def test_ambiguous_nested_duplicate_still_blocks_index_build(self) -> None:
        """Duplicate IDs without one flat canonical source remain hard errors."""
        _write_record(
            self.tag_dir / "subtree_a" / "copy-a" / "record.yaml",
            "synth:ambiguous:001",
            repo_slug="ambiguous-a",
        )
        _write_record(
            self.tag_dir / "subtree_b" / "copy-b" / "record.yaml",
            "synth:ambiguous:001",
            repo_slug="ambiguous-b",
        )

        with self.assertRaises(ValueError) as ctx:
            self.tool.build_indices(self.tag_dir, self.index_dir)
        self.assertIn("duplicate record_id", str(ctx.exception))

    def test_mixed_corpus_flat_plus_multiple_nested_subtrees(self) -> None:
        """End-to-end: 1 flat + 5 distinct nested subtrees all flow through."""
        _write_record(self.tag_dir / "flat_a.yaml", "synth:mix:flat:a")
        for i, subtree in enumerate(
            [
                "contest_platform_findings",
                "audit_firm_public_reports",
                "major_defi_fix_history",
                "zk_circuit_bugs",
                "solana_svm",
            ],
            start=1,
        ):
            _write_record(
                self.tag_dir / subtree / f"synth-mix-{i:03d}" / "record.yaml",
                f"synth:mix:nested:{i:03d}",
                repo_slug=f"mix{i}",
                attack_class="oracle-manipulation" if i % 2 else "access-control",
            )
        counts = self.tool.build_indices(self.tag_dir, self.index_dir)
        self.assertEqual(counts["records_indexed"], 6, counts)
        record_ids = {row["record_id"] for row in self._read_rows("by_attack_class")}
        self.assertEqual(
            record_ids,
            {
                "synth:mix:flat:a",
                "synth:mix:nested:001",
                "synth:mix:nested:002",
                "synth:mix:nested:003",
                "synth:mix:nested:004",
                "synth:mix:nested:005",
            },
        )

    def test_quarantine_and_deprecated_coexist_with_real_nested(self) -> None:
        """Real nested records remain indexed while excluded subtrees are dropped."""
        _write_record(
            self.tag_dir
            / "contest_platform_findings"
            / "sherlock-real"
            / "record.yaml",
            "synth:real:001",
        )
        _write_record(
            self.tag_dir
            / "_QUARANTINE_FABRICATED_CVE"
            / "fab-1"
            / "record.yaml",
            "synth:quarantined:003",
        )
        _write_record(
            self.tag_dir / "_deprecated" / "legacy_pdf" / "record.yaml",
            "synth:deprecated:002",
        )
        counts = self.tool.build_indices(self.tag_dir, self.index_dir)
        self.assertEqual(counts["records_indexed"], 1, counts)
        record_ids = {row["record_id"] for row in self._read_rows("by_attack_class")}
        self.assertEqual(record_ids, {"synth:real:001"})

    def test_non_recursive_regression_would_drop_nested(self) -> None:
        """Regression sentinel: only flat-root records would survive non-recursive glob.

        This test would PASS under the old (broken) ``Path.glob("*.yaml")`` walker
        with ``self.assertEqual(counts["records_indexed"], 1)`` and FAIL after the
        rglob extension. Inverting the assertion is the regression sentinel.
        """
        _write_record(self.tag_dir / "flat_root.yaml", "synth:reg:flat")
        _write_record(
            self.tag_dir / "contest_platform_findings" / "n1" / "record.yaml",
            "synth:reg:nested:1",
        )
        _write_record(
            self.tag_dir / "vyper_compiler_fix_history" / "n2" / "record.yaml",
            "synth:reg:nested:2",
        )
        counts = self.tool.build_indices(self.tag_dir, self.index_dir)
        # Under the OLD non-recursive walker this would be 1.
        # The recursive walker MUST surface all 3.
        self.assertEqual(counts["records_indexed"], 3, counts)


class ExcludedPathHelperTests(unittest.TestCase):
    """Unit-level coverage of the ``_is_excluded_path`` helper."""

    def setUp(self) -> None:
        self.tool = _load_tool()
        self.tmp = tempfile.TemporaryDirectory()
        self.tag_dir = Path(self.tmp.name) / "tags"
        self.tag_dir.mkdir(parents=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_flat_root_is_not_excluded(self) -> None:
        self.assertFalse(
            self.tool._is_excluded_path(self.tag_dir / "foo.yaml", self.tag_dir)
        )

    def test_quarantine_prefix_is_excluded(self) -> None:
        self.assertTrue(
            self.tool._is_excluded_path(
                self.tag_dir
                / "_QUARANTINE_FABRICATED_CVE"
                / "vyper_cve_fabricated"
                / "x.yaml",
                self.tag_dir,
            )
        )

    def test_deprecated_prefix_is_excluded(self) -> None:
        self.assertTrue(
            self.tool._is_excluded_path(
                self.tag_dir / "_deprecated" / "legacy" / "record.yaml",
                self.tag_dir,
            )
        )

    def test_innocuous_subtree_not_excluded(self) -> None:
        self.assertFalse(
            self.tool._is_excluded_path(
                self.tag_dir / "contest_platform_findings" / "s1" / "record.yaml",
                self.tag_dir,
            )
        )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
