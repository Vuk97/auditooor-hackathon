"""Tests for the YAML/JSON dual-form walker harmonization of hackerman-index-build.

Spec anchor: Wave-2 PR-A walker harmonization (2026-05-16), closing the
structural root cause behind the by_ghsa_id surgical patch at ``58eed3f43a``.

Pre-harmonization the index walker globbed only ``record.yaml`` / ``*.yaml``
/ ``*.yml`` (see ``tools/hackerman-index-build.py::load_records`` lines
338-343 at HEAD ``58eed3f43a``). The post-migration validator
(``tools/wave2-w21-post-migration-validator.py::iter_record_files``)
correctly iterated both ``record.yaml`` AND ``record.json``; its
``check_index_drift`` extension caught a JSON-only record's ghsa_id row
missing from ``by_ghsa_id.jsonl``. The surgical patch at ``58eed3f43a``
added the row by hand; this test pins the structural fix.

39 JSON-only records exist in the corpus as of 2026-05-16; the
harmonized walker indexes them alongside ``record.yaml``. When a
directory contains BOTH ``record.yaml`` and ``record.json`` the YAML
form is canonical and the JSON sibling is skipped to prevent
double-counting (6,258 dual-form records exist; all must dedupe).

Synthetic-fixture marker: every test record below has ``synthetic_fixture:
true`` (or its functional equivalent) embedded via a ``record_id`` prefixed
``synth:`` so a grep of the live corpus would never collide.
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
    spec = importlib.util.spec_from_file_location(
        "_hackerman_index_build_yaml_json_dual", str(TOOL_PATH)
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


# Synthetic v1 YAML body parametrised by record_id (synthetic_fixture: true).
_YAML_TEMPLATE = """schema_version: auditooor.hackerman_record.v1
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


def _json_body(
    record_id: str,
    repo_slug: str = "rec",
    attack_class: str = "reentrancy",
) -> dict:
    """Mirror of _YAML_TEMPLATE as a Python dict (for record.json fixtures).

    JSON-only records in the real corpus typically use schema v1.1; we mirror
    the v1 minimum-required-field set here because we want this test to pin
    walker behaviour, not schema dispatch (covered by
    ``test_hackerman_index_build_v1_1_fields.py``).
    """
    return {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": record_id,
        "source_audit_ref": record_id,
        "target_domain": "lending",
        "target_language": "solidity",
        "target_repo": f"synthetic/{repo_slug}",
        "target_component": f"SyntheticComponent.{repo_slug}",
        "function_shape": {
            "raw_signature": f"function action_{repo_slug}(uint256 amount) external",
            "shape_tags": ["external-nonpayable-token-transfer"],
        },
        "bug_class": "logic-error",
        "attack_class": attack_class,
        "attacker_role": "unprivileged",
        "attacker_action_sequence": "Step 1: setup. Step 2: trigger. Step 3: profit.",
        "required_preconditions": ["synthetic precondition"],
        "impact_class": "theft",
        "impact_actor": "arbitrary-user",
        "impact_dollar_class": "$10K-$100K",
        "fix_pattern": "validate inputs before mutation",
        "fix_anti_pattern_avoided": "missing validation",
        "severity_at_finding": "medium",
        "year": 2025,
        "cross_language_analogues": [],
        "related_records": [],
    }


def _write_yaml(
    path: Path,
    record_id: str,
    repo_slug: str = "rec",
    attack_class: str = "reentrancy",
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        _YAML_TEMPLATE.format(
            record_id=record_id,
            repo_slug=repo_slug,
            attack_class=attack_class,
        ),
        encoding="utf-8",
    )


def _write_json(
    path: Path,
    record_id: str,
    repo_slug: str = "rec",
    attack_class: str = "reentrancy",
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            _json_body(record_id, repo_slug=repo_slug, attack_class=attack_class),
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


class YamlJsonDualWalkerTests(unittest.TestCase):
    """Wave-2 PR-A acceptance: walker indexes record.yaml AND record.json,
    deduping when both are present in the same directory.
    """

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

    # ---- 4 mandated cases (spec deliverable §6) ---------------------------

    def test_yaml_only_record_is_indexed(self) -> None:
        """Case 1: directory with ``record.yaml`` only - indexed via YAML path."""
        _write_yaml(
            self.tag_dir / "synth_subtree" / "synth-yaml-only" / "record.yaml",
            "synth:yaml-only:001",
        )
        counts = self.tool.build_indices(self.tag_dir, self.index_dir)
        self.assertEqual(counts["records_indexed"], 1, counts)
        record_ids = {row["record_id"] for row in self._read_rows("by_attack_class")}
        self.assertEqual(record_ids, {"synth:yaml-only:001"})
        # tag_file should point at the YAML.
        rows = self._read_rows("by_attack_class")
        self.assertTrue(rows[0]["tag_file"].endswith("record.yaml"), rows[0]["tag_file"])

    def test_json_only_record_is_indexed(self) -> None:
        """Case 2: directory with ``record.json`` only - the NEW behaviour.

        This is the structural fix: 39 such records exist in the live corpus
        (closest analogue: ``move_aptos_sui/movebit:move:...``). Pre-fix the
        walker dropped them silently.
        """
        _write_json(
            self.tag_dir / "synth_subtree" / "synth-json-only" / "record.json",
            "synth:json-only:001",
        )
        counts = self.tool.build_indices(self.tag_dir, self.index_dir)
        self.assertEqual(counts["records_indexed"], 1, counts)
        record_ids = {row["record_id"] for row in self._read_rows("by_attack_class")}
        self.assertEqual(record_ids, {"synth:json-only:001"})
        # tag_file should point at the JSON.
        rows = self._read_rows("by_attack_class")
        self.assertTrue(rows[0]["tag_file"].endswith("record.json"), rows[0]["tag_file"])

    def test_dual_form_yaml_canonical_json_skipped(self) -> None:
        """Case 3: directory with BOTH ``record.yaml`` and ``record.json`` -
        YAML wins, JSON is skipped (no double-count).
        """
        dual_dir = self.tag_dir / "synth_subtree" / "synth-dual-form"
        _write_yaml(dual_dir / "record.yaml", "synth:dual-form:001")
        _write_json(dual_dir / "record.json", "synth:dual-form:001-from-json")
        counts = self.tool.build_indices(self.tag_dir, self.index_dir)
        # Exactly one record indexed (the YAML form).
        self.assertEqual(counts["records_indexed"], 1, counts)
        record_ids = {row["record_id"] for row in self._read_rows("by_attack_class")}
        # The YAML form is canonical, JSON sibling is dropped.
        self.assertEqual(record_ids, {"synth:dual-form:001"})
        self.assertNotIn("synth:dual-form:001-from-json", record_ids)
        rows = self._read_rows("by_attack_class")
        self.assertTrue(rows[0]["tag_file"].endswith("record.yaml"), rows[0]["tag_file"])

    def test_mixed_corpus_all_three_cases_coexist(self) -> None:
        """Case 4: a corpus with all three shapes - yaml-only, json-only,
        dual-form - indexes correctly (3 records, no double-count).
        """
        _write_yaml(
            self.tag_dir / "mix" / "yaml-side" / "record.yaml",
            "synth:mix:yaml-only:001",
            repo_slug="ya",
            attack_class="reentrancy",
        )
        _write_json(
            self.tag_dir / "mix" / "json-side" / "record.json",
            "synth:mix:json-only:002",
            repo_slug="jo",
            attack_class="access-control",
        )
        dual_dir = self.tag_dir / "mix" / "dual-side"
        _write_yaml(
            dual_dir / "record.yaml",
            "synth:mix:dual-yaml:003",
            repo_slug="du",
            attack_class="oracle-manipulation",
        )
        _write_json(
            dual_dir / "record.json",
            "synth:mix:dual-json:003-loser",
            repo_slug="du",
            attack_class="oracle-manipulation",
        )
        counts = self.tool.build_indices(self.tag_dir, self.index_dir)
        self.assertEqual(counts["records_indexed"], 3, counts)
        record_ids = {row["record_id"] for row in self._read_rows("by_attack_class")}
        self.assertEqual(
            record_ids,
            {
                "synth:mix:yaml-only:001",
                "synth:mix:json-only:002",
                "synth:mix:dual-yaml:003",
            },
        )
        # The JSON sibling of the dual-form pair must NOT appear.
        self.assertNotIn("synth:mix:dual-json:003-loser", record_ids)

    # ---- additional defense-in-depth coverage -----------------------------

    def test_json_only_with_invalid_json_surfaces_parse_error(self) -> None:
        """A malformed ``record.json`` surfaces a JSON parse error in the
        index-builder's error stream (mirrors the YAML parse-error path).
        """
        bad = self.tag_dir / "synth_bad_json" / "broken" / "record.json"
        bad.parent.mkdir(parents=True, exist_ok=True)
        bad.write_text("{ not valid json,,, ", encoding="utf-8")
        records, errors, _skipped = self.tool.load_records(self.tag_dir)
        self.assertEqual(records, [])
        self.assertEqual(len(errors), 1, errors)
        self.assertIn("JSON parse error", errors[0])

    def test_quarantine_subtree_still_excluded_for_json(self) -> None:
        """``_QUARANTINE_*`` exclusion must apply to ``record.json`` too."""
        _write_yaml(self.tag_dir / "kept.yaml", "synth:kept:json-q:001")
        _write_json(
            self.tag_dir
            / "_QUARANTINE_FABRICATED_CVE"
            / "synth-fabricated-json"
            / "record.json",
            "synth:quarantined:json:002",
        )
        counts = self.tool.build_indices(self.tag_dir, self.index_dir)
        self.assertEqual(counts["records_indexed"], 1, counts)
        record_ids = {row["record_id"] for row in self._read_rows("by_attack_class")}
        self.assertEqual(record_ids, {"synth:kept:json-q:001"})

    def test_deprecated_subtree_still_excluded_for_json(self) -> None:
        """``_deprecated/`` exclusion must apply to ``record.json`` too."""
        _write_yaml(self.tag_dir / "kept2.yaml", "synth:kept:json-d:001")
        _write_json(
            self.tag_dir / "_deprecated" / "old_json_format" / "record.json",
            "synth:deprecated:json:002",
        )
        counts = self.tool.build_indices(self.tag_dir, self.index_dir)
        self.assertEqual(counts["records_indexed"], 1, counts)
        record_ids = {row["record_id"] for row in self._read_rows("by_attack_class")}
        self.assertEqual(record_ids, {"synth:kept:json-d:001"})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
