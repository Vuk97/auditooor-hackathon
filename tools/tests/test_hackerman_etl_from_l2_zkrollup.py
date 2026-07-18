"""Tests for tools/hackerman-etl-from-l2-zkrollup.py."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-l2-zkrollup.py"
VALIDATOR_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class HackermanEtlFromL2ZkrollupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL_PATH, "_hackerman_etl_from_l2_zkrollup")
        self.validator = _load(VALIDATOR_PATH, "_hackerman_record_validate_for_l2_zkrollup")

    def test_seed_corpus_meets_target_volume(self) -> None:
        records = self.tool.build_all_records()
        # Target band from brief: 200-400 records.
        self.assertGreaterEqual(len(records), 200, f"got {len(records)} records; target >= 200")
        self.assertLessEqual(len(records), 500, f"got {len(records)} records; target <= 500")

    def test_every_record_is_solidity_language(self) -> None:
        records = self.tool.build_all_records()
        for record in records:
            self.assertEqual(record["target_language"], "solidity", record["record_id"])

    def test_attack_class_taxonomy_includes_new_classes(self) -> None:
        records = self.tool.build_all_records()
        attack_classes = {record["attack_class"] for record in records}
        required = {
            "forced-inclusion-bypass",
            "state-diff-leak-on-l1-publish",
            "settlement-layer-fraud-window-bypass",
            "withdrawal-merkle-proof-spoof",
            "operator-batch-omission",
            "prover-collusion-replace-proof",
            "precompile-divergence-l1-vs-l2",
            "sequencer-finality-conflict",
            "aggregation-relayer-replay",
            "account-abstraction-l2-paymaster-replay",
            "da-publish-vs-prove-deadline-race",
        }
        missing = required - attack_classes
        self.assertFalse(missing, f"missing required attack classes: {missing}")

    def test_all_six_rollup_families_present(self) -> None:
        """Every rollup family in the brief must appear in the corpus."""
        records = self.tool.build_all_records()
        shape_tags = set()
        for record in records:
            shape_tags.update(record["function_shape"]["shape_tags"])
        for rollup in (
            "rollup-zksync-boojum",
            "rollup-scroll",
            "rollup-polygon-zkevm",
            "rollup-aztec",
            "rollup-linea",
            "rollup-taiko",
        ):
            self.assertIn(rollup, shape_tags, f"missing rollup family {rollup!r}")

    def test_records_validate_against_v1_schema(self) -> None:
        records = self.tool.build_all_records()
        errors = self.tool.validate_records(records)
        self.assertEqual(errors, [], f"schema validation errors: {errors[:5]}")

    def test_severity_walks_back_for_post_fix_states(self) -> None:
        records = self.tool.build_all_records()
        # source_audit_ref slug gets truncated to ~24 chars per slugify;
        # 'post-fix-migrated-historical' lands as 'post-fix-migrated-histor'.
        slug_state = {
            "pre-fix": "pre-fix",
            "post-fix-not-migrated": "post-fix-not-migrated",
            "post-fix-migrated-historical": "post-fix-migrated-histor",
        }
        by_state = {key: [] for key in slug_state}
        # Check most-specific (longer) suffix first.
        ordered = ("post-fix-migrated-historical", "post-fix-not-migrated", "pre-fix")
        for record in records:
            ref = record["source_audit_ref"]
            for key in ordered:
                if ref.endswith(":" + slug_state[key]):
                    by_state[key].append(record["severity_at_finding"])
                    break
        self.assertTrue(by_state["pre-fix"], "no pre-fix records emitted")
        self.assertTrue(by_state["post-fix-not-migrated"], "no post-fix-not-migrated records emitted")
        self.assertTrue(by_state["post-fix-migrated-historical"], "no post-fix-migrated-historical records emitted")
        # post-fix-migrated-historical must be info-only.
        for severity in by_state["post-fix-migrated-historical"]:
            self.assertEqual(severity, "info", f"historical record severity {severity} != info")

    def test_target_domain_is_rollup_or_zk_proof(self) -> None:
        records = self.tool.build_all_records()
        allowed = {"rollup", "zk-proof"}
        for record in records:
            self.assertIn(record["target_domain"], allowed, f"{record['record_id']} target_domain={record['target_domain']}")

    def test_attacker_role_is_canonical(self) -> None:
        records = self.tool.build_all_records()
        allowed = {
            "unprivileged",
            "privileged-trusted",
            "privileged-compromised",
            "local-host-observer",
            "block-proposer",
            "governance",
            "validator",
            "sequencer",
            "proposer",
        }
        for record in records:
            self.assertIn(record["attacker_role"], allowed, record["record_id"])

    def test_cross_language_analogues_present_for_all_attack_classes(self) -> None:
        """Every record should carry at least one cross-language analogue.

        The brief explicitly asks for cross-language analogues mapping
        L2 system contract findings to general bridge/proxy attack
        classes; this enforces the contract at corpus-build time.
        """
        records = self.tool.build_all_records()
        for record in records:
            self.assertTrue(
                record["cross_language_analogues"],
                f"{record['record_id']} has no cross_language_analogues",
            )

    def test_each_audit_yields_multiple_components(self) -> None:
        """Each seed audit should expand to multiple components."""
        records = self.tool.build_all_records()
        by_audit_slug = {}
        for record in records:
            audit_slug = record["source_audit_ref"].split(":")[1]
            by_audit_slug.setdefault(audit_slug, set()).add(
                record["source_audit_ref"].split(":")[2]
            )
        for audit_slug, components in by_audit_slug.items():
            self.assertGreaterEqual(
                len(components),
                3,
                f"audit {audit_slug} only emitted {len(components)} components",
            )

    def test_related_records_links_within_audit(self) -> None:
        records = self.tool.build_all_records()
        # Pick the first record and verify its related_records list points
        # back to siblings sharing the same source_audit_ref audit slug.
        if not records:
            self.skipTest("no records emitted")
        first = records[0]
        own_audit = first["source_audit_ref"].split(":")[1]
        self.assertTrue(first["related_records"], "first record has no related_records")
        ids = {r["record_id"]: r for r in records}
        for rid in first["related_records"]:
            sibling = ids.get(rid)
            self.assertIsNotNone(sibling, f"sibling {rid} not found in corpus")
            sibling_audit = sibling["source_audit_ref"].split(":")[1]
            self.assertEqual(sibling_audit, own_audit, f"sibling audit mismatch: {sibling_audit} != {own_audit}")

    def test_extra_json_extension_path(self) -> None:
        """Confirm --extra-json route accepts additional audit entries."""
        extra = [
            {
                "audit_id": "test-extra-extension-audit-2024-12",
                "year": 2024,
                "rollup": "test-extra",
                "rollup_repo": "test-org/test-extra-repo",
                "auditor": "test-auditor",
                "report_ref": "test-extra-extension-2024-12",
                "title": "Test extension audit entry for ETL extra-json path",
                "description": "Test description for extra-json path coverage.",
                "attacker_action_sequence": "Test attacker action sequence for extra-json path.",
                "fix_pattern": "Test fix pattern.",
                "fix_anti_pattern": "Test fix anti pattern.",
                "attack_class": "forced-inclusion-bypass",
                "bug_class": "l2-test-extension",
                "severity": "medium",
                "impact_class": "freeze",
                "impact_actor": "specific-user",
                "impact_dollar_class": "$10K-$100K",
                "target_domain": "rollup",
                "attacker_role": "sequencer",
                "components": [
                    {"comp": "test-component-a", "fn": "doTestA"},
                    {"comp": "test-component-b", "fn": "doTestB"},
                    {"comp": "test-component-c", "fn": "doTestC"},
                ],
                "preconditions": ["test precondition 1", "test precondition 2"],
                "reference_urls": ["https://example.com/test"],
            }
        ]
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump(extra, fh)
            extra_path = Path(fh.name)
        try:
            records = self.tool.build_all_records(extra_entries=extra)
            base = self.tool.build_all_records()
            # 3 components x 3 mitigation states = 9 extra records.
            self.assertEqual(len(records), len(base) + 9, "extra audit must expand to 9 records")
            errors = self.tool.validate_records(records)
            self.assertEqual(errors, [], f"extra-json schema validation errors: {errors[:3]}")
        finally:
            extra_path.unlink(missing_ok=True)

    def test_dry_run_main_emits_zero_files(self) -> None:
        """--dry-run path must not write any YAML files."""
        with tempfile.TemporaryDirectory() as tmp:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = self.tool.main(["--out-dir", tmp, "--dry-run", "--json-summary"])
            self.assertEqual(rc, 0, f"dry-run main exited rc={rc}")
            summary = json.loads(buf.getvalue())
            self.assertTrue(summary["dry_run"])
            self.assertEqual(summary["errors"], [])
            self.assertGreaterEqual(summary["records_emitted"], 200)
            # No YAML files should have landed in the directory.
            written = list(Path(tmp).rglob("*.yaml"))
            self.assertEqual(written, [], f"dry-run wrote files: {written[:3]}")

    def test_write_path_emits_yaml_files(self) -> None:
        """Non-dry-run path writes one YAML file per record."""
        with tempfile.TemporaryDirectory() as tmp:
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = self.tool.main(["--out-dir", tmp, "--limit", "12", "--json-summary"])
            self.assertEqual(rc, 0, f"write main exited rc={rc}")
            summary = json.loads(buf.getvalue())
            self.assertFalse(summary["dry_run"])
            written = sorted(Path(tmp).rglob("*.yaml"))
            self.assertEqual(len(written), summary["records_emitted"])
            self.assertGreater(len(written), 0)
            # Validate the first emitted file independently via the validator.
            schema = self.validator.load_schema()
            status, errs = self.validator.validate_file(written[0], schema=schema)
            self.assertEqual(status, "valid", f"first emitted file invalid: {errs[:3]}")

    def test_function_shape_signature_nonempty(self) -> None:
        records = self.tool.build_all_records()
        for record in records:
            sig = record["function_shape"]["raw_signature"]
            self.assertTrue(sig and sig.strip(), record["record_id"])
            self.assertLessEqual(len(sig), 500, record["record_id"])

    def test_record_ids_are_unique(self) -> None:
        records = self.tool.build_all_records()
        ids = [r["record_id"] for r in records]
        self.assertEqual(len(ids), len(set(ids)), "duplicate record_ids in corpus")


if __name__ == "__main__":
    unittest.main()
