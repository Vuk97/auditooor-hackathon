"""Tests for tools/hackerman-etl-from-vyper-cve.py."""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-vyper-cve.py"
VALIDATOR_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class HackermanEtlFromVyperCveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL_PATH, "_hackerman_etl_from_vyper_cve")
        self.validator = _load(VALIDATOR_PATH, "_hackerman_record_validate_for_vyper_cve")

    def test_seed_corpus_meets_target_volume(self) -> None:
        records = self.tool.build_all_records()
        # Target band from brief: 60-90 records.
        self.assertGreaterEqual(len(records), 60, f"got {len(records)} records; target >= 60")
        self.assertLessEqual(len(records), 120, f"got {len(records)} records; target <= 120")

    def test_every_record_is_vyper_language(self) -> None:
        records = self.tool.build_all_records()
        for record in records:
            self.assertEqual(record["target_language"], "vyper", record["record_id"])

    def test_attack_class_taxonomy_includes_new_classes(self) -> None:
        records = self.tool.build_all_records()
        attack_classes = {record["attack_class"] for record in records}
        required = {
            "vyper-compiler-reentrancy-lock-malloc-corruption",
            "vyper-compiler-saturating-arithmetic-reentrancy",
            "vyper-compiler-call-builtin-bypass",
            "vyper-compiler-immutables-default-value",
            "vyper-compiler-incorrect-storage-write",
            "vyper-compiler-default-export-visibility",
            "vyper-compiler-decimal-bounds-bypass",
            "vyper-amm-readonly-reentrancy-curve-pool",
        }
        missing = required - attack_classes
        self.assertFalse(missing, f"missing required attack classes: {missing}")

    def test_curve_july_2023_pools_present(self) -> None:
        records = self.tool.build_all_records()
        components = {record["target_component"] for record in records}
        # Each of the four affected pools must appear at least once.
        for pool in (
            "Curve alETH/ETH pool",
            "Curve msETH/ETH pool",
            "Curve pETH/ETH pool",
            "Curve CRV/ETH pool",
        ):
            self.assertIn(pool, components, f"missing Curve July 2023 pool {pool!r}")

    def test_records_validate_against_v1_schema(self) -> None:
        records = self.tool.build_all_records()
        errors = self.tool.validate_records(records)
        self.assertEqual(errors, [], f"schema validation errors: {errors[:5]}")

    def test_severity_walks_back_for_post_fix_states(self) -> None:
        records = self.tool.build_all_records()
        by_state = {"pre-fix": [], "post-fix-not-migrated": [], "post-fix-migrated-historical": []}
        for record in records:
            for state in by_state:
                if state in record["source_audit_ref"]:
                    by_state[state].append(record["severity_at_finding"])
                    break
        # Pre-fix should include critical entries (CVE-2023-32674 family).
        self.assertIn("critical", by_state["pre-fix"])
        # Post-fix-not-migrated should never be critical (one tier lower).
        self.assertNotIn("critical", by_state["post-fix-not-migrated"])
        # Post-fix-migrated-historical should be info-only.
        self.assertTrue(all(sev == "info" for sev in by_state["post-fix-migrated-historical"]))

    def test_related_records_cross_link_within_same_cve(self) -> None:
        records = self.tool.build_all_records()
        by_id = {record["record_id"]: record for record in records}
        # Pick a CVE-2023-32674 record; its related_records must point only
        # to other CVE-2023-32674 records.
        target = None
        for record in records:
            if "cve-2023-32674:curve-aleth-eth-pool:pre-fix" in record["source_audit_ref"]:
                target = record
                break
        self.assertIsNotNone(target)
        self.assertGreater(len(target["related_records"]), 0)
        for related in target["related_records"]:
            self.assertIn(related, by_id, f"related record {related!r} not in emitted set")
            self.assertTrue(
                related.startswith("vyper-cve:cve-2023-32674:"),
                f"related record {related!r} crosses CVE boundary",
            )

    def test_cli_writes_schema_valid_yaml_and_deterministic_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            with contextlib.redirect_stdout(io.StringIO()):
                rc = self.tool.main(
                    [
                        "--out-dir",
                        str(out_dir),
                        "--json-summary",
                    ]
                )
            self.assertEqual(rc, 0)
            files = sorted(out_dir.glob("*.yaml"))
            self.assertGreaterEqual(len(files), 60)
            # Filenames should be sorted-stable across runs.
            self.assertEqual([path.name for path in files], sorted(path.name for path in files))
            schema = self.validator.load_schema()
            for path in files[:8]:
                status, errors = self.validator.validate_file(path, schema)
                self.assertEqual(status, "valid", (path, errors))

    def test_cli_dry_run_does_not_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out_dry"
            with contextlib.redirect_stdout(io.StringIO()):
                rc = self.tool.main(
                    [
                        "--out-dir",
                        str(out_dir),
                        "--dry-run",
                        "--json-summary",
                    ]
                )
            self.assertEqual(rc, 0)
            self.assertFalse(out_dir.exists(), "dry-run must not create out_dir")

    def test_cli_limit_caps_records(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out_limit"
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = self.tool.main(
                    [
                        "--out-dir",
                        str(out_dir),
                        "--limit",
                        "5",
                        "--json-summary",
                    ]
                )
            self.assertEqual(rc, 0)
            summary = json.loads(buf.getvalue())
            self.assertEqual(summary["records_emitted"], 5)
            self.assertEqual(summary["file_count"], 5)

    def test_extra_json_extends_seed(self) -> None:
        extra_entry = [{
            "cve_id": "CVE-TEST-EXTRA-2025",
            "year": 2025,
            "title": "Synthetic extra entry for test harness",
            "description": "Synthetic extra entry used to verify --extra-json wiring works end-to-end.",
            "attacker_action_sequence": "Synthetic action sequence used in test harness.",
            "fix_pattern": "Apply the synthetic fix pattern.",
            "fix_anti_pattern": "Avoid the synthetic anti-pattern.",
            "attack_class": "vyper-compiler-bug-test-only",
            "bug_class": "vyper-compiler-bug",
            "severity": "low",
            "impact_class": "griefing",
            "impact_actor": "arbitrary-user",
            "impact_dollar_class": "<$10K",
            "target_domain": "vault",
            "components": [{"pool": "Synthetic synthetic synthetic", "address": "n/a", "loss_usd": 0}],
            "preconditions": ["synthetic precondition"],
            "vyper_versions_affected": ["0.0.0"],
            "vyper_versions_fixed": ["0.0.1"],
        }]
        with tempfile.TemporaryDirectory() as tmp:
            extra_path = Path(tmp) / "extra.json"
            extra_path.write_text(json.dumps(extra_entry), encoding="utf-8")
            out_dir = Path(tmp) / "out_extra"
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = self.tool.main(
                    [
                        "--out-dir",
                        str(out_dir),
                        "--extra-json",
                        str(extra_path),
                        "--dry-run",
                        "--json-summary",
                    ]
                )
            self.assertEqual(rc, 0)
            summary = json.loads(buf.getvalue())
            # 3 mitigation states x 1 extra component = 3 extra records.
            self.assertEqual(summary["extra_entries"], 1)
            self.assertEqual(summary["records_emitted"], 78 + 3)

    def test_record_id_unique_and_pattern_safe(self) -> None:
        records = self.tool.build_all_records()
        ids = [record["record_id"] for record in records]
        self.assertEqual(len(ids), len(set(ids)), "record_ids must be unique")
        for rid in ids:
            self.assertRegex(rid, r"^[A-Za-z0-9._:/-]{8,160}$")

    def test_cross_language_analogues_present_for_reentrancy_class(self) -> None:
        records = self.tool.build_all_records()
        reentrancy = [r for r in records if "reentrancy-lock" in r["attack_class"]]
        self.assertTrue(reentrancy)
        for record in reentrancy:
            langs = {item["target_language"] for item in record["cross_language_analogues"]}
            self.assertIn("solidity", langs, record["record_id"])
            self.assertIn("rust", langs, record["record_id"])


if __name__ == "__main__":
    unittest.main()
