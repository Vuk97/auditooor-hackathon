from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "hackerman-etl-from-near-ink.py"
VALIDATOR = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules.setdefault(spec.name, mod)
    spec.loader.exec_module(mod)
    return mod


class HackermanEtlFromNearInkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL, "_hackerman_etl_from_near_ink")
        self.validator = _load(VALIDATOR, "_hackerman_record_validate_for_near_ink")

    # -----------------------------------------------------------------
    # Schema validation: every emitted record must validate.
    # -----------------------------------------------------------------
    def test_dry_run_emits_records_with_zero_errors(self) -> None:
        with tempfile.TemporaryDirectory(prefix="near-ink-dry-") as tmp:
            summary = self.tool.convert(Path(tmp) / "out", dry_run=True)
        self.assertEqual(summary["errors"], [])
        self.assertGreater(summary["records_emitted"], 0)
        self.assertEqual(summary["records_emitted"], summary["records_attempted"])

    def test_target_record_count_is_in_band(self) -> None:
        """EXEC-WAVE6-NEAR-INK brief target: ~20-50 records."""
        with tempfile.TemporaryDirectory(prefix="near-ink-count-") as tmp:
            summary = self.tool.convert(Path(tmp) / "out", dry_run=True)
        self.assertGreaterEqual(summary["records_emitted"], 20)
        self.assertLessEqual(summary["records_emitted"], 50)

    def test_both_ecosystems_present(self) -> None:
        with tempfile.TemporaryDirectory(prefix="near-ink-eco-") as tmp:
            summary = self.tool.convert(Path(tmp) / "out", dry_run=True)
        self.assertIn("near", summary["by_ecosystem"])
        self.assertIn("ink", summary["by_ecosystem"])
        self.assertGreater(summary["by_ecosystem"]["near"], 0)
        self.assertGreater(summary["by_ecosystem"]["ink"], 0)

    def test_three_mitigation_states_present(self) -> None:
        with tempfile.TemporaryDirectory(prefix="near-ink-states-") as tmp:
            summary = self.tool.convert(Path(tmp) / "out", dry_run=True)
        for state in ("proposed", "mitigated", "regressed"):
            self.assertIn(state, summary["by_mitigation_state"])
            self.assertGreater(summary["by_mitigation_state"][state], 0)
        # All severity rows are >= medium so the three states are balanced.
        states = summary["by_mitigation_state"]
        self.assertEqual(states["proposed"], states["mitigated"])
        self.assertEqual(states["mitigated"], states["regressed"])

    # -----------------------------------------------------------------
    # Taxonomy coverage: 5 new attack classes.
    # -----------------------------------------------------------------
    def test_taxonomy_covers_five_new_attack_classes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="near-ink-tax-") as tmp:
            summary = self.tool.convert(Path(tmp) / "out", dry_run=True)
        required_classes = {
            "near-callback-promise-replay",
            "near-yield-callback-state-divergence",
            "near-fungible-token-burn-without-callback-fail",
            "ink-storage-key-shadow",
            "ink-cross-contract-trapped-balance",
        }
        for cls in required_classes:
            self.assertIn(cls, summary["by_attack_class"], f"missing taxonomy class {cls}")

    def test_filter_ecosystem_restricts_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="near-ink-filter-") as tmp:
            summary = self.tool.convert(
                Path(tmp) / "out", dry_run=True, filter_ecosystem="ink"
            )
        self.assertGreater(summary["records_emitted"], 0)
        self.assertEqual(set(summary["by_ecosystem"]), {"ink"})

    # -----------------------------------------------------------------
    # Schema correctness on real write.
    # -----------------------------------------------------------------
    def test_all_emitted_records_validate_against_v1_schema(self) -> None:
        with tempfile.TemporaryDirectory(prefix="near-ink-write-") as tmp:
            out_dir = Path(tmp) / "out"
            summary = self.tool.convert(out_dir, limit=12)
            self.assertEqual(summary["errors"], [])
            self.assertGreater(summary["file_count"], 0)
            schema = self.validator.load_schema()
            seen = 0
            for path in out_dir.glob("*.yaml"):
                seen += 1
                status, errors = self.validator.validate_file(path, schema)
                self.assertEqual(status, "valid", f"{path}: {errors}")
            self.assertEqual(seen, summary["file_count"])

    def test_emitted_record_has_required_rust_signals(self) -> None:
        with tempfile.TemporaryDirectory(prefix="near-ink-detail-") as tmp:
            out_dir = Path(tmp) / "out"
            self.tool.convert(out_dir, limit=1)
            path = next(out_dir.glob("*.yaml"))
            record = self.validator.load_yaml(path)
        self.assertEqual(record["schema_version"], self.tool.SCHEMA_VERSION)
        self.assertEqual(record["target_language"], "rust")
        self.assertIn(record["severity_at_finding"], {"critical", "high", "medium", "low", "info"})
        self.assertEqual(record["record_tier"], "public-corpus")
        self.assertEqual(record["source_extraction_method"], "corpus-etl")
        # The mitigation-state marker is embedded in the action sequence.
        self.assertRegex(
            record["attacker_action_sequence"],
            r"\[mitigation-state=(proposed|mitigated|regressed);",
        )
        # The shape_tags include an "ecosystem-near" or "ecosystem-ink" tag.
        eco_tags = [t for t in record["function_shape"]["shape_tags"] if t.startswith("ecosystem-")]
        self.assertEqual(len(eco_tags), 1)
        self.assertIn(eco_tags[0], {"ecosystem-near", "ecosystem-ink"})

    def test_record_ids_are_unique(self) -> None:
        records = self.tool.build_records()
        ids = [r["record_id"] for r in records]
        self.assertEqual(len(ids), len(set(ids)), "record_id collisions detected")

    def test_near_classes_have_rpc_infra_domain(self) -> None:
        records = self.tool.build_records()
        near_records = [
            r
            for r in records
            if any(t == "ecosystem-near" for t in r["function_shape"]["shape_tags"])
        ]
        self.assertGreater(len(near_records), 0)
        # All three NEAR attack classes were tagged target_domain = rpc-infra
        # in the taxonomy (cross-shard callback / yield / FT-burn surface).
        for r in near_records:
            self.assertEqual(r["target_domain"], "rpc-infra")

    def test_ink_storage_key_shadow_raw_signature_has_literal_braces(self) -> None:
        """Regression: the raw_signature template contains literal Rust braces
        (e.g. 'struct Contract { balances: Mapping<...> }') which would crash
        str.format() if the ETL ever reverted to a naive format() call."""
        records = [
            r
            for r in self.tool.build_records()
            if r["attack_class"] == "ink-storage-key-shadow"
        ]
        self.assertGreater(len(records), 0)
        for r in records:
            sig = r["function_shape"]["raw_signature"]
            self.assertIn("{", sig)
            self.assertIn("}", sig)
            self.assertIn("Mapping", sig)

    # -----------------------------------------------------------------
    # YAML rendering.
    # -----------------------------------------------------------------
    def test_yaml_scalar_emits_float_as_number(self) -> None:
        self.assertEqual(self.tool.yaml_scalar(3.0), "3.0")
        self.assertEqual(self.tool.yaml_scalar(0.55), "0.55")

    def test_yaml_scalar_emits_bool_as_unquoted_bool(self) -> None:
        self.assertEqual(self.tool.yaml_scalar(True), "true")
        self.assertEqual(self.tool.yaml_scalar(False), "false")

    # -----------------------------------------------------------------
    # CLI surface.
    # -----------------------------------------------------------------
    def test_cli_dry_run_and_json_summary(self) -> None:
        with tempfile.TemporaryDirectory(prefix="near-ink-cli-") as tmp:
            out_dir = Path(tmp) / "out"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = self.tool.main(
                    [
                        "--out-dir",
                        str(out_dir),
                        "--dry-run",
                        "--json-summary",
                        "--limit",
                        "5",
                    ]
                )
            self.assertEqual(rc, 0)
            self.assertIn('"records_emitted": 5', stdout.getvalue())
            self.assertFalse(out_dir.exists())  # dry-run must not create dir

    def test_cli_limit_rejects_negative(self) -> None:
        rc = self.tool.main(["--out-dir", "/tmp/should-not-be-created-near-ink", "--limit", "-1"])
        self.assertEqual(rc, 2)

    def test_cli_filter_ecosystem_near(self) -> None:
        with tempfile.TemporaryDirectory(prefix="near-ink-cli-near-") as tmp:
            out_dir = Path(tmp) / "out"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = self.tool.main(
                    [
                        "--out-dir",
                        str(out_dir),
                        "--dry-run",
                        "--json-summary",
                        "--filter-ecosystem",
                        "near",
                    ]
                )
            self.assertEqual(rc, 0)
            self.assertIn('"near":', stdout.getvalue())
            self.assertNotIn(
                '"ink":',
                stdout.getvalue().split('"by_ecosystem"', 1)[-1].split('"by_mitigation_state"', 1)[0],
            )


if __name__ == "__main__":
    unittest.main()
