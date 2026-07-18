from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-zkbugs-catalog.py"
VALIDATOR_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class HackermanEtlFromZkbugsCatalogTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL_PATH, "_hackerman_etl_zkbugs_catalog")
        self.validator = _load(VALIDATOR_PATH, "_hackerman_record_validate_for_zkbugs_etl")

    # ------------------------------------------------------------------
    # Seed shape
    # ------------------------------------------------------------------

    def test_seed_catalogue_covers_canonical_zk_attack_classes(self) -> None:
        classes = {seed["attack_class"] for seed in self.tool.SEED_CATALOGUE}
        # Spot-check: every ZK class enumerated in the EXEC-WAVE4-ZK brief
        # has either an exact entry or a structurally-equivalent one in this
        # miner.
        required = {
            "unconstrained-variable",
            "missing-range-check",
            "proof-malleability",
            "circuit-aliased-witness",
            "fiat-shamir-domain-confusion",
            "trusted-setup-bypass",
            "circuit-lookup-table-poisoning",
            "verifier-not-binding-public-input",
            "precompile-incomplete",
            "kzg-malicious-tau",
            "fri-folding-incorrect",
            "circuit-degree-overflow",
        }
        self.assertTrue(required.issubset(classes), f"missing classes: {required - classes}")

    def test_seed_catalogue_volume_in_target_band(self) -> None:
        total = sum(len(seed["components"]) for seed in self.tool.SEED_CATALOGUE)
        # Brief targets ~30-50 but the seed catalogue is intentionally
        # larger to also serve the Wave-4 aggregate floor of 730-1550.
        self.assertGreaterEqual(total, 30)
        self.assertLessEqual(total, 250)

    def test_dsl_to_language_includes_circom_and_rust(self) -> None:
        self.assertIn("circom", self.tool.DSL_TO_LANGUAGE)
        self.assertEqual(self.tool.DSL_TO_LANGUAGE["circom"], "circom")
        self.assertEqual(self.tool.DSL_TO_LANGUAGE["halo2-rust"], "rust")
        self.assertEqual(self.tool.DSL_TO_LANGUAGE["plonky2-rust"], "rust")
        self.assertEqual(self.tool.DSL_TO_LANGUAGE["noir"], "noir")

    # ------------------------------------------------------------------
    # Record building
    # ------------------------------------------------------------------

    def test_extract_records_emits_expected_volume(self) -> None:
        records, counters = self.tool.extract_records()
        self.assertEqual(counters["attack_classes_seen"], len(self.tool.SEED_CATALOGUE))
        self.assertEqual(len(records), counters["components_seen"])
        self.assertGreaterEqual(len(records), 30)

    def test_records_are_unique_by_record_id(self) -> None:
        records, _ = self.tool.extract_records()
        ids = [r["record_id"] for r in records]
        self.assertEqual(len(ids), len(set(ids)), "duplicate record_id collision")

    def test_records_carry_zkbugs_shape_tag(self) -> None:
        records, _ = self.tool.extract_records()
        for record in records:
            tags = record["function_shape"]["shape_tags"]
            self.assertIn(
                "zkbugs",
                tags,
                f"missing zkbugs tag on {record['record_id']}: {tags}",
            )

    def test_records_emit_zk_proof_domain(self) -> None:
        records, _ = self.tool.extract_records()
        for record in records:
            self.assertEqual(record["target_domain"], "zk-proof")

    def test_records_emit_wave4_optional_fields(self) -> None:
        records, _ = self.tool.extract_records()
        for record in records:
            self.assertIn("circuit_shape", record)
            self.assertIn("circuit_dsl", record)
            self.assertIn("proof_system", record)
            self.assertTrue(record["circuit_shape"].endswith("-circuit") or "-zkvm" in record["circuit_shape"])

    def test_records_use_extended_language_enum_where_required(self) -> None:
        records, _ = self.tool.extract_records()
        # At least one circom record should emit target_language="circom"
        # to exercise the Wave-4 schema enum extension.
        circom_records = [r for r in records if r["circuit_dsl"] == "circom"]
        self.assertGreater(len(circom_records), 0)
        for record in circom_records:
            self.assertEqual(record["target_language"], "circom")

    # ------------------------------------------------------------------
    # Schema validity
    # ------------------------------------------------------------------

    def test_all_records_are_schema_valid(self) -> None:
        records, _ = self.tool.extract_records()
        schema = self.validator.load_schema()
        for record in records:
            errors = self.validator.validate_doc(record, schema)
            self.assertEqual(
                errors,
                [],
                f"schema errors on {record['record_id']}: {errors}",
            )

    def test_cli_writes_schema_valid_yaml_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            with contextlib.redirect_stdout(io.StringIO()):
                rc = self.tool.main(["--out-dir", str(out_dir), "--json-summary"])
            self.assertEqual(rc, 0)
            files = sorted(out_dir.glob("*.yaml"))
            self.assertGreaterEqual(len(files), 30)
            schema = self.validator.load_schema()
            for path in files:
                status, errors = self.validator.validate_file(path, schema)
                self.assertEqual(status, "valid", (path, errors))

    # ------------------------------------------------------------------
    # CLI behaviour
    # ------------------------------------------------------------------

    def test_dry_run_does_not_write_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            with contextlib.redirect_stdout(io.StringIO()):
                rc = self.tool.main(["--out-dir", str(out_dir), "--dry-run", "--json-summary"])
            self.assertEqual(rc, 0)
            self.assertFalse(out_dir.exists())

    def test_limit_caps_record_count(self) -> None:
        records, _ = self.tool.extract_records(limit=5)
        self.assertEqual(len(records), 5)

    def test_negative_limit_is_rejected(self) -> None:
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            rc = self.tool.main(["--out-dir", "/tmp/nope", "--limit", "-3"])
        self.assertEqual(rc, 2)

    def test_json_summary_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = self.tool.main(["--out-dir", str(out_dir), "--dry-run", "--json-summary"])
            self.assertEqual(rc, 0)
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload["source_kind"], "zkbugs-catalog")
            self.assertEqual(payload["platform_tag"], "zkbugs")
            self.assertIn("records_emitted", payload)


if __name__ == "__main__":
    unittest.main()
