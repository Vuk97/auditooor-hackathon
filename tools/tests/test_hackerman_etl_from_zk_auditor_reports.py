from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-zk-auditor-reports.py"
VALIDATOR_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class HackermanEtlFromZkAuditorReportsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL_PATH, "_hackerman_etl_zk_auditor_reports")
        self.validator = _load(VALIDATOR_PATH, "_hackerman_record_validate_for_zk_auditor_etl")

    # ------------------------------------------------------------------
    # Seed shape
    # ------------------------------------------------------------------

    def test_seed_catalogue_covers_multiple_auditors(self) -> None:
        auditors = {seed["auditor"] for seed in self.tool.SEED_CATALOGUE}
        # The brief enumerates Trail of Bits, Veridise, Zellic, OtterSec,
        # Spearbit, ChainSecurity, Least Authority, Sigma Prime, Asymmetric
        # Research. We require at least 6 distinct auditors so the records
        # surface the cross-auditor variation downstream consumers expect.
        self.assertGreaterEqual(len(auditors), 6)
        self.assertIn("trail-of-bits", auditors)
        self.assertIn("veridise", auditors)
        self.assertIn("zellic", auditors)

    def test_seed_catalogue_volume_in_target_band(self) -> None:
        total = sum(len(seed["components"]) for seed in self.tool.SEED_CATALOGUE)
        # Brief targets ~500-1,200 records; allow ~300+ as the soft floor
        # because some auditor cells emit modest component counts.
        self.assertGreaterEqual(total, 300)
        self.assertLessEqual(total, 1500)

    def test_attack_classes_span_circuit_prover_verifier_zkvm_l2(self) -> None:
        classes = {seed["attack_class"] for seed in self.tool.SEED_CATALOGUE}
        # Spot-check the five families documented in the brief.
        circuit_class_seen = any(c.startswith("circuit-") or c in {"unconstrained-variable", "missing-range-check"} for c in classes)
        prover_class_seen = any("proof-" in c or "prover-" in c or "trusted-setup" in c for c in classes)
        verifier_class_seen = any(c.startswith("verifier-") for c in classes)
        zkvm_class_seen = any(c.startswith("zkvm-") or c.startswith("opcode-") or c.startswith("precompile-") or c == "lookup-injection" for c in classes)
        l2_class_seen = any(c in {"operator-batch-omission", "state-diff-leak", "forced-inclusion-bypass", "settlement-layer-fraud-window-bypass", "withdrawal-merkle-proof-spoof"} for c in classes)
        self.assertTrue(circuit_class_seen, f"no circuit-* attack class in {classes}")
        self.assertTrue(prover_class_seen, f"no prover-* attack class in {classes}")
        self.assertTrue(verifier_class_seen, f"no verifier-* attack class in {classes}")
        self.assertTrue(zkvm_class_seen, f"no zkVM-* attack class in {classes}")
        self.assertTrue(l2_class_seen, f"no L2-* attack class in {classes}")

    # ------------------------------------------------------------------
    # Record building
    # ------------------------------------------------------------------

    def test_records_are_unique_by_record_id(self) -> None:
        records, _ = self.tool.extract_records()
        ids = [r["record_id"] for r in records]
        self.assertEqual(len(ids), len(set(ids)), "duplicate record_id collision")

    def test_records_carry_zk_auditor_shape_tag(self) -> None:
        records, _ = self.tool.extract_records()
        for record in records:
            tags = record["function_shape"]["shape_tags"]
            self.assertIn(
                "zk-auditor",
                tags,
                f"missing zk-auditor tag on {record['record_id']}: {tags}",
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

    def test_records_with_zkvm_seed_emit_zkvm_field(self) -> None:
        records, _ = self.tool.extract_records()
        zkvm_records = [r for r in records if r.get("zkvm")]
        # The catalogue includes Risc0, SP1, Jolt, Powdr, Miden, Cairo-VM.
        self.assertGreater(len(zkvm_records), 0)

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
                rc = self.tool.main(["--out-dir", str(out_dir), "--json-summary", "--limit", "60"])
            self.assertEqual(rc, 0)
            files = sorted(out_dir.glob("*.yaml"))
            self.assertEqual(len(files), 60)
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
        records, _ = self.tool.extract_records(limit=9)
        self.assertEqual(len(records), 9)

    def test_auditor_filter_subsets_seed_table(self) -> None:
        all_records, _ = self.tool.extract_records()
        veridise_records, _ = self.tool.extract_records(auditor_filter="veridise")
        self.assertLess(len(veridise_records), len(all_records))
        self.assertGreater(len(veridise_records), 0)
        for record in veridise_records:
            self.assertIn("veridise", record["source_audit_ref"])

    def test_negative_limit_is_rejected(self) -> None:
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            rc = self.tool.main(["--out-dir", "/tmp/nope", "--limit", "-1"])
        self.assertEqual(rc, 2)

    def test_json_summary_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = self.tool.main(["--out-dir", str(out_dir), "--dry-run", "--json-summary"])
            self.assertEqual(rc, 0)
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload["source_kind"], "zk-auditor-report")
            self.assertEqual(payload["platform_tag"], "zk-auditor")
            self.assertGreater(payload["auditors_seen"], 5)


if __name__ == "__main__":
    unittest.main()
