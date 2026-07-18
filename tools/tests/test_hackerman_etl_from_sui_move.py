from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-sui-move.py"
VALIDATOR_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class HackermanEtlFromSuiMoveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL_PATH, "_hackerman_etl_from_sui_move")
        self.validator = _load(VALIDATOR_PATH, "_hackerman_record_validate_for_sui_move_etl")

    # ------------------------------------------------------------------
    # Seed catalogue shape
    # ------------------------------------------------------------------

    def test_seed_catalogue_covers_six_sui_specific_attack_classes(self) -> None:
        classes = {seed["attack_class"] for seed in self.tool.SEED_CATALOGUE}
        expected = {
            "object-id-spoof",
            "object-mutation-without-mutref",
            "ability-escalation-via-key-store",
            "dynamic-field-collision",
            "shared-vs-owned-object-confusion",
            "display-spoofing-by-publish-rights",
        }
        self.assertEqual(classes, expected)

    def test_seed_catalogue_component_count_in_target_band(self) -> None:
        total = sum(len(seed["components"]) for seed in self.tool.SEED_CATALOGUE)
        # Brief specifies 80-120 records target.
        self.assertGreaterEqual(total, 80)
        self.assertLessEqual(total, 120)

    def test_target_language_is_canonical_move(self) -> None:
        # Schema enum uses `move`; Sui-vs-Aptos lives in shape_tags / target_repo.
        self.assertEqual(self.tool.TARGET_LANGUAGE, "move")
        self.assertEqual(self.tool.SHAPE_PLATFORM_TAG, "sui-move")

    # ------------------------------------------------------------------
    # Record building
    # ------------------------------------------------------------------

    def test_extract_records_emits_expected_volume(self) -> None:
        records, counters = self.tool.extract_records()
        self.assertEqual(counters["attack_classes_seen"], 6)
        self.assertEqual(len(records), counters["components_seen"])
        self.assertGreaterEqual(len(records), 80)
        self.assertLessEqual(len(records), 120)

    def test_records_are_unique_by_record_id(self) -> None:
        records, _ = self.tool.extract_records()
        ids = [r["record_id"] for r in records]
        self.assertEqual(len(ids), len(set(ids)), "duplicate record_id collision")

    def test_records_carry_sui_move_shape_tag(self) -> None:
        records, _ = self.tool.extract_records()
        for record in records:
            tags = record["function_shape"]["shape_tags"]
            self.assertIn(
                "sui-move",
                tags,
                f"missing sui-move shape tag on {record['record_id']}: {tags}",
            )

    def test_records_use_move_language_enum(self) -> None:
        records, _ = self.tool.extract_records()
        for record in records:
            self.assertEqual(record["target_language"], "move")

    def test_records_reference_real_sui_repos(self) -> None:
        # Sui-specificity check: every target_repo must reference a recognisable
        # Sui org / package; this is the structural distinction from Aptos.
        recognisable = (
            "MystenLabs/",
            "scallop-io/",
            "naviprotocol/",
            "CetusProtocol/",
            "turbos-finance/",
            "AftermathFinance/",
            "kriya-dex/",
            "Typus-Lab/",
            "wormhole-foundation/",
        )
        records, _ = self.tool.extract_records()
        for record in records:
            repo = record["target_repo"]
            self.assertTrue(
                repo.startswith(recognisable),
                f"{repo!r} does not look like a Sui-ecosystem repo",
            )

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
                rc = self.tool.main(
                    ["--out-dir", str(out_dir), "--json-summary"]
                )
            self.assertEqual(rc, 0)
            files = sorted(out_dir.glob("*.yaml"))
            self.assertGreaterEqual(len(files), 80)
            self.assertLessEqual(len(files), 120)

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
                rc = self.tool.main(
                    ["--out-dir", str(out_dir), "--dry-run", "--json-summary"]
                )
            self.assertEqual(rc, 0)
            self.assertFalse(out_dir.exists())

    def test_limit_caps_record_count(self) -> None:
        records, _ = self.tool.extract_records(limit=7)
        self.assertEqual(len(records), 7)

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
                rc = self.tool.main(
                    ["--out-dir", str(out_dir), "--dry-run", "--json-summary"]
                )
            self.assertEqual(rc, 0)
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload["target_language"], "move")
            self.assertEqual(payload["platform_tag"], "sui-move")
            self.assertEqual(payload["attack_classes_seen"], 6)
            self.assertIn("records_emitted", payload)
            self.assertIn("files", payload)


if __name__ == "__main__":
    unittest.main()
