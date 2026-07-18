from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-zk-contests.py"
VALIDATOR_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class HackermanEtlFromZkContestsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL_PATH, "_hackerman_etl_zk_contests")
        self.validator = _load(VALIDATOR_PATH, "_hackerman_record_validate_for_zk_contests_etl")

    # ------------------------------------------------------------------
    # Seed shape
    # ------------------------------------------------------------------

    def test_seed_catalogue_covers_multiple_platforms(self) -> None:
        platforms = {seed["platform"] for seed in self.tool.SEED_CATALOGUE}
        # The brief enumerates Code4rena / Cantina / Sherlock / Immunefi /
        # Hats Finance. We require at least 4 distinct platforms.
        self.assertGreaterEqual(len(platforms), 4)
        self.assertIn("code4rena", platforms)
        self.assertIn("cantina", platforms)

    def test_seed_catalogue_volume_in_target_band(self) -> None:
        total = sum(len(seed["components"]) for seed in self.tool.SEED_CATALOGUE)
        # Brief targets ~200-400; allow ~100+ as soft floor and 800 as ceiling.
        self.assertGreaterEqual(total, 100)
        self.assertLessEqual(total, 800)

    # ------------------------------------------------------------------
    # Record building
    # ------------------------------------------------------------------

    def test_records_are_unique_by_record_id(self) -> None:
        records, _ = self.tool.extract_records()
        ids = [r["record_id"] for r in records]
        self.assertEqual(len(ids), len(set(ids)), "duplicate record_id collision")

    def test_records_carry_zk_contest_shape_tag(self) -> None:
        records, _ = self.tool.extract_records()
        for record in records:
            tags = record["function_shape"]["shape_tags"]
            self.assertIn(
                "zk-contest",
                tags,
                f"missing zk-contest tag on {record['record_id']}: {tags}",
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

    def test_records_reference_real_contest_targets(self) -> None:
        # Sanity: every record's target_repo must look like a real public
        # repo (owner/repo, not empty). Pattern enforced by schema, but
        # we cross-check the public-target intent here.
        records, _ = self.tool.extract_records()
        for record in records:
            repo = record["target_repo"]
            self.assertIn("/", repo, f"non-canonical repo: {repo}")
            owner, name = repo.split("/", 1)
            self.assertTrue(owner and name, f"empty owner/name: {repo}")

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
                rc = self.tool.main(["--out-dir", str(out_dir), "--json-summary", "--limit", "40"])
            self.assertEqual(rc, 0)
            files = sorted(out_dir.glob("*.yaml"))
            self.assertEqual(len(files), 40)
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
        records, _ = self.tool.extract_records(limit=11)
        self.assertEqual(len(records), 11)

    def test_platform_filter_subsets_seed_table(self) -> None:
        all_records, _ = self.tool.extract_records()
        c4_records, _ = self.tool.extract_records(platform_filter="code4rena")
        self.assertLess(len(c4_records), len(all_records))
        self.assertGreater(len(c4_records), 0)
        for record in c4_records:
            self.assertIn("code4rena", record["source_audit_ref"])

    def test_negative_limit_is_rejected(self) -> None:
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            rc = self.tool.main(["--out-dir", "/tmp/nope", "--limit", "-2"])
        self.assertEqual(rc, 2)

    def test_json_summary_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "out"
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = self.tool.main(["--out-dir", str(out_dir), "--dry-run", "--json-summary"])
            self.assertEqual(rc, 0)
            payload = json.loads(buf.getvalue())
            self.assertEqual(payload["source_kind"], "zk-contest-archive")
            self.assertEqual(payload["platform_tag"], "zk-contest")
            self.assertGreater(payload["platforms_seen"], 3)


if __name__ == "__main__":
    unittest.main()
