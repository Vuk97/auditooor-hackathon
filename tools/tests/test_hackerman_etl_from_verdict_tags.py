from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-verdict-tags.py"
VALIDATOR_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"
FIXTURE_DIR = REPO_ROOT / "tools" / "tests" / "fixtures" / "hackerman_etl_verdict_tags"


def _load_tool():
    spec = importlib.util.spec_from_file_location("_hackerman_etl_from_verdict_tags", str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


def _load_validator():
    spec = importlib.util.spec_from_file_location("_hackerman_record_validate_for_etl", str(VALIDATOR_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class HackermanEtlFromVerdictTagsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()
        self.validator = _load_validator()
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.tag_dir = self.tmp_path / "tags"
        self.out_dir = self.tmp_path / "out"
        self.tag_dir.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _copy_fixture(self, name: str) -> None:
        shutil.copy(FIXTURE_DIR / name, self.tag_dir / name)

    def _load_output_record(self, out_file: str):
        path = self.out_dir / out_file
        return self.validator.load_yaml(path)

    def test_v2_verdict_tag_converts_to_schema_valid_hackerman_record(self) -> None:
        self._copy_fixture("legacy_v2_oracle.yaml")

        summary = self.tool.run_etl(self.tag_dir, self.out_dir)

        self.assertEqual(summary["emitted"], 1)
        out_file = summary["outputs"][0]["out_file"]
        status, errors = self.validator.validate_file(self.out_dir / out_file, self.validator.load_schema())
        self.assertEqual((status, errors), ("valid", []))
        record = self._load_output_record(out_file)
        self.assertEqual(record["source_audit_ref"], "audits/oracle-2025/ORACLE-STALE.md")
        self.assertEqual(record["target_language"], "solidity")
        self.assertEqual(record["target_repo"], "makerdao/dss")
        self.assertEqual(record["target_domain"], "oracle")
        self.assertEqual(record["bug_class"], "oracle-price-stale")
        self.assertEqual(record["attack_class"], "stale-oracle-liquidation")
        self.assertEqual(record["severity_at_finding"], "high")
        self.assertEqual(record["year"], 2025)
        self.assertEqual(record["proof_artifact_path"], "poc_execution/oracle_stale_poc.log")
        self.assertEqual(record["function_shape"]["raw_signature"], "function poke(bytes32 ilk) external")
        self.assertEqual(record["function_shape"]["shape_tags"], ["22222222bbbbbbbb", "11111111aaaaaaaa"])
        self.assertIn("# source_tag_file: legacy_v2_oracle.yaml", (self.out_dir / out_file).read_text(encoding="utf-8"))

    def test_unsafe_poc_path_is_not_promoted_to_proof_artifact_path(self) -> None:
        self.assertEqual(
            self.tool.derive_proof_artifact_path({"poc_path": "https://example.com/poc.log"}),
            "",
        )
        self.assertEqual(
            self.tool.derive_proof_artifact_path({"poc_path": "/tmp/poc.log"}),
            "",
        )

    def test_no_schema_legacy_tag_converts_and_invalid_repo_becomes_unknown(self) -> None:
        self._copy_fixture("legacy_no_schema_bridge.yaml")

        summary = self.tool.run_etl(self.tag_dir, self.out_dir)

        record = self._load_output_record(summary["outputs"][0]["out_file"])
        self.assertEqual(record["target_language"], "go")
        self.assertEqual(record["target_repo"], "unknown")
        self.assertEqual(record["target_domain"], "bridge")
        self.assertEqual(record["attack_class"], "bridge-proof-domain-bypass")
        self.assertEqual(record["severity_at_finding"], "medium")
        self.assertEqual(record["year"], 2024)
        self.assertEqual(record["related_records"], ["base/contracts@1234567:parity-precedent"])

    def test_dry_run_and_limit_plan_without_writing(self) -> None:
        self._copy_fixture("already_hackerman_record.yaml")
        self._copy_fixture("legacy_no_schema_bridge.yaml")
        self._copy_fixture("legacy_v2_oracle.yaml")

        summary = self.tool.run_etl(self.tag_dir, self.out_dir, dry_run=True, limit=1)

        self.assertEqual(summary["emitted"], 1)
        self.assertEqual(summary["skipped"], 1)
        self.assertEqual(summary["outputs"][0]["status"], "planned")
        self.assertFalse(self.out_dir.exists())

    def test_output_is_deterministic(self) -> None:
        self._copy_fixture("legacy_v2_oracle.yaml")

        first = self.tool.run_etl(self.tag_dir, self.out_dir)
        first_file = first["outputs"][0]["out_file"]
        first_text = (self.out_dir / first_file).read_text(encoding="utf-8")
        shutil.rmtree(self.out_dir)
        second = self.tool.run_etl(self.tag_dir, self.out_dir)
        second_file = second["outputs"][0]["out_file"]
        second_text = (self.out_dir / second_file).read_text(encoding="utf-8")

        self.assertEqual(first_file, second_file)
        self.assertEqual(first_text, second_text)

    def test_cli_json_summary(self) -> None:
        self._copy_fixture("legacy_v2_oracle.yaml")
        stdout = io.StringIO()

        with contextlib.redirect_stdout(stdout):
            rc = self.tool.main(
                [
                    "--tag-dir",
                    str(self.tag_dir),
                    "--out-dir",
                    str(self.out_dir),
                    "--dry-run",
                    "--json-summary",
                ]
            )

        self.assertEqual(rc, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["schema_version"], self.tool.SUMMARY_SCHEMA)
        self.assertEqual(payload["outputs"][0]["tag_file"], "legacy_v2_oracle.yaml")


if __name__ == "__main__":
    unittest.main()
