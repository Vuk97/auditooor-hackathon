from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-etl-from-git-mining.py"
VALIDATOR_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"
FIXTURE_REPORTS = REPO_ROOT / "tools" / "tests" / "fixtures" / "hackerman_etl_from_git_mining" / "reports"


def _load_module(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HackermanGitMiningEtlTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.etl = _load_module("_hackerman_etl_from_git_mining", TOOL_PATH)
        cls.validator = _load_module("_hackerman_record_validate_for_git_etl", VALIDATOR_PATH)
        cls.schema = cls.validator.load_schema()

    def test_writes_schema_valid_records_with_git_source_refs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = pathlib.Path(tmp)
            summary = self.etl.convert_reports(FIXTURE_REPORTS, out_dir)

            self.assertEqual(summary["records"], 2)
            files = sorted(out_dir.glob("*.yaml"))
            self.assertEqual(len(files), 2)
            self.assertEqual(
                [p.name for p in files],
                [
                    "git-mining-example-protocol-vault-aaaaaaaaaaaa-role-overscope-on-destructive-submit-eae77288.yaml",
                    "git-mining-example-protocol-vault-bbbbbbbbbbbb-upgrade-storage-d5658ca6.yaml",
                ],
            )

            records = [self.validator.load_yaml(path) for path in files]
            for path, record in zip(files, records):
                errors = self.validator.validate_doc(record, self.schema)
                self.assertEqual(errors, [], f"{path} failed validation: {errors}")
                self.assertEqual(record["schema_version"], "auditooor.hackerman_record.v1")
                self.assertEqual(record["target_repo"], "example/protocol-vault")
                self.assertEqual(record["target_language"], "solidity")
                self.assertTrue(record["source_audit_ref"].startswith("git-mining:tools/tests/fixtures/"))

            access_record = records[0]
            self.assertEqual(access_record["bug_class"], "role-overscope-on-destructive-submit")
            self.assertEqual(access_record["attack_class"], "privileged-role-abuse")
            self.assertEqual(
                access_record["function_shape"]["raw_signature"],
                "function submitBurnShares(uint256 shares) external",
            )
            self.assertIn("site:contracts/adapters/VaultAdapter.sol", access_record["function_shape"]["shape_tags"])
            self.assertIn(
                "pattern:sol.access_control.role_overscope_on_destructive_submit",
                access_record["function_shape"]["shape_tags"],
            )

    def test_limit_and_dry_run_do_not_write_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = pathlib.Path(tmp)
            summary = self.etl.convert_reports(FIXTURE_REPORTS, out_dir, dry_run=True, limit=1)

            self.assertEqual(summary["records"], 1)
            self.assertTrue(summary["dry_run"])
            self.assertEqual(summary["files_written"], [])
            self.assertEqual(len(summary["files_planned"]), 1)
            self.assertEqual(list(out_dir.glob("*.yaml")), [])

    def test_cli_json_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            stdout = io.StringIO()
            argv = [
                "--reports-dir",
                str(FIXTURE_REPORTS),
                "--out-dir",
                tmp,
                "--limit",
                "1",
                "--json-summary",
            ]
            with contextlib.redirect_stdout(stdout):
                rc = self.etl.main(argv)

            self.assertEqual(rc, 0)
            summary = json.loads(stdout.getvalue())
            self.assertEqual(summary["records"], 1)
            self.assertEqual(summary["reports_scanned"], 1)


if __name__ == "__main__":
    unittest.main()
