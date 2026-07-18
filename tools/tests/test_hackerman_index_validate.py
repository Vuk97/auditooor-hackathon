"""Wave-2 PR-A: tests for ``tools/hackerman-index-validate.py``."""
from __future__ import annotations

import importlib.util
import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-index-validate.py"
BUILD_TOOL_PATH = REPO_ROOT / "tools" / "hackerman-index-build.py"
FIXTURE_DIR = REPO_ROOT / "tools" / "tests" / "fixtures" / "hackerman_records"


def _load(path: Path, mod_name: str):
    spec = importlib.util.spec_from_file_location(mod_name, str(path))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class HackermanIndexValidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load(TOOL_PATH, "_hackerman_index_validate")
        self.build_tool = _load(BUILD_TOOL_PATH, "_hackerman_index_build_for_validate")
        self.tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.tmp.name)
        self.tag_dir = self.tmp_path / "tags"
        self.index_dir = self.tmp_path / "index"
        self.tag_dir.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _seed_corpus(self) -> None:
        # ``valid_lending_share_inflation`` (v1) and the v1.1 sibling share a
        # record_id; load only the v1.1 variant so the duplicate-record-id
        # guard does not fire while we still exercise both schema dispatch
        # paths via valid_go_fee_bypass (v1).
        for name in (
            "valid_go_fee_bypass.yml",
            "valid_v1_1_lending_share_inflation.yaml",
        ):
            shutil.copy(FIXTURE_DIR / name, self.tag_dir / name)
        self.build_tool.build_indices(self.tag_dir, self.index_dir, preserve_existing=False)

    def test_clean_corpus_passes(self) -> None:
        self._seed_corpus()
        verdict = self.tool.validate_indexes(self.index_dir)
        self.assertEqual(verdict["verdict"], "pass", verdict)
        self.assertEqual(verdict["missing_indexes"], [])
        self.assertEqual(verdict["errors"], [])
        self.assertTrue(verdict["root_manifest"]["present"])
        self.assertRegex(verdict["root_manifest"]["corpus_index_hash"], r"^[0-9a-f]{64}$")
        # All 16 canonical indexes should be present and reported.
        self.assertEqual(
            sorted(verdict["indexes"].keys()),
            sorted(self.build_tool.INDEX_NAMES),
        )

    def test_missing_index_dir_fails(self) -> None:
        verdict = self.tool.validate_indexes(self.tmp_path / "does-not-exist")
        self.assertEqual(verdict["verdict"], "fail")
        codes = [err["code"] for err in verdict["errors"]]
        self.assertIn("index-dir-missing", codes)

    def test_missing_index_file_fails(self) -> None:
        self._seed_corpus()
        # Remove one monolith and verify it surfaces as missing.
        (self.index_dir / "by_cve_id.jsonl").unlink()
        verdict = self.tool.validate_indexes(self.index_dir)
        self.assertEqual(verdict["verdict"], "fail")
        self.assertIn("by_cve_id", verdict["missing_indexes"])

    def test_malformed_row_fails(self) -> None:
        self._seed_corpus()
        # Append a malformed line to a monolith index.
        target = self.index_dir / "by_attack_class.jsonl"
        with target.open("a", encoding="utf-8") as fh:
            fh.write("not-json\n")
        verdict = self.tool.validate_indexes(self.index_dir)
        self.assertEqual(verdict["verdict"], "fail")
        codes = [err["code"] for err in verdict["errors"]]
        self.assertIn("json-decode-error", codes)

    def test_sharded_manifest_rows_mismatch_fails(self) -> None:
        self._seed_corpus()
        manifest_path = self.index_dir / "by_function_shape.d" / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["rows"] = manifest.get("rows", 0) + 9999
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        verdict = self.tool.validate_indexes(self.index_dir)
        self.assertEqual(verdict["verdict"], "fail")
        codes = [err["code"] for err in verdict["errors"]]
        self.assertIn("manifest-rows-mismatch", codes)

    def test_sharded_manifest_schema_mismatch_fails(self) -> None:
        self._seed_corpus()
        manifest_path = self.index_dir / "by_function_shape.d" / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["schema"] = "auditooor.hackerman_index_shards.v0-bogus"
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        verdict = self.tool.validate_indexes(self.index_dir)
        self.assertEqual(verdict["verdict"], "fail")
        codes = [err["code"] for err in verdict["errors"]]
        self.assertIn("manifest-schema-mismatch", codes)

    def test_unknown_index_listed_but_not_a_failure(self) -> None:
        self._seed_corpus()
        # An unexpected by_extra.jsonl should be reported but not fail the verdict
        # (treated as forward-compat / experimental surface).
        (self.index_dir / "by_extra.jsonl").write_text(
            json.dumps({"key": "x", "record_id": "x"}, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        verdict = self.tool.validate_indexes(self.index_dir)
        self.assertIn("by_extra", verdict["unknown_indexes"])
        self.assertEqual(verdict["verdict"], "pass")

    def test_validate_fails_stale_root_manifest_after_valid_index_mutation(self) -> None:
        self._seed_corpus()
        target = self.index_dir / "by_attack_class.jsonl"
        with target.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"key": "extra", "record_id": "extra"}, sort_keys=True) + "\n")

        verdict = self.tool.validate_indexes(self.index_dir)

        self.assertEqual(verdict["verdict"], "fail")
        codes = [err["code"] for err in verdict["errors"]]
        self.assertIn("root-manifest-files-mismatch", codes)
        self.assertIn("root-manifest-hash-mismatch", codes)

    def test_validate_fails_root_manifest_schema_filecount_or_sha_mismatch(self) -> None:
        self._seed_corpus()
        manifest_path = self.index_dir / "manifest.json"

        cases = [
            ("schema", "auditooor.hackerman_index_manifest.v0", "root-manifest-schema-mismatch"),
            ("file_count", 9999, "root-manifest-filecount-mismatch"),
            ("sha256", "0" * 64, "root-manifest-files-mismatch"),
            ("corpus_index_hash", "0" * 64, "root-manifest-hash-mismatch"),
        ]
        for field, value, expected_code in cases:
            with self.subTest(field=field):
                self._seed_corpus()
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                if field == "sha256":
                    manifest["files"][0]["sha256"] = value
                else:
                    manifest[field] = value
                manifest_path.write_text(
                    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )

                verdict = self.tool.validate_indexes(self.index_dir)

                self.assertEqual(verdict["verdict"], "fail")
                codes = [err["code"] for err in verdict["errors"]]
                self.assertIn(expected_code, codes)

    def test_cli_main_returns_zero_on_clean(self) -> None:
        self._seed_corpus()
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = self.tool.main(["--index-dir", str(self.index_dir), "--summary-only"])
        self.assertEqual(rc, 0)
        self.assertIn("indexes present", buf.getvalue())

    def test_cli_main_returns_nonzero_on_missing(self) -> None:
        self._seed_corpus()
        (self.index_dir / "by_cve_id.jsonl").unlink()
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = self.tool.main(["--index-dir", str(self.index_dir), "--quiet"])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
