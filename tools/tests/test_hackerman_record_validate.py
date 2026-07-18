from __future__ import annotations

import copy
import importlib.util
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-record-validate.py"
FIXTURE_DIR = REPO_ROOT / "tools" / "tests" / "fixtures" / "hackerman_records"


def _load_tool():
    spec = importlib.util.spec_from_file_location("_hackerman_record_validate", str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class HackermanRecordValidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()
        self.schema = self.tool.load_schema()

    def _load_valid_record(self) -> dict[str, object]:
        return copy.deepcopy(self.tool.load_yaml(FIXTURE_DIR / "valid_lending_share_inflation.yaml"))

    def test_valid_hackerman_record_passes(self) -> None:
        status, errors = self.tool.validate_file(
            FIXTURE_DIR / "valid_lending_share_inflation.yaml",
            self.schema,
        )
        self.assertEqual(status, "valid")
        self.assertEqual(errors, [])

    def test_proof_artifact_path_accepts_relative_local_path(self) -> None:
        doc = self._load_valid_record()
        doc["proof_artifact_path"] = "poc_execution/foo.log"

        errors = self.tool.validate_doc(doc, self.schema)

        self.assertEqual(errors, [])

    def test_proof_artifact_path_rejects_url_and_absolute_path(self) -> None:
        for bad_path in ("https://example.com/foo.log", "/tmp/foo.log"):
            with self.subTest(bad_path=bad_path):
                doc = self._load_valid_record()
                doc["proof_artifact_path"] = bad_path

                errors = self.tool.validate_doc(doc, self.schema)

                self.assertTrue(errors, errors)
                self.assertTrue(any("proof_artifact_path" in err for err in errors), errors)

    def test_missing_required_field_fails(self) -> None:
        status, errors = self.tool.validate_file(
            FIXTURE_DIR / "invalid_missing_attack_class.yaml",
            self.schema,
        )
        self.assertEqual(status, "invalid")
        self.assertTrue(any("attack_class" in err for err in errors), errors)

    def test_legacy_verdict_tag_is_skipped_by_default(self) -> None:
        status, errors = self.tool.validate_file(
            FIXTURE_DIR / "legacy_verdict_tag.yaml",
            self.schema,
        )
        self.assertEqual(status, "skipped")
        self.assertEqual(errors, [])

    def test_strict_all_validates_legacy_and_fails(self) -> None:
        status, errors = self.tool.validate_file(
            FIXTURE_DIR / "legacy_verdict_tag.yaml",
            self.schema,
            strict_all=True,
        )
        self.assertEqual(status, "invalid")
        self.assertTrue(any("schema_version" in err for err in errors), errors)

    def test_cli_directory_succeeds_when_only_invalid_file_is_excluded(self) -> None:
        rc = self.tool.main(
            [
                "--validate",
                str(FIXTURE_DIR / "valid_lending_share_inflation.yaml"),
                "--validate",
                str(FIXTURE_DIR / "legacy_verdict_tag.yaml"),
                "--quiet",
            ]
        )
        self.assertEqual(rc, 0)


class HackermanRecordValidateV1_1Tests(unittest.TestCase):
    """Wave-2 v1.1 schema dispatch coverage.

    Verifies that the validator auto-selects the v1.1 schema for records
    declaring ``schema_version: auditooor.hackerman_record.v1.1`` while
    leaving v1 behaviour unchanged (backward-compat).
    """

    def setUp(self) -> None:
        self.tool = _load_tool()

    def _load_valid_v1_1_record(self) -> dict[str, object]:
        return copy.deepcopy(
            self.tool.load_yaml(FIXTURE_DIR / "valid_v1_1_lending_share_inflation.yaml")
        )

    def test_resolve_schema_path_picks_v1_for_v1_records(self) -> None:
        path = self.tool.resolve_schema_path({"schema_version": "auditooor.hackerman_record.v1"})
        self.assertEqual(path, self.tool.DEFAULT_SCHEMA_PATH_V1)

    def test_resolve_schema_path_picks_v1_1_for_v1_1_records(self) -> None:
        path = self.tool.resolve_schema_path({"schema_version": "auditooor.hackerman_record.v1.1"})
        self.assertEqual(path, self.tool.DEFAULT_SCHEMA_PATH_V1_1)

    def test_resolve_schema_path_falls_back_to_v1_for_unknown(self) -> None:
        path = self.tool.resolve_schema_path({"schema_version": "auditooor.something_else"})
        self.assertEqual(path, self.tool.DEFAULT_SCHEMA_PATH_V1)

    def test_is_hackerman_record_accepts_v1_1(self) -> None:
        self.assertTrue(
            self.tool.is_hackerman_record({"schema_version": "auditooor.hackerman_record.v1.1"})
        )

    def test_is_hackerman_record_still_accepts_v1(self) -> None:
        self.assertTrue(
            self.tool.is_hackerman_record({"schema_version": "auditooor.hackerman_record.v1"})
        )

    def test_is_hackerman_record_rejects_unknown(self) -> None:
        self.assertFalse(
            self.tool.is_hackerman_record({"schema_version": "auditooor.hackerman_record.v2"})
        )

    def test_valid_v1_1_record_passes_with_auto_dispatch(self) -> None:
        # schema=None forces auto-dispatch off schema_version.
        status, errors = self.tool.validate_file(
            FIXTURE_DIR / "valid_v1_1_lending_share_inflation.yaml",
            schema=None,
        )
        self.assertEqual(status, "valid", errors)
        self.assertEqual(errors, [])

    def test_validate_doc_auto_selects_v1_1_when_schema_omitted(self) -> None:
        doc = self._load_valid_v1_1_record()
        errors = self.tool.validate_doc(doc)
        self.assertEqual(errors, [])

    def test_v1_1_fields_rejected_under_v1_schema(self) -> None:
        # Force the v1 schema explicitly; v1.1-only fields must fail.
        doc = self._load_valid_v1_1_record()
        v1_schema = self.tool.load_schema(self.tool.DEFAULT_SCHEMA_PATH_V1)
        errors = self.tool.validate_doc(doc, v1_schema)
        self.assertTrue(errors, "expected v1.1-only fields to be rejected under v1 schema")
        # v1 schema_version enum does not include v1.1; auto + properties enforce
        # additionalProperties:false on the new top-level fields.
        joined = " ".join(errors)
        self.assertTrue(
            "schema_version" in joined or "verification_tier" in joined,
            errors,
        )

    def test_v1_records_still_validate_under_auto_dispatch(self) -> None:
        # Backward-compat: a v1 record must still validate when the
        # validator is invoked without an explicit schema (auto-dispatch).
        status, errors = self.tool.validate_file(
            FIXTURE_DIR / "valid_lending_share_inflation.yaml",
            schema=None,
        )
        self.assertEqual(status, "valid", errors)
        self.assertEqual(errors, [])

    def test_invalid_v1_1_record_with_bad_verification_tier_fails(self) -> None:
        status, errors = self.tool.validate_file(
            FIXTURE_DIR / "invalid_v1_1_bad_verification_tier.yaml",
            schema=None,
        )
        self.assertEqual(status, "invalid")
        self.assertTrue(any("verification_tier" in err for err in errors), errors)

    def test_invalid_v1_1_record_with_bad_cve_id_fails(self) -> None:
        doc = self._load_valid_v1_1_record()
        doc["cve_id"] = "NOT-A-CVE"
        errors = self.tool.validate_doc(doc)
        self.assertTrue(errors)
        self.assertTrue(any("cve_id" in err for err in errors), errors)

    def test_invalid_v1_1_record_with_bad_ghsa_id_fails(self) -> None:
        doc = self._load_valid_v1_1_record()
        doc["ghsa_id"] = "GHSA-bad"
        errors = self.tool.validate_doc(doc)
        self.assertTrue(errors)
        self.assertTrue(any("ghsa_id" in err for err in errors), errors)

    def test_cli_auto_dispatch_mixed_v1_and_v1_1_succeeds(self) -> None:
        rc = self.tool.main(
            [
                "--validate",
                str(FIXTURE_DIR / "valid_lending_share_inflation.yaml"),
                "--validate",
                str(FIXTURE_DIR / "valid_v1_1_lending_share_inflation.yaml"),
                "--quiet",
            ]
        )
        self.assertEqual(rc, 0)

    def test_cli_forced_schema_path_still_honoured(self) -> None:
        # Forcing --schema-path bypasses auto-dispatch (legacy behaviour).
        # Validating a v1.1 record under the v1 schema must fail.
        rc = self.tool.main(
            [
                "--validate",
                str(FIXTURE_DIR / "valid_v1_1_lending_share_inflation.yaml"),
                "--schema-path",
                str(self.tool.DEFAULT_SCHEMA_PATH_V1),
                "--quiet",
            ]
        )
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
