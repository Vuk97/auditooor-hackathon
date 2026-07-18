"""Tests for tools/source-read-parity-check.py (B6 Codex/source-read parity).

>=7 cases covering:
  1. Manifest entry with linked hacker-question artifact -> PASS
  2. Manifest entry with NO_HACKER_QUESTIONS reason     -> PASS
  3. Manifest entry reviewing a source file with neither -> FAIL
  4. --strict exits non-zero on fail rows
  5. GENERATE mode produces a card artifact (mocked injector)
  6. Parser-gap extension auto-accepted as NO_HACKER_QUESTIONS
  7. JSON output carries required schema fields
  8. Missing manifest file -> error row (defensive)
  9. Non-source-file entries skipped gracefully
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "source-read-parity-check.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("_srpc_tool", str(TOOL_PATH))
    assert spec and spec.loader, f"cannot load {TOOL_PATH}"
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_srpc_tool"] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


def _write_manifest(directory: Path, name: str, entries: list) -> Path:
    """Write a JSON manifest file with a list of entries."""
    p = directory / name
    p.write_text(json.dumps(entries, indent=2), encoding="utf-8")
    return p


class TestCheckModePass(unittest.TestCase):
    """Test 1: Manifest entry with a linked hacker-question artifact -> PASS."""

    def test_linked_artifact_pass(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            # Create a fake artifact file on disk
            artifact = td_path / "contract.sol.hacker_questions.json"
            artifact.write_text(json.dumps({"schema": "auditooor.pre_source_read_injection.v1"}))

            entries = [
                {
                    "source_file": "contracts/contract.sol",
                    "hacker_questions_artifact": str(artifact),
                }
            ]
            mf = td_path / "review_manifest.json"
            mf.write_text(json.dumps(entries))

            report = tool.check_workspace(manifest_path=mf)
            rows = [r for r in report["rows"] if r["verdict"] != "skip_not_source"]
            self.assertTrue(any(r["verdict"] == "pass_hq_linked" for r in rows),
                            f"expected pass_hq_linked, got {rows}")
            self.assertEqual(report["summary"]["gate"], "PASS")


class TestCheckModeNoHQReason(unittest.TestCase):
    """Test 2: Manifest entry with NO_HACKER_QUESTIONS reason -> PASS."""

    def test_no_hq_reason_pass(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            entries = [
                {
                    "source_file": "src/keeper.go",
                    "no_hacker_questions": "operator_override",
                }
            ]
            mf = td_path / "manifest.json"
            mf.write_text(json.dumps(entries))
            report = tool.check_workspace(manifest_path=mf)
            rows = [r for r in report["rows"] if r["verdict"] != "skip_not_source"]
            self.assertTrue(any(r["verdict"] == "pass_no_hq" for r in rows),
                            f"expected pass_no_hq, got {rows}")
            self.assertEqual(report["summary"]["gate"], "PASS")


class TestCheckModeFail(unittest.TestCase):
    """Test 3: Manifest entry reviewing a source file with no parity -> FAIL."""

    def test_missing_parity_fail(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            entries = [
                {
                    "source_file": "contracts/Vault.sol",
                    "reviewed_at": "2026-05-22",
                    # No hacker_questions_artifact, no no_hacker_questions
                }
            ]
            mf = td_path / "manifest.json"
            mf.write_text(json.dumps(entries))
            report = tool.check_workspace(manifest_path=mf)
            fail_rows = [r for r in report["rows"] if r["verdict"] == "fail_missing"]
            self.assertTrue(len(fail_rows) >= 1,
                            f"expected at least one fail_missing row, got {report['rows']}")
            self.assertEqual(report["summary"]["gate"], "FAIL")
            self.assertGreater(report["summary"]["fail"], 0)


class TestStrictModeExit(unittest.TestCase):
    """Test 4: --strict exits non-zero when FAIL rows are present."""

    def test_strict_nonzero_on_fail(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            entries = [{"source_file": "module/handler.go"}]
            mf = td_path / "manifest.json"
            mf.write_text(json.dumps(entries))
            rc = tool.main(["--manifest", str(mf), "--strict"])
            self.assertNotEqual(rc, 0, "strict mode should return non-zero on FAIL")

    def test_strict_zero_on_pass(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            entries = [
                {
                    "source_file": "module/handler.go",
                    "no_hacker_questions": "test_file",
                }
            ]
            mf = td_path / "manifest.json"
            mf.write_text(json.dumps(entries))
            rc = tool.main(["--manifest", str(mf), "--strict"])
            self.assertEqual(rc, 0, "strict mode should return 0 on PASS")


class TestGenerateMode(unittest.TestCase):
    """Test 5: GENERATE mode produces a card artifact (mocked injector subprocess)."""

    def test_generate_writes_artifact(self):
        fake_payload = {
            "schema": "auditooor.pre_source_read_injection.v1",
            "functions_analyzed": 0,
            "skipped_reasons": ["no-parser-for-python"],
            "summary": {"hacker_question_count": 0},
        }

        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            # Write a fake source file
            src = td_path / "contract.sol"
            src.write_text("pragma solidity ^0.8.0;\ncontract Vault {}\n")

            out = td_path / "contract.sol.hacker_questions.json"

            # Patch subprocess.run to return our fake payload
            with patch("subprocess.run") as mock_run:
                mock_proc = MagicMock()
                mock_proc.returncode = 0
                mock_proc.stdout = json.dumps(fake_payload)
                mock_run.return_value = mock_proc

                result = tool.generate_hacker_question_card(src, out_path=out)

            self.assertIsNone(result.get("error"), f"unexpected error: {result.get('error')}")
            self.assertEqual(result["artifact_path"], str(out))
            self.assertTrue(out.is_file(), "artifact file should exist on disk")
            written = json.loads(out.read_text())
            self.assertEqual(written["schema"], "auditooor.pre_source_read_injection.v1")

    def test_generate_missing_source(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "nonexistent.sol"
            result = tool.generate_hacker_question_card(src)
            self.assertIsNotNone(result.get("error"))
            self.assertIn("not found", result["error"])


class TestParserGapAutoAccept(unittest.TestCase):
    """Test 6: Parser-gap extension (.ts, .py) auto-accepted."""

    def test_ts_file_auto_parser_gap(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            entries = [
                {
                    "source_file": "src/index.ts",
                    # No HQ artifact, no no_hacker_questions - but .ts is auto-accepted
                }
            ]
            mf = td_path / "manifest.json"
            mf.write_text(json.dumps(entries))
            report = tool.check_workspace(manifest_path=mf)
            rows = [r for r in report["rows"] if r["source_file"].endswith(".ts")]
            self.assertTrue(any(r["verdict"] == "pass_parser_gap" for r in rows),
                            f"expected pass_parser_gap for .ts, got {rows}")
            self.assertEqual(report["summary"]["gate"], "PASS")

    def test_py_file_auto_parser_gap(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            entries = [{"source_file": "tools/helper.py"}]
            mf = td_path / "manifest.json"
            mf.write_text(json.dumps(entries))
            report = tool.check_workspace(manifest_path=mf)
            rows = [r for r in report["rows"] if r["source_file"].endswith(".py")]
            self.assertTrue(any(r["verdict"] == "pass_parser_gap" for r in rows),
                            f"expected pass_parser_gap for .py, got {rows}")


class TestJsonSchemaFields(unittest.TestCase):
    """Test 7: JSON output carries required schema fields."""

    def test_check_json_schema_fields(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            entries = [{"source_file": "pkg/msg_server.go", "no_hacker_questions": "test_file"}]
            mf = td_path / "manifest.json"
            mf.write_text(json.dumps(entries))
            report = tool.check_workspace(manifest_path=mf)
            self.assertEqual(report["schema"], tool.SCHEMA_ID)
            self.assertIn("mode", report)
            self.assertIn("checked_at_utc", report)
            self.assertIn("rows", report)
            self.assertIn("summary", report)
            summary = report["summary"]
            for key in ("total_rows", "pass", "fail", "gate", "verdict_counts"):
                self.assertIn(key, summary, f"missing summary key: {key}")

    def test_generate_json_schema_fields(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            src = td_path / "vault.sol"
            src.write_text("pragma solidity ^0.8.0;\n")

            fake_payload = {
                "schema": "auditooor.pre_source_read_injection.v1",
                "functions_analyzed": 0,
                "summary": {"hacker_question_count": 0},
                "skipped_reasons": [],
            }
            with patch("subprocess.run") as mock_run:
                mock_proc = MagicMock()
                mock_proc.returncode = 0
                mock_proc.stdout = json.dumps(fake_payload)
                mock_run.return_value = mock_proc

                result = tool.generate_hacker_question_card(src)

            self.assertEqual(result["schema"], tool.SCHEMA_ID)
            self.assertIn("mode", result)
            self.assertIn("source_file", result)
            self.assertIn("generated_at_utc", result)
            self.assertIn("artifact_path", result)
            self.assertIn("payload", result)


class TestMissingManifest(unittest.TestCase):
    """Test 8: Missing manifest file -> error row (defensive, no crash)."""

    def test_missing_manifest_error_row(self):
        report = tool.check_workspace(manifest_path=Path("/nonexistent/review.json"))
        self.assertTrue(len(report["rows"]) >= 1)
        error_rows = [r for r in report["rows"] if r["verdict"] == "error"]
        self.assertTrue(len(error_rows) >= 1, f"expected error row, got {report['rows']}")
        # Tool should not crash -- gate is FAIL but graceful
        self.assertEqual(report["summary"]["gate"], "FAIL")


class TestNonSourceFilesSkipped(unittest.TestCase):
    """Test 9: Non-source-file entries skipped gracefully."""

    def test_non_source_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            entries = [
                {"source_file": "docs/README.md"},           # .md -> skip
                {"file_path": "reports/analysis.json"},       # .json -> skip
                {"source_file": "src/keeper.go", "no_hacker_questions": "test_file"},  # go -> pass
            ]
            mf = td_path / "manifest.json"
            mf.write_text(json.dumps(entries))
            report = tool.check_workspace(manifest_path=mf)
            # Only the .go file should produce a non-skip row
            non_skip = [r for r in report["rows"] if r["verdict"] != "skip_not_source"]
            self.assertEqual(len(non_skip), 1, f"expected 1 non-skip row, got {non_skip}")
            self.assertEqual(non_skip[0]["verdict"], "pass_no_hq")


class TestMixedManifest(unittest.TestCase):
    """Test 10: Mixed manifest with some passing and some failing entries."""

    def test_mixed_pass_fail(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            # Create a real artifact file for the linked case
            artifact = td_path / "good.sol.hacker_questions.json"
            artifact.write_text(json.dumps({"schema": "auditooor.pre_source_read_injection.v1"}))

            entries = [
                {
                    "source_file": "contracts/Good.sol",
                    "hacker_questions_artifact": str(artifact),
                },
                {
                    "source_file": "contracts/Bad.sol",
                    # No artifact, no NO_HACKER_QUESTIONS
                },
                {
                    "source_file": "pkg/util.go",
                    "no_hacker_questions": "parser_gap",
                },
            ]
            mf = td_path / "manifest.json"
            mf.write_text(json.dumps(entries))
            report = tool.check_workspace(manifest_path=mf)

            verdicts = {r["source_file"]: r["verdict"] for r in report["rows"]}
            self.assertEqual(verdicts.get("contracts/Good.sol"), "pass_hq_linked")
            self.assertEqual(verdicts.get("contracts/Bad.sol"), "fail_missing")
            self.assertEqual(verdicts.get("pkg/util.go"), "pass_no_hq")
            self.assertEqual(report["summary"]["gate"], "FAIL")
            self.assertEqual(report["summary"]["pass"], 2)
            self.assertEqual(report["summary"]["fail"], 1)


class TestLinkedArtifactMissingOnDisk(unittest.TestCase):
    """Test 11: Linked artifact key present but file does not exist -> FAIL."""

    def test_linked_artifact_file_missing(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            entries = [
                {
                    "source_file": "contracts/Token.sol",
                    "hacker_questions_artifact": "/nonexistent/path/cards.json",
                }
            ]
            mf = td_path / "manifest.json"
            mf.write_text(json.dumps(entries))
            report = tool.check_workspace(manifest_path=mf)
            rows = [r for r in report["rows"] if r["source_file"].endswith(".sol")]
            self.assertTrue(any(r["verdict"] == "fail_missing" for r in rows),
                            f"expected fail_missing for missing artifact file, got {rows}")
            self.assertEqual(report["summary"]["gate"], "FAIL")


if __name__ == "__main__":
    unittest.main()
