#!/usr/bin/env python3
"""Tests for tools/scanner-autonomy-semantic-repair.py."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "scanner-autonomy-semantic-repair.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("scanner_autonomy_semantic_repair", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ScannerAutonomySemanticRepairTests(unittest.TestCase):
    def test_terminal_semantic_rows_get_exact_next_commands(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            execution = Path(tmp) / "execution.json"
            execution.write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "source_id": "SSI-FIX-VULN",
                                "status": "terminal_vulnerable_fixture_no_detector_hit",
                                "argv": ["python3", "tool.py", "--pattern", "vulnerable-no-hit"],
                            },
                            {
                                "source_id": "SSI-FIX-CLEAN",
                                "status": "terminal_clean_fixture_false_positive",
                                "argv": ["python3", "tool.py", "--pattern", "clean-false-positive"],
                            },
                            {
                                "source_id": "SSI-FIX-GUARD",
                                "status": "terminal_fixture_pair_materialized_canonical_smoke_blocked",
                                "argv": ["python3", "tool.py", "--pattern", "canonical-guard"],
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            report = tool.build_report(execution)
        self.assertEqual(report["status_counts"]["terminal_vulnerable_fixture_no_detector_hit"], 1)
        self.assertEqual(report["status_counts"]["terminal_clean_fixture_false_positive"], 1)
        self.assertEqual(report["status_counts"]["terminal_fixture_pair_materialized_canonical_smoke_blocked"], 1)
        by_id = {row["source_id"]: row for row in report["rows"]}
        self.assertIn("detector_predicate_or_vulnerable_fixture_semantics_mismatch", by_id["SSI-FIX-VULN"]["blockers"])
        self.assertIn("detector_predicate_or_clean_fixture_semantics_mismatch", by_id["SSI-FIX-CLEAN"]["blockers"])
        self.assertIn("canonical_fixture_path_guard_blocks_smoke", by_id["SSI-FIX-GUARD"]["blockers"])
        self.assertTrue(by_id["SSI-FIX-VULN"]["canonical_vulnerable_fixture"].endswith("vulnerable_no_hit_semantic_vulnerable.sol"))
        self.assertTrue(by_id["SSI-FIX-CLEAN"]["canonical_clean_fixture"].endswith("clean_false_positive_semantic_clean.sol"))

    def test_missing_compile_workdir_is_terminal_not_promoted(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            execution = Path(tmp) / "execution.json"
            execution.write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "source_id": "SSI-FIX-MISSING",
                                "status": "terminal_generated_fixture_compile_failure",
                                "argv": ["python3", "tool.py", "--pattern", "definitely-missing-workdir-for-test"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            report = tool.build_report(execution)
        self.assertEqual(report["status_counts"]["terminal_repair_workdir_missing"], 1)
        self.assertEqual(report["closed_rows"], 0)
        self.assertFalse(report["promotion_allowed"])

    def test_synthetic_fixture_avoids_function_state_name_collision(self) -> None:
        tool = load_tool()
        vuln, clean, meta = tool._synthetic_pair_for_detector("a-dark-age-can-end-prematurely")
        self.assertIsNotNone(vuln)
        self.assertIsNotNone(clean)
        self.assertEqual(meta["detector_skeleton"], "name_match_missing_require")
        vuln_text = Path(vuln).read_text(encoding="utf-8")
        clean_text = Path(clean).read_text(encoding="utf-8")
        self.assertIn("uint256 internal isDarkAgeState;", vuln_text)
        self.assertIn("function isDarkAge", vuln_text)
        self.assertIn("require(isDarkAgeState", clean_text)

    def test_manifest_bundle_records_materialization_gates(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            out_dir = Path(tmp) / "manifests"
            row = {
                "source_id": "SSI-FIX-READY",
                "task_id": "SAE-READY",
                "pattern": "ready-pattern",
                "status": "local_semantic_repair_smoke_passed",
                "baseline_status": "terminal_vulnerable_fixture_no_detector_hit",
                "detector_path": "/repo/detectors/wave15/ready_pattern.py",
                "detector_skeleton": "name_match_missing_call",
                "synthetic_vulnerable_fixture": "/tmp/ready_vulnerable.sol",
                "synthetic_clean_fixture": "/tmp/ready_clean.sol",
                "canonical_vulnerable_fixture": "/repo/detectors/test_fixtures/ready_pattern_semantic_vulnerable.sol",
                "canonical_clean_fixture": "/repo/detectors/test_fixtures/ready_pattern_semantic_clean.sol",
            }
            report = {"input_execution": "execution.json", "rows": [row]}
            tool._write_manifest_bundle(report, out_dir, runner_python="/venv/bin/python")
            summary = json.loads((out_dir / "_summary.json").read_text(encoding="utf-8"))
            self.assertEqual(summary["manifest_count"], 1)
            self.assertEqual(summary["materialization_ready_count"], 1)
            manifest_path = next(path for path in out_dir.glob("ssi-fix-ready_*.json") if path.name != "_summary.json")
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertTrue(manifest["materialization_ready"])
        self.assertFalse(manifest["promotion_allowed"])
        self.assertIn("human_review_confirms_synthetic_pair_matches_original_bug_family", manifest["review_gates"])
        self.assertIn("canonical_vulnerable_smoke", manifest["proof_commands"])
        self.assertIn("vulnerable_fixture_or_detector_predicate_addresses_prior_no_hit", manifest["review_gates"])


if __name__ == "__main__":
    unittest.main()
