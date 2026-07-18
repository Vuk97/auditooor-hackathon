from __future__ import annotations

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


TOOL = Path(__file__).resolve().parents[1] / "one-run-measurement.py"
SPEC = importlib.util.spec_from_file_location("one_run_measurement", TOOL)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class OneRunMeasurementTests(unittest.TestCase):
    def test_records_existing_artifacts_without_reinterpreting_them(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "heldout.json"
            recall = root / "recall.json"
            manifest.write_text(json.dumps({"schema": MODULE.MANIFEST_SCHEMA, "samples": [{"id": "case-1"}]}), encoding="utf-8")
            recall.write_text(json.dumps({"schema": "auditooor.realworld_recall_scoreboard.v1", "summary": {"same_class_recall": 0.5}}), encoding="utf-8")
            record = MODULE.build_record(manifest, repo_revision="a" * 40, config={"mode": "strict"}, tool_versions={"slither": "x"}, inputs={"recall": recall}, run_id="run-1")
            self.assertEqual(record["measurements"]["recall"]["summary"]["same_class_recall"], 0.5)
            self.assertEqual(record["run"]["case_set"]["case_ids"], ["case-1"])

    def test_refuses_comparison_when_provenance_differs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "heldout.json"
            manifest.write_text(json.dumps({"schema": MODULE.MANIFEST_SCHEMA, "samples": [{"id": "case-1"}]}), encoding="utf-8")
            baseline = MODULE.build_record(manifest, repo_revision="a" * 40, config={}, tool_versions={}, inputs={}, run_id="before")
            candidate = copy.deepcopy(baseline)
            candidate["run"]["toolchain"]["config_digest"] = "different"
            result = MODULE.compare(baseline, candidate)
            self.assertFalse(result["comparable"])
            self.assertIn("toolchain.config_digest", result["reasons"])

    def test_comparable_records_preserve_both_measurements(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "heldout.json"
            manifest.write_text(json.dumps({"schema": MODULE.MANIFEST_SCHEMA, "samples": [{"id": "case-1"}]}), encoding="utf-8")
            baseline = MODULE.build_record(manifest, repo_revision="a" * 40, config={}, tool_versions={}, inputs={}, run_id="before")
            candidate = copy.deepcopy(baseline)
            candidate["run"]["run_id"] = "after"
            result = MODULE.compare(baseline, candidate)
            self.assertTrue(result["comparable"])
            self.assertEqual(result["candidate_run_id"], "after")


if __name__ == "__main__":
    unittest.main()
