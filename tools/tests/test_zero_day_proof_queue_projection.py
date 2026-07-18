#!/usr/bin/env python3
"""Focused coverage for frozen zero-day proof queue projection."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "zero-day-proof-queue-projection.py"
SPEC = importlib.util.spec_from_file_location("zero_day_proof_queue_projection_test", TOOL)
assert SPEC and SPEC.loader
PROJECTION = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PROJECTION
SPEC.loader.exec_module(PROJECTION)


class ZeroDayProofQueueProjectionTest(unittest.TestCase):
    def _validated(self, workspace: Path) -> dict:
        parent = ("zdo_parent", "zdr_revision")
        questions = []
        tasks = {}
        sidecars = {}
        for axis in PROJECTION.HUNT.AXES:
            question_id = f"q-{axis}"
            questions.append({"question_id": question_id, "parent_ids": list(parent), "axis": axis})
            tasks[question_id] = {
                "task_id": question_id,
                "sidecar_path": f".auditooor/ordered_hunt/sidecars/{question_id}.json",
                "sidecar_sha256": "a" * 64,
            }
            sidecars[question_id] = {"result": "{}"}
        return {
            "workspace": workspace,
            "current": {"sources": {"src/A.sol": {"path": workspace / "src" / "A.sol"}}},
            "bus": {
                "receipt": {"receipt_id": "b" * 64, "input_fingerprint": "c" * 64},
                "obligation_by_parent": {parent: {
                    "source_row_sha256": "d" * 64,
                    "source_refs": ["src/A.sol:1"],
                    "logical": {
                        "target_unit": "src/A.sol::f",
                        "asset_invariant": "assets conserved",
                        "violation_relation": "withdrawal breaks accounting",
                        "actor_model": "permissionless attacker",
                        "impact_class": "direct-theft-funds",
                    },
                }},
                "questions": questions,
            },
            "tasks_by_id": tasks,
            "sidecars_by_task": sidecars,
        }

    def test_projects_every_axis_under_exact_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            (workspace / "src").mkdir()
            (workspace / "src" / "A.sol").write_text("contract A {}\n", encoding="utf-8")
            validated = self._validated(workspace)
            result = {
                "applies_to_target": "maybe",
                "confidence": "low",
                "candidate_finding": "nonterminal",
                "file_line": "src/A.sol:1",
                "code_excerpt": "contract A {}",
                "severity_estimate": "unknown",
                "rubric_row_cited": "unknown",
                "dupe_check": "pending",
                "falsification_attempt": "pending",
                "notes": "nonterminal",
            }
            with mock.patch.object(PROJECTION.HUNT, "_validate_provider_result", return_value=result):
                payload = PROJECTION.project(validated)
        self.assertEqual(PROJECTION.QUEUE_SCHEMA, payload["schema"])
        self.assertEqual(1, len(payload["queue"]))
        row = payload["queue"][0]
        self.assertEqual("zdo_parent", row["obligation_id"])
        self.assertEqual("zdr_revision", row["revision_id"])
        self.assertEqual(len(PROJECTION.HUNT.AXES), len(row["zero_day_proof_projection"]["question_evidence"]))
        self.assertEqual("needs_source", row["proof_status"])

    def test_rejects_missing_sidecar_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            (workspace / "src").mkdir()
            (workspace / "src" / "A.sol").write_text("contract A {}\n", encoding="utf-8")
            validated = self._validated(workspace)
            validated["sidecars_by_task"]["q-asset_invariant"].pop("result")
            with self.assertRaisesRegex(PROJECTION.ProjectionError, "proof_queue_sidecar_result_missing"):
                PROJECTION.project(validated)

    def test_run_removes_stale_output_when_current_hunt_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary)
            output = workspace / ".auditooor" / "typed_proof_queue.json"
            output.parent.mkdir()
            output.write_text("stale", encoding="utf-8")
            with mock.patch.object(PROJECTION.HUNT, "validate_current_ordered_hunt",
                                   side_effect=PROJECTION.HUNT.HuntError("ordered_hunt_stale_relative_to_freeze")):
                with self.assertRaisesRegex(PROJECTION.ProjectionError, "ordered_hunt_stale_relative_to_freeze"):
                    PROJECTION.run(workspace, output)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
