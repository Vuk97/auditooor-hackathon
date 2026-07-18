from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import time
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "audit" / "realworld-recall-drilldown.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("_realworld_recall_drilldown_test", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(mod)
    return mod


class RealworldRecallDrilldownTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()

    def _write_fixture(self, root: Path) -> tuple[Path, Path]:
        priorities_path = root / "realworld_recall_gap_priorities.json"
        priorities = {
            "schema": "auditooor.realworld_recall_gap_priorities.v1",
            "generated_at": "2026-05-17T00:00:00Z",
            "priorities": [
                {
                    "rank": 1,
                    "attack_class": "bridge-proof-domain-bypass",
                    "priority_band": "P0",
                    "priority_score": 93.8,
                    "same_class_recall": 0.0,
                    "same_class_misses": 2,
                    "samples_total": 2,
                    "realworld_recall_any": 0.5,
                    "gap_vs_any_pp": 50.0,
                    "gap_vs_self_test_pp": 20.0,
                    "external_evidence": {
                        "measured_external_samples": 2,
                        "external_same_class_recall": 0.0,
                        "repo_examples": [{"repo": "snowbridge", "samples": 2}],
                    },
                    "miss_examples": [
                        {
                            "slug": "snowbridge/beefy",
                            "source": "external_repo:snowbridge",
                            "sample_origin": "external_repo",
                            "own_detector_fired": False,
                            "independent_any_fired": True,
                            "independent_firing_detectors": ["cross-class-a", "cross-class-b"],
                        }
                    ],
                    "top_cross_class_detectors_on_misses": [{"detector": "cross-class-a", "count": 2}],
                },
                {
                    "rank": 2,
                    "attack_class": "fund-loss-via-arithmetic",
                    "priority_band": "P1",
                    "priority_score": 66.0,
                    "same_class_recall": 0.5,
                    "same_class_misses": 1,
                    "samples_total": 2,
                    "miss_examples": [],
                    "top_cross_class_detectors_on_misses": [],
                },
            ],
        }
        priorities_path.write_text(json.dumps(priorities, indent=2), encoding="utf-8")
        priorities_sha = self.tool._sha256(priorities_path)
        queue_path = root / "realworld_recall_work_queue.jsonl"
        queue_rows = [
            {
                "schema": "auditooor.realworld_recall_work_queue.row.v1",
                "queue_id": "rwrq-bridge-proof-domain-bypass-1",
                "status": "quality_blocked",
                "source_report_sha256": priorities_sha,
                "source_priority": {"attack_class": "bridge-proof-domain-bypass"},
                "work_item": {
                    "task_type": "source-state-validation",
                    "summary": "Replace fixed rows with vulnerable snapshots.",
                },
                "provider_dispatch_ready": False,
                "workability_status": "needs_source_state_validation",
                "workability_blockers": ["quality_blocked_needs_source_state_validation"],
                "provider_dispatch_reason": "blocked: quality_blocked_needs_source_state_validation",
                "external_recall_quality": {
                    "quality_blocked": True,
                    "quality_blocked_reason": "disqualified_source_state",
                    "quality_report_paths": ["reports/quality.json"],
                    "required_actions": ["replace fixed rows"],
                },
                "suggested_commands": ["make external-recall-select REPO_ROOT=/repo REPO_ID=snowbridge ATTACK_CLASS=bridge-proof-domain-bypass JSON=1"],
                "closeout_requirements": ["Do not broaden detectors until source state is valid."],
            },
            {
                "schema": "auditooor.realworld_recall_work_queue.row.v1",
                "queue_id": "rwrq-fund-loss-via-arithmetic-1",
                "status": "open",
                "source_report_sha256": priorities_sha,
                "source_priority": {"attack_class": "fund-loss-via-arithmetic"},
                "work_item": {"task_type": "detector-generalization", "summary": "Generalize arithmetic detector."},
                "provider_dispatch_ready": True,
                "workability_status": "ready_for_provider_dispatch",
                "workability_blockers": [],
                "provider_dispatch_reason": "ready: row has the bounded evidence needed for provider review",
                "suggested_commands": ["make hackerman-sidecar-refresh-check CHECK=1 JSON=1"],
                "closeout_requirements": ["Add a control sample."],
            },
        ]
        queue_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in queue_rows), encoding="utf-8")
        return priorities_path, queue_path

    def test_default_selects_top_priority_and_surfaces_quality_block(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rwr-drilldown-") as td:
            priorities, queue = self._write_fixture(Path(td))
            packet = self.tool.build_packet(priorities_path=priorities, queue_path=queue)

            self.assertEqual(packet["schema"], "auditooor.realworld_recall_drilldown.v1")
            self.assertEqual(packet["submission_posture"], "NOT_SUBMIT_READY")
            self.assertEqual(packet["selection"]["attack_class"], "bridge-proof-domain-bypass")
            self.assertEqual(packet["selection"]["selection_reason"], "top_priority")
            self.assertTrue(packet["freshness"]["current_for_priorities"])
            self.assertTrue(packet["quality_state"]["quality_blocked"])
            self.assertEqual(packet["queue_work_items"][0]["task_type"], "source-state-validation")
            self.assertFalse(packet["queue_work_items"][0]["provider_dispatch_ready"])
            self.assertEqual(packet["queue_work_items"][0]["workability_status"], "needs_source_state_validation")
            self.assertEqual(packet["queue_workability"]["provider_dispatch_blocked_rows"], 1)
            self.assertEqual(
                packet["queue_workability"]["workability_blocker_counts"],
                {"quality_blocked_needs_source_state_validation": 1},
            )
            self.assertTrue(any("Quality-blocked external rows" in item for item in packet["control_obligations"]))

    def test_explicit_attack_class_filters_queue_rows(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rwr-drilldown-filter-") as td:
            priorities, queue = self._write_fixture(Path(td))
            packet = self.tool.build_packet(
                priorities_path=priorities,
                queue_path=queue,
                attack_class="fund-loss-via-arithmetic",
            )

            self.assertEqual(packet["selection"]["attack_class"], "fund-loss-via-arithmetic")
            self.assertEqual(packet["selection"]["selection_reason"], "explicit_attack_class")
            self.assertEqual(len(packet["queue_work_items"]), 1)
            self.assertEqual(packet["queue_work_items"][0]["task_type"], "detector-generalization")
            self.assertTrue(packet["queue_work_items"][0]["provider_dispatch_ready"])
            self.assertEqual(packet["queue_workability"]["provider_dispatch_ready_rows"], 1)
            self.assertFalse(packet["quality_state"]["quality_blocked"])

    def test_stale_queue_rows_warn_and_are_not_current(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rwr-drilldown-stale-") as td:
            priorities, queue = self._write_fixture(Path(td))
            rows = [json.loads(line) for line in queue.read_text(encoding="utf-8").splitlines() if line]
            rows[0]["source_report_sha256"] = "0" * 64
            queue.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")

            packet = self.tool.build_packet(priorities_path=priorities, queue_path=queue)

            self.assertFalse(packet["freshness"]["current_for_priorities"])
            self.assertEqual(packet["freshness"]["stale_queue_rows"], 1)
            self.assertTrue(any("refresh the queue" in warning for warning in packet["freshness"]["warnings"]))

    def test_queue_loader_accepts_v2_rows_and_rejects_unknown_schema(self) -> None:
        with tempfile.TemporaryDirectory(prefix="rwr-drilldown-schema-") as td:
            queue = Path(td) / "queue.jsonl"
            queue.write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "schema": "auditooor.realworld_recall_work_queue.row.v2",
                                "queue_id": "rwrq-bridge-proof-domain-bypass-v2",
                            },
                            sort_keys=True,
                        ),
                        json.dumps(
                            {
                                "schema": "auditooor.realworld_recall_work_queue.row.future",
                                "queue_id": "rwrq-ignored",
                            },
                            sort_keys=True,
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            rows, warnings = self.tool.load_queue_rows(queue)

            self.assertEqual([row["queue_id"] for row in rows], ["rwrq-bridge-proof-domain-bypass-v2"])
            self.assertTrue(any("schema mismatch" in warning for warning in warnings))

    def test_resolve_default_queue_uses_latest_generated_queue(self) -> None:
        original_default = self.tool.DEFAULT_QUEUE
        missing_default = REPO_ROOT / "reports" / "realworld_recall_work_queue_missing_default_drilldown_test.jsonl"
        newer = REPO_ROOT / "reports" / "realworld_recall_work_queue_zz_drilldown_test.jsonl"
        try:
            self.tool.DEFAULT_QUEUE = missing_default
            newer.write_text("", encoding="utf-8")
            future = time.time() + 60
            os.utime(newer, (future, future))
            resolved = self.tool.resolve_queue_path(self.tool.DEFAULT_QUEUE)
            self.assertEqual(resolved, newer.resolve())
        finally:
            self.tool.DEFAULT_QUEUE = original_default
            newer.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
