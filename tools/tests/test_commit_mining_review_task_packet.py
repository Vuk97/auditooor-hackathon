#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "commit-mining-review-task-packet.py"


def _load_module() -> types.ModuleType:
    spec = importlib.util.spec_from_file_location("commit_mining_review_task_packet", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MOD = _load_module()


def queue_row(
    task_id: str,
    action_type: str,
    *,
    status: str = "queued",
    packet_status: str = "source_review_packet_emitted",
    focus: list[str] | None = None,
    files: list[str] | None = None,
    directories: list[str] | None = None,
) -> dict:
    focus = focus or ["consensus_or_fork_logic"]
    files = files or ["crates/consensus/protocol/src/attributes.rs"]
    directories = directories or ["crates/consensus"]
    return {
        "disposition_id": f"source-disposition-{task_id}",
        "queue_index": 1,
        "status": status,
        "action_type": action_type,
        "task_id": task_id,
        "source_row_id": task_id.replace("scan-task-", ""),
        "target": "Base Azul",
        "repo_identity": "github.com/base/base",
        "commit_sha": "a" * 40,
        "commit_short": "a" * 12,
        "packet_status": packet_status,
        "rationale": "review rationale",
        "next_action": "review next action",
        "source_review_summary": "review summary",
        "bounded_review": {
            "max_files": 5,
            "max_directories": 3,
            "selected_files": files,
            "selected_directories": directories,
            "review_focus": focus,
        },
    }


class CommitMiningReviewTaskPacketTest(unittest.TestCase):
    def test_build_report_selects_only_eligible_rows(self) -> None:
        payload = {
            "schema": "auditooor.commit_mining_source_disposition.v1",
            "generated_at_utc": "2026-05-05T18:36:58+00:00",
            "disposition_queue": [
                queue_row("scan-task-BA-HIST-01", "broad_import_triage"),
                queue_row(
                    "scan-task-BA-PATCH-01",
                    "narrow_consensus_patch_review",
                    focus=["consensus_or_fork_logic", "state_transition"],
                ),
                queue_row(
                    "scan-task-BA-PIN-01",
                    "prover_service_review",
                    focus=["proof_or_hashing", "tests_or_fixtures"],
                    files=["crates/proof/zk/service/src/backends/op_succinct/backend.rs"],
                    directories=["crates/proof"],
                ),
            ],
        }

        report = MOD.build_report(payload, ROOT, input_path=ROOT / "reports" / "commit_mining_source_disposition_2026-05-05.json")

        self.assertEqual(report["schema"], MOD.SCHEMA)
        self.assertTrue(report["advisory_only"])
        self.assertFalse(report["network_used"])
        self.assertEqual(report["summary"]["source_queue_rows_seen"], 3)
        self.assertEqual(report["summary"]["eligible_rows_seen"], 2)
        self.assertEqual(report["summary"]["emitted_task_count"], 2)
        self.assertEqual(report["summary"]["selected_action_counts"]["narrow_consensus_patch_review"], 1)
        self.assertEqual(report["summary"]["selected_action_counts"]["prover_service_review"], 1)
        tasks = {task["source_task_id"]: task for task in report["tasks"]}
        self.assertNotIn("scan-task-BA-HIST-01", tasks)
        self.assertEqual(
            tasks["scan-task-BA-PATCH-01"]["review_prompts"][-1],
            "Which state-transition preconditions or invariants should a later proof task verify separately?",
        )
        self.assertEqual(
            tasks["scan-task-BA-PIN-01"]["review_prompts"][-1],
            "Which proof, hashing, or backend assumptions should a later proof task verify separately?",
        )
        self.assertEqual(report["skipped_rows"][0]["reason"], "action_not_selected")

    def test_build_report_enforces_task_limit_and_skip_reasons(self) -> None:
        incomplete = queue_row("scan-task-BA-PATCH-03", "narrow_consensus_patch_review")
        incomplete["bounded_review"]["selected_files"] = []
        incomplete["bounded_review"]["selected_directories"] = []
        payload = {
            "schema": "auditooor.commit_mining_source_disposition.v1",
            "disposition_queue": [
                queue_row("scan-task-BA-PATCH-01", "narrow_consensus_patch_review"),
                queue_row("scan-task-BA-PATCH-02", "narrow_consensus_patch_review", status="blocked_no_op"),
                queue_row(
                    "scan-task-BA-PIN-01",
                    "prover_service_review",
                    packet_status="blocked",
                ),
                incomplete,
                queue_row("scan-task-BA-PATCH-04", "narrow_consensus_patch_review"),
            ],
        }

        report = MOD.build_report(payload, ROOT, max_tasks=1)

        self.assertEqual(report["summary"]["emitted_task_count"], 1)
        self.assertEqual(
            report["summary"]["skipped_reason_counts"],
            {
                "bounded_review_missing_or_incomplete": 1,
                "max_tasks_reached": 1,
                "row_not_queued": 1,
                "source_packet_not_emitted": 1,
            },
        )

    def test_terminal_evidence_skips_stale_queued_rows(self) -> None:
        payload = {
            "schema": "auditooor.commit_mining_source_disposition.v1",
            "disposition_queue": [
                queue_row("scan-task-BA-PATCH-01", "narrow_consensus_patch_review"),
                queue_row("scan-task-BA-PATCH-02", "narrow_consensus_patch_review"),
            ],
        }
        terminal_evidence = [
            {
                "evidence_path": "reports/ba_patch_01_proof_execution_2026-05-05.json",
                "source_row_id": "BA-PATCH-01",
                "source_task_id": "scan-task-BA-PATCH-01",
                "commit_sha": "a" * 40,
                "final_disposition": (
                    "proved_patch_regression_fixed_and_detector_regression_ready__"
                    "blocked_for_exploitability_or_submission"
                ),
            },
            {
                "evidence_path": "reports/unrelated_2026-05-05.json",
                "source_row_id": "BA-PATCH-02",
                "source_task_id": "scan-task-BA-PATCH-02",
                "commit_sha": "b" * 40,
                "final_disposition": "regression_only__blocked_for_exploitability_or_submission",
            },
        ]

        report = MOD.build_report(payload, ROOT, terminal_evidence=terminal_evidence)

        self.assertEqual(report["summary"]["emitted_task_count"], 1)
        self.assertEqual(report["summary"]["terminal_evidence_count"], 2)
        self.assertEqual(
            report["summary"]["skipped_reason_counts"],
            {"terminal_source_disposition_present": 1},
        )
        self.assertEqual(report["tasks"][0]["source_task_id"], "scan-task-BA-PATCH-02")
        skipped = report["skipped_rows"][0]
        self.assertEqual(skipped["task_id"], "scan-task-BA-PATCH-01")
        self.assertEqual(skipped["reason"], "terminal_source_disposition_present")
        self.assertEqual(
            skipped["terminal_evidence"][0]["evidence_path"],
            "reports/ba_patch_01_proof_execution_2026-05-05.json",
        )

    def test_load_terminal_evidence_discovers_final_dispositions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence_path = root / "reports" / "ba_patch_01_detector_2026-05-05.json"
            evidence_path.parent.mkdir(parents=True)
            evidence_path.write_text(
                json.dumps(
                    {
                        "source_task_id": "scan-task-BA-PATCH-01",
                        "source_row_id": "BA-PATCH-01",
                        "final_disposition": "detectorized_regression_only__blocked_for_exploitability_or_submission",
                    }
                ),
                encoding="utf-8",
            )
            ignored_path = root / "reports" / "open_detector_2026-05-05.json"
            ignored_path.write_text(
                json.dumps(
                    {
                        "source_task_id": "scan-task-BA-PATCH-02",
                        "source_row_id": "BA-PATCH-02",
                        "final_disposition": "needs_followup",
                    }
                ),
                encoding="utf-8",
            )

            paths = MOD.discover_terminal_evidence_paths(root)
            evidence = MOD.load_terminal_evidence(paths, root)

        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["source_task_id"], "scan-task-BA-PATCH-01")
        self.assertEqual(evidence[0]["evidence_path"], "reports/ba_patch_01_detector_2026-05-05.json")

    def test_report_omits_claim_posture_fields(self) -> None:
        report = MOD.build_report(
            {
                "schema": "auditooor.commit_mining_source_disposition.v1",
                "disposition_queue": [
                    queue_row("scan-task-BA-PATCH-01", "narrow_consensus_patch_review")
                ],
            },
            ROOT,
        )

        encoded = json.dumps(report, sort_keys=True)
        for field in ("severity_claim", "impact_claim", "exploitability_claim", "submission_posture", "submit_ready"):
            self.assertNotIn(field, encoded)

    def test_cli_writes_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            input_report = root / "source_disposition.json"
            output_report = root / "review_task_packet.json"
            markdown = root / "review_task_packet.md"
            input_report.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.commit_mining_source_disposition.v1",
                        "disposition_queue": [
                            queue_row("scan-task-BA-PATCH-01", "narrow_consensus_patch_review")
                        ],
                    }
                ),
                encoding="utf-8",
            )

            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--repo",
                    str(root),
                    "--input",
                    str(input_report),
                    "--out",
                    str(output_report),
                    "--markdown-out",
                    str(markdown),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            report = json.loads(output_report.read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["emitted_task_count"], 1)
            rendered = markdown.read_text(encoding="utf-8")
            self.assertIn("Commit Mining Review Task Packet", rendered)
            self.assertIn("narrow_consensus_patch_review", rendered)


if __name__ == "__main__":
    unittest.main()
