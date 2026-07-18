#!/usr/bin/env python3
from __future__ import annotations

import json
import unittest

from tools.control.report import PROOF_BOUNDARY, SCHEMA, build_control_report, render_json, render_markdown


class ControlReportTests(unittest.TestCase):
    def test_builds_takeover_packet_from_control_inputs(self) -> None:
        snapshot = {
            "workspace": "/tmp/audit/demo",
            "target_name": "demo",
            "generated_at": "2026-05-03T00:00:00Z",
            "status": {
                "readiness": {
                    "scope": {"status": "ready"},
                    "severity": {"status": "ready"},
                    "oos": {"status": "blocked_unknown"},
                }
            },
            "candidates": [
                {
                    "id": "amp-zero",
                    "title": "Zero amplification blocks swaps",
                    "status": "candidate",
                    "severity": "High",
                    "paste_ready_blockers": ["missing_inline_poc", "missing_poc_result"],
                },
                {
                    "id": "ready",
                    "title": "Ready lane",
                    "status": "candidate",
                    "paste_ready_blockers": [],
                },
            ],
            "runs": {
                "proof_counted": {"true": 1, "false": 1},
                "rows": [
                    {
                        "tool": "poc-execution",
                        "artifact_path": "poc_execution/ready/execution_manifest.json",
                        "execution_state": "executed",
                        "proof_counted": True,
                        "warnings": [],
                    },
                    {
                        "tool": "rust-scan",
                        "artifact_path": "scanners/rust/SCAN_RUST_SUMMARY.json",
                        "execution_state": "blocked",
                        "proof_counted": False,
                    },
                ],
            },
        }
        gaps = {
            "rows": [
                {
                    "id": "impact_contract_gating:amp-zero",
                    "category": "impact_contract_gating",
                    "priority": "P0",
                    "title": "Candidate amp-zero lacks impact-contract fields",
                    "reason": "missing severity or listed impact",
                    "evidence": ["missing=impact"],
                    "next_command": "python3 tools/program-impact-mapping-check.py draft.md",
                    "stop_condition": "impact contract mapped",
                },
                {
                    "id": "dirty_workspace_hygiene",
                    "category": "dirty_workspace_hygiene",
                    "priority": "P1",
                    "title": "Dirty workspace needs explicit hygiene handling",
                    "reason": "dirty rows present",
                    "evidence": ["M:tools/control/status.py"],
                    "next_command": "git status --short",
                    "stop_condition": "dirty rows handled",
                },
                {"id": "provider_routing", "category": "provider_routing", "priority": "P2"},
            ]
        }
        provider_tasks = [
            {
                "id": "kimi:source-extract:amp-zero",
                "provider": "kimi",
                "task_kind": "source-extract",
                "subject_id": "amp-zero",
                "title": "Extract production evidence",
                "priority": 30,
                "calibration_status": "blocked",
                "calibration_blockers": ["provider_output_advisory_only"],
                "proof_boundary": "Kimi output is advisory.",
            },
            {
                "id": "claude:harness-plan:amp-zero",
                "provider": "claude",
                "task_kind": "harness-plan",
                "subject_id": "amp-zero",
                "title": "Wire executable PoC",
                "priority": 45,
                "calibration_status": "ready",
                "proof_boundary": "Claude output requires Codex gate.",
            },
        ]
        execution_plan = {
            "dry_run": True,
            "would_execute": False,
            "command_count": 2,
            "counts_by_classification": {"safe-local": 1, "proof-recording": 1},
            "commands": [
                {
                    "command": "make semantic-graph WS=/tmp/audit/demo",
                    "classification": "safe-local",
                    "command_hash": "a" * 64,
                    "blockers": [],
                },
                {
                    "command": "make poc-execution-record WS=/tmp/audit/demo BRIEF=draft.md CMD='forge test'",
                    "classification": "proof-recording",
                    "command_hash": "b" * 64,
                    "blockers": [],
                },
            ],
        }

        report = build_control_report(
            snapshot,
            gaps=gaps,
            provider_tasks=provider_tasks,
            execution_plan=execution_plan,
        )

        self.assertEqual(report["schema"], SCHEMA)
        self.assertEqual(report["readiness"]["status"], "blocked")
        self.assertIn("oos_readiness=blocked_unknown", report["readiness"]["reasons"])
        self.assertIn("p0_gaps=1", report["readiness"]["reasons"])
        self.assertEqual(report["candidate_blockers"][0]["id"], "amp-zero")
        self.assertEqual(report["proof_counted_runs"]["count"], 1)
        self.assertEqual(report["proof_counted_runs"]["by_tool"], {"poc-execution": 1})
        self.assertEqual([row["id"] for row in report["p0_gaps"]], ["impact_contract_gating:amp-zero"])
        self.assertEqual([row["id"] for row in report["p1_gaps"]], ["dirty_workspace_hygiene"])
        self.assertEqual(report["provider_task_routing"]["by_provider"]["kimi"]["blocked"], 1)
        self.assertEqual(report["provider_task_routing"]["by_provider"]["claude"]["task_kinds"], ["harness-plan"])
        self.assertEqual(report["dry_run_command_plan"]["command_count"], 2)
        self.assertFalse(report["dry_run_command_plan"]["would_execute"])
        self.assertEqual(report["proof_boundary"], PROOF_BOUNDARY)

    def test_renderers_are_stable_and_json_friendly(self) -> None:
        report = build_control_report(
            {
                "workspace": "/tmp/audit/ready",
                "target_name": "ready",
                "status": {"readiness": {"scope": {"status": "ready"}}},
                "candidates": [],
                "runs": {
                    "rows": [
                        {
                            "tool": "poc-execution",
                            "artifact_path": "poc_execution/ready/execution_manifest.json",
                            "execution_state": "executed",
                            "proof_counted": True,
                        }
                    ]
                },
            },
            gaps=[],
            provider_tasks=[],
            execution_plan={"commands": []},
        )

        encoded = render_json(report)
        decoded = json.loads(encoded)
        markdown = render_markdown(report)

        self.assertEqual(decoded, report)
        self.assertTrue(encoded.endswith("\n"))
        self.assertIn("# Control Takeover Packet: ready", markdown)
        self.assertIn("## Readiness", markdown)
        self.assertIn("status: ready_for_codex_gate", markdown)
        self.assertIn("## Proof Boundary", markdown)
        self.assertIn("Provider output", markdown)

    def test_no_proof_counted_runs_blocks_even_without_gap_rows(self) -> None:
        report = build_control_report(
            {
                "workspace": "/tmp/audit/no-proof",
                "target_name": "no-proof",
                "status": {"readiness": {"scope": {"status": "ready"}}},
                "candidates": [],
                "runs": {"rows": []},
            }
        )

        self.assertEqual(report["readiness"]["status"], "blocked")
        self.assertIn("proof_counted_runs=0", report["readiness"]["reasons"])
        self.assertEqual(report["proof_counted_runs"]["count"], 0)


if __name__ == "__main__":
    unittest.main()
