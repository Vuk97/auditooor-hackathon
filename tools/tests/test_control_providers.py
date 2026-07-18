#!/usr/bin/env python3
"""Tests for control-plane provider routing primitives."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.control.providers import (
    build_provider_tasks,
    calibrate_provider_task,
    calibrate_provider_tasks,
    promotion_blockers,
    provider_profiles,
)


class ControlProviderRoutingTests(unittest.TestCase):
    def test_planned_candidate_routes_to_advisory_and_claude_work(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tasks = build_provider_tasks(
                Path(tmp),
                candidates=[
                    {
                        "id": "A-ORACLE",
                        "title": "Oracle stale price path",
                        "status": "candidate",
                        "proof_state": "planned",
                        "source_paths": ["src/Oracle.sol"],
                    }
                ],
            )

        by_provider_kind = {(task["provider"], task["task_kind"]): task for task in tasks}

        self.assertIn(("kimi", "source-extract"), by_provider_kind)
        self.assertIn(("minimax", "adversarial-kill"), by_provider_kind)
        self.assertIn(("claude", "harness-plan"), by_provider_kind)
        self.assertNotIn(("codex", "proof-gate"), by_provider_kind)
        self.assertEqual(by_provider_kind[("kimi", "source-extract")]["evidence_rule"], "advisory_only")
        self.assertIn("advisory", by_provider_kind[("minimax", "adversarial-kill")]["proof_boundary"])
        self.assertIn(
            "poc_execution/**/execution_manifest.json",
            by_provider_kind[("claude", "harness-plan")]["required_artifacts"],
        )

    def test_proved_candidate_with_oos_routes_to_codex_gate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tasks = build_provider_tasks(
                Path(tmp),
                candidates=[
                    {
                        "id": "amp-zero",
                        "title": "Amplification factor can be zero",
                        "proof_state": "proved",
                        "oos_checked": True,
                        "draft_path": "submissions/ready/amp-zero.md",
                    }
                ],
                runs=[
                    {
                        "tool": "poc-execution",
                        "artifact_path": "poc_execution/amp-zero/execution_manifest.json",
                        "execution_state": "executed",
                        "proof_counted": True,
                    }
                ],
            )

        codex_tasks = [task for task in tasks if task["provider"] == "codex"]

        self.assertEqual(len(codex_tasks), 1)
        task = codex_tasks[0]
        self.assertEqual(task["task_kind"], "proof-gate")
        self.assertIn("poc_execution/amp-zero/execution_manifest.json", task["required_artifacts"])
        self.assertIn(
            "submission language does not rely on advisory provider output",
            task["fail_closed_promotion_criteria"],
        )
        calibrated = calibrate_provider_task(task)
        self.assertEqual(calibrated["calibration_status"], "ready")

    def test_advisory_provider_cannot_promote_even_with_artifact_names(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = build_provider_tasks(
                Path(tmp),
                candidates=[{"id": "source-only", "title": "Source-only lead", "status": "lead"}],
            )[0]

        blockers = promotion_blockers(task, artifacts_present=task["required_artifacts"])
        calibrated = calibrate_provider_task(task)

        self.assertEqual(task["provider"], "kimi")
        self.assertIn("advisory_provider_cannot_promote", blockers)
        self.assertEqual(calibrated["calibration_status"], "blocked")
        self.assertIn("provider_output_advisory_only", calibrated["calibration_blockers"])

    def test_blocked_run_and_proof_next_action_generate_work_tasks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tasks = build_provider_tasks(
                Path(tmp),
                runs=[
                    {
                        "tool": "audit-deep",
                        "artifact_path": ".audit_logs/audit_deep_all_manifest.json",
                        "execution_state": "partial",
                    }
                ],
                next_actions=[
                    {
                        "priority": 25,
                        "reason": "candidate needs proof language review",
                        "artifact": "submissions/ready/finding.md",
                        "stop_condition": "pre-submit-check passes",
                    }
                ],
            )

        by_subject = {(task["subject_type"], task["provider"], task["task_kind"]) for task in tasks}

        self.assertIn(("run", "claude", "closure-work"), by_subject)
        self.assertIn(("next_action", "codex", "proof-gate"), by_subject)
        codex_action = [task for task in tasks if task["subject_type"] == "next_action"][0]
        self.assertEqual(codex_action["priority"], 25)
        self.assertIn("pre-submit-check passes", codex_action["fail_closed_promotion_criteria"])

    def test_provider_profiles_are_defensive_copies_and_calibrate_unknown_blocks(self) -> None:
        profiles = provider_profiles()
        profiles["kimi"]["default_task_kinds"].append("mutated")

        self.assertNotIn("mutated", provider_profiles()["kimi"]["default_task_kinds"])

        calibrated = calibrate_provider_tasks(
            [
                {
                    "provider": "unknown",
                    "required_artifacts": [],
                    "fail_closed_promotion_criteria": [],
                }
            ]
        )
        self.assertEqual(calibrated[0]["calibration_status"], "blocked")
        self.assertIn("unknown_provider", calibrated[0]["calibration_blockers"])


if __name__ == "__main__":
    unittest.main()
