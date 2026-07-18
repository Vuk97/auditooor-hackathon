#!/usr/bin/env python3
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.control.providers import build_provider_tasks
from tools.control.workpacks import (
    SCHEMA,
    build_workpack_report,
    build_workpacks,
    render_json,
    render_markdown,
)


class ControlWorkpackTests(unittest.TestCase):
    def test_builds_safe_provider_prompts_with_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            tasks = build_provider_tasks(
                ws,
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
            gaps = {
                "rows": [
                    {
                        "id": "harness_execution_replay:A-ORACLE",
                        "category": "harness_execution_replay",
                        "priority": "P0",
                        "title": "Candidate lacks executed harness/replay proof",
                        "evidence": ["proof_state=planned"],
                        "stop_condition": "poc_execution manifest records command output",
                    }
                ]
            }

            packs = build_workpacks(ws, provider_tasks=tasks, gap_rows=gaps)

        by_provider = {pack["provider"]: pack for pack in packs}
        self.assertEqual({pack["schema"] for pack in packs}, {SCHEMA})
        self.assertIn("kimi", by_provider)
        self.assertIn("minimax", by_provider)
        self.assertIn("claude", by_provider)
        self.assertNotIn("codex", by_provider)

        kimi = by_provider["kimi"]
        self.assertEqual(kimi["owned_files"], ["provider_outputs/kimi/a-oracle.md"])
        self.assertIn("src/Oracle.sol", kimi["read_only_refs"])
        self.assertIn("advisory_provider_cannot_promote", kimi["promotion_blockers"])
        self.assertIn("Do not launch workers", kimi["prompt"])
        self.assertIn("Do not promote advisory model text as proof", kimi["prompt"])

        claude = by_provider["claude"]
        self.assertIn("poc_execution/**/execution_manifest.json", claude["owned_files"])
        self.assertIn("claude_output_requires_codex_gate", claude["promotion_blockers"])
        self.assertIn("harness_execution_replay", claude["prompt"])

    def test_codex_gate_keeps_required_artifacts_and_no_launch_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            tasks = build_provider_tasks(
                ws,
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
            packs = build_workpacks(
                ws,
                provider_tasks=[task for task in tasks if task["provider"] == "codex"],
                gap_rows=[
                    {
                        "id": "submission_paste_readiness:amp-zero",
                        "category": "submission_paste_readiness",
                        "priority": "P0",
                        "title": "Candidate needs paste-ready gate",
                        "evidence": ["draft_path=submissions/ready/amp-zero.md"],
                    }
                ],
            )

        self.assertEqual(len(packs), 1)
        pack = packs[0]
        self.assertEqual(pack["provider"], "codex")
        self.assertEqual(pack["launch_command"], "")
        self.assertIn("poc_execution/amp-zero/execution_manifest.json", pack["required_artifacts"])
        self.assertIn("poc_execution/amp-zero/execution_manifest.json", pack["owned_files"])
        self.assertIn("pre-submit-check passes for the exact draft", pack["prompt"])
        self.assertIn("Codex gates", pack["proof_boundary"])

    def test_report_and_renderers_are_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            tasks = [
                {
                    "id": "custom:kimi:one",
                    "provider": "kimi",
                    "task_kind": "source-extract",
                    "subject_type": "gap",
                    "subject_id": "scanner",
                    "title": "Extract scanner facts",
                    "required_artifacts": ["provider-packets/source-extract"],
                    "fail_closed_promotion_criteria": ["local check recorded"],
                    "proof_boundary": "Kimi is advisory only.",
                    "input_refs": {"source_paths": ["src/A.sol"]},
                }
            ]

            report = build_workpack_report(ws, provider_tasks=tasks, gap_rows=[])

        self.assertEqual(report["schema"], SCHEMA)
        self.assertEqual(report["workpack_count"], 1)
        self.assertEqual(report["counts_by_provider"], {"kimi": 1})
        json_payload = json.loads(render_json(report))
        self.assertEqual(json_payload["schema"], SCHEMA)
        markdown = render_markdown(report)
        self.assertIn("# Control Workpacks", markdown)
        self.assertIn("custom:kimi:one", markdown)

    def test_time_budget_and_kill_conditions_defaults_and_rendering(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            tasks = [
                {
                    "id": "custom:kimi:explicit",
                    "provider": "kimi",
                    "task_kind": "source-extract",
                    "subject_type": "gap",
                    "subject_id": "explicit",
                    "title": "Extract bounded facts",
                    "time_budget_minutes": "45",
                    "kill_conditions": [
                        "Stop if scope is ambiguous.",
                        "Stop if no line-cited source path exists.",
                    ],
                    "required_artifacts": ["provider-packets/source-extract"],
                    "fail_closed_promotion_criteria": ["local source check recorded"],
                    "proof_boundary": "Kimi is advisory only.",
                },
                {
                    "id": "custom:kimi:default",
                    "provider": "kimi",
                    "task_kind": "source-extract",
                    "subject_type": "gap",
                    "subject_id": "default",
                    "title": "Extract default-bounded facts",
                    "required_artifacts": ["provider-packets/source-extract"],
                    "fail_closed_promotion_criteria": ["local source check recorded"],
                    "proof_boundary": "Kimi is advisory only.",
                },
            ]

            report = build_workpack_report(ws, provider_tasks=tasks, gap_rows=[])

        by_task = {pack["task_id"]: pack for pack in report["workpacks"]}
        explicit = by_task["custom:kimi:explicit"]
        self.assertEqual(explicit["time_budget_minutes"], 45)
        self.assertEqual(
            explicit["kill_conditions"],
            [
                "Stop if scope is ambiguous.",
                "Stop if no line-cited source path exists.",
            ],
        )
        self.assertIn("Time budget minutes:\n- 45", explicit["prompt"])
        self.assertIn("Kill conditions:\n- Stop if scope is ambiguous.", explicit["prompt"])

        default = by_task["custom:kimi:default"]
        self.assertIsNone(default["time_budget_minutes"])
        self.assertEqual(default["kill_conditions"], [])
        self.assertIn("Time budget minutes:\n- null", default["prompt"])
        self.assertIn("No explicit kill conditions supplied", default["prompt"])

        markdown = render_markdown(report)
        self.assertIn("- Time budget minutes: 45", markdown)
        self.assertIn("- Kill conditions:\n- Stop if scope is ambiguous.", markdown)
        self.assertIn("- Time budget minutes: null", markdown)
        self.assertIn("No explicit kill conditions supplied", markdown)


if __name__ == "__main__":
    unittest.main()
