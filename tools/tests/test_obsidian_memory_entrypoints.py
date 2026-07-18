import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "obsidian-memory-entrypoints.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("obsidian_memory_entrypoints", TOOL)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class ObsidianMemoryEntrypointsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-obs-entrypoints-")
        self.root = Path(self.tmp.name)
        self.old_env = {
            "AUDITOOOR_MEMORY_ROOT": os.environ.get("AUDITOOOR_MEMORY_ROOT"),
            "AUDITOOOR_OBSIDIAN_VAULT": os.environ.get("AUDITOOOR_OBSIDIAN_VAULT"),
        }
        os.environ["AUDITOOOR_MEMORY_ROOT"] = str(self.root)
        os.environ["AUDITOOOR_OBSIDIAN_VAULT"] = str(self.root / "obsidian-vault")
        subprocess.run(["git", "init", "-b", "fresh-memory-root"], cwd=self.root, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (self.root / "tools").mkdir()
        (self.root / "docs").mkdir()
        (self.root / "reports").mkdir()
        (self.root / "obsidian-vault" / "gap-analysis").mkdir(parents=True)
        (self.root / "obsidian-vault" / "dispatch").mkdir()
        for rel in ("INDEX.md", "INDEX_active.md", "NEXT_LOOP.md"):
            (self.root / "obsidian-vault" / rel).write_text("# note\n", encoding="utf-8")
        (self.root / "obsidian-vault" / "DASHBOARD.md").write_text(
            '---\ngenerated: "2026-05-04T20:21Z"\n---\n# dashboard\n',
            encoding="utf-8",
        )
        (self.root / "obsidian-vault" / "harness-failures").mkdir()
        (self.root / "obsidian-vault" / "knowledge-gaps").mkdir()
        (self.root / "obsidian-vault" / "harness-failures" / "INDEX.md").write_text("# harness\n", encoding="utf-8")
        (self.root / "obsidian-vault" / "knowledge-gaps" / "INDEX.md").write_text("# gaps\n", encoding="utf-8")
        (self.root / "docs" / "SHARED_MEMORY_INDEX_2026-05-05.md").write_text("# index\n", encoding="utf-8")
        (self.root / "reports" / "shared_memory_index_2026-05-05.json").write_text("{}\n", encoding="utf-8")
        (self.root / "docs" / "MEMORY_BRIEF_2026-05-05.md").write_text("# brief\n", encoding="utf-8")
        (self.root / "reports" / "memory_brief_2026-05-05.json").write_text(
            json.dumps(
                {
                    "briefs": [
                        {
                            "category": "audit_handoff",
                            "objects_by_source_category": {
                                "current_state": [
                                    {
                                        "source_path": "docs/CURRENT_STATE.md",
                                        "key_points": [
                                            "**GitHub state:** `main` is at PR #638. PR #605 remains the continuation",
                                            "**Memory/model takeover state:** shared-memory indexing, compact memory",
                                        ],
                                    }
                                ],
                                "goal_loop": [
                                    {
                                        "source_path": "docs/GOAL_LOOP_STATUS_2026-05-05.md",
                                        "key_points": [
                                            "Goal status: `active_continuous_loop`",
                                            "Terminal completion allowed: `False`",
                                        ],
                                    }
                                ],
                                "model_handoff": [
                                    {
                                        "source_path": "reports/memory_audit_packet_status_2026-05-05.json",
                                        "counts": {"blocked_items_count": 8},
                                    }
                                ],
                                "operational_memory_day_to_day": [
                                    {
                                        "source_path": "reports/operational_memory_day_to_day_2026-05-05.json",
                                        "counts": {"dispatch_blocker_count": 18},
                                    }
                                ],
                            },
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        (self.root / "reports" / "goal_loop_status_2026-05-05.json").write_text(
            json.dumps({"goal_policy": {"status": "active_continuous_loop", "terminal_completion_allowed": False}}),
            encoding="utf-8",
        )
        (self.root / "reports" / "known_limitations_dispatch_2026-05-05.json").write_text(
            json.dumps(
                {
                    "branch": "continuation-plan",
                    "blocked_backlog": ["KLBQ-002", "KLBQ-004"],
                    "top_ready_now": ["KLBQ-001", "KLBQ-006", "KLBQ-008"],
                    "summary": {"blocked_total": 2},
                    "loop_schedule": [
                        {
                            "loop_index": 1,
                            "items": ["KLBQ-001", "KLBQ-006", "KLBQ-008"],
                            "lanes": ["harness_execution", "commit_mining", "memory_handoff"],
                            "total_expected_loop_cost": 3,
                        }
                    ],
                    "work_items": [
                        {
                            "limitation_id": "KLBQ-002",
                            "dispatch_lane": "blocked_needs_source",
                            "blocker": "Missing exact local source roots.",
                            "next_action": "Acquire exact local source roots.",
                            "dispatch_ready": False,
                        },
                        {
                            "limitation_id": "KLBQ-004",
                            "dispatch_lane": "blocked_needs_user_input",
                            "blocker": "Harness commands are still prose.",
                            "next_action": "Emit exact local harness commands.",
                            "dispatch_ready": False,
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        (self.root / "reports" / "known_limitations_harness_memory_status_2026-05-05.json").write_text(
            json.dumps(
                {
                    "schema": "auditooor.known_limitations_harness_memory_status.v1",
                    "summary": {"open_focus_row_count": 1, "open_rows_with_actionable_now_commands": 1},
                    "open_focus_rows": [
                        {
                            "id": "KLBQ-006",
                            "dispatch_lane": "harness_execution",
                            "current_status": "partially_implemented_v0_partial_pass",
                            "next_action": "Run executable status refresh.",
                            "next_action_status": "actionable_now_with_blocked_followups",
                            "actionable_now_commands": ["python3 tools/known-limitations-harness-memory-status.py --output reports/known_limitations_harness_memory_status_2026-05-05.json"],
                            "blocked_command_templates": [
                                {
                                    "command": "forge test --root <renft-source-root>",
                                    "missing_inputs": ["<renft-source-root>"],
                                }
                            ],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        (self.root / "obsidian-vault" / "dispatch" / "next_dispatch_manifest.preview.json").write_text(
            json.dumps(
                {
                    "dispatchable": False,
                    "candidate_count": 168,
                    "emitted": [
                        {
                            "slot_id": "slot-1",
                            "category": "scanner-wiring",
                            "gap_id": "SCANNER-WIRING-333",
                            "dispatchable": False,
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        (self.root / "obsidian-vault" / "gap-analysis" / "2026-05-05.md").write_text(
            "# gap analysis\n",
            encoding="utf-8",
        )
        (self.root / "obsidian-vault" / "gap-analysis" / "candidates.jsonl").write_text(
            json.dumps(
                {
                    "gap_id": "G1-001",
                    "category": "G1",
                    "title": "Uncategorized detector blindspots need taxonomy assignment",
                    "priority_score": 2.1,
                    "remediation": "Refine BUG_CLASSES.",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        for script in (
            "shared-memory-index.py",
            "memory-brief.py",
            "vault-mcp-server.py",
            "obsidian-vault-emit.py",
            "obsidian-vault-sync.py",
        ):
            (self.root / "tools" / script).write_text("#!/usr/bin/env python3\n", encoding="utf-8")
        (self.root / "Makefile").write_text(
            "vault-refresh:\n"
            "vault-status:\n"
            "vault-mcp-server:\n"
            "vault-mcp-self-test:\n"
            "shared-memory-index:\n"
            "memory-brief:\n",
            encoding="utf-8",
        )

    def tearDown(self):
        for key, value in self.old_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self.tmp.cleanup()

    def test_build_report_finds_core_entrypoints(self):
        mod = load_tool()
        report = mod.build_report(self.root)

        self.assertEqual(report["schema"], "auditooor.obsidian_memory_entrypoints.v1")
        self.assertFalse(report["network_used"])
        self.assertFalse(report["gui_opened"])
        self.assertEqual(report["primary_vault"]["path"], str((self.root / "obsidian-vault").resolve()))
        self.assertEqual(report["memory_root"], str(self.root.resolve()))
        self.assertEqual(report["memory_branch"], "fresh-memory-root")
        self.assertEqual(report["active_vault"], str(mod.DEFAULT_ACTIVE_VAULT))
        self.assertIn("CLI open", report["human_answer"])
        self.assertIn("Markdown", report["non_obsidian_usage"])
        self.assertGreaterEqual(report["entrypoint_counts"]["key_vault_files"]["present"], 3)
        self.assertEqual(report["entrypoint_counts"]["workspace_vault_files"]["present"], 7)
        self.assertEqual(report["entrypoint_counts"]["shared_memory_entrypoints"]["present"], 3)
        self.assertEqual(report["entrypoint_counts"]["memory_brief_entrypoints"]["present"], 3)
        self.assertEqual(report["entrypoint_counts"]["mcp_commands"]["available"], 4)
        self.assertEqual(report["operational_snapshot"]["active_blockers"]["blocked_backlog"], ["KLBQ-002", "KLBQ-004"])
        self.assertEqual(report["operational_snapshot"]["priority_order"], ["MEMORY", "HARNESS", "KNOWN LIMITATION BURNDOWN"])
        self.assertEqual(report["operational_snapshot"]["active_blockers"]["harness_memory_actionable_open_rows"], 1)
        self.assertEqual(
            report["operational_snapshot"]["active_blockers"]["harness_memory_actionability"][0]["next_action_status"],
            "actionable_now_with_blocked_followups",
        )
        self.assertEqual(report["operational_snapshot"]["next_loop"]["dispatch_preview"]["candidate_count"], 168)
        self.assertEqual(report["operational_snapshot"]["pr_605_handoff"]["branch"], "fresh-memory-root")
        self.assertEqual(
            report["operational_snapshot"]["pr_605_handoff"]["source_branch_from_known_limitations"],
            "continuation-plan",
        )
        self.assertTrue(
            any(row["scope"] == "known_limitations_branch_mismatch" for row in report["stale_source_guards"])
        )
        self.assertTrue(
            any(row["scope"] == "external_active_vault_freshness" for row in report["stale_source_guards"])
        )
        self.assertEqual(report["freshness_summary"]["operational_status"], "READY")
        self.assertEqual(report["freshness_summary"]["blocking_count"], 0)
        self.assertTrue(all(not row["blocking"] for row in report["stale_source_guards"]))

    def test_cli_writes_json_and_markdown(self):
        json_out = self.root / "reports" / "entrypoints.json"
        md_out = self.root / "docs" / "entrypoints.md"

        subprocess.run(
            [
                sys.executable,
                str(TOOL),
                "--repo-root",
                str(self.root),
                "--output",
                str(json_out),
                "--markdown-output",
                str(md_out),
            ],
            check=True,
            text=True,
            capture_output=True,
            env={**os.environ},
        )

        report = json.loads(json_out.read_text(encoding="utf-8"))
        self.assertEqual(report["schema"], "auditooor.obsidian_memory_entrypoints.v1")
        markdown = md_out.read_text(encoding="utf-8")
        self.assertIn("Active vault: `/Users/wolf/Documents/Codex/auditooor/obsidian-vault`", markdown)
        self.assertIn("Obsidian vault folder", markdown)
        self.assertIn("may not register the vault in Obsidian", markdown)
        self.assertIn("Without Obsidian", markdown)
        self.assertIn("Memory/control-plane branch: `fresh-memory-root`", markdown)
        self.assertIn("make vault-mcp-server", markdown)
        self.assertIn("## Current Loop", markdown)
        self.assertIn("PR #605 remains the continuation", markdown)
        self.assertIn("## Active Blockers", markdown)
        self.assertIn("## Priority Order", markdown)
        self.assertIn("MEMORY > HARNESS > KNOWN LIMITATION BURNDOWN", markdown)
        self.assertIn("actionable_now_with_blocked_followups", markdown)
        self.assertIn("## Freshness Guards", markdown)
        self.assertIn("No blocking stale-memory guards", markdown)
        self.assertIn("KLBQ-002", markdown)
        self.assertIn("## PR #605 Handoff", markdown)
        self.assertIn("obsidian-vault/DASHBOARD.md", markdown)

    def test_selected_root_branch_overrides_stale_klbq_handoff_branch(self):
        mod = load_tool()
        report = mod.build_report(self.root)

        self.assertEqual(report["memory_root"], str(self.root.resolve()))
        self.assertEqual(report["memory_branch"], "fresh-memory-root")
        self.assertEqual(report["operational_snapshot"]["branch"], "fresh-memory-root")
        self.assertEqual(report["operational_snapshot"]["pr_605_handoff"]["branch"], "fresh-memory-root")
        self.assertIn("KLBQ-004", report["operational_snapshot"]["active_blockers"]["blocked_backlog"])


if __name__ == "__main__":
    unittest.main()
