from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "lesson-promotion-review-queue.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("lesson_promotion_review_queue_test", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


class LessonPromotionReviewQueueTests(unittest.TestCase):
    def test_build_queue_preserves_review_boundaries(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "case_study").mkdir()
            (root / "case_study" / "one.md").write_text("Lesson: admin action is prerequisite.\n", encoding="utf-8")
            (root / "case_study" / "two.md").write_text("Lesson: temporary DoS is capped.\n", encoding="utf-8")
            (root / ".auditooor").mkdir()
            write_json(
                root / ".auditooor" / "agent_artifact_lesson_candidates.json",
                {
                    "schema": "auditooor.agent_artifact_lesson_candidates.v1",
                    "advisory_only": True,
                    "promotion_authority": False,
                    "candidates": [
                        {
                            "candidate_id": "aalc-demo",
                            "title": "Agent proof lesson",
                            "lesson_kind": "proof_artifact",
                            "lesson_statement": "Candidate lesson to review: proof claims need manifests.",
                            "evidence_tier": "primary",
                            "confidence": "high",
                            "confidence_score": 0.86,
                            "candidate_truth_claim": False,
                            "provenance": [{"path": "agent_outputs/demo.md", "source_type": "agent_outputs_summary"}],
                        }
                    ],
                },
            )
            inventory = {
                "schema": "auditooor.lesson_source_inventory.v1",
                "root": str(root),
                "workspace": "",
                "coverage_blockers": [
                    {
                        "code": "lesson_source_requires_promotion_review",
                        "source_kind": "case_study",
                        "path": "case_study",
                        "lesson_candidates": 2,
                        "admissibility": "candidate_hard_requires_review",
                        "gate_role": "candidate_lesson_promotion_queue",
                        "reason": "case studies require review",
                    },
                    {
                        "code": "lesson_source_requires_promotion_review",
                        "source_kind": "agent_artifacts",
                        "path": ".auditooor",
                        "lesson_candidates": 1,
                        "admissibility": "candidate_hard_requires_human_review",
                        "gate_role": "agent_learning_candidate_queue",
                        "reason": "agent artifacts require review",
                    },
                ],
                "rows": [
                    {
                        "source_kind": "case_study",
                        "path": "case_study",
                        "records_seen": 1,
                        "lesson_candidates": 2,
                        "compiled_predicates": ["admin_or_team_action_prerequisite"],
                        "compiled_predicate_count": 1,
                        "source_refs": ["case_study/one.md"],
                    },
                    {
                        "source_kind": "agent_artifacts",
                        "path": ".auditooor",
                        "records_seen": 2,
                        "lesson_candidates": 1,
                        "compiled_predicates": [],
                        "compiled_predicate_count": 0,
                        "source_refs": [".auditooor/agent_artifact_lesson_candidates.json"],
                    },
                ],
            }

            payload = tool.build_queue(inventory, root=root, inventory_path=root / "inventory.json", limit=10)
            decisions = tool.build_decisions(payload, root=root)

        self.assertEqual(payload["schema"], tool.SCHEMA)
        self.assertTrue(payload["advisory_only"])
        self.assertFalse(payload["promotion_authority"])
        self.assertFalse(payload["truth_claims_made"])
        self.assertFalse(payload["agent_artifact_direct_hard_gate_promotion_allowed"])
        self.assertEqual(payload["summary"]["coverage_blockers_seen"], 2)
        self.assertEqual(payload["summary"]["coverage_blockers_resolved_by_queue"], 0)
        self.assertEqual(payload["summary"]["coverage_blockers_remaining"], 2)
        self.assertEqual(payload["summary"]["packets_emitted"], 3)
        self.assertEqual(payload["summary"]["by_source_kind"]["case_study"], 2)
        by_kind = {}
        for packet in payload["packets"]:
            by_kind.setdefault(packet["source_kind"], packet)
        case_packet = by_kind["case_study"]
        self.assertTrue(case_packet["hard_gate_after_review_possible"])
        self.assertFalse(case_packet["direct_hard_gate_promotion_allowed"])
        self.assertEqual(case_packet["quarantine_boundary"], "candidate_review_until_curated")
        agent_packet = by_kind["agent_artifacts"]
        self.assertFalse(agent_packet["hard_gate_after_review_possible"])
        self.assertFalse(agent_packet["agent_artifact_direct_hard_gate_promotion_allowed"])
        self.assertEqual(agent_packet["quarantine_boundary"], "agent_artifact_review_quarantine")
        self.assertEqual(agent_packet["candidate"]["candidate_id"], "aalc-demo")
        self.assertFalse(agent_packet["candidate"]["candidate_truth_claim"])
        self.assertEqual(decisions["schema"], tool.DECISIONS_SCHEMA)
        self.assertEqual(decisions["summary"]["decisions"], 3)
        self.assertEqual(decisions["summary"]["decision_counts"], {"NO_ACTION": 3})
        self.assertEqual(decisions["summary"]["terminal_agent_artifact_decisions"], 1)
        self.assertTrue(all(row["agent_artifact_claim_trusted"] is False for row in decisions["decisions"]))
        agent_decision = [row for row in decisions["decisions"] if row["source_kind"] == "agent_artifacts"][0]
        self.assertEqual(agent_decision["source_ref"], "aalc-demo")
        self.assertEqual(agent_decision["decision_outcome"], "NO_ACTION")
        self.assertFalse(agent_decision["direct_hard_gate_promotion_allowed"])

    def test_case_study_frontmatter_promotes_to_curated_lesson_decision(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "case_study").mkdir()
            (root / "case_study" / "reviewed.md").write_text(
                """---
case_id: reviewed-case
extracted_lesson: >
  Admin action prerequisite must not be reported as permissionless attacker reachability.
stop_criterion: >
  STOP drafting until owner-only setup is removed from the attacker path.
---
# Reviewed
""",
                encoding="utf-8",
            )
            inventory = {
                "schema": "auditooor.lesson_source_inventory.v1",
                "root": str(root),
                "workspace": "",
                "coverage_blockers": [
                    {
                        "code": "lesson_source_requires_promotion_review",
                        "source_kind": "case_study",
                        "path": "case_study",
                        "lesson_candidates": 1,
                        "admissibility": "candidate_hard_requires_review",
                        "gate_role": "candidate_lesson_promotion_queue",
                        "reason": "case studies require review",
                    }
                ],
                "rows": [
                    {
                        "source_kind": "case_study",
                        "path": "case_study",
                        "records_seen": 1,
                        "lesson_candidates": 1,
                        "compiled_predicates": ["admin_or_team_action_prerequisite"],
                        "compiled_predicate_count": 1,
                        "source_refs": ["case_study/reviewed.md"],
                    }
                ],
            }

            payload = tool.build_queue(inventory, root=root, inventory_path=root / "inventory.json", limit=10)
            decisions = tool.build_decisions(payload, root=root)

        self.assertEqual(decisions["summary"]["decision_counts"], {"CURATED_LESSON": 1})
        decision = decisions["decisions"][0]
        self.assertEqual(decision["decision_outcome"], "CURATED_LESSON")
        self.assertTrue(decision["terminal_for_source_coverage"])
        self.assertEqual(decision["curated_lesson"]["compiled_predicates"], ["admin_or_team_action_prerequisite"])
        self.assertFalse(decision["hard_gate_changes"])

    def test_agent_artifact_primary_anchor_requires_human_primary_review(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".auditooor").mkdir()
            write_json(
                root / ".auditooor" / "agent_artifact_lesson_candidates.json",
                {
                    "schema": "auditooor.agent_artifact_lesson_candidates.v1",
                    "candidates": [
                        {
                            "candidate_id": "aalc-primary",
                            "title": "Primary proof candidate",
                            "lesson_kind": "proof_artifact",
                            "lesson_statement": "Candidate lesson to review: execution manifests need exact impact binding.",
                            "evidence_tier": "primary",
                            "confidence": "high",
                            "candidate_truth_claim": False,
                            "provenance": [
                                {
                                    "path": ".auditooor/agent_artifact_mining_report.json",
                                    "artifact_provenance_ref": "poc_execution/demo/execution_manifest.json",
                                    "source_type": "agent_artifact_mining_report",
                                }
                            ],
                        }
                    ],
                },
            )
            inventory = {
                "schema": "auditooor.lesson_source_inventory.v1",
                "root": str(root),
                "workspace": "",
                "coverage_blockers": [
                    {
                        "code": "lesson_source_requires_promotion_review",
                        "source_kind": "agent_artifacts",
                        "path": ".auditooor",
                        "lesson_candidates": 1,
                        "admissibility": "candidate_hard_requires_human_review",
                        "gate_role": "agent_learning_candidate_queue",
                        "reason": "agent artifacts require review",
                    }
                ],
                "rows": [
                    {
                        "source_kind": "agent_artifacts",
                        "path": ".auditooor",
                        "records_seen": 1,
                        "lesson_candidates": 1,
                        "compiled_predicates": [],
                        "compiled_predicate_count": 0,
                        "source_refs": [".auditooor/agent_artifact_lesson_candidates.json"],
                    }
                ],
            }

            payload = tool.build_queue(inventory, root=root, inventory_path=root / "inventory.json", limit=10)
            decisions = tool.build_decisions(payload, root=root)

        self.assertEqual(decisions["summary"]["decision_counts"], {"NEEDS_HUMAN_PRIMARY_REVIEW": 1})
        decision = decisions["decisions"][0]
        self.assertEqual(decision["source_kind"], "agent_artifacts")
        self.assertEqual(decision["source_ref"], "aalc-primary")
        self.assertTrue(decision["terminal_for_source_coverage"])
        self.assertTrue(decision["primary_anchor"])
        self.assertFalse(decision["promotion_authority"])
        self.assertFalse(decision["hard_gate_changes"])

    def test_merge_decisions_preserves_other_source_kind_reviews(self) -> None:
        tool = load_tool()
        existing = {
            "schema": tool.DECISIONS_SCHEMA,
            "decisions": [
                {
                    "source_kind": "case_study",
                    "source_ref": "case_study/one.md",
                    "decision_outcome": "NO_ACTION",
                    "terminal_for_source_coverage": True,
                }
            ],
        }
        new = {
            "schema": tool.DECISIONS_SCHEMA,
            "decisions": [
                {
                    "source_kind": "agent_artifacts",
                    "source_ref": "aalc-one",
                    "decision_outcome": "NO_ACTION",
                    "terminal_for_source_coverage": True,
                }
            ],
        }

        merged = tool.merge_decisions(existing, new)

        self.assertEqual(merged["summary"]["decisions"], 2)
        self.assertEqual(merged["summary"]["terminal_case_study_decisions"], 1)
        self.assertEqual(merged["summary"]["terminal_agent_artifact_decisions"], 1)
        self.assertEqual(merged["summary"]["decision_counts"], {"NO_ACTION": 2})

    def test_cli_writes_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            inventory_path = root / "inventory.json"
            out_json = root / "queue.json"
            out_md = root / "queue.md"
            out_decisions = root / "decisions.json"
            (root / "case_study").mkdir()
            (root / "case_study" / "one.md").write_text("Lesson: temporary DoS is capped.\n", encoding="utf-8")
            write_json(
                inventory_path,
                {
                    "schema": "auditooor.lesson_source_inventory.v1",
                    "root": str(root),
                    "workspace": "",
                    "coverage_blockers": [
                        {
                            "code": "lesson_source_requires_promotion_review",
                            "source_kind": "case_study",
                            "path": "case_study",
                            "lesson_candidates": 1,
                            "admissibility": "candidate_hard_requires_review",
                            "gate_role": "candidate_lesson_promotion_queue",
                            "reason": "case studies require review",
                        }
                    ],
                    "rows": [
                        {
                            "source_kind": "case_study",
                            "path": "case_study",
                            "records_seen": 1,
                            "lesson_candidates": 1,
                            "compiled_predicates": ["low_severity_cap_triggered"],
                            "compiled_predicate_count": 1,
                            "source_refs": ["case_study/one.md"],
                        }
                    ],
                },
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--root",
                    str(root),
                    "--inventory",
                    str(inventory_path),
                    "--out-json",
                    str(out_json),
                    "--out-md",
                    str(out_md),
                    "--out-decisions",
                    str(out_decisions),
                    "--json",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            payload = json.loads(proc.stdout)
            written = json.loads(out_json.read_text(encoding="utf-8"))
            markdown = out_md.read_text(encoding="utf-8")
            decisions = json.loads(out_decisions.read_text(encoding="utf-8"))

        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(payload["schema"], "auditooor.lesson_promotion_review_queue.v1")
        self.assertEqual(written["summary"]["packets_emitted"], 1)
        self.assertIn("Lesson Promotion Review Queue", markdown)
        self.assertIn("LPR-CS-001", markdown)
        self.assertEqual(decisions["schema"], "auditooor.lesson_source_decisions.v1")
        self.assertEqual(decisions["summary"]["decisions"], 1)


if __name__ == "__main__":
    unittest.main()
