from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "lesson-source-inventory.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("lesson_source_inventory_test", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class LessonSourceInventoryTests(unittest.TestCase):
    def test_inventory_separates_default_gates_from_promotion_candidates(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            (root / "reference").mkdir(parents=True)
            (root / "reference" / "curated_lessons.jsonl").write_text(
                json.dumps({"lesson": "Severity is capped to Low because no material loss."}) + "\n",
                encoding="utf-8",
            )
            (root / "reference" / "outcomes.jsonl").write_text(
                json.dumps({"rejection_reason": "No attacker profit; gas cost exceeds value."}) + "\n",
                encoding="utf-8",
            )
            (root / "reference" / "triager_patterns.md").write_text(
                "Requires admin action; onlyOwner team action prerequisite.\n",
                encoding="utf-8",
            )
            (root / "case_study").mkdir()
            (root / "case_study" / "lesson.md").write_text(
                "Generic DoS scope risk: temporary DoS is out of scope.\n",
                encoding="utf-8",
            )
            (root / "reference" / "corpus_mined").mkdir()
            (root / "reference" / "corpus_mined" / "slice.md").write_text(
                "Ambient MEV only is not a protocol bug.\n",
                encoding="utf-8",
            )
            (root / "audit" / "corpus_tags" / "tags" / "bridge" / "demo").mkdir(parents=True)
            (root / "audit" / "corpus_tags" / "tags" / "bridge" / "demo" / "record.json").write_text(
                json.dumps({"record_id": "bridge.demo", "attack_class": "bridge-replay"}),
                encoding="utf-8",
            )
            (workspace / ".auditooor").mkdir(parents=True)
            (workspace / ".auditooor" / "agent_artifact_mining_report.json").write_text(
                json.dumps({"total_artifacts": 2, "artifact_type_counts": {"report": 2}}),
                encoding="utf-8",
            )
            (workspace / ".auditooor" / "agent_artifact_lesson_candidates.json").write_text(
                json.dumps({"candidates": [{"candidate_id": "a1"}]}),
                encoding="utf-8",
            )

            payload = tool.build_inventory(root, workspace=workspace, max_compile_files=10)

        rows = {row["source_kind"]: row for row in payload["rows"]}
        self.assertEqual(payload["schema"], tool.SCHEMA)
        self.assertTrue(payload["offline_only"])
        self.assertFalse(payload["network_access"])
        self.assertEqual(payload["summary"]["default_enforcement_sources"], 3)
        self.assertIn("curated_lessons", rows)
        self.assertTrue(rows["curated_lessons"]["included_in_default_lesson_enforcement"])
        self.assertIn("outcomes", rows)
        self.assertTrue(rows["outcomes"]["included_in_default_lesson_enforcement"])
        self.assertIn("triager_patterns", rows)
        self.assertTrue(rows["triager_patterns"]["included_in_default_lesson_enforcement"])
        self.assertIn("case_study", rows)
        self.assertFalse(rows["case_study"]["included_in_default_lesson_enforcement"])
        self.assertIn("agent_artifacts", rows)
        self.assertEqual(rows["agent_artifacts"]["records_seen"], 2)
        self.assertEqual(rows["agent_artifacts"]["lesson_candidates"], 1)
        self.assertIn("hackerman_corpus_tags", rows)
        self.assertEqual(rows["hackerman_corpus_tags"]["records_seen"], 1)
        blocker_kinds = {row["source_kind"] for row in payload["coverage_blockers"]}
        self.assertIn("case_study", blocker_kinds)
        self.assertIn("agent_artifacts", blocker_kinds)

    def test_first_class_corpus_families_are_context_or_candidate_only(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "reference" / "patterns.dsl.test").mkdir(parents=True)
            (root / "reference" / "patterns.dsl.test" / "missing-auth.yaml").write_text(
                "name: missing-auth\nseverity: high\n",
                encoding="utf-8",
            )
            (root / "reference" / "corpus_txt" / "auditor").mkdir(parents=True)
            (root / "reference" / "corpus_txt" / "auditor" / "report.txt").write_text(
                "Generic DoS scope risk: temporary DoS is out of scope.\n",
                encoding="utf-8",
            )
            (root / "audit" / "corpus_tags" / "derived" / "exploit_predicates.d").mkdir(parents=True)
            (root / "audit" / "corpus_tags" / "derived" / "exploit_predicates.d" / "shard-00000.jsonl").write_text(
                json.dumps({"record_id": "p1", "predicate": "attacker_can_trigger"}) + "\n",
                encoding="utf-8",
            )
            (root / "provider_outputs" / "slice").mkdir(parents=True)
            (root / "provider_outputs" / "slice" / "kimi.source-extract.out.txt").write_text(
                "Requires admin action; onlyOwner team action prerequisite.\n",
                encoding="utf-8",
            )
            nested = root / ".auditooor" / "provider_fanout" / "campaign" / "runs" / "run-1" / "provider_outputs"
            nested.mkdir(parents=True)
            (nested / "minimax.out.txt").write_text(
                "Provider advisory: no local source proof; route to local verification.\n",
                encoding="utf-8",
            )

            payload = tool.build_inventory(root, max_compile_files=10)

        rows = {row["source_kind"]: row for row in payload["rows"]}
        for source_kind in (
            "reference_patterns_dsl",
            "reference_corpus_txt",
            "exploit_predicates",
            "provider_outputs",
        ):
            self.assertIn(source_kind, rows)
            self.assertFalse(rows[source_kind]["included_in_default_lesson_enforcement"])

        self.assertEqual(rows["reference_patterns_dsl"]["records_seen"], 1)
        self.assertEqual(rows["reference_corpus_txt"]["lesson_candidates"], 1)
        self.assertEqual(rows["exploit_predicates"]["records_seen"], 1)
        self.assertEqual(rows["provider_outputs"]["records_seen"], 2)
        self.assertEqual(rows["provider_outputs"]["lesson_candidates"], 0)
        self.assertEqual(rows["provider_outputs"]["compiled_predicates"], [])
        self.assertIn(
            ".auditooor/provider_fanout/campaign/runs/run-1/provider_outputs",
            rows["provider_outputs"]["provider_output_roots"],
        )
        blocker_kinds = {row["source_kind"] for row in payload["coverage_blockers"]}
        self.assertNotIn("reference_patterns_dsl", blocker_kinds)
        self.assertNotIn("reference_corpus_txt", blocker_kinds)
        self.assertNotIn("exploit_predicates", blocker_kinds)
        self.assertNotIn("provider_outputs", blocker_kinds)

    def test_cli_writes_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "out.json"
            (root / "reference").mkdir()
            (root / "reference" / "outcomes.jsonl").write_text(
                json.dumps({"reason": "Severity is capped to Low because no material loss."}) + "\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [sys.executable, str(TOOL), "--root", str(root), "--out-json", str(out), "--json"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            written = json.loads(out.read_text(encoding="utf-8"))

        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema"], "auditooor.lesson_source_inventory.v1")
        self.assertEqual(written["schema"], payload["schema"])
        self.assertEqual(payload["summary"]["default_enforcement_sources"], 1)

    def test_terminal_case_study_decisions_resolve_case_study_blocker_only(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            decisions = root / ".auditooor" / "lesson_source_decisions.json"
            (root / "reference").mkdir(parents=True)
            (root / "reference" / "outcomes.jsonl").write_text(
                json.dumps({"rejection_reason": "No attacker profit; gas cost exceeds value."}) + "\n",
                encoding="utf-8",
            )
            (root / "case_study").mkdir()
            (root / "case_study" / "lesson.md").write_text(
                "Generic DoS scope risk: temporary DoS is out of scope.\n",
                encoding="utf-8",
            )
            (workspace / ".auditooor").mkdir(parents=True)
            (workspace / ".auditooor" / "agent_artifact_lesson_candidates.json").write_text(
                json.dumps({"candidates": [{"candidate_id": "a1"}]}),
                encoding="utf-8",
            )
            decisions.parent.mkdir(parents=True)
            decisions.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.lesson_source_decisions.v1",
                        "decisions": [
                            {
                                "source_kind": "case_study",
                                "source_ref": "case_study/lesson.md",
                                "decision_outcome": "NO_ACTION",
                                "terminal_for_source_coverage": True,
                                "agent_artifact_claim_trusted": False,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            payload = tool.build_inventory(root, workspace=workspace, max_compile_files=10, decisions_path=decisions)

        blockers = {row["source_kind"]: row for row in payload["coverage_blockers"]}
        rows = {row["source_kind"]: row for row in payload["rows"]}
        self.assertNotIn("case_study", blockers)
        self.assertIn("agent_artifacts", blockers)
        self.assertEqual(payload["summary"]["coverage_blocker_count"], 1)
        self.assertEqual(rows["case_study"]["lesson_candidates_unresolved"], 0)
        self.assertEqual(rows["case_study"]["review_decisions"]["decision_counts"], {"NO_ACTION": 1})
        self.assertEqual(payload["summary"]["source_decisions"]["terminal_decision_count"], 1)

    def test_terminal_agent_artifact_decisions_resolve_agent_artifact_blocker(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            decisions = root / ".auditooor" / "lesson_source_decisions.json"
            (root / "reference").mkdir(parents=True)
            (root / "reference" / "outcomes.jsonl").write_text(
                json.dumps({"rejection_reason": "No attacker profit; gas cost exceeds value."}) + "\n",
                encoding="utf-8",
            )
            (workspace / ".auditooor").mkdir(parents=True)
            (workspace / ".auditooor" / "agent_artifact_lesson_candidates.json").write_text(
                json.dumps({"candidates": [{"candidate_id": "aalc-secondary"}, {"candidate_id": "aalc-primary"}]}),
                encoding="utf-8",
            )
            decisions.parent.mkdir(parents=True)
            decisions.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.lesson_source_decisions.v1",
                        "decisions": [
                            {
                                "source_kind": "agent_artifacts",
                                "source_ref": "aalc-secondary",
                                "decision_outcome": "NO_ACTION",
                                "terminal_for_source_coverage": True,
                                "agent_artifact_claim_trusted": False,
                            },
                            {
                                "source_kind": "agent_artifacts",
                                "source_ref": "aalc-primary",
                                "decision_outcome": "NEEDS_HUMAN_PRIMARY_REVIEW",
                                "terminal_for_source_coverage": True,
                                "agent_artifact_claim_trusted": False,
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            payload = tool.build_inventory(root, workspace=workspace, max_compile_files=10, decisions_path=decisions)

        blockers = {row["source_kind"]: row for row in payload["coverage_blockers"]}
        rows = {row["source_kind"]: row for row in payload["rows"]}
        self.assertNotIn("agent_artifacts", blockers)
        self.assertEqual(rows["agent_artifacts"]["lesson_candidates_unresolved"], 0)
        self.assertEqual(
            rows["agent_artifacts"]["review_decisions"]["decision_counts"],
            {"NEEDS_HUMAN_PRIMARY_REVIEW": 1, "NO_ACTION": 1},
        )
        self.assertEqual(payload["summary"]["coverage_blocker_count"], 0)


if __name__ == "__main__":
    unittest.main()
