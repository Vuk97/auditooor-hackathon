from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "lesson-enforcement-inventory.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("lesson_enforcement_inventory_test", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class LessonEnforcementInventoryTests(unittest.TestCase):
    def test_inventory_scans_json_and_markdown_into_enforcement_rows(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "feedback.md").write_text(
                "- no attacker profit; gas cost exceeds value\n"
                "- requires admin action; onlyOwner team action prerequisite\n",
                encoding="utf-8",
            )
            (root / "outcomes.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "id": "o1",
                                "triager_feedback": "Generic DoS scope risk: temporary DoS is out of scope.",
                            },
                            {
                                "id": "o2",
                                "triager_feedback": (
                                    "Late entrants only participate in future reward-stream emissions; "
                                    "this does not prove accrued reward dilution."
                                ),
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            payload = tool.build_inventory([root], max_lessons=20)

        predicates = {row["predicate"] for row in payload["enforcement_rows"]}
        self.assertEqual(payload["schema"], tool.SCHEMA)
        self.assertEqual(payload["schema_version"], tool.SCHEMA_VERSION)
        self.assertTrue(payload["offline_only"])
        self.assertFalse(payload["network_access"])
        self.assertEqual(payload["summary"]["files_scanned"], 2)
        self.assertIn("economic_viability_missing", predicates)
        self.assertIn("admin_or_team_action_prerequisite", predicates)
        self.assertIn("generic_dos_scope_risk", predicates)
        self.assertIn("future_reward_eligibility_not_accrued_reward_loss", predicates)
        self.assertGreaterEqual(payload["summary"]["enforcement_level_counts"]["hard_pre_poc"], 2)
        self.assertGreaterEqual(payload["summary"]["enforcement_level_counts"]["hard_pre_submit"], 1)

    def test_curated_lessons_default_sink_affects_inventory_counts(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            outcome = root / "outcomes.jsonl"
            curated = root / "curated_lessons.jsonl"
            outcome.write_text(
                json.dumps({"rejection_reason": "No attacker profit; gas cost exceeds value."}) + "\n",
                encoding="utf-8",
            )
            curated.write_text(
                json.dumps({"lesson": "Requires admin action; onlyOwner team action prerequisite."}) + "\n",
                encoding="utf-8",
            )

            baseline = tool.build_inventory([outcome], max_lessons=20)
            with_curated = tool.build_inventory([outcome, curated], max_lessons=20)

        self.assertIn("curated_lessons.jsonl", {path.name for path in tool.DEFAULT_INPUTS})
        self.assertEqual(baseline["summary"]["lessons_compiled"], 1)
        self.assertEqual(with_curated["summary"]["lessons_compiled"], 2)
        self.assertEqual(with_curated["summary"]["predicate_counts"]["admin_or_team_action_prerequisite"], 1)
        self.assertIn(str(curated.resolve()), with_curated["source_files"])

    def test_default_curated_lessons_activate_reserve_reward_stream_gate(self) -> None:
        tool = load_tool()

        payload = tool.build_inventory([ROOT / "reference" / "curated_lessons.jsonl"], max_lessons=20)

        self.assertIn(
            "future_reward_eligibility_not_accrued_reward_loss",
            payload["summary"]["predicate_counts"],
        )
        row = next(
            row
            for row in payload["enforcement_rows"]
            if row["predicate"] == "future_reward_eligibility_not_accrued_reward_loss"
        )
        self.assertEqual(row["enforcement_level"], "hard_pre_poc")

    def test_inventory_bounds_files_and_skips_unsupported_suffixes(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.md").write_text("no attacker profit\n", encoding="utf-8")
            (root / "b.txt").write_text("severity is capped to Low\n", encoding="utf-8")
            (root / "ignore.csv").write_text("generic DoS is out of scope\n", encoding="utf-8")

            files, warnings, truncated = tool.iter_input_files([root], max_files=1)
            payload = tool.build_inventory([root], max_files=1, max_lessons=10)

        self.assertEqual(len(files), 1)
        self.assertTrue(truncated)
        self.assertFalse(warnings)
        self.assertEqual(payload["summary"]["files_scanned"], 1)
        self.assertTrue(payload["summary"]["file_limit_truncated"])
        self.assertEqual(len(payload["source_files"]), 1)

    def test_cli_json_output_is_read_only_and_has_no_positive_reward_claim(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "lesson.md"
            source.write_text(
                "Paid $9000 bounty.\n\n"
                "Severity is capped to Low because no material loss.\n",
                encoding="utf-8",
            )

            proc = subprocess.run(
                [sys.executable, str(TOOL), str(root), "--json"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            after = source.read_text(encoding="utf-8")

        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        serialized = json.dumps(payload).lower()
        self.assertIn("low_severity_cap_triggered", payload["summary"]["predicate_counts"])
        self.assertEqual(payload["summary"]["positive_reward_claim_lines_suppressed"], 1)
        self.assertNotIn("paid $9000", serialized)
        self.assertEqual(after, "Paid $9000 bounty.\n\nSeverity is capped to Low because no material loss.\n")


if __name__ == "__main__":
    unittest.main()
