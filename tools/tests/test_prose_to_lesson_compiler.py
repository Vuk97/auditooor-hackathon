from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "prose-to-lesson-compiler.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("prose_to_lesson_compiler_test", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ProseToLessonCompilerTests(unittest.TestCase):
    def test_markdown_classifies_all_required_predicates(self) -> None:
        tool = load_tool()
        text = "\n\n".join(
            [
                "- Triager: lacks attacker profit; gas cost exceeds extractable value.",
                "- Actor mismatch: the attacker is not the intended actor and cannot perform this role.",
                "- Ambient MEV only: normal arbitrage in the mempool is not a protocol bug.",
                "- MEV amplifies a protocol bug: not merely MEV; the contract root cause allows stale settlement.",
                "- Documented mechanics: docs say this is expected behavior and there is no stronger design intent.",
                "- Severity is capped at Low because there is no funds at risk.",
                "- Requires admin action; onlyOwner governance team action is a prerequisite.",
                "- Generic DoS scope risk: temporary DoS via gas griefing is out of scope.",
                "- Reward-token sniping lesson: late entrants only share future reward-stream emissions; "
                "this does not prove accrued reward dilution.",
            ]
        )

        payload = tool.compile_text(text, label="lessons.md", generated_at="2026-05-20T00:00:00+00:00")
        predicates = {row["predicate"] for row in payload["lessons"]}

        self.assertEqual(payload["schema"], tool.SCHEMA)
        self.assertEqual(payload["schema_version"], tool.SCHEMA_VERSION)
        self.assertTrue(payload["offline_only"])
        self.assertFalse(payload["network_access"])
        self.assertTrue(
            {
                "economic_viability_missing",
                "intended_actor_mismatch",
                "ambient_mev_not_protocol_bug",
                "protocol_bug_amplified_by_mev",
                "documented_mechanics_no_stronger_intent",
                "low_severity_cap_triggered",
                "admin_or_team_action_prerequisite",
                "generic_dos_scope_risk",
                "future_reward_eligibility_not_accrued_reward_loss",
            }.issubset(predicates)
        )
        self.assertTrue(all(row["schema_version"] == tool.SCHEMA_VERSION for row in payload["lessons"]))
        self.assertTrue(all(row["promotion_authority"] is False for row in payload["lessons"]))
        self.assertTrue(all(row["submit_ready"] is False for row in payload["lessons"]))

    def test_json_rows_are_supported_and_positive_reward_claims_are_not_surfaced(self) -> None:
        tool = load_tool()
        raw = json.dumps(
            {
                "rows": [
                    {
                        "id": "r1",
                        "triager_feedback": "This lacks attacker profit and cost exceeds value.",
                        "outcome": "rejected",
                    },
                    {
                        "id": "r2",
                        "triager_feedback": "Paid $5000 bounty.",
                        "lesson": "Severity is capped to Low because impact is dust only.",
                    },
                ]
            }
        )

        payload = tool.compile_text(raw, label="fixture.json", generated_at="2026-05-20T00:00:00+00:00")
        serialized = json.dumps(payload).lower()

        self.assertEqual(payload["input"]["format"], "json")
        self.assertEqual(payload["summary"]["predicate_counts"]["economic_viability_missing"], 1)
        self.assertEqual(payload["summary"]["predicate_counts"]["low_severity_cap_triggered"], 1)
        self.assertEqual(payload["summary"]["positive_reward_claim_lines_suppressed"], 1)
        self.assertNotIn("paid $5000", serialized)
        self.assertNotIn("5000 bounty", serialized)

    def test_max_lessons_bounds_output(self) -> None:
        tool = load_tool()
        text = "\n\n".join(
            [
                "lacks attacker profit and gas cost exceeds value",
                "generic DoS scope risk; temporary DoS is out of scope",
                "severity is capped to Low because bounded impact",
            ]
        )

        payload = tool.compile_text(
            text,
            label="bounded.txt",
            max_lessons=2,
            generated_at="2026-05-20T00:00:00+00:00",
        )

        self.assertEqual(len(payload["lessons"]), 2)
        self.assertTrue(payload["summary"]["truncated"])

    def test_cli_accepts_text_file_and_prints_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lesson.txt"
            path.write_text("ambient MEV only; normal trading is not a protocol bug\n", encoding="utf-8")

            proc = subprocess.run(
                [sys.executable, str(TOOL), str(path), "--print-json"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["summary"]["predicate_counts"]["ambient_mev_not_protocol_bug"], 1)

    def test_every_compiled_lesson_carries_output_type_in_j2_vocabulary(self) -> None:
        """J2 regression: every compiled row must declare an output_type from the J2 typed-output
        vocabulary so consumers can route lessons to the correct enforcement target without
        inspecting predicate names."""
        tool = load_tool()
        text = "\n\n".join(
            [
                "- Triager: lacks attacker profit; gas cost exceeds extractable value.",
                "- Severity is capped at Low because there is no funds at risk.",
                "- Requires admin action; onlyOwner governance team action is a prerequisite.",
                "- Generic DoS scope risk: temporary DoS is out of scope.",
                "- Ambient MEV only: normal arbitrage in the mempool is not a protocol bug.",
                "- MEV amplifies a protocol bug: not merely MEV; the contract root cause allows stale settlement.",
                "- Documented mechanics: docs say this is expected behavior and there is no stronger design intent.",
                "- Actor mismatch: the attacker is not the intended actor and cannot perform this role.",
                "- Reward-token sniping lesson: late entrants only share future reward-stream emissions; "
                "this does not prove accrued reward dilution.",
            ]
        )
        payload = tool.compile_text(text, label="j2_routing.md", generated_at="2026-05-22T00:00:00+00:00")

        # Every lesson row must carry output_type.
        for row in payload["lessons"]:
            self.assertIn(
                "output_type",
                row,
                msg=f"lesson row for predicate '{row.get('predicate')}' missing output_type",
            )
            self.assertIn(
                row["output_type"],
                tool.J2_OUTPUT_TYPES,
                msg=f"predicate '{row.get('predicate')}' output_type '{row['output_type']}' not in J2_OUTPUT_TYPES",
            )

        # Predicate catalog must also expose output_type per entry.
        for entry in payload["predicate_catalog"]:
            self.assertIn("output_type", entry, msg=f"catalog entry {entry.get('predicate')} missing output_type")
            self.assertIn(entry["output_type"], tool.J2_OUTPUT_TYPES)

        # Spot-check specific expected output_type values.
        output_types_by_predicate = {row["predicate"]: row["output_type"] for row in payload["lessons"]}
        self.assertEqual(output_types_by_predicate.get("economic_viability_missing"), "economic_viability_rule")
        self.assertEqual(
            output_types_by_predicate.get("future_reward_eligibility_not_accrued_reward_loss"),
            "economic_viability_rule",
        )
        self.assertEqual(output_types_by_predicate.get("low_severity_cap_triggered"), "kill_rubric")
        self.assertEqual(output_types_by_predicate.get("admin_or_team_action_prerequisite"), "kill_rubric")
        self.assertEqual(output_types_by_predicate.get("generic_dos_scope_risk"), "scope_oos_rule")
        self.assertEqual(output_types_by_predicate.get("ambient_mev_not_protocol_bug"), "scope_oos_rule")
        self.assertEqual(output_types_by_predicate.get("protocol_bug_amplified_by_mev"), "known_limitation")
        self.assertEqual(output_types_by_predicate.get("documented_mechanics_no_stronger_intent"), "kill_rubric")
        self.assertEqual(output_types_by_predicate.get("intended_actor_mismatch"), "triager_objection")


if __name__ == "__main__":
    unittest.main()
