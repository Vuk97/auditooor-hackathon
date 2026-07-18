from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "post-filing-outcome-replay-pattern-distiller.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("post_filing_outcome_replay_pattern_distiller", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def write_jsonl(path: Path, rows: list[dict | str]) -> None:
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            if isinstance(row, str):
                fh.write(row.rstrip("\n") + "\n")
            else:
                fh.write(json.dumps(row, sort_keys=True) + "\n")


class PostFilingOutcomeReplayPatternDistillerTests(unittest.TestCase):
    def test_accepted_and_rejected_examples_emit_replay_patterns(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            outcomes = Path(tmp) / "outcomes.jsonl"
            write_jsonl(
                outcomes,
                [
                    {
                        "workspace": "foo",
                        "report_id": "R-1",
                        "title": "vault withdrawal accounting drift",
                        "outcome": "rejected",
                        "status": "Rejected",
                        "rejection_reason": "No runnable PoC / missing proof artifact; could not reproduce.",
                        "new_rule_codified": False,
                    },
                    {
                        "workspace": "foo",
                        "report_id": "A-1",
                        "title": "bridge withdraw accepted with production path evidence",
                        "outcome": "accepted",
                        "status": "Accepted",
                        "static_gate_feedback": (
                            "pre-submit scope_oos_gate failed and blocked as OOS, "
                            "but triage accepted after production-path evidence."
                        ),
                        "new_rule_codified": False,
                    },
                ],
            )

            report = tool.build_report([outcomes], generated_at="2026-05-24T00:00:00Z")

        patterns = {
            (row["triggering_outcome"], row["missed_signal"]): row
            for row in report["patterns"]
        }
        self.assertIn(("rejected", "proof_artifact_missing_or_not_reproducible"), patterns)
        self.assertIn(("accepted", "accepted_static_gate_false_positive_scope"), patterns)

        proof = patterns[("rejected", "proof_artifact_missing_or_not_reproducible")]
        self.assertEqual(proof["gate_id"], "pre_submit_proof_artifact_gate")
        self.assertTrue(proof["new_rule_codified"]["recommended"])
        self.assertEqual(proof["evidence_refs"][0]["record_id"], "R-1")
        self.assertIn("counterfactual_pre_submit_question", proof)

    def test_malformed_rows_are_reported_and_foreign_rows_preserved(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            outcomes = Path(tmp) / "mixed.jsonl"
            write_jsonl(
                outcomes,
                [
                    "{not-json",
                    {"schema": "auditooor.foreign_telemetry.v1", "payload": {"x": 1}},
                    {
                        "workspace": "bar",
                        "report_id": "R-2",
                        "title": "market report rejected as out of scope",
                        "outcome": "rejected",
                        "rejection_reason": "Out of scope: excluded by scope boundary.",
                    },
                ],
            )

            report = tool.build_report(
                [outcomes],
                generated_at="2026-05-24T00:00:00Z",
                include_foreign_rows=True,
            )

        self.assertEqual(report["input_summary"]["malformed_rows"], 1)
        self.assertEqual(report["input_summary"]["foreign_rows_preserved"], 1)
        self.assertEqual(report["foreign_rows_preserved"][0]["schema"], "auditooor.foreign_telemetry.v1")
        self.assertEqual(report["malformed_rows"][0]["line"], 1)
        self.assertTrue(
            any(row["missed_signal"] == "scope_or_oos_boundary_not_resolved" for row in report["patterns"])
        )

    def test_dedupe_and_stable_ordering_for_repeated_outcomes(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            outcomes = Path(tmp) / "dupes.jsonl"
            write_jsonl(
                outcomes,
                [
                    {
                        "workspace": "baz",
                        "report_id": "B",
                        "title": "second proof gap",
                        "outcome": "rejected",
                        "rejection_reason": "Missing proof artifact.",
                    },
                    {
                        "workspace": "baz",
                        "report_id": "A",
                        "title": "first proof gap",
                        "outcome": "rejected",
                        "rejection_reason": "Missing proof artifact.",
                    },
                    {
                        "workspace": "baz",
                        "report_id": "A",
                        "title": "first proof gap duplicate ledger transition",
                        "outcome": "rejected",
                        "rejection_reason": "Missing proof artifact.",
                    },
                ],
            )

            report1 = tool.build_report([outcomes], generated_at="2026-05-24T00:00:00Z")
            report2 = tool.build_report([outcomes], generated_at="2026-05-24T00:00:00Z")

        self.assertEqual(report1["patterns"], report2["patterns"])
        proof_patterns = [
            row
            for row in report1["patterns"]
            if row["missed_signal"] == "proof_artifact_missing_or_not_reproducible"
        ]
        self.assertEqual(len(proof_patterns), 1)
        self.assertEqual(proof_patterns[0]["support_count"], 2)
        self.assertEqual(
            [ref["record_id"] for ref in proof_patterns[0]["evidence_refs"]],
            ["A", "B"],
        )

    def test_output_schema_contains_required_pattern_fields(self) -> None:
        tool = load_tool()
        required = {
            "gate_id",
            "proposed_check",
            "triggering_outcome",
            "missed_signal",
            "counterfactual_pre_submit_question",
            "confidence",
            "confidence_score",
            "evidence_refs",
            "new_rule_codified",
        }
        with tempfile.TemporaryDirectory() as tmp:
            outcomes_json = Path(tmp) / "outcomes.json"
            outcomes_json.write_text(
                json.dumps(
                    [
                        {
                            "engagement": "qux",
                            "submission_id": "Q-1",
                            "title": "admin prerequisite rejected",
                            "outcome_class": "rejected",
                            "status": "Rejected: requires owner action prerequisite.",
                            "rejection_reason": "Requires owner action prerequisite.",
                        }
                    ]
                ),
                encoding="utf-8",
            )

            report = tool.build_report([outcomes_json], generated_at="2026-05-24T00:00:00Z")

        self.assertEqual(report["schema"], tool.SCHEMA)
        self.assertEqual(report["schema_version"], tool.SCHEMA_VERSION)
        self.assertEqual(report["input_summary"]["patterns_emitted"], len(report["patterns"]))
        self.assertTrue(report["patterns"])
        pattern = report["patterns"][0]
        self.assertTrue(required.issubset(pattern.keys()))
        self.assertIn(pattern["confidence"], {"low", "medium", "high"})
        self.assertIsInstance(pattern["confidence_score"], float)
        self.assertIsInstance(pattern["evidence_refs"], list)
        self.assertIn("recommended", pattern["new_rule_codified"])

    def test_cli_prints_json_and_strict_fails_on_malformed_input(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            outcomes = Path(tmp) / "bad.jsonl"
            write_jsonl(outcomes, ["{bad-json"])

            proc = subprocess.run(
                [sys.executable, str(TOOL), "--outcomes", str(outcomes), "--strict"],
                check=False,
                text=True,
                capture_output=True,
            )

        self.assertEqual(proc.returncode, 1)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["schema"], "auditooor.post_filing_outcome_replay_pattern_distiller.v1")
        self.assertEqual(payload["input_summary"]["malformed_rows"], 1)


if __name__ == "__main__":
    unittest.main()
