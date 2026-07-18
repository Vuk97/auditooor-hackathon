from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


outcome_telemetry = _load_module(
    "outcome_telemetry_unknown_reason",
    TOOLS / "outcome-telemetry.py",
)
per_platform_precision = _load_module(
    "per_platform_precision_unknown_reason",
    TOOLS / "per-platform-precision.py",
)
outcome_feedback_loop = _load_module(
    "outcome_feedback_loop_unknown_reason",
    TOOLS / "outcome-feedback-loop.py",
)
outcome_calibration_scorecard = _load_module(
    "outcome_calibration_scorecard_unknown_reason",
    TOOLS / "outcome-calibration-scorecard.py",
)
outcome_semantics = _load_module(
    "outcome_semantics_direct_regression",
    TOOLS / "outcome_semantics.py",
)


class UnknownReasonDeclineSemanticsTests(unittest.TestCase):
    def test_invalid_status_does_not_match_valid_acceptance_token(self) -> None:
        rejected_values = [
            "invalid",
            "triager_invalid",
            "not valid",
            "declined by platform",
            "OOS duplicate of invalid original",
        ]
        for value in rejected_values:
            with self.subTest(value=value):
                self.assertEqual(outcome_semantics.normalize_outcome(value), "rejected")

        self.assertEqual(outcome_semantics.normalize_outcome("valid"), "accepted")
        self.assertEqual(
            outcome_semantics.normalize_outcome("Paid (duplicate, originally rejected + re-accepted)"),
            "accepted",
        )

    def test_outcome_telemetry_marks_base_rate_only_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "morpho"
            submissions = ws / "submissions"
            submissions.mkdir(parents=True)
            (submissions / "SUBMISSIONS.md").write_text(
                "# Test Submissions\n\n"
                "| Cantina # | Date | Severity | Status | Title |\n"
                "|---:|---|---|---|---|\n"
                "| **I2.A** | 2026-04-16 | Critical | Rejected | Unknown-reason decline |\n",
                encoding="utf-8",
            )
            reference = ws / "reference"
            reference.mkdir(parents=True)
            (reference / "outcomes.jsonl").write_text(
                json.dumps({
                    "report_id": "I2.A",
                    "outcome": "rejected",
                    "rejection_reason": "unknown:no decline reason provided by platform",
                }) + "\n",
                encoding="utf-8",
            )

            records = outcome_telemetry.load_workspace_records(ws)

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].outcome, "rejected")
        self.assertTrue(records[0].base_rate_only_rejection)
        self.assertEqual(records[0].learning_scope, "platform_base_rate_only")

    def test_blank_reason_decline_status_is_base_rate_only(self) -> None:
        rows = [
            {
                "status": "Rejected",
                "outcome_class": "rejected",
                "rejection_reason": "unknown:no-decline-reason",
            },
            {
                "status": "DECLINED (no decline reason provided to operator)",
                "outcome_class": "rejected",
                "rejection_reason": "",
            },
            {
                "status": "No reason provided",
                "outcome_class": "rejected",
                "rejection_reason": "",
            },
            {
                "final_triager_outcome": "reason missing",
                "outcome": "declined",
                "rejection_reason": "",
            },
            {
                "status": "DECLINED",
                "outcome": "rejected",
                "rejection_reason": "No reason provided",
            },
        ]
        for row in rows:
            with self.subTest(row=row):
                semantics = outcome_semantics.derive_outcome_semantics(row)
                self.assertEqual(semantics.outcome, "rejected")
                self.assertTrue(semantics.base_rate_only_rejection)
                self.assertFalse(semantics.eligible_for_learning)

    def test_per_platform_keeps_base_rate_rejection_but_skips_pattern_learning(self) -> None:
        raw_rows = [
            {
                "workspace": "morpho",
                "source": "cantina",
                "title": "Oracle manipulation accepted",
                "outcome": "accepted",
                "status": "Paid",
                "date": "2026-04-10",
            },
            {
                "workspace": "morpho",
                "source": "cantina",
                "title": "Oracle manipulation unknown decline",
                "outcome": "rejected",
                "status": "DECLINED by Cantina (no decline reason provided to operator)",
                "rejection_reason": "unknown:no decline reason provided by platform",
                "date": "2026-05-05",
            },
        ]

        rows = per_platform_precision.build_finding_rows(raw_rows)
        stats = per_platform_precision.compute_platform_stats(rows, "2026-05-05T00:00:00Z")
        cantina = stats["Cantina"]
        by_pattern = {row.pattern_id: row for row in cantina.pattern_rows}

        self.assertEqual(cantina.accepted, 1)
        self.assertEqual(cantina.rejected, 1)
        self.assertIn("oracle-manipulation", by_pattern)
        self.assertEqual(by_pattern["oracle-manipulation"].accepted, 1)
        self.assertEqual(by_pattern["oracle-manipulation"].rejected, 0)

    def test_feedback_loop_ignores_unknown_reason_decline_for_pattern_stats(self) -> None:
        raw_rows = [
            {
                "engagement": "morpho",
                "title": "Oracle manipulation unknown decline",
                "outcome_class": "rejected",
                "status": "DECLINED by Cantina (no decline reason provided to operator)",
                "rejection_reason": "unknown:no decline reason provided by platform",
                "submitted_date": "2026-05-05",
            }
        ]

        rows = outcome_feedback_loop.build_outcome_rows(raw_rows)
        stats = outcome_feedback_loop.aggregate_pattern_stats(rows)

        self.assertEqual(stats, {})

    def test_feedback_loop_routes_named_no_reason_declines_to_memory_actions(self) -> None:
        raw_rows = [
            {
                "workspace": "morpho",
                "finding_id": "I2.A",
                "title": "#I2.A",
                "outcome_class": "rejected",
                "status": "DECLINED by Cantina (no decline reason provided to operator)",
                "rejection_reason": "unknown:no-decline-reason",
                "severity_claimed": "Critical",
                "submitted_date": "2026-04-16",
            },
            {
                "workspace": "morpho",
                "finding_id": "I2.B",
                "title": "#I2.B",
                "outcome_class": "rejected",
                "status": "DECLINED by Cantina (no decline reason provided to operator)",
                "rejection_reason": "unknown:no decline reason provided by platform",
                "severity_claimed": "Medium",
                "submitted_date": "2026-04-16",
            },
            {
                "workspace": "centrifuge",
                "finding_id": "#418",
                "title": (
                    "Holdings.decrease returns unclamped decrement while state is clamped - "
                    "Hub Accounting Equity ledger can go persistently negative"
                ),
                "outcome_class": "rejected",
                "status": "DECLINED (no decline reason provided to operator)",
                "rejection_reason": "",
                "severity_claimed": "Medium",
            },
        ]

        rows = outcome_feedback_loop.build_outcome_rows(raw_rows)
        stats = outcome_feedback_loop.aggregate_pattern_stats(rows)
        adjustments = outcome_feedback_loop.compute_adjustments(
            stats,
            registry={},
            now_str="2026-05-05T00:00:00Z",
        )
        report = outcome_feedback_loop.build_report(
            rows,
            stats,
            adjustments,
            registry_size=0,
            now_str="2026-05-05T00:00:00Z",
            dry_run=True,
        )

        self.assertEqual({row.finding_id for row in rows}, {"I2.A", "I2.B", "#418"})
        for row in rows:
            with self.subTest(row=row.finding_id):
                self.assertEqual(row.outcome, "rejected")
                self.assertEqual(row.learning_scope, "platform_base_rate_only")
                self.assertEqual(row.platform, "Cantina")

        self.assertEqual(stats, {})
        self.assertEqual(adjustments, [])
        self.assertEqual(report["input_summary"]["outcome_distribution"]["rejected"], 3)
        self.assertEqual(report["input_summary"]["base_rate_only_rejections"], 3)
        routing = report["memory_action_routing"]["unknown_no_reason_declines"]
        self.assertEqual(routing["count"], 3)
        self.assertTrue(routing["report_valid"])
        self.assertFalse(routing["causal_reason_inference_allowed"])
        self.assertEqual(routing["actionability_status"], "actionable_base_rate_only")
        self.assertEqual(
            routing["next_commands"],
            [
                "python3 tools/outcome-feedback-loop.py --dry-run "
                "--outcomes reference/outcomes.jsonl --print-json"
            ],
        )
        self.assertIn("explicit triager/platform rejection text", routing["stop_condition"])
        self.assertIn("platform_base_rate_calibration", routing["routes"])
        self.assertIn("self_learning_followup", routing["routes"])
        self.assertIn(
            "platform-base-rate:update_terminal_decline_baseline",
            routing["follow_up_cues"],
        )
        self.assertIn(
            "self-learning:review_no_reason_decline_without_causal_label",
            routing["follow_up_cues"],
        )
        by_id = {row["finding_id"]: row for row in routing["rows"]}
        for finding_id in ("I2.A", "I2.B", "#418"):
            with self.subTest(finding_id=finding_id):
                cue = by_id[finding_id]
                self.assertEqual(cue["terminal_state"], "terminal_rejected")
                self.assertTrue(cue["report_valid"])
                self.assertFalse(cue["causal_reason_inferred"])
                self.assertFalse(cue["pattern_fp_learning_allowed"])
                self.assertEqual(cue["actionability_status"], "actionable_base_rate_only")
                self.assertEqual(
                    cue["next_command"],
                    "python3 tools/outcome-feedback-loop.py --dry-run "
                    "--outcomes reference/outcomes.jsonl --print-json",
                )
                self.assertIn(
                    "count terminal decline in platform/base-rate calibration",
                    cue["operator_checklist"],
                )
                self.assertIn("explicit triager/platform rejection text", cue["stop_condition"])

    def test_scorecard_excludes_base_rate_only_rejection_from_calibration_queue(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            outcome = root / "outcome.json"
            outcome.write_text(
                json.dumps({
                    "records": [
                        {
                            "workspace": "morpho",
                            "finding_id": "I2.A",
                            "title": "Unknown-reason decline",
                            "outcome": "rejected",
                            "learning_scope": "platform_base_rate_only",
                            "outcome_row_present": True,
                        }
                    ],
                }),
                encoding="utf-8",
            )
            empty = root / "empty.json"
            empty.write_text(json.dumps({}), encoding="utf-8")
            seed = root / "seed.json"
            seed.write_text(json.dumps({"rows": []}), encoding="utf-8")
            stale_validator = root / "stale-validation.json"
            stale_validator.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.outcome_calibration_resolved_linkage_validator.v1",
                        "summary": {
                            "valid_linked_rows": 0,
                            "terminalized_missing_linkage_rows": 0,
                            "missing_linkage_rows": 1,
                            "calibration_closure_status": "open_missing_linkage",
                        },
                    }
                ),
                encoding="utf-8",
            )

            payload = outcome_calibration_scorecard.build_scorecard(
                outcome_json=[outcome],
                provider_verification_json=empty,
                provider_queue_json=empty,
                seed_json=seed,
                triager_patterns_json=empty,
                known_limitations_json=empty,
                terminal_rows_jsonl=[],
                resolved_linkage_validation_json=stale_validator,
                limit=50,
                min_samples=20,
                min_precision_pct=70,
            )

        outcome_rows = payload["scorecard"]["outcome_rows"]
        self.assertEqual(outcome_rows["resolved"], 1)
        self.assertEqual(outcome_rows["calibration_eligible_resolved"], 0)
        self.assertEqual(outcome_rows["base_rate_only_resolved"], 1)
        self.assertEqual(outcome_rows["linked_for_calibration"], 0)
        self.assertEqual(outcome_rows["missing_linkage"], 0)
        self.assertFalse(
            any(item["queue_type"] == "outcome_linkage_backfill" for item in payload["queue"])
        )

    def test_scorecard_no_reason_text_overrides_stale_full_learning_scope(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            outcome = root / "outcome.json"
            outcome.write_text(
                json.dumps({
                    "records": [
                        {
                            "workspace": "morpho",
                            "finding_id": "I2.A",
                            "title": "Unknown-reason decline",
                            "outcome": "rejected",
                            "status": "No reason provided",
                            "rejection_reason": "No reason provided",
                            "learning_scope": "full",
                            "outcome_row_present": True,
                        }
                    ],
                }),
                encoding="utf-8",
            )
            empty = root / "empty.json"
            empty.write_text(json.dumps({}), encoding="utf-8")
            seed = root / "seed.json"
            seed.write_text(json.dumps({"rows": []}), encoding="utf-8")
            stale_validator = root / "stale-validation.json"
            stale_validator.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.outcome_calibration_resolved_linkage_validator.v1",
                        "summary": {
                            "valid_linked_rows": 0,
                            "terminalized_missing_linkage_rows": 0,
                            "missing_linkage_rows": 1,
                            "calibration_closure_status": "open_missing_linkage",
                        },
                    }
                ),
                encoding="utf-8",
            )

            payload = outcome_calibration_scorecard.build_scorecard(
                outcome_json=[outcome],
                provider_verification_json=empty,
                provider_queue_json=empty,
                seed_json=seed,
                triager_patterns_json=empty,
                known_limitations_json=empty,
                terminal_rows_jsonl=[],
                resolved_linkage_validation_json=stale_validator,
                limit=50,
                min_samples=20,
                min_precision_pct=70,
            )

        outcome_rows = payload["scorecard"]["outcome_rows"]
        self.assertEqual(outcome_rows["resolved"], 1)
        self.assertEqual(outcome_rows["calibration_eligible_resolved"], 0)
        self.assertEqual(outcome_rows["base_rate_only_resolved"], 1)
        self.assertEqual(outcome_rows["missing_linkage"], 0)
        self.assertFalse(
            any(item["queue_type"] == "outcome_linkage_backfill" for item in payload["queue"])
        )


if __name__ == "__main__":
    unittest.main()
