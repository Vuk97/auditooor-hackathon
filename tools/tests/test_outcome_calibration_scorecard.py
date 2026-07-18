from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "outcome-calibration-scorecard.py"


def _import():
    spec = importlib.util.spec_from_file_location("outcome_calibration_scorecard_test", str(TOOL))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class OutcomeCalibrationScorecardTests(unittest.TestCase):
    def test_builds_queue_without_inventing_outcomes(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            outcome = root / "outcome.json"
            outcome.write_text(
                json.dumps({
                    "records": [
                        {
                            "workspace": "fixture-audit",
                            "finding_id": "42",
                            "title": "Accepted but missing linkage",
                            "outcome": "accepted",
                            "outcome_row_present": True,
                            "lane": "",
                            "model_route": "",
                            "proof_artifact": "",
                            "production_path_status": "",
                            "production_path_blockers_cleared": "",
                            "final_triager_outcome": "",
                        },
                        {
                            "workspace": "fixture-audit",
                            "finding_id": "43",
                            "title": "Still pending",
                            "outcome": "pending",
                        },
                    ],
                }),
                encoding="utf-8",
            )
            provider_verification = root / "provider_verification.json"
            provider_verification.write_text(
                json.dumps({
                    "candidate_harvest_count": 1,
                    "verified_row_count": 1,
                    "local_status_counts": {"source_symbol_confirmed": 1},
                    "classification_counts": {"local_grep_advisory": 1},
                    "rows": [
                        {
                            "task_id": "worker-bz-001",
                            "local_status": "source_symbol_confirmed",
                            "classifications": ["local_grep_advisory"],
                            "local_check_count": 2,
                            "provider_outputs": {
                                "kimi": "worker-bz-001.kimi.out.jsonl",
                                "minimax": "worker-bz-001.minimax.out.jsonl",
                            },
                        },
                    ],
                }),
                encoding="utf-8",
            )
            provider_queue = root / "provider_queue.json"
            provider_queue.write_text(json.dumps({"summary": {"total_queue_items": 1}}), encoding="utf-8")
            seed = root / "seed.json"
            seed.write_text(
                json.dumps({
                    "rows": [
                        {
                            "provider": "kimi",
                            "task_type": "source-extraction",
                            "sample_count": 0,
                            "precision_pct": "insufficient-data",
                        },
                        {
                            "provider": "minimax",
                            "task_type": "adversarial-kill",
                            "sample_count": 20,
                            "precision_pct": 75,
                        },
                    ],
                }),
                encoding="utf-8",
            )
            patterns = root / "triager_patterns.json"
            patterns.write_text(json.dumps({"rejections": [], "acceptances": []}), encoding="utf-8")
            limitations = root / "limitations.json"
            limitations.write_text(
                json.dumps({
                    "rows": [
                        {
                            "limitation_id": "P0-3",
                            "title": "Outcome calibration",
                            "stop_condition_met": False,
                            "next_command": "make outcome-calibration-scorecard",
                            "stop_condition": "calibrated routing",
                        },
                    ],
                }),
                encoding="utf-8",
            )
            terminal_rows = root / "terminal_rows.jsonl"
            terminal_rows.write_text("", encoding="utf-8")

            payload = mod.build_scorecard(
                outcome_json=[outcome],
                provider_verification_json=provider_verification,
                provider_queue_json=provider_queue,
                seed_json=seed,
                triager_patterns_json=patterns,
                known_limitations_json=limitations,
                terminal_rows_jsonl=[terminal_rows],
                resolved_linkage_validation_json=root / "missing_validation.json",
                limit=50,
                min_samples=20,
                min_precision_pct=70,
            )

        self.assertTrue(payload["no_invented_acceptance_or_rejection"])
        self.assertEqual(payload["summary"]["invented_outcomes"], 0)
        self.assertGreaterEqual(payload["summary"]["total_queue_items"], 5)
        types = {item["queue_type"] for item in payload["queue"]}
        self.assertIn("outcome_linkage_backfill", types)
        self.assertIn("provider_local_terminal_adjudication", types)
        self.assertIn("routing_sample_gap", types)
        self.assertIn("triager_feedback_sync", types)
        self.assertIn("known_limitation_route_adjustment", types)
        by_route = {
            (row["provider"], row["task_type"]): row
            for row in payload["scorecard"]["routing_rows"]
        }
        self.assertEqual(by_route[("kimi", "source-extraction")]["route_status"], "needs_samples")
        self.assertEqual(by_route[("minimax", "adversarial-kill")]["route_status"], "primary_ready")
        self.assertEqual(payload["scorecard"]["outcome_rows"]["resolved"], 1)
        self.assertEqual(payload["scorecard"]["outcome_rows"]["missing_linkage"], 1)
        self.assertEqual(payload["scorecard"]["outcome_rows"]["terminalized_missing_linkage"], 0)

    def test_limit_caps_to_target_queue_size(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            outcome = root / "outcome.json"
            outcome.write_text(
                json.dumps({
                    "records": [
                        {
                            "workspace": "fixture",
                            "finding_id": str(index),
                            "title": f"Finding {index}",
                            "outcome": "rejected",
                        }
                        for index in range(80)
                    ],
                }),
                encoding="utf-8",
            )
            empty = root / "empty.json"
            empty.write_text(json.dumps({}), encoding="utf-8")
            seed = root / "seed.json"
            seed.write_text(json.dumps({"rows": []}), encoding="utf-8")

            payload = mod.build_scorecard(
                outcome_json=[outcome],
                provider_verification_json=empty,
                provider_queue_json=empty,
                seed_json=seed,
                triager_patterns_json=empty,
                known_limitations_json=empty,
                terminal_rows_jsonl=[],
                resolved_linkage_validation_json=root / "missing_validation.json",
                limit=50,
                min_samples=20,
                min_precision_pct=70,
            )

        self.assertEqual(payload["summary"]["total_queue_items"], 50)
        self.assertEqual(payload["queue"][-1]["rank"], 50)
        self.assertTrue(all(item["known_outcome"] == "rejected" for item in payload["queue"]))

    def test_terminal_rows_reduce_missing_linkage_without_counting_calibration(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            outcome = root / "outcome.json"
            outcome.write_text(
                json.dumps({
                    "records": [
                        {
                            "workspace": "polymarket",
                            "finding_id": "182",
                            "title": "Known rejected row",
                            "outcome": "rejected",
                            "outcome_row_present": False,
                        }
                    ],
                }),
                encoding="utf-8",
            )
            terminal_rows = root / "terminal.jsonl"
            terminal_rows.write_text(
                json.dumps({
                    "schema": "auditooor.outcome_calibration_terminal_row.v1",
                    "workspace": "polymarket",
                    "finding_id": "182",
                    "report_id": "POLY-182",
                    "terminal_outcome": "rejected",
                    "terminal_row_status": "evidence_exists_linkage_not_invented",
                }) + "\n",
                encoding="utf-8",
            )
            empty = root / "empty.json"
            empty.write_text(json.dumps({}), encoding="utf-8")
            seed = root / "seed.json"
            seed.write_text(json.dumps({"rows": []}), encoding="utf-8")

            payload = mod.build_scorecard(
                outcome_json=[outcome],
                provider_verification_json=empty,
                provider_queue_json=empty,
                seed_json=seed,
                triager_patterns_json=empty,
                known_limitations_json=empty,
                terminal_rows_jsonl=[terminal_rows],
                resolved_linkage_validation_json=root / "missing_validation.json",
                limit=50,
                min_samples=20,
                min_precision_pct=70,
            )

        self.assertEqual(payload["scorecard"]["outcome_rows"]["resolved"], 1)
        self.assertEqual(payload["scorecard"]["outcome_rows"]["linked_for_calibration"], 0)
        self.assertEqual(payload["scorecard"]["outcome_rows"]["terminalized_missing_linkage"], 1)
        self.assertEqual(payload["scorecard"]["outcome_rows"]["missing_linkage"], 0)
        self.assertTrue(payload["scorecard"]["outcome_rows"]["all_resolved_rows_accounted_for"])
        self.assertEqual(payload["scorecard"]["outcome_rows"]["calibration_closure_status"], "terminalized_missing_linkage_not_calibration")
        self.assertEqual(payload["queue"][0]["queue_type"], "outcome_linkage_terminalized_missing_linkage")

    def test_partial_linkage_does_not_count_as_calibration_sample(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            outcome = root / "outcome.json"
            outcome.write_text(
                json.dumps({
                    "records": [
                        {
                            "workspace": "fixture-audit",
                            "finding_id": "7",
                            "title": "Partially linked accepted row",
                            "outcome": "accepted",
                            "outcome_row_present": True,
                            "lane": "detector",
                            "model_route": "kimi/source-extraction",
                            "proof_artifact": "proof.json",
                            "production_path_status": "",
                            "production_path_blockers_cleared": "",
                            "final_triager_outcome": "",
                        }
                    ],
                }),
                encoding="utf-8",
            )
            empty = root / "empty.json"
            empty.write_text(json.dumps({}), encoding="utf-8")
            seed = root / "seed.json"
            seed.write_text(json.dumps({"rows": []}), encoding="utf-8")

            payload = mod.build_scorecard(
                outcome_json=[outcome],
                provider_verification_json=empty,
                provider_queue_json=empty,
                seed_json=seed,
                triager_patterns_json=empty,
                known_limitations_json=empty,
                terminal_rows_jsonl=[],
                resolved_linkage_validation_json=root / "missing_validation.json",
                limit=50,
                min_samples=20,
                min_precision_pct=70,
            )

        self.assertEqual(payload["scorecard"]["outcome_rows"]["resolved"], 1)
        self.assertEqual(payload["scorecard"]["outcome_rows"]["linked_for_calibration"], 0)
        self.assertEqual(payload["scorecard"]["outcome_rows"]["missing_linkage"], 1)
        self.assertEqual(
            payload["scorecard"]["outcome_rows"]["strict_linkage_fields"],
            list(mod.LINKAGE_FIELDS),
        )

    def test_resolved_linkage_validation_feeds_strict_scorecard_counts(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            outcome = root / "outcome.json"
            outcome.write_text(
                json.dumps({
                    "records": [
                        {
                            "workspace": "fixture-audit",
                            "finding_id": "7",
                            "title": "Validated accepted row",
                            "outcome": "accepted",
                        }
                    ],
                }),
                encoding="utf-8",
            )
            validation = root / "validation.json"
            validation.write_text(
                json.dumps({
                    "schema": "auditooor.outcome_calibration_resolved_linkage_validator.v1",
                    "summary": {
                        "valid_linked_rows": 1,
                        "terminalized_missing_linkage_rows": 0,
                        "missing_linkage_rows": 0,
                        "calibration_closure_status": "linked_rows_validated",
                    },
                    "inputs": {"linkage_jsonl": "linkage.jsonl"},
                }),
                encoding="utf-8",
            )
            empty = root / "empty.json"
            empty.write_text(json.dumps({}), encoding="utf-8")
            seed = root / "seed.json"
            seed.write_text(json.dumps({"rows": []}), encoding="utf-8")

            payload = mod.build_scorecard(
                outcome_json=[outcome],
                provider_verification_json=empty,
                provider_queue_json=empty,
                seed_json=seed,
                triager_patterns_json=empty,
                known_limitations_json=empty,
                terminal_rows_jsonl=[],
                resolved_linkage_validation_json=validation,
                limit=50,
                min_samples=20,
                min_precision_pct=70,
            )

        outcome_rows = payload["scorecard"]["outcome_rows"]
        self.assertEqual(outcome_rows["resolved"], 1)
        self.assertEqual(outcome_rows["linked_for_calibration"], 1)
        self.assertEqual(outcome_rows["missing_linkage"], 0)
        self.assertEqual(outcome_rows["resolved_linkage_validator_status"], "linked_rows_validated")
        self.assertEqual(outcome_rows["calibration_closure_status"], "closed_for_current_terminal_rows")

    def test_markdown_names_advisory_contract(self) -> None:
        mod = _import()
        payload = {
            "advisory_only": True,
            "summary": {"total_queue_items": 0, "target_queue_items": 50, "invented_outcomes": 0},
            "scorecard": {
                "routing_rows": [],
                "outcome_rows": {"resolved": 0, "linked_for_calibration": 0, "terminalized_missing_linkage": 0, "missing_linkage": 0},
            },
            "queue": [],
        }
        md = mod.render_markdown(payload)
        self.assertIn("Outcome Calibration Scorecard", md)
        self.assertIn("No row invents an acceptance or rejection outcome", md)
        self.assertIn("Routing Scorecard", md)


if __name__ == "__main__":
    unittest.main()
