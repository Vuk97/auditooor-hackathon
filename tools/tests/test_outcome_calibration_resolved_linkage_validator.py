from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "outcome-calibration-resolved-linkage-validator.py"


def _import():
    spec = importlib.util.spec_from_file_location("outcome_calibration_resolved_linkage_validator_test", str(TOOL))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class OutcomeCalibrationResolvedLinkageValidatorTests(unittest.TestCase):
    def test_valid_linkage_row_requires_matching_outcome_and_proof_artifact(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            proof = ws / "proofs" / "finding-7.json"
            proof.parent.mkdir()
            proof.write_text(json.dumps({"proved": True}), encoding="utf-8")
            outcome = ws / "outcome.json"
            outcome.write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "workspace": "fixture-audit",
                                "finding_id": "7",
                                "title": "Linked accepted row",
                                "outcome": "accepted",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            linkage = ws / "linkage.jsonl"
            linkage.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.outcome_calibration_resolved_linkage.v1",
                        "workspace": "fixture-audit",
                        "finding_id": "7",
                        "title": "Linked accepted row",
                        "final_triager_outcome": "accepted",
                        "lane": "source-proof",
                        "model_route": "kimi/source-extraction",
                        "proof_artifact": "proofs/finding-7.json",
                        "production_path_status": "verified",
                        "production_path_blockers_cleared": True,
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            payload = mod.build_payload(
                workspace=ws,
                outcome_json=[outcome],
                linkage_jsonl=linkage,
                terminal_rows_jsonl=[],
            )

        self.assertEqual(payload["summary"]["resolved_outcome_rows"], 1)
        self.assertEqual(payload["summary"]["valid_linked_rows"], 1)
        self.assertEqual(payload["summary"]["missing_linkage_rows"], 0)
        self.assertEqual(payload["summary"]["calibration_closure_status"], "linked_rows_validated")
        self.assertTrue(payload["rows"][0]["valid_for_calibration"])

    def test_outcome_class_only_row_validates_when_normalized_outcome_matches(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            proof = ws / "proofs" / "finding-d1.json"
            proof.parent.mkdir()
            proof.write_text(json.dumps({"proved": True}), encoding="utf-8")
            outcome = ws / "outcome.json"
            outcome.write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "workspace": "fixture-audit",
                                "finding_id": "D1",
                                "title": "Duplicate normalized row",
                                "outcome_class": "duplicate",
                                "status": "Duplicate",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            linkage = ws / "linkage.jsonl"
            linkage.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.outcome_calibration_resolved_linkage.v1",
                        "workspace": "fixture-audit",
                        "finding_id": "D1",
                        "title": "Duplicate normalized row",
                        "final_triager_outcome": "duplicate",
                        "lane": "detector",
                        "model_route": "minimax/adversarial-kill",
                        "proof_artifact": "proofs/finding-d1.json",
                        "production_path_status": "verified",
                        "production_path_blockers_cleared": True,
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            payload = mod.build_payload(
                workspace=ws,
                outcome_json=[outcome],
                linkage_jsonl=linkage,
                terminal_rows_jsonl=[],
            )

        self.assertEqual(payload["summary"]["valid_linked_rows"], 1)
        self.assertNotIn("final_triager_outcome_mismatch", payload["rows"][0]["problem_codes"])

    def test_unknown_reason_decline_is_base_rate_only_not_linkage_pressure(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            outcome = ws / "outcome.json"
            outcome.write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "workspace": "morpho",
                                "finding_id": "I2.A",
                                "title": "Unknown-reason decline",
                                "outcome": "rejected",
                                "rejection_reason": "unknown:no decline reason provided by platform",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            linkage = ws / "missing.jsonl"

            payload = mod.build_payload(
                workspace=ws,
                outcome_json=[outcome],
                linkage_jsonl=linkage,
                terminal_rows_jsonl=[],
            )

        self.assertEqual(payload["summary"]["resolved_outcome_rows_total"], 1)
        self.assertEqual(payload["summary"]["resolved_outcome_rows"], 0)
        self.assertEqual(payload["summary"]["base_rate_only_resolved_rows"], 1)
        self.assertEqual(payload["summary"]["valid_linked_rows"], 0)
        self.assertEqual(payload["summary"]["missing_linkage_rows"], 0)
        self.assertEqual(
            payload["summary"]["calibration_closure_status"],
            "no_calibration_eligible_resolved_rows",
        )
        self.assertEqual(payload["resolved_row_units"], [])

    def test_blank_reason_no_reason_decline_is_base_rate_only(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            outcome = ws / "outcome.json"
            outcome.write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "workspace": "centrifuge",
                                "finding_id": "418",
                                "title": "Declined without a reason",
                                "outcome": "rejected",
                                "status": "DECLINED (no decline reason provided to operator)",
                                "rejection_reason": "",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            linkage = ws / "missing.jsonl"

            payload = mod.build_payload(
                workspace=ws,
                outcome_json=[outcome],
                linkage_jsonl=linkage,
                terminal_rows_jsonl=[],
            )

        self.assertEqual(payload["summary"]["resolved_outcome_rows_total"], 1)
        self.assertEqual(payload["summary"]["resolved_outcome_rows"], 0)
        self.assertEqual(payload["summary"]["base_rate_only_resolved_rows"], 1)
        self.assertEqual(payload["summary"]["missing_linkage_rows"], 0)
        self.assertEqual(payload["resolved_row_units"], [])

    def test_negative_row_does_not_count_when_outcome_mismatches_or_proof_missing(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            outcome = ws / "outcome.json"
            outcome.write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "workspace": "fixture-audit",
                                "finding_id": "8",
                                "title": "Rejected row",
                                "outcome": "rejected",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            linkage = ws / "linkage.jsonl"
            linkage.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.outcome_calibration_resolved_linkage.v1",
                        "workspace": "fixture-audit",
                        "finding_id": "8",
                        "title": "Rejected row",
                        "final_triager_outcome": "accepted",
                        "lane": "detector",
                        "model_route": "minimax/adversarial-kill",
                        "proof_artifact": "missing-proof.json",
                        "production_path_status": "verified",
                        "production_path_blockers_cleared": True,
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            payload = mod.build_payload(
                workspace=ws,
                outcome_json=[outcome],
                linkage_jsonl=linkage,
                terminal_rows_jsonl=[],
            )

        self.assertEqual(payload["summary"]["valid_linked_rows"], 0)
        self.assertEqual(payload["summary"]["invalid_linkage_rows"], 1)
        self.assertEqual(payload["summary"]["missing_linkage_rows"], 1)
        self.assertIn("final_triager_outcome_mismatch", payload["rows"][0]["problem_codes"])
        self.assertIn("proof_artifact_missing", payload["rows"][0]["problem_codes"])

    def test_terminal_rows_account_for_missing_linkage_without_calibration(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            outcome = ws / "outcome.json"
            outcome.write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "workspace": "polymarket",
                                "finding_id": "182",
                                "title": "Known rejected row",
                                "outcome": "rejected",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            terminal = ws / "terminal.jsonl"
            terminal.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.outcome_calibration_terminal_row.v1",
                        "workspace": "polymarket",
                        "finding_id": "182",
                        "report_id": "POLY-182",
                        "terminal_outcome": "rejected",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            linkage = ws / "missing.jsonl"

            payload = mod.build_payload(
                workspace=ws,
                outcome_json=[outcome],
                linkage_jsonl=linkage,
                terminal_rows_jsonl=[terminal],
            )

        self.assertEqual(payload["summary"]["valid_linked_rows"], 0)
        self.assertEqual(payload["summary"]["terminalized_missing_linkage_rows"], 1)
        self.assertEqual(payload["summary"]["missing_linkage_rows"], 0)
        self.assertEqual(payload["summary"]["calibration_closure_status"], "terminalized_missing_linkage_not_calibration")
        self.assertEqual(payload["summary"]["resolved_unit_state_counts"], {"terminalized_missing_linkage_not_calibration": 1})
        self.assertEqual(payload["resolved_row_units"][0]["state"], "terminalized_missing_linkage_not_calibration")

    def test_resolved_row_units_split_valid_invalid_terminal_and_missing_linkage(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            proof = ws / "proofs" / "accepted-1.json"
            proof.parent.mkdir()
            proof.write_text(json.dumps({"artifact": "real local proof"}), encoding="utf-8")
            outcome = ws / "outcome.json"
            outcome.write_text(
                json.dumps(
                    {
                        "records": [
                            {"workspace": "fixture", "finding_id": "1", "title": "Accepted", "outcome": "accepted"},
                            {"workspace": "fixture", "finding_id": "2", "title": "Duplicate", "outcome": "duplicate"},
                            {"workspace": "fixture", "finding_id": "3", "title": "Rejected terminal", "outcome": "rejected"},
                            {"workspace": "fixture", "finding_id": "4", "title": "Missing", "outcome": "rejected"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            linkage = ws / "linkage.jsonl"
            linkage.write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "schema": "auditooor.outcome_calibration_resolved_linkage.v1",
                                "workspace": "fixture",
                                "finding_id": "1",
                                "title": "Accepted",
                                "final_triager_outcome": "accepted",
                                "lane": "source-proof",
                                "model_route": "kimi/source-extraction",
                                "proof_artifact": "proofs/accepted-1.json",
                                "production_path_status": "verified",
                                "production_path_blockers_cleared": True,
                            }
                        ),
                        json.dumps(
                            {
                                "schema": "auditooor.outcome_calibration_resolved_linkage.v1",
                                "workspace": "fixture",
                                "finding_id": "2",
                                "title": "Duplicate",
                                "final_triager_outcome": "duplicate",
                                "lane": "routing",
                                "model_route": "minimax/adversarial-kill",
                                "proof_artifact": "missing.json",
                                "production_path_status": "blocked",
                                "production_path_blockers_cleared": False,
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            terminal = ws / "terminal.jsonl"
            terminal.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.outcome_calibration_terminal_row.v1",
                        "workspace": "fixture",
                        "finding_id": "3",
                        "title": "Rejected terminal",
                        "terminal_outcome": "rejected",
                        "terminal_row_status": "evidence_exists_linkage_not_invented",
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            payload = mod.build_payload(
                workspace=ws,
                outcome_json=[outcome],
                linkage_jsonl=linkage,
                terminal_rows_jsonl=[terminal],
            )

        self.assertEqual(payload["summary"]["valid_linked_rows"], 1)
        self.assertEqual(payload["summary"]["invalid_linkage_rows"], 1)
        self.assertEqual(payload["summary"]["terminalized_missing_linkage_rows"], 1)
        self.assertEqual(payload["summary"]["missing_linkage_rows"], 2)
        self.assertEqual(
            payload["summary"]["resolved_unit_state_counts"],
            {
                "invalid_strict_linkage_row": 1,
                "linked_for_calibration": 1,
                "missing_strict_linkage_row": 1,
                "terminalized_missing_linkage_not_calibration": 1,
            },
        )
        by_id = {row["finding_id"]: row for row in payload["resolved_row_units"]}
        self.assertEqual(by_id["1"]["state"], "linked_for_calibration")
        self.assertEqual(by_id["2"]["state"], "invalid_strict_linkage_row")
        self.assertIn("proof_artifact_missing", by_id["2"]["problem_codes"])
        self.assertEqual(by_id["3"]["state"], "terminalized_missing_linkage_not_calibration")
        self.assertEqual(by_id["4"]["state"], "missing_strict_linkage_row")


if __name__ == "__main__":
    unittest.main()
