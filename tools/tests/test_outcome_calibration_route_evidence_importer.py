from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "outcome-calibration-route-evidence-importer.py"


def _import():
    spec = importlib.util.spec_from_file_location("outcome_calibration_route_evidence_importer_test", str(TOOL))
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class OutcomeCalibrationRouteEvidenceImporterTests(unittest.TestCase):
    def test_valid_true_route_evidence_imports_linkage_row(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            proof = ws / "proofs" / "route-7.json"
            proof.parent.mkdir()
            proof.write_text(json.dumps({"terminal_route_verdict": "TRUE"}), encoding="utf-8")
            outcome = ws / "outcome.json"
            outcome.write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "workspace": "fixture-audit",
                                "finding_id": "7",
                                "title": "Accepted routed finding",
                                "outcome": "accepted",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            evidence = ws / "route-evidence.jsonl"
            evidence.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.outcome_calibration_route_evidence.v1",
                        "workspace": "fixture-audit",
                        "finding_id": "7",
                        "title": "Accepted routed finding",
                        "lane": "source-proof",
                        "model_route": "kimi/source-extraction",
                        "terminal_route_verdict": "TRUE",
                        "final_triager_outcome": "accepted",
                        "proof_artifact": "proofs/route-7.json",
                        "production_path_status": "verified",
                        "production_path_blockers_cleared": True,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            linkage = ws / "linkage.jsonl"

            payload = mod.build_payload(
                workspace=ws,
                outcome_json=[outcome],
                input_jsonl=evidence,
                linkage_jsonl=linkage,
                write_linkage=True,
            )

            rows = [json.loads(line) for line in linkage.read_text(encoding="utf-8").splitlines()]

        self.assertEqual(payload["summary"]["valid_import_rows"], 1)
        self.assertEqual(payload["summary"]["linkage_rows_written"], 1)
        self.assertEqual(payload["summary"]["import_status"], "valid_route_evidence_imported")
        self.assertEqual(rows[0]["schema"], "auditooor.outcome_calibration_resolved_linkage.v1")
        self.assertEqual(rows[0]["terminal_route_verdict"], "TRUE")
        self.assertEqual(rows[0]["final_triager_outcome"], "accepted")

    def test_partial_route_evidence_is_allowed_when_triager_outcome_is_real(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            proof = ws / "proofs" / "partial.json"
            proof.parent.mkdir()
            proof.write_text(json.dumps({"terminal_route_verdict": "PARTIAL"}), encoding="utf-8")
            outcome = ws / "outcome.json"
            outcome.write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "workspace": "fixture-audit",
                                "finding_id": "8",
                                "title": "Duplicate routed finding",
                                "outcome": "duplicate",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            evidence = ws / "route-evidence.jsonl"
            evidence.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.outcome_calibration_route_evidence.v1",
                        "workspace": "fixture-audit",
                        "finding_id": "8",
                        "title": "Duplicate routed finding",
                        "lane": "detector",
                        "model_route": "minimax/adversarial-kill",
                        "terminal_route_verdict": "PARTIAL",
                        "final_triager_outcome": "duplicate",
                        "proof_artifact": "proofs/partial.json",
                        "production_path_status": "verified",
                        "production_path_blockers_cleared": "yes",
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            payload = mod.build_payload(
                workspace=ws,
                outcome_json=[outcome],
                input_jsonl=evidence,
                linkage_jsonl=ws / "linkage.jsonl",
                write_linkage=True,
            )

        self.assertEqual(payload["summary"]["valid_import_rows"], 1)
        self.assertEqual(payload["summary"]["terminal_route_verdict_counts"], {"PARTIAL": 1})

    def test_base_rate_only_decline_cannot_import_route_linkage(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            proof = ws / "proofs" / "decline.json"
            proof.parent.mkdir()
            proof.write_text(json.dumps({"terminal_route_verdict": "FALSE"}), encoding="utf-8")
            outcome = ws / "outcome.json"
            outcome.write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "workspace": "morpho",
                                "finding_id": "I2.A",
                                "title": "Unknown reason decline",
                                "outcome_class": "rejected",
                                "status": "No reason provided",
                                "rejection_reason": "",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            evidence = ws / "route-evidence.jsonl"
            evidence.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.outcome_calibration_route_evidence.v1",
                        "workspace": "morpho",
                        "finding_id": "I2.A",
                        "title": "Unknown reason decline",
                        "lane": "source-proof",
                        "model_route": "kimi/source-extraction",
                        "terminal_route_verdict": "FALSE",
                        "final_triager_outcome": "rejected",
                        "proof_artifact": "proofs/decline.json",
                        "production_path_status": "verified",
                        "production_path_blockers_cleared": True,
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            linkage = ws / "linkage.jsonl"

            payload = mod.build_payload(
                workspace=ws,
                outcome_json=[outcome],
                input_jsonl=evidence,
                linkage_jsonl=linkage,
                write_linkage=True,
            )

        self.assertEqual(payload["summary"]["valid_import_rows"], 0)
        self.assertEqual(payload["summary"]["problem_counts"]["no_matching_resolved_outcome"], 1)
        self.assertFalse(linkage.exists())

    def test_outcome_class_only_row_imports_when_normalized_outcome_matches(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            proof = ws / "proofs" / "duplicate.json"
            proof.parent.mkdir()
            proof.write_text(json.dumps({"terminal_route_verdict": "PARTIAL"}), encoding="utf-8")
            outcome = ws / "outcome.json"
            outcome.write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "workspace": "fixture-audit",
                                "finding_id": "D1",
                                "title": "Duplicate class-only row",
                                "outcome_class": "duplicate",
                                "status": "Duplicate",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            evidence = ws / "route-evidence.jsonl"
            evidence.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.outcome_calibration_route_evidence.v1",
                        "workspace": "fixture-audit",
                        "finding_id": "D1",
                        "title": "Duplicate class-only row",
                        "lane": "detector",
                        "model_route": "minimax/adversarial-kill",
                        "terminal_route_verdict": "PARTIAL",
                        "final_triager_outcome": "duplicate",
                        "proof_artifact": "proofs/duplicate.json",
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
                input_jsonl=evidence,
                linkage_jsonl=ws / "linkage.jsonl",
                write_linkage=True,
            )

        self.assertEqual(payload["summary"]["valid_import_rows"], 1)
        self.assertNotIn("final_triager_outcome_mismatch", payload["rows"][0]["problem_codes"])

    def test_invalid_rows_do_not_import_or_fabricate_outcomes(self) -> None:
        mod = _import()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            proof = ws / "proofs" / "route-9.json"
            proof.parent.mkdir()
            proof.write_text(json.dumps({"terminal_route_verdict": "FALSE"}), encoding="utf-8")
            outcome = ws / "outcome.json"
            outcome.write_text(
                json.dumps(
                    {
                        "records": [
                            {
                                "workspace": "fixture-audit",
                                "finding_id": "9",
                                "title": "Rejected routed finding",
                                "outcome": "rejected",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            evidence = ws / "route-evidence.jsonl"
            evidence.write_text(
                "\n".join(
                    [
                        json.dumps(
                            {
                                "schema": "auditooor.outcome_calibration_route_evidence.v1",
                                "workspace": "fixture-audit",
                                "finding_id": "9",
                                "title": "Rejected routed finding",
                                "lane": "source-proof",
                                "model_route": "kimi/source-extraction",
                                "terminal_route_verdict": "FALSE",
                                "final_triager_outcome": "accepted",
                                "proof_artifact": "proofs/route-9.json",
                                "production_path_status": "verified",
                                "production_path_blockers_cleared": True,
                            }
                        ),
                        json.dumps(
                            {
                                "schema": "auditooor.outcome_calibration_route_evidence.v1",
                                "workspace": "fixture-audit",
                                "finding_id": "10",
                                "title": "Invented routed finding",
                                "lane": "detector",
                                "model_route": "minimax/adversarial-kill",
                                "terminal_route_verdict": "TRUE",
                                "final_triager_outcome": "accepted",
                                "proof_artifact": "proofs/missing.json",
                                "production_path_status": "verified",
                                "production_path_blockers_cleared": True,
                            }
                        ),
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            linkage = ws / "linkage.jsonl"

            payload = mod.build_payload(
                workspace=ws,
                outcome_json=[outcome],
                input_jsonl=evidence,
                linkage_jsonl=linkage,
                write_linkage=True,
            )
            linkage_text = linkage.read_text(encoding="utf-8")

        self.assertEqual(payload["summary"]["valid_import_rows"], 0)
        self.assertEqual(payload["summary"]["invalid_import_rows"], 2)
        self.assertEqual(payload["summary"]["linkage_rows_written"], 0)
        self.assertEqual(payload["summary"]["problem_counts"]["final_triager_outcome_mismatch"], 1)
        self.assertEqual(payload["summary"]["problem_counts"]["no_matching_resolved_outcome"], 1)
        self.assertEqual(payload["summary"]["problem_counts"]["proof_artifact_missing"], 1)
        self.assertEqual(linkage_text, "")


if __name__ == "__main__":
    unittest.main()
