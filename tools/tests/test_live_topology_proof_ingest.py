from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INGEST_TOOL = ROOT / "tools" / "live-topology-proof-ingest.py"
EXECUTOR_TOOL = ROOT / "tools" / "live-topology-proof-executor.py"
RUNNER_TOOL = ROOT / "tools" / "live-check-runner.py"


def _run(*args: Path | str) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        [str(arg) for arg in args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(proc.stderr or proc.stdout)
    return proc


def _write_requirements(audit_dir: Path) -> None:
    pair_id = "LTPR-001-pair"
    (audit_dir / "live_topology_proof_requirements.json").write_text(
        json.dumps(
            {
                "schema": "auditooor.live_topology_proof_requirements.v1",
                "requirements": [
                    {
                        "requirement_id": "LTPR-001",
                        "source_item_id": "A-HERMETIC",
                        "required_proof_pair_id": pair_id,
                        "required_contracts": ["HermeticPortal", "HermeticBridge"],
                        "required_live_rows": [
                            {
                                "id": "LTPR-001-edge",
                                "contract": "HermeticPortal",
                                "evidence_class": "topology-relation",
                                "proof_pair_id": pair_id,
                                "requirement_role": "relation-edge",
                            },
                            {
                                "id": "LTPR-001-authority",
                                "contract": "HermeticBridge",
                                "evidence_class": "topology-relation",
                                "proof_pair_id": pair_id,
                                "requirement_role": "authority-or-wiring",
                            },
                        ],
                        "submission_posture": "NOT_SUBMIT_READY",
                        "promotion_allowed": False,
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )


def _write_requirements_with_proof_rows(audit_dir: Path, proof_rows: list[dict[str, object]]) -> None:
    pair_id = "LTPR-001-pair"
    payload = {
        "schema": "auditooor.live_topology_proof_requirements.v1",
        "ingested_proof_rows": proof_rows,
        "requirements": [
            {
                "requirement_id": "LTPR-001",
                "source_item_id": "A-HERMETIC",
                "required_proof_pair_id": pair_id,
                "required_contracts": ["HermeticPortal", "HermeticBridge"],
                "required_live_rows": [
                    {
                        "id": "LTPR-001-edge",
                        "contract": "HermeticPortal",
                        "evidence_class": "topology-relation",
                        "proof_pair_id": pair_id,
                        "requirement_role": "relation-edge",
                    },
                    {
                        "id": "LTPR-001-authority",
                        "contract": "HermeticBridge",
                        "evidence_class": "topology-relation",
                        "proof_pair_id": pair_id,
                        "requirement_role": "authority-or-wiring",
                    },
                ],
                "submission_posture": "NOT_SUBMIT_READY",
                "promotion_allowed": False,
            }
        ],
    }
    (audit_dir / "live_topology_proof_requirements.json").write_text(
        json.dumps(payload) + "\n",
        encoding="utf-8",
    )


def _seed_strict_evidence(ws: Path) -> None:
    (ws / "contracts").mkdir()
    (ws / "contracts" / "HermeticPortal.sol").write_text(
        "contract HermeticPortal {}\n",
        encoding="utf-8",
    )
    (ws / "deployment_topology.json").write_text(
        json.dumps({"entries": [{"contract": "HermeticPortal", "resolved_address": "0x1"}]}) + "\n",
        encoding="utf-8",
    )
    (ws / "proofs").mkdir()
    (ws / "proofs" / "live_topology_pass.txt").write_text(
        "Suite result: ok. 1 passed; 0 failed.\n",
        encoding="utf-8",
    )


def _valid_ingested_row() -> dict[str, object]:
    return {
        "id": "LTPR-001-edge",
        "title": "Hermetic edge relation",
        "contract": "HermeticPortal",
        "network": "hermetic",
        "block": "424242",
        "address": "0x0000000000000000000000000000000000000001",
        "status": "pass",
        "match": True,
        "actual": "0x0000000000000000000000000000000000000002",
        "expected": "0x0000000000000000000000000000000000000002",
        "evidence_class": "topology-relation",
        "related_angle_ids": ["A-HERMETIC"],
        "proof_pair_id": "LTPR-001-pair",
        "source_refs": ["contracts/HermeticPortal.sol:1"],
        "configured_topology_path": "deployment_topology.json",
        "configured_topology_evidence": "deployment_topology.json resolves HermeticPortal",
        "proof_artifact_path": "proofs/live_topology_pass.txt",
        "harness_evidence": "Suite result: ok. 1 passed; 0 failed.",
    }


class LiveTopologyProofIngestTest(unittest.TestCase):
    def test_ingest_writes_spec_and_not_collected_canonical_skeleton(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            _write_requirements(audit_dir)

            _run(sys.executable, INGEST_TOOL, "--workspace", ws, "--write-canonical-skeleton")

            ingest = json.loads((audit_dir / "live_topology_proof_ingest.json").read_text(encoding="utf-8"))
            self.assertEqual(ingest["schema"], "auditooor.live_topology_proof_ingest.v1")
            self.assertEqual(ingest["generated_check_count"], 2)
            self.assertEqual(ingest["generated_pair_count"], 1)
            self.assertEqual(ingest["submission_posture"], "NOT_SUBMIT_READY")
            self.assertFalse(ingest["promotion_allowed"])

            spec = json.loads((ws / "monitoring" / "live_topology_proof_requirements.generated.json").read_text(encoding="utf-8"))
            self.assertEqual(spec["checks"][0]["proof_pair_id"], "LTPR-001-pair")
            self.assertEqual(spec["checks"][0]["evidence_class"], "topology-relation")

            live = json.loads((ws / "live_topology_checks.json").read_text(encoding="utf-8"))
            self.assertEqual(live["proof_pairs"][0]["status"], "required_not_collected")
            self.assertEqual(live["results"][0]["status"], "required_not_collected")

            _run(sys.executable, EXECUTOR_TOOL, "--workspace", ws)
            execution = json.loads((audit_dir / "live_topology_proof_executor.json").read_text(encoding="utf-8"))
            self.assertTrue(execution["live_topology_available"])
            self.assertEqual(execution["status_counts"], {"terminal_required_not_collected_pair": 1})
            self.assertEqual(execution["blocker_kind_counts"], {"required_not_collected_pair": 1})
            self.assertIn("proof pair status is not proved", execution["rows"][0]["blockers"])
            self.assertTrue(execution["rows"][0]["exact_next_commands"])

    def test_live_check_runner_preserves_generated_pair_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            _write_requirements(audit_dir)
            _run(sys.executable, INGEST_TOOL, "--workspace", ws)

            spec = ws / "monitoring" / "live_topology_proof_requirements.generated.json"
            _run(sys.executable, RUNNER_TOOL, ws, "--spec", spec, "--dry-run")

            live = json.loads((ws / "live_topology_checks.json").read_text(encoding="utf-8"))
            self.assertEqual(live["results"][0]["proof_pair_id"], "LTPR-001-pair")
            self.assertEqual(live["results"][0]["requirement_id"], "LTPR-001")
            self.assertEqual(live["proof_pairs"][0]["id"], "LTPR-001-pair")
            self.assertEqual(live["proof_pairs"][0]["status"], "partial")

    def test_executed_manual_proof_import_auto_closes_hermetic_non_base_pair(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            proof_dir = ws / "manual_proofs"
            audit_dir.mkdir()
            proof_dir.mkdir()
            _write_requirements(audit_dir)
            (proof_dir / "hermetic_pair.json").write_text(
                json.dumps(
                    {
                        "workspace": str(ws),
                        "summary": {"dry_run": False},
                        "results": [
                            {
                                "id": "LTPR-001-edge",
                                "title": "Hermetic edge relation",
                                "contract": "HermeticPortal",
                                "network": "hermetic",
                                "block": "424242",
                                "address": "0x0000000000000000000000000000000000000001",
                                "status": "pass",
                                "match": True,
                                "actual": "0x0000000000000000000000000000000000000002",
                                "expected": "0x0000000000000000000000000000000000000002",
                                "evidence_class": "topology-relation",
                                "related_angle_ids": ["A-HERMETIC"],
                                "proof_pair_id": "LTPR-001-pair",
                                "live_result": {"sig": "owner()", "args": [], "actual_normalized": "0x2"},
                            },
                            {
                                "id": "LTPR-001-authority",
                                "title": "Hermetic authority relation",
                                "contract": "HermeticBridge",
                                "network": "hermetic",
                                "block": "424242",
                                "address": "0x0000000000000000000000000000000000000002",
                                "status": "pass",
                                "match": True,
                                "actual": "0x0000000000000000000000000000000000000001",
                                "expected": "0x0000000000000000000000000000000000000001",
                                "evidence_class": "topology-relation",
                                "related_angle_ids": ["A-HERMETIC"],
                                "proof_pair_id": "LTPR-001-pair",
                                "live_result": {"sig": "owner()", "args": [], "actual_normalized": "0x1"},
                            },
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            _run(sys.executable, RUNNER_TOOL, ws, "--import-manual-proofs")
            live = json.loads((ws / "live_topology_checks.json").read_text(encoding="utf-8"))
            self.assertEqual(live["proof_pairs"][0]["status"], "proved")
            self.assertEqual(live["proof_pairs"][0]["shared_block"], "424242")

            _run(sys.executable, EXECUTOR_TOOL, "--workspace", ws)
            execution = json.loads((audit_dir / "live_topology_proof_executor.json").read_text(encoding="utf-8"))
            self.assertEqual(execution["depth_closure_candidate_count"], 1)
            self.assertEqual(execution["rows"][0]["status"], "closure_candidate_same_block_pair_validated")
            self.assertEqual(execution["rows"][0]["submission_posture"], "NOT_SUBMIT_READY")

    def test_manual_proof_import_with_failed_half_does_not_prove_pair(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            proof_dir = ws / "manual_proofs"
            audit_dir.mkdir()
            proof_dir.mkdir()
            _write_requirements(audit_dir)
            (proof_dir / "hermetic_pair.json").write_text(
                json.dumps(
                    {
                        "workspace": str(ws),
                        "summary": {"dry_run": False},
                        "results": [
                            {
                                "id": "LTPR-001-edge",
                                "title": "Hermetic edge relation",
                                "contract": "HermeticPortal",
                                "network": "hermetic",
                                "block": "424242",
                                "address": "0x0000000000000000000000000000000000000001",
                                "status": "pass",
                                "match": True,
                                "expected": "0x0000000000000000000000000000000000000002",
                                "actual": "0x0000000000000000000000000000000000000002",
                                "evidence_class": "topology-relation",
                                "proof_pair_id": "LTPR-001-pair",
                                "live_result": {"sig": "owner()", "args": []},
                            },
                            {
                                "id": "LTPR-001-authority",
                                "title": "Hermetic authority relation",
                                "contract": "HermeticBridge",
                                "network": "hermetic",
                                "block": "424242",
                                "address": "0x0000000000000000000000000000000000000002",
                                "status": "fail",
                                "match": False,
                                "expected": "0x0000000000000000000000000000000000000001",
                                "actual": "0x0000000000000000000000000000000000000003",
                                "evidence_class": "topology-relation",
                                "proof_pair_id": "LTPR-001-pair",
                                "live_result": {"sig": "owner()", "args": []},
                            },
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            _run(sys.executable, RUNNER_TOOL, ws, "--import-manual-proofs")
            live = json.loads((ws / "live_topology_checks.json").read_text(encoding="utf-8"))
            self.assertEqual(live["proof_pairs"][0]["status"], "failed")
            self.assertEqual(live["proof_pair_summary"]["failed"], 1)

            _run(sys.executable, EXECUTOR_TOOL, "--workspace", ws)
            execution = json.loads((audit_dir / "live_topology_proof_executor.json").read_text(encoding="utf-8"))
            self.assertEqual(execution["depth_closure_candidate_count"], 0)
            self.assertIn("proof pair status is not proved", execution["rows"][0]["blockers"])
            self.assertIn("proof pair has failing rows: LTPR-001-authority", execution["rows"][0]["blockers"])

    def test_strict_ingested_proof_row_accepts_current_source_topology_and_proof(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            _seed_strict_evidence(ws)
            _write_requirements_with_proof_rows(audit_dir, [_valid_ingested_row()])

            _run(sys.executable, INGEST_TOOL, "--workspace", ws, "--write-canonical-skeleton")

            ingest = json.loads((audit_dir / "live_topology_proof_ingest.json").read_text(encoding="utf-8"))
            self.assertEqual(ingest["accepted_ingested_proof_row_count"], 1)
            self.assertEqual(ingest["rejected_ingested_proof_row_count"], 0)
            accepted = ingest["accepted_ingested_proof_rows"][0]
            self.assertEqual(accepted["ingest_status"], "accepted")
            self.assertEqual(accepted["ingest_rejection_reasons"], [])
            self.assertTrue(accepted["current_workspace_source_refs"])
            self.assertTrue(accepted["configured_topology_refs"])
            self.assertTrue(accepted["concrete_proof_or_harness_evidence"])

            live = json.loads((ws / "live_topology_checks.json").read_text(encoding="utf-8"))
            rows_by_id = {row["id"]: row for row in live["results"]}
            self.assertEqual(rows_by_id["LTPR-001-edge"]["ingest_status"], "accepted")
            self.assertEqual(rows_by_id["LTPR-001-edge"]["status"], "pass")

    def test_strict_ingested_proof_row_rejects_missing_source_refs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            _seed_strict_evidence(ws)
            row = _valid_ingested_row()
            row.pop("source_refs")
            _write_requirements_with_proof_rows(audit_dir, [row])

            _run(sys.executable, INGEST_TOOL, "--workspace", ws)

            ingest = json.loads((audit_dir / "live_topology_proof_ingest.json").read_text(encoding="utf-8"))
            self.assertEqual(ingest["accepted_ingested_proof_row_count"], 0)
            self.assertEqual(ingest["rejected_ingested_proof_row_count"], 1)
            rejected = ingest["rejected_ingested_proof_rows"][0]
            self.assertEqual(rejected["ingest_status"], "rejected")
            self.assertIn("missing_source_refs", rejected["ingest_rejection_reasons"])
            self.assertEqual(ingest["ingested_proof_rejection_reason_counts"]["missing_source_refs"], 1)

    def test_strict_ingested_proof_row_rejects_stale_workspace_source_refs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            _seed_strict_evidence(ws)
            row = _valid_ingested_row()
            row["source_refs"] = ["contracts/MissingPortal.sol:1"]
            _write_requirements_with_proof_rows(audit_dir, [row])

            _run(sys.executable, INGEST_TOOL, "--workspace", ws)

            ingest = json.loads((audit_dir / "live_topology_proof_ingest.json").read_text(encoding="utf-8"))
            rejected = ingest["rejected_ingested_proof_rows"][0]
            self.assertIn("stale_workspace_source_refs", rejected["ingest_rejection_reasons"])
            self.assertTrue(rejected["source_ref_blockers"])

    def test_strict_ingested_proof_row_rejects_missing_topology_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            _seed_strict_evidence(ws)
            row = _valid_ingested_row()
            row.pop("configured_topology_path")
            row.pop("configured_topology_evidence")
            _write_requirements_with_proof_rows(audit_dir, [row])

            _run(sys.executable, INGEST_TOOL, "--workspace", ws)

            ingest = json.loads((audit_dir / "live_topology_proof_ingest.json").read_text(encoding="utf-8"))
            rejected = ingest["rejected_ingested_proof_rows"][0]
            self.assertIn("missing_configured_topology_evidence", rejected["ingest_rejection_reasons"])

    def test_strict_ingested_proof_row_propagates_blocker_markers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            _seed_strict_evidence(ws)
            row = _valid_ingested_row()
            row["blockers"] = ["operator required before use"]
            _write_requirements_with_proof_rows(audit_dir, [row])

            _run(sys.executable, INGEST_TOOL, "--workspace", ws)

            ingest = json.loads((audit_dir / "live_topology_proof_ingest.json").read_text(encoding="utf-8"))
            rejected = ingest["rejected_ingested_proof_rows"][0]
            self.assertIn("blocker_marker_present", rejected["ingest_rejection_reasons"])
            self.assertEqual(ingest["ingested_proof_rejection_reason_counts"]["blocker_marker_present"], 1)


if __name__ == "__main__":
    unittest.main()
