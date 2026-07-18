from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
EXECUTOR_TOOL = ROOT / "tools" / "live-topology-proof-executor.py"


def _run(*args: Path | str) -> None:
    proc = subprocess.run(
        [str(arg) for arg in args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(proc.stderr or proc.stdout)


def _write_requirements(
    audit_dir: Path,
    *,
    source_ref: str | None = None,
    topology_path: str | None = None,
    proof_command: str | None = None,
) -> None:
    pair_id = "LTPR-001-pair"
    requirement = {
        "requirement_id": "LTPR-001",
        "required_proof_pair_id": pair_id,
        "required_contracts": ["Portal", "Bridge"],
        "required_live_rows": [
            {
                "id": "LTPR-001-edge",
                "contract": "Portal",
                "evidence_class": "topology-relation",
                "proof_pair_id": pair_id,
            },
            {
                "id": "LTPR-001-authority",
                "contract": "Bridge",
                "evidence_class": "topology-relation",
                "proof_pair_id": pair_id,
            },
        ],
        "submission_posture": "NOT_SUBMIT_READY",
        "promotion_allowed": False,
    }
    if source_ref is not None:
        requirement["source_refs"] = [source_ref]
    if topology_path is not None:
        requirement["configured_topology_path"] = topology_path
        requirement["configured_topology_evidence"] = f"deployment relation verified at {topology_path}"
    if proof_command is not None:
        requirement["proof_command"] = proof_command
    (audit_dir / "live_topology_proof_requirements.json").write_text(
        json.dumps(
            {
                "schema": "auditooor.live_topology_proof_requirements.v1",
                "requirements": [requirement],
            }
        ),
        encoding="utf-8",
    )


def _write_strict_fixtures(ws: Path) -> None:
    (ws / "src").mkdir(parents=True)
    (ws / "deployments").mkdir()
    (ws / "proofs").mkdir()
    (ws / "src" / "Portal.sol").write_text("contract Portal {}\n", encoding="utf-8")
    (ws / "deployments" / "topology.json").write_text('{"Portal":"Bridge"}\n', encoding="utf-8")
    (ws / "proofs" / "run_topology.py").write_text("print('ok')\n", encoding="utf-8")


def _write_live_topology(
    ws: Path,
    *,
    authority_block: str = "123",
    evidence_class: str = "topology-relation",
    edge_blockers: list[str] | None = None,
    edge_advisory_only: bool = False,
) -> None:
    pair_id = "LTPR-001-pair"
    pair_blocks = sorted({"123", authority_block})
    edge_row = {
        "id": "LTPR-001-edge",
        "status": "pass",
        "contract": "Portal",
        "evidence_class": "topology-relation",
        "block": "123",
        "proof_pair_id": pair_id,
    }
    if edge_blockers:
        edge_row["proof_blockers"] = edge_blockers
    if edge_advisory_only:
        edge_row["execution_contract"] = {"claim": "runnable_harness", "advisory_only": True}
    (ws / "live_topology_checks.json").write_text(
        json.dumps(
            {
                "results": [
                    edge_row,
                    {
                        "id": "LTPR-001-authority",
                        "status": "pass",
                        "contract": "Bridge",
                        "evidence_class": evidence_class,
                        "block": authority_block,
                        "proof_pair_id": pair_id,
                    },
                ],
                "proof_pairs": [
                    {
                        "id": pair_id,
                        "status": "proved" if len(pair_blocks) == 1 else "conflicting",
                        "row_ids": ["LTPR-001-edge", "LTPR-001-authority"],
                        "shared_block": "123" if len(pair_blocks) == 1 else "",
                        "pair_blocks": pair_blocks,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def _write_live_topology_with_statuses(
    ws: Path,
    *,
    edge_status: str = "pass",
    authority_status: str = "pass",
    include_row_blocks: bool = True,
) -> None:
    pair_id = "LTPR-001-pair"
    edge_row = {
        "id": "LTPR-001-edge",
        "status": edge_status,
        "contract": "Portal",
        "evidence_class": "topology-relation",
        "proof_pair_id": pair_id,
    }
    authority_row = {
        "id": "LTPR-001-authority",
        "status": authority_status,
        "contract": "Bridge",
        "evidence_class": "topology-relation",
        "proof_pair_id": pair_id,
    }
    if include_row_blocks:
        edge_row["block"] = "123"
        authority_row["block"] = "123"
    (ws / "live_topology_checks.json").write_text(
        json.dumps(
            {
                "results": [edge_row, authority_row],
                "proof_pairs": [
                    {
                        "id": pair_id,
                        "status": "proved",
                        "row_ids": ["LTPR-001-edge", "LTPR-001-authority"],
                        "shared_block": "123",
                        "pair_blocks": ["123"],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


class LiveTopologyProofExecutorTest(unittest.TestCase):
    def test_absent_live_topology_is_terminal_not_submit_ready(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            _write_requirements(audit_dir)

            _run(sys.executable, EXECUTOR_TOOL, "--workspace", ws)

            payload = json.loads((audit_dir / "live_topology_proof_executor.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "auditooor.live_topology_proof_executor.v1")
            self.assertFalse(payload["live_topology_available"])
            self.assertEqual(payload["depth_closure_candidate_count"], 0)
            self.assertEqual(payload["status_counts"], {"terminal_missing_live_topology_checks": 1})
            self.assertEqual(payload["blocker_kind_counts"], {"missing_live_topology_artifact": 1})
            self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
            self.assertFalse(payload["promotion_allowed"])

    def test_same_block_topology_pair_becomes_depth_closure_candidate_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            _write_requirements(audit_dir)
            _write_live_topology(ws)

            _run(sys.executable, EXECUTOR_TOOL, "--workspace", ws)

            payload = json.loads((audit_dir / "live_topology_proof_executor.json").read_text(encoding="utf-8"))
            self.assertTrue(payload["live_topology_available"])
            self.assertEqual(payload["depth_closure_candidate_count"], 1)
            row = payload["rows"][0]
            self.assertEqual(row["status"], "closure_candidate_same_block_pair_validated")
            self.assertTrue(row["depth_closure_candidate"])
            self.assertEqual(row["exact_next_commands"], [])
            self.assertEqual(row["closure_scope"], "semantic_live_topology_depth_only")
            self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")
            self.assertEqual(row["severity"], "none")
            self.assertFalse(row["promotion_allowed"])

    def test_execution_ready_pass_requires_current_source_topology_and_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            _write_strict_fixtures(ws)
            _write_requirements(
                audit_dir,
                source_ref="src/Portal.sol:1",
                topology_path="deployments/topology.json",
                proof_command="python3 proofs/run_topology.py",
            )
            _write_live_topology(ws)

            _run(sys.executable, EXECUTOR_TOOL, "--workspace", ws)

            payload = json.loads((audit_dir / "live_topology_proof_executor.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["execution_ready_count"], 1)
            self.assertEqual(payload["execution_non_ready_count"], 0)
            row = payload["rows"][0]
            self.assertEqual(row["execution_readiness_status"], "execution_ready")
            self.assertTrue(row["execution_ready"])
            self.assertEqual(row["execution_readiness_reasons"], [])
            self.assertEqual(row["source_refs"][0]["path"], "src/Portal.sol:1")
            self.assertEqual(row["configured_topology_refs"][0]["path"], "deployments/topology.json")
            self.assertEqual(row["proof_commands"], ["python3 proofs/run_topology.py"])
            self.assertFalse(row["advisory_only"])
            self.assertEqual(row["submission_posture"], "EXECUTION_READY_NOT_SUBMIT_READY")
            self.assertFalse(row["promotion_allowed"])

    def test_execution_ready_blocks_when_source_refs_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            _write_strict_fixtures(ws)
            _write_requirements(
                audit_dir,
                topology_path="deployments/topology.json",
                proof_command="python3 proofs/run_topology.py",
            )
            _write_live_topology(ws)

            _run(sys.executable, EXECUTOR_TOOL, "--workspace", ws)

            payload = json.loads((audit_dir / "live_topology_proof_executor.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["execution_ready_count"], 0)
            self.assertEqual(len(payload["rows"]), 1)
            row = payload["rows"][0]
            self.assertFalse(row["execution_ready"])
            self.assertEqual(row["execution_readiness_status"], "blocked_execution_readiness_inputs")
            self.assertIn("missing_current_workspace_source_refs", row["execution_readiness_reasons"])
            self.assertEqual(payload["execution_readiness_reason_counts"]["missing_current_workspace_source_refs"], 1)

    def test_execution_ready_blocks_when_source_refs_are_stale(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            _write_strict_fixtures(ws)
            _write_requirements(
                audit_dir,
                source_ref="src/Missing.sol:1",
                topology_path="deployments/topology.json",
                proof_command="python3 proofs/run_topology.py",
            )
            _write_live_topology(ws)

            _run(sys.executable, EXECUTOR_TOOL, "--workspace", ws)

            payload = json.loads((audit_dir / "live_topology_proof_executor.json").read_text(encoding="utf-8"))
            row = payload["rows"][0]
            self.assertFalse(row["execution_ready"])
            self.assertIn("stale_workspace_source_refs", row["execution_readiness_reasons"])
            self.assertEqual(row["source_ref_blockers"][0]["reason"], "stale_workspace_source_ref")
            self.assertEqual(row["source_ref_blockers"][0]["path"], "src/Missing.sol:1")

    def test_execution_ready_blocks_when_configured_topology_evidence_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            _write_strict_fixtures(ws)
            _write_requirements(
                audit_dir,
                source_ref="src/Portal.sol:1",
                proof_command="python3 proofs/run_topology.py",
            )
            _write_live_topology(ws)

            _run(sys.executable, EXECUTOR_TOOL, "--workspace", ws)

            payload = json.loads((audit_dir / "live_topology_proof_executor.json").read_text(encoding="utf-8"))
            row = payload["rows"][0]
            self.assertFalse(row["execution_ready"])
            self.assertIn("missing_configured_topology_evidence", row["execution_readiness_reasons"])
            self.assertEqual(row["configured_topology_evidence"], [])
            self.assertEqual(row["configured_topology_refs"], [])

    def test_execution_ready_blocks_and_propagates_existing_blockers(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            _write_strict_fixtures(ws)
            _write_requirements(
                audit_dir,
                source_ref="src/Portal.sol:1",
                topology_path="deployments/topology.json",
                proof_command="python3 proofs/run_topology.py",
            )
            _write_live_topology(ws, edge_blockers=["rpc_mismatch"], edge_advisory_only=True)

            _run(sys.executable, EXECUTOR_TOOL, "--workspace", ws)

            payload = json.loads((audit_dir / "live_topology_proof_executor.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["depth_closure_candidate_count"], 1)
            self.assertEqual(payload["execution_ready_count"], 0)
            row = payload["rows"][0]
            self.assertFalse(row["execution_ready"])
            self.assertTrue(row["depth_closure_candidate"])
            self.assertIn("proof_blockers_present", row["execution_readiness_reasons"])
            self.assertIn("advisory_only_evidence", row["execution_readiness_reasons"])
            self.assertEqual(row["blocking_markers"], ["rpc_mismatch"])
            self.assertEqual(payload["execution_readiness_reason_counts"]["proof_blockers_present"], 1)
            self.assertEqual(payload["execution_readiness_reason_counts"]["advisory_only_evidence"], 1)

    def test_cross_block_or_wrong_evidence_pair_stays_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            _write_requirements(audit_dir)
            _write_live_topology(ws, authority_block="124", evidence_class="balance-proof")

            _run(sys.executable, EXECUTOR_TOOL, "--workspace", ws)

            payload = json.loads((audit_dir / "live_topology_proof_executor.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["depth_closure_candidate_count"], 0)
            row = payload["rows"][0]
            self.assertEqual(row["status"], "blocked_pair_not_exact")
            self.assertIn("proof pair status is not proved", row["blockers"])
            self.assertIn("proof pair rows are not all topology-relation evidence", row["blockers"])
            self.assertIn("proof pair is not pinned to one shared block", row["blockers"])
            self.assertEqual(row["blocker_kind"], "pair_not_exact")

    def test_failed_same_block_pair_cannot_be_depth_closure_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            _write_requirements(audit_dir)
            _write_live_topology_with_statuses(ws, authority_status="fail")

            _run(sys.executable, EXECUTOR_TOOL, "--workspace", ws)

            payload = json.loads((audit_dir / "live_topology_proof_executor.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["depth_closure_candidate_count"], 0)
            row = payload["rows"][0]
            self.assertEqual(row["status"], "blocked_pair_not_exact")
            self.assertIn("proof pair has failing rows: LTPR-001-authority", row["blockers"])
            self.assertIn("proof pair has fewer than two passing rows", row["blockers"])
            self.assertEqual(row["failing_row_ids"], ["LTPR-001-authority"])

    def test_pair_metadata_block_without_row_blocks_stays_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            _write_requirements(audit_dir)
            _write_live_topology_with_statuses(ws, include_row_blocks=False)

            _run(sys.executable, EXECUTOR_TOOL, "--workspace", ws)

            payload = json.loads((audit_dir / "live_topology_proof_executor.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["depth_closure_candidate_count"], 0)
            row = payload["rows"][0]
            self.assertIn("executed proof pair rows are missing block pins: LTPR-001-authority,LTPR-001-edge", row["blockers"])
            self.assertIn("proof pair is not pinned to one shared block", row["blockers"])
            self.assertEqual(row["pair_declared_blocks"], ["123"])
            self.assertEqual(row["validated_blocks"], [])

    def test_not_collected_skeleton_pair_gets_exact_terminal_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            _write_requirements(audit_dir)
            pair_id = "LTPR-001-pair"
            (ws / "live_topology_checks.json").write_text(
                json.dumps(
                    {
                        "results": [
                            {
                                "id": "LTPR-001-edge",
                                "status": "required_not_collected",
                                "contract": "Portal",
                                "evidence_class": "topology-relation",
                                "proof_pair_id": pair_id,
                                "requirement_id": "LTPR-001",
                            },
                            {
                                "id": "LTPR-001-authority",
                                "status": "required_not_collected",
                                "contract": "Bridge",
                                "evidence_class": "topology-relation",
                                "proof_pair_id": pair_id,
                                "requirement_id": "LTPR-001",
                            },
                        ],
                        "proof_pairs": [
                            {
                                "id": pair_id,
                                "status": "required_not_collected",
                                "row_ids": ["LTPR-001-edge", "LTPR-001-authority"],
                                "shared_block": None,
                                "pair_blocks": [],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            _run(sys.executable, EXECUTOR_TOOL, "--workspace", ws)

            payload = json.loads((audit_dir / "live_topology_proof_executor.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["status_counts"], {"terminal_required_not_collected_pair": 1})
            self.assertEqual(payload["blocker_kind_counts"], {"required_not_collected_pair": 1})
            row = payload["rows"][0]
            self.assertEqual(row["status"], "terminal_required_not_collected_pair")
            self.assertEqual(row["blocker_kind"], "required_not_collected_pair")
            self.assertEqual(row["required_proof_pair_id"], pair_id)
            self.assertIn("LTPR-001-edge", row["required_live_row_ids"])
            self.assertTrue(any("live-check-runner.py" in command for command in row["exact_next_commands"]))

    def test_demo_fixture_proves_workspace_neutral_non_base_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            _write_requirements(audit_dir)

            _run(sys.executable, EXECUTOR_TOOL, "--workspace", ws, "--demo-fixture")

            payload = json.loads((audit_dir / "live_topology_proof_executor.json").read_text(encoding="utf-8"))
            demo = payload["demo_fixture"]
            self.assertEqual(demo["fixture_kind"], "hermetic_non_base_same_block_pair")
            self.assertEqual(demo["depth_closure_candidate_count"], 1)
            self.assertEqual(demo["status_counts"], {"closure_candidate_same_block_pair_validated": 1})
            self.assertIn("HermeticPortal", demo["rows"][0]["validated_contracts"])


if __name__ == "__main__":
    unittest.main()
