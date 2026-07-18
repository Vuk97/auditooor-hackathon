from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
CLOSURE_TOOL = ROOT / "tools" / "live-topology-execution-closure.py"


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


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_strict_closure_inputs(
    ws: Path,
    *,
    requirement: dict,
    runner_rows: list[dict],
    executor_after_row: dict,
) -> None:
    audit_dir = ws / ".auditooor"
    pair_id = str(requirement["required_proof_pair_id"])
    row_ids = [str(row["id"]) for row in requirement["required_live_rows"]]
    _write_json(
        audit_dir / "live_topology_proof_requirements.json",
        {
            "schema": "auditooor.live_topology_proof_requirements.v1",
            "requirements": [requirement],
        },
    )
    _write_json(
        ws / "live_topology_checks.json",
        {
            "summary": {"pass": len(runner_rows)},
            "results": runner_rows,
            "proof_pairs": [
                {
                    "id": pair_id,
                    "status": "proved",
                    "row_ids": row_ids,
                    "shared_block": "777",
                    "pair_blocks": ["777"],
                }
            ],
            "proof_pair_summary": {"proved": 1},
        },
    )
    _write_json(
        audit_dir / "live_topology_runner_eo.json",
        {
            "summary": {"pass": len(runner_rows)},
            "manual_imports": {"enabled": True, "imported_rows": len(runner_rows)},
            "proof_pair_summary": {"proved": 1},
            "results": runner_rows,
        },
    )
    _write_json(
        audit_dir / "live_topology_proof_executor.json",
        {"status_counts": {"terminal_required_not_collected_pair": 1}, "rows": []},
    )
    _write_json(
        audit_dir / "live_topology_proof_executor_eo_runner.json",
        {
            "depth_closure_candidate_count": 1,
            "exact_same_block_pair_ids": [pair_id],
            "status_counts": {"closure_candidate_same_block_pair_validated": 1},
            "rows": [executor_after_row],
        },
    )
    _write_json(
        ws / "monitoring" / "live_topology_proof_requirements.generated.json",
        {"checks": [{"id": row_id, "address": "0x1000000000000000000000000000000000000000", "block": "777"} for row_id in row_ids]},
    )


def _base_requirement(*, source_ref: str | None = None, topology_path: str | None = None, proof_command: str | None = None) -> dict:
    pair_id = "LTPR-001-pair"
    requirement = {
        "requirement_id": "LTPR-001",
        "source_item_id": "A-STRICT",
        "source_component": "Portal.relay",
        "target_component": "Bridge.owner",
        "required_proof_pair_id": pair_id,
        "required_contracts": ["Portal", "Bridge"],
        "same_block_required": True,
        "required_live_rows": [
            {
                "id": "LTPR-001-edge",
                "contract": "Portal",
                "evidence_class": "topology-relation",
                "proof_pair_id": pair_id,
                "requirement_role": "relation-edge",
            },
            {
                "id": "LTPR-001-authority",
                "contract": "Bridge",
                "evidence_class": "topology-relation",
                "proof_pair_id": pair_id,
                "requirement_role": "authority-or-wiring",
            },
        ],
    }
    if source_ref is not None:
        requirement["source_refs"] = [source_ref]
    if topology_path is not None:
        requirement["configured_topology_path"] = topology_path
        requirement["configured_topology_evidence"] = f"configured topology in {topology_path}"
    if proof_command is not None:
        requirement["proof_command"] = proof_command
    return requirement


def _passing_runner_rows(requirement: dict, *, advisory: bool = False, blockers: list[str] | None = None) -> list[dict]:
    rows: list[dict] = []
    for raw in requirement["required_live_rows"]:
        row = {
            **raw,
            "title": raw["id"],
            "network": "hermetic",
            "status": "pass",
            "address": "0x1000000000000000000000000000000000000000",
            "block": "777",
            "check": {"call": "owner()", "expect": "0x2000000000000000000000000000000000000000"},
            "requirement_id": requirement["requirement_id"],
        }
        rows.append(row)
    if advisory:
        rows[0]["execution_contract"] = {"claim": "runnable_harness", "advisory_only": True}
    if blockers:
        rows[0]["proof_blockers"] = blockers
    return rows


def _ready_executor_row(requirement: dict) -> dict:
    return {
        "requirement_id": requirement["requirement_id"],
        "status": "closure_candidate_same_block_pair_validated",
        "depth_closure_candidate": True,
        "required_proof_pair_id": requirement["required_proof_pair_id"],
        "blockers": [],
    }


class LiveTopologyExecutionClosureTest(unittest.TestCase):
    def test_groups_unresolved_execution_attempts_without_fabricating_proof(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            pair_id = "LTPR-001-pair"
            req_rows = [
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
            ]
            _write_json(
                audit_dir / "live_topology_proof_requirements.json",
                {
                    "schema": "auditooor.live_topology_proof_requirements.v1",
                    "requirements": [
                        {
                            "requirement_id": "LTPR-001",
                            "source_item_id": "A-HERMETIC",
                            "source_component": "HermeticPortal.relay",
                            "target_component": "HermeticBridge.owner",
                            "required_proof_pair_id": pair_id,
                            "required_contracts": ["HermeticPortal", "HermeticBridge"],
                            "same_block_required": True,
                            "required_live_rows": req_rows,
                        }
                    ],
                },
            )
            _write_json(
                ws / "live_topology_checks.json",
                {
                    "summary": {"required_not_collected": 2},
                    "proof_pair_summary": {"declared": 1, "required_not_collected": 1},
                    "results": [
                        {**req_rows[0], "status": "required_not_collected"},
                        {**req_rows[1], "status": "required_not_collected"},
                    ],
                    "proof_pairs": [
                        {
                            "id": pair_id,
                            "status": "required_not_collected",
                            "row_ids": ["LTPR-001-edge", "LTPR-001-authority"],
                        }
                    ],
                },
            )
            runner_rows = [
                {
                    **req_rows[0],
                    "title": "LTPR-001 relation-edge",
                    "network": "hermetic",
                    "status": "blocked_unresolved_address",
                    "blocked_reason": "no resolved address in spec or deployment_topology.json",
                    "related_angle_ids": ["A-HERMETIC"],
                    "check": {"call": "owner()", "expect": "<fill-from-deployment-topology>"},
                    "requirement_id": "LTPR-001",
                },
                {
                    **req_rows[1],
                    "title": "LTPR-001 authority-or-wiring",
                    "network": "hermetic",
                    "status": "blocked_unresolved_address",
                    "blocked_reason": "no resolved address in spec or deployment_topology.json",
                    "related_angle_ids": ["A-HERMETIC"],
                    "check": {"call": "owner()", "expect": "<fill-from-deployment-topology>"},
                    "requirement_id": "LTPR-001",
                },
            ]
            _write_json(
                audit_dir / "live_topology_runner_eo.json",
                {
                    "summary": {"declared": 2, "blocked_unresolved_address": 2, "ready": 0},
                    "manual_imports": {"enabled": False, "imported_rows": 0},
                    "proof_pair_summary": {"declared": 1, "partial": 1},
                    "results": runner_rows,
                },
            )
            _write_json(
                audit_dir / "live_topology_proof_executor.json",
                {
                    "status_counts": {"terminal_required_not_collected_pair": 1},
                    "blocker_kind_counts": {"required_not_collected_pair": 1},
                    "rows": [
                        {
                            "requirement_id": "LTPR-001",
                            "status": "terminal_required_not_collected_pair",
                            "required_proof_pair_id": pair_id,
                        }
                    ],
                },
            )
            _write_json(
                audit_dir / "live_topology_proof_executor_eo_runner.json",
                {
                    "status_counts": {"blocked_pair_not_exact": 1},
                    "blocker_kind_counts": {"pair_not_exact": 1},
                    "blocker_reason_counts": {"proof pair has fewer than two executed rows": 1},
                    "depth_closure_candidate_count": 0,
                    "exact_same_block_pair_ids": [],
                    "rows": [
                        {
                            "requirement_id": "LTPR-001",
                            "status": "blocked_pair_not_exact",
                            "required_proof_pair_id": pair_id,
                        }
                    ],
                    "demo_fixture": {
                        "fixture_kind": "hermetic_non_base_same_block_pair",
                        "depth_closure_candidate_count": 1,
                        "status_counts": {"closure_candidate_same_block_pair_validated": 1},
                        "rows": [{"validated_contracts": ["HermeticPortal", "HermeticBridge"]}],
                    },
                },
            )
            _write_json(
                ws / "monitoring" / "live_topology_proof_requirements.generated.json",
                {"checks": [{"id": "LTPR-001-edge"}, {"id": "LTPR-001-authority"}]},
            )

            _run(sys.executable, CLOSURE_TOOL, "--workspace", ws)

            payload = json.loads((audit_dir / "live_topology_execution_closure_eo.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "auditooor.live_topology_execution_closure.v1")
            self.assertEqual(payload["closure"]["closed_requirement_count"], 0)
            self.assertEqual(payload["closure"]["reduced_requirement_count"], 1)
            self.assertEqual(payload["groups"]["missing_address"]["row_count"], 2)
            self.assertEqual(payload["groups"]["missing_block"]["requirement_count"], 1)
            self.assertEqual(payload["groups"]["missing_manual_proof_id"]["row_count"], 2)
            self.assertEqual(payload["closure"]["terminal_blocker_counts"]["address_unresolved"], 2)
            self.assertEqual(payload["closure"]["terminal_blocker_counts"]["manual_proof_missing"], 2)
            self.assertEqual(payload["closure"]["terminal_blocker_counts"]["same_block_unpinned"], 1)
            self.assertEqual(payload["groups"]["missing_rpc"]["items"][0]["network"], "hermetic")
            self.assertEqual(payload["groups"]["missing_rpc"]["items"][0]["rpc_env_var"], "HERMETIC_RPC_URL")
            requirement = payload["groups"]["by_requirement"]["items"][0]
            self.assertEqual(requirement["proof_pair_id"], pair_id)
            self.assertIn("LTPR-001-edge", requirement["missing_manual_proof_ids"])
            self.assertIn("address_unresolved:LTPR-001-edge:HermeticPortal", requirement["terminal_blockers"])
            self.assertIn("manual_proof_missing:LTPR-001-edge", requirement["terminal_blockers"])
            self.assertIn("same_block_unpinned:LTPR-001-pair", requirement["terminal_blockers"])
            self.assertTrue(any("--proof-pair-id LTPR-001-pair" in command for command in requirement["next_commands"]))
            self.assertTrue(payload["hermetic_non_base_demo"]["present"])
            self.assertEqual(payload["hermetic_non_base_demo"]["fixture_kind"], "hermetic_non_base_same_block_pair")
            self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
            self.assertFalse(payload["promotion_allowed"])

    def test_depth_candidate_is_not_closed_without_strict_execution_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            (ws / ".env").write_text("HERMETIC_RPC_URL=http://127.0.0.1:8545\n", encoding="utf-8")
            requirement = _base_requirement()
            for row in requirement["required_live_rows"]:
                _write_json(ws / "manual_proofs" / f"{row['id']}.json", {"results": [{"id": row["id"]}]})
            _write_strict_closure_inputs(
                ws,
                requirement=requirement,
                runner_rows=_passing_runner_rows(requirement),
                executor_after_row=_ready_executor_row(requirement),
            )

            _run(sys.executable, CLOSURE_TOOL, "--workspace", ws)

            payload = json.loads((audit_dir / "live_topology_execution_closure_eo.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["closure"]["depth_closure_candidate_count"], 1)
            self.assertEqual(payload["closure"]["closed_requirement_count"], 0)
            self.assertEqual(payload["groups"]["closure_readiness"]["non_ready_requirement_count"], 1)
            reasons = payload["groups"]["closure_readiness"]["non_ready_rows"][0]["closure_readiness_reasons"]
            self.assertIn("missing_source_refs", reasons)
            self.assertIn("missing_topology_evidence", reasons)
            self.assertIn("missing_execution_proof", reasons)
            self.assertEqual(payload["closure"]["closure_readiness_reason_counts"]["missing_source_refs"], 1)
            self.assertEqual(payload["groups"]["by_requirement"]["items"][0]["closure_readiness_status"], "blocked_closure_readiness_inputs")

    def test_closure_ready_requires_current_source_topology_and_proof_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            (ws / ".env").write_text("HERMETIC_RPC_URL=http://127.0.0.1:8545\n", encoding="utf-8")
            (ws / "src").mkdir()
            (ws / "deployments").mkdir()
            (ws / "proofs").mkdir()
            (ws / "src" / "Portal.sol").write_text("contract Portal {}\n", encoding="utf-8")
            (ws / "deployments" / "topology.json").write_text('{"Portal":"Bridge"}\n', encoding="utf-8")
            (ws / "proofs" / "run_topology.py").write_text("print('ok')\n", encoding="utf-8")
            requirement = _base_requirement(
                source_ref="src/Portal.sol:1",
                topology_path="deployments/topology.json",
                proof_command="python3 proofs/run_topology.py",
            )
            for row in requirement["required_live_rows"]:
                _write_json(ws / "manual_proofs" / f"{row['id']}.json", {"results": [{"id": row["id"]}]})
            _write_strict_closure_inputs(
                ws,
                requirement=requirement,
                runner_rows=_passing_runner_rows(requirement),
                executor_after_row=_ready_executor_row(requirement),
            )

            _run(sys.executable, CLOSURE_TOOL, "--workspace", ws)

            payload = json.loads((audit_dir / "live_topology_execution_closure_eo.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["closure"]["closed_requirement_count"], 1)
            self.assertEqual(payload["groups"]["closure_readiness"]["ready_requirement_count"], 1)
            ready = payload["groups"]["closure_readiness"]["ready_rows"][0]
            self.assertTrue(ready["closure_ready"])
            self.assertEqual(ready["closure_readiness_reasons"], [])
            self.assertEqual(ready["current_source_refs"][0]["path"], "src/Portal.sol:1")
            self.assertEqual(ready["configured_topology_refs"][0]["path"], "deployments/topology.json")
            self.assertEqual(ready["proof_commands"], ["python3 proofs/run_topology.py"])

    def test_non_ready_reasons_include_stale_source_blocker_and_advisory_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            audit_dir = ws / ".auditooor"
            audit_dir.mkdir()
            (ws / ".env").write_text("HERMETIC_RPC_URL=http://127.0.0.1:8545\n", encoding="utf-8")
            (ws / "deployments").mkdir()
            (ws / "deployments" / "topology.json").write_text('{"Portal":"Bridge"}\n', encoding="utf-8")
            requirement = _base_requirement(
                source_ref="src/Missing.sol:1",
                topology_path="deployments/topology.json",
                proof_command="python3 proofs/run_topology.py",
            )
            for row in requirement["required_live_rows"]:
                _write_json(ws / "manual_proofs" / f"{row['id']}.json", {"results": [{"id": row["id"]}]})
            _write_strict_closure_inputs(
                ws,
                requirement=requirement,
                runner_rows=_passing_runner_rows(requirement, advisory=True, blockers=["rpc_mismatch"]),
                executor_after_row=_ready_executor_row(requirement),
            )

            _run(sys.executable, CLOSURE_TOOL, "--workspace", ws)

            payload = json.loads((audit_dir / "live_topology_execution_closure_eo.json").read_text(encoding="utf-8"))
            row = payload["groups"]["closure_readiness"]["non_ready_rows"][0]
            self.assertFalse(row["closure_ready"])
            self.assertIn("stale_source_refs", row["closure_readiness_reasons"])
            self.assertIn("blocker_present", row["closure_readiness_reasons"])
            self.assertIn("advisory_only", row["closure_readiness_reasons"])
            self.assertEqual(row["source_ref_blockers"][0]["path"], "src/Missing.sol:1")
            self.assertEqual(row["blocking_markers"], ["rpc_mismatch"])
            self.assertEqual(payload["closure"]["closure_readiness_reason_counts"]["stale_source_refs"], 1)


if __name__ == "__main__":
    unittest.main()
