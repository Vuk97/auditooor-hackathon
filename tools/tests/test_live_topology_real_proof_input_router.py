from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "live-topology-real-proof-input-router.py"
MATERIALIZER = ROOT / "tools" / "live-topology-manual-proof-materializer.py"


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


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


def _bridge_payload() -> dict:
    rows = []
    for suffix, contract, address_seed in [("edge", "Portal", "1"), ("authority", "Registry", "2")]:
        row_id = f"LTPR-001-{suffix}"
        rows.append(
            {
                "row_id": row_id,
                "contract": contract,
                "network": "mainnet",
                "candidate_address": "0x" + address_seed * 40,
                "expected_value": "owner=0xabc",
                "capture_command_after_candidate_verification": (
                    f"python3 tools/live-state-checker.py --workspace /tmp/ws --address 0x{address_seed * 40} "
                    f"--block 123456 --call owner --expect owner=0xabc --save-workspace-proof {row_id}"
                ),
            }
        )
    return {
        "schema": "auditooor.live_topology_proof_input_bridge.v1",
        "proof_pairs": [
            {
                "proof_pair_id": "LTPR-001-pair",
                "requirement_id": "LTPR-001",
                "input_acquisition_class": "partial_candidate_address_needs_counterpart",
                "row_ids": ["LTPR-001-edge", "LTPR-001-authority"],
                "rows": rows,
                "executor_command_after_import": "python3 tools/live-topology-proof-executor.py --workspace /tmp/ws",
            }
        ],
    }


def _seed_real_input_files(ws: Path, row_id: str, contract: str) -> None:
    _write_text(ws / "contracts" / f"{contract}.sol", f"contract {contract} {{}}\n")
    _write_json(
        ws / "deployments" / "mainnet.json",
        {
            "network": "mainnet",
            "configured_contracts": [contract],
        },
    )
    _write_json(
        ws / "proofs" / f"{row_id}.json",
        {
            "row_id": row_id,
            "status": "pass",
            "evidence": "rpc returned expected value at the shared block",
        },
    )


def _real_input(
    row_id: str,
    contract: str,
    address_seed: str,
    *,
    block: str = "123456",
    source_refs: list[str] | None = None,
    include_source_refs: bool = True,
    include_topology_evidence: bool = True,
    include_proof_evidence: bool = True,
    blockers: list[str] | None = None,
) -> dict:
    row = {
        "id": row_id,
        "row_id": row_id,
        "proof_pair_id": "LTPR-001-pair",
        "evidence_class": "topology-relation",
        "contract": contract,
        "network": "mainnet",
        "address": "0x" + address_seed * 40,
        "status": "pass",
        "block": block,
        "expected": "owner=0xabc",
        "actual": "owner=0xabc",
        "source_kind": "rpc",
        "capture_command": f"python3 tools/live-state-checker.py --workspace /tmp/ws --address 0x{address_seed * 40}",
    }
    if include_source_refs:
        row["source_refs"] = source_refs or [f"contracts/{contract}.sol:1"]
    if include_topology_evidence:
        row["configured_topology_evidence"] = {
            "source_ref": "deployments/mainnet.json:1",
            "description": f"{contract} is configured on mainnet",
        }
    if include_proof_evidence:
        row["proof_evidence"] = {
            "artifact_path": f"proofs/{row_id}.json",
            "description": "RPC capture returned the expected value",
        }
    if blockers is not None:
        row["blockers"] = blockers
    return row


def _seed_pair_files(ws: Path) -> None:
    _seed_real_input_files(ws, "LTPR-001-edge", "Portal")
    _seed_real_input_files(ws, "LTPR-001-authority", "Registry")


class LiveTopologyRealProofInputRouterTests(unittest.TestCase):
    def test_routes_same_block_real_inputs_to_materializer_without_closing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_real_router_") as tmp:
            ws = Path(tmp)
            _seed_pair_files(ws)
            _write_json(ws / ".auditooor" / "live_topology_proof_input_bridge.json", _bridge_payload())
            _write_json(
                ws / ".auditooor" / "live_topology_real_proof_inputs" / "LTPR-001-pair.json",
                {
                    "schema": "auditooor.operator_rpc_live_topology_input.v1",
                    "rows": [
                        _real_input("LTPR-001-edge", "Portal", "1"),
                        _real_input("LTPR-001-authority", "Registry", "2"),
                    ],
                },
            )

            _run(sys.executable, TOOL, "--workspace", ws)

            payload = json.loads((ws / ".auditooor" / "live_topology_real_proof_input_router.json").read_text())
            self.assertEqual(payload["schema"], "auditooor.live_topology_real_proof_input_router.v1")
            self.assertEqual(payload["summary"]["same_block_ready_pairs"], 1)
            self.assertEqual(payload["summary"]["provided_rows_written"], 2)
            self.assertEqual(payload["summary"]["proof_pairs_closed"], 0)
            self.assertFalse(payload["promotion_allowed"])
            self.assertTrue((ws / ".auditooor" / "live_topology_provided_manual_proofs" / "LTPR-001-edge.json").exists())

            _write_json(
                ws / ".auditooor" / "live_topology_proof_input_validator.json",
                {
                    "schema": "auditooor.live_topology_proof_input_validator.v1",
                    "pair_validations": [
                        {
                            "proof_pair_id": "LTPR-001-pair",
                            "row_ids": ["LTPR-001-edge", "LTPR-001-authority"],
                            "row_validations": [
                                {"row_id": "LTPR-001-edge", "contract": "Portal"},
                                {"row_id": "LTPR-001-authority", "contract": "Registry"},
                            ],
                        }
                    ],
                },
            )
            _run(sys.executable, MATERIALIZER, "--workspace", ws)
            materializer = json.loads((ws / ".auditooor" / "live_topology_manual_proof_materializer.json").read_text())
            self.assertEqual(materializer["summary"]["canonical_import_ready_pairs"], 1)
            self.assertEqual(materializer["summary"]["canonical_rows_materialized"], 2)
            self.assertEqual(materializer["summary"]["proof_pairs_closed"], 0)

    def test_rejects_cross_block_real_inputs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_real_router_cross_block_") as tmp:
            ws = Path(tmp)
            _seed_pair_files(ws)
            _write_json(ws / ".auditooor" / "live_topology_proof_input_bridge.json", _bridge_payload())
            _write_json(ws / ".auditooor" / "live_topology_real_proof_inputs" / "LTPR-001-edge.json", _real_input("LTPR-001-edge", "Portal", "1", block="123456"))
            _write_json(
                ws / ".auditooor" / "live_topology_real_proof_inputs" / "LTPR-001-authority.json",
                _real_input("LTPR-001-authority", "Registry", "2", block="123457"),
            )

            _run(sys.executable, TOOL, "--workspace", ws)

            payload = json.loads((ws / ".auditooor" / "live_topology_real_proof_input_router.json").read_text())
            self.assertEqual(payload["summary"]["same_block_ready_pairs"], 0)
            self.assertEqual(payload["summary"]["provided_rows_written"], 0)
            self.assertEqual(
                payload["summary"]["pair_routing_state_counts"],
                {"partial_or_cross_block_real_proof_inputs": 1},
            )
            self.assertEqual(payload["pair_routes"][0]["pair_problems"], ["cross_block_real_proof_inputs"])

    def test_missing_source_refs_stays_unrouted_with_typed_reasons(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_real_router_missing_refs_") as tmp:
            ws = Path(tmp)
            _seed_pair_files(ws)
            _write_json(ws / ".auditooor" / "live_topology_proof_input_bridge.json", _bridge_payload())
            _write_json(
                ws / ".auditooor" / "live_topology_real_proof_inputs" / "LTPR-001-pair.json",
                {
                    "schema": "auditooor.operator_rpc_live_topology_input.v1",
                    "rows": [
                        _real_input("LTPR-001-edge", "Portal", "1", include_source_refs=False),
                        _real_input("LTPR-001-authority", "Registry", "2", include_source_refs=False),
                    ],
                },
            )

            _run(sys.executable, TOOL, "--workspace", ws)

            payload = json.loads((ws / ".auditooor" / "live_topology_real_proof_input_router.json").read_text())
            self.assertEqual(payload["summary"]["same_block_ready_pairs"], 0)
            self.assertEqual(payload["summary"]["provided_rows_written"], 0)
            self.assertEqual(payload["summary"]["row_routing_state_counts"], {"real_proof_row_invalid": 2})
            for row in payload["pair_routes"][0]["row_routes"]:
                self.assertEqual(row["routing_state"], "real_proof_row_invalid")
                self.assertIn("missing_current_workspace_source_refs", row["problems"])

    def test_stale_workspace_source_refs_stay_unrouted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_real_router_stale_refs_") as tmp:
            ws = Path(tmp)
            stale_root = ws.parent / f"{ws.name}_stale"
            _seed_pair_files(ws)
            _write_text(stale_root / "contracts" / "Portal.sol", "contract Portal {}\n")
            _write_text(stale_root / "contracts" / "Registry.sol", "contract Registry {}\n")
            _write_json(ws / ".auditooor" / "live_topology_proof_input_bridge.json", _bridge_payload())
            _write_json(
                ws / ".auditooor" / "live_topology_real_proof_inputs" / "LTPR-001-pair.json",
                {
                    "schema": "auditooor.operator_rpc_live_topology_input.v1",
                    "rows": [
                        _real_input(
                            "LTPR-001-edge",
                            "Portal",
                            "1",
                            source_refs=[str(stale_root / "contracts" / "Portal.sol") + ":1"],
                        ),
                        _real_input(
                            "LTPR-001-authority",
                            "Registry",
                            "2",
                            source_refs=[str(stale_root / "contracts" / "Registry.sol") + ":1"],
                        ),
                    ],
                },
            )

            _run(sys.executable, TOOL, "--workspace", ws)

            payload = json.loads((ws / ".auditooor" / "live_topology_real_proof_input_router.json").read_text())
            self.assertEqual(payload["summary"]["same_block_ready_pairs"], 0)
            self.assertEqual(payload["summary"]["provided_rows_written"], 0)
            for row in payload["pair_routes"][0]["row_routes"]:
                self.assertIn("stale_or_unresolved_source_refs", row["problems"])

    def test_missing_topology_evidence_stays_unrouted(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_real_router_missing_topology_") as tmp:
            ws = Path(tmp)
            _seed_pair_files(ws)
            _write_json(ws / ".auditooor" / "live_topology_proof_input_bridge.json", _bridge_payload())
            _write_json(
                ws / ".auditooor" / "live_topology_real_proof_inputs" / "LTPR-001-pair.json",
                {
                    "schema": "auditooor.operator_rpc_live_topology_input.v1",
                    "rows": [
                        _real_input("LTPR-001-edge", "Portal", "1", include_topology_evidence=False),
                        _real_input("LTPR-001-authority", "Registry", "2", include_topology_evidence=False),
                    ],
                },
            )

            _run(sys.executable, TOOL, "--workspace", ws)

            payload = json.loads((ws / ".auditooor" / "live_topology_real_proof_input_router.json").read_text())
            self.assertEqual(payload["summary"]["same_block_ready_pairs"], 0)
            self.assertEqual(payload["summary"]["provided_rows_written"], 0)
            for row in payload["pair_routes"][0]["row_routes"]:
                self.assertIn("missing_configured_topology_evidence", row["problems"])

    def test_input_blockers_propagate_and_prevent_routing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_real_router_blockers_") as tmp:
            ws = Path(tmp)
            _seed_pair_files(ws)
            _write_json(ws / ".auditooor" / "live_topology_proof_input_bridge.json", _bridge_payload())
            _write_json(
                ws / ".auditooor" / "live_topology_real_proof_inputs" / "LTPR-001-pair.json",
                {
                    "schema": "auditooor.operator_rpc_live_topology_input.v1",
                    "rows": [
                        _real_input("LTPR-001-edge", "Portal", "1", blockers=["operator_blocked_pending_rpc"]),
                        _real_input("LTPR-001-authority", "Registry", "2"),
                    ],
                },
            )

            _run(sys.executable, TOOL, "--workspace", ws)

            payload = json.loads((ws / ".auditooor" / "live_topology_real_proof_input_router.json").read_text())
            self.assertEqual(payload["summary"]["same_block_ready_pairs"], 0)
            self.assertEqual(payload["summary"]["provided_rows_written"], 0)
            blocked_row = payload["pair_routes"][0]["row_routes"][0]
            self.assertEqual(blocked_row["input_blockers"], ["operator_blocked_pending_rpc"])
            self.assertIn("input_blocker_present:operator_blocked_pending_rpc", blocked_row["problems"])
            self.assertFalse((ws / ".auditooor" / "live_topology_provided_manual_proofs" / "LTPR-001-edge.json").exists())

    def test_current_missing_inputs_emit_exact_blockers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_real_router_missing_") as tmp:
            ws = Path(tmp)
            _write_json(ws / ".auditooor" / "live_topology_proof_input_bridge.json", _bridge_payload())

            _run(sys.executable, TOOL, "--workspace", ws, "--dry-run")

            payload = json.loads((ws / ".auditooor" / "live_topology_real_proof_input_router.json").read_text())
            self.assertEqual(payload["summary"]["same_block_ready_pairs"], 0)
            self.assertEqual(payload["summary"]["provided_rows_written"], 0)
            self.assertEqual(payload["summary"]["pair_routing_state_counts"], {"real_proof_inputs_missing": 1})
            self.assertEqual(payload["summary"]["row_routing_state_counts"], {"real_proof_row_missing": 2})
            row = payload["pair_routes"][0]["row_routes"][0]
            self.assertIn("real_proof_input_missing", row["problems"])


if __name__ == "__main__":
    unittest.main()
