from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "live-topology-proof-input-bridge.py"


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


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


def _row(row_id: str, contract: str, missing: list[str], *, candidate: str | None = None) -> dict:
    return {
        "row_id": row_id,
        "contract": contract,
        "network": "mainnet",
        "rpc_env_var": "MAINNET_RPC_URL",
        "candidate_address": candidate,
        "required_address": f"<resolved-{contract}-address>",
        "required_same_block": "<same-block-for-LTPR-001>",
        "expected_value": "<fill-from-deployment-topology>",
        "missing": missing,
        "capture_command": (
            "python3 tools/live-state-checker.py --workspace /tmp/ws "
            f"--address '<resolved-{contract}-address>' --block '<same-block-for-LTPR-001>' "
            f"--save-workspace-proof {row_id}"
        ),
        "manual_import_command": f"python3 tools/live-check-runner.py /tmp/ws --manual-proof-id {row_id}",
        "capture_ready": False,
        "import_ready": False,
        "executor_ready": False,
    }


def _write_source_fixture(ws: Path) -> None:
    src = ws / "src"
    src.mkdir(parents=True, exist_ok=True)
    (src / "Portal.sol").write_text("contract Portal {}\n", encoding="utf-8")
    (src / "Registry.sol").write_text("contract Registry {}\n", encoding="utf-8")


def _strict_row(
    row_id: str,
    contract: str,
    source_ref: str | None,
    *,
    topology: bool = True,
) -> dict:
    row = _row(row_id, contract, [])
    row.update(
        {
            "required_address": "0x1111111111111111111111111111111111111111",
            "required_same_block": "12345",
            "expected_value": "0x0000000000000000000000000000000000000000",
            "manual_status": "pass",
            "manual_block": "12345",
            "live_status": "pass",
            "live_block": "12345",
            "strict_missing": [],
            "concrete_proof_or_harness_evidence": True,
            "base_executor_ready": True,
            "capture_ready": True,
            "import_ready": True,
            "executor_ready": True,
        }
    )
    if source_ref is not None:
        row["source_refs"] = [source_ref]
    if topology:
        row["topology_paths"] = [source_ref or "src/Portal.sol:1"]
        row["configured_topology_evidence"] = [f"{contract} deployment relation verified"]
    return row


def _strict_readiness(*, rows: list[dict], blocker_class: str = "none", status: str = "same_block_executor_ready") -> dict:
    missing = [] if blocker_class == "none" else ["missing_manual_proof"]
    return {
        "schema": "auditooor.live_topology_proof_readiness.v1",
        "proof_pairs": [
            {
                "proof_pair_id": "LTPR-900-pair",
                "requirement_id": "LTPR-900",
                "status": status,
                "blocker_class": blocker_class,
                "row_ids": [row["row_id"] for row in rows],
                "required_contracts": [row["contract"] for row in rows],
                "missing": missing,
                "strict_missing": [],
                "rows": rows,
            }
        ],
    }


class LiveTopologyProofInputBridgeTests(unittest.TestCase):
    def test_classifies_partial_candidate_pair_and_writes_bundles(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_input_bridge_") as tmp:
            ws = Path(tmp)
            readiness = {
                "schema": "auditooor.live_topology_proof_readiness.v1",
                "proof_pairs": [
                    {
                        "proof_pair_id": "LTPR-001-pair",
                        "requirement_id": "LTPR-001",
                        "status": "terminal_missing_local_inputs",
                        "blocker_class": "address_resolution_required",
                        "row_ids": ["LTPR-001-edge", "LTPR-001-authority"],
                        "required_contracts": ["Portal", "Registry"],
                        "missing": [
                            "candidate_address_requires_manual_verification",
                            "missing_verified_address",
                            "missing_rpc",
                            "missing_same_block",
                            "missing_expected_value",
                            "missing_manual_proof",
                            "imported_live_row_not_executed",
                        ],
                        "rows": [
                            _row(
                                "LTPR-001-edge",
                                "Portal",
                                [
                                    "candidate_address_requires_manual_verification",
                                    "missing_rpc",
                                    "missing_same_block",
                                    "missing_expected_value",
                                    "missing_manual_proof",
                                ],
                                candidate="0x1111111111111111111111111111111111111111",
                            ),
                            _row(
                                "LTPR-001-authority",
                                "Registry",
                                [
                                    "missing_verified_address",
                                    "missing_rpc",
                                    "missing_same_block",
                                    "missing_expected_value",
                                    "missing_manual_proof",
                                ],
                            ),
                        ],
                    }
                ],
            }
            _write_json(ws / ".auditooor" / "live_topology_proof_readiness.json", readiness)

            _run(sys.executable, TOOL, "--workspace", ws)

            payload = json.loads((ws / ".auditooor" / "live_topology_proof_input_bridge.json").read_text())
            self.assertEqual(payload["schema"], "auditooor.live_topology_proof_input_bridge.v1")
            self.assertEqual(payload["summary"]["proof_pairs_total"], 1)
            self.assertEqual(payload["summary"]["proof_pairs_closed"], 0)
            self.assertEqual(
                payload["summary"]["input_acquisition_class_counts"],
                {"partial_candidate_address_needs_counterpart": 1},
            )
            self.assertEqual(payload["summary"]["operator_input_counts"]["verified_address"], 1)
            self.assertEqual(payload["summary"]["operator_input_counts"]["candidate_address_verification"], 1)
            pair = payload["proof_pairs"][0]
            candidate_command = pair["rows"][0]["capture_command_after_candidate_verification"]
            self.assertIn("0x1111111111111111111111111111111111111111", candidate_command)
            self.assertTrue((ws / ".auditooor" / "live_topology_proof_input_bundles" / "pairs" / "LTPR-001-pair.json").is_file())
            self.assertTrue((ws / ".auditooor" / "live_topology_proof_input_bundles" / "networks" / "mainnet.json").is_file())

    def test_preflights_same_block_manual_proofs_without_promoting(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_input_bridge_ready_") as tmp:
            ws = Path(tmp)
            rows = []
            for row_id, contract in [("LTPR-002-edge", "Portal"), ("LTPR-002-authority", "Registry")]:
                row = _row(row_id, contract, [])
                row.update(
                    {
                        "manual_proof_path": f"/tmp/manual/{row_id}.json",
                        "manual_status": "pass",
                        "manual_block": "12345",
                        "capture_ready": True,
                        "import_ready": True,
                    }
                )
                rows.append(row)
            readiness = {
                "schema": "auditooor.live_topology_proof_readiness.v1",
                "proof_pairs": [
                    {
                        "proof_pair_id": "LTPR-002-pair",
                        "requirement_id": "LTPR-002",
                        "status": "manual_proofs_ready_for_import",
                        "blocker_class": "ready_to_import_manual_proofs",
                        "row_ids": ["LTPR-002-edge", "LTPR-002-authority"],
                        "required_contracts": ["Portal", "Registry"],
                        "missing": [],
                        "rows": rows,
                    }
                ],
            }
            _write_json(ws / ".auditooor" / "live_topology_proof_readiness.json", readiness)

            _run(sys.executable, TOOL, "--workspace", ws, "--no-write-bundles")

            payload = json.loads((ws / ".auditooor" / "live_topology_proof_input_bridge.json").read_text())
            self.assertEqual(
                payload["summary"]["input_acquisition_class_counts"],
                {"ready_to_import_manual_proofs": 1},
            )
            self.assertEqual(
                payload["summary"]["manual_import_preflight_counts"],
                {"same_block_manual_proofs_ready": 1},
            )
            self.assertEqual(payload["summary"]["proof_pairs_closed"], 0)
            self.assertFalse(payload["promotion_allowed"])

    def test_bridges_only_when_strict_evidence_is_current_and_concrete(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_input_bridge_strict_pass_") as tmp:
            ws = Path(tmp)
            _write_source_fixture(ws)
            readiness = _strict_readiness(
                rows=[
                    _strict_row("LTPR-900-edge", "Portal", "src/Portal.sol:1"),
                    _strict_row("LTPR-900-authority", "Registry", "src/Registry.sol:1"),
                ]
            )
            _write_json(ws / ".auditooor" / "live_topology_proof_readiness.json", readiness)

            _run(sys.executable, TOOL, "--workspace", ws, "--no-write-bundles")

            payload = json.loads((ws / ".auditooor" / "live_topology_proof_input_bridge.json").read_text())
            pair = payload["proof_pairs"][0]
            self.assertEqual(payload["summary"]["proof_pairs_bridged"], 1)
            self.assertEqual(payload["summary"]["rows_bridged"], 2)
            self.assertTrue(pair["proof_input_bridge"]["bridged"])
            self.assertEqual(pair["bridge_status"], "bridged")
            self.assertEqual(pair["bridge_reasons"], [])
            self.assertTrue(all(row["proof_input_bridge"]["bridged"] for row in pair["rows"]))

    def test_does_not_bridge_when_source_refs_are_missing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_input_bridge_missing_refs_") as tmp:
            ws = Path(tmp)
            _write_source_fixture(ws)
            readiness = _strict_readiness(
                rows=[
                    _strict_row("LTPR-900-edge", "Portal", None),
                    _strict_row("LTPR-900-authority", "Registry", "src/Registry.sol:1"),
                ]
            )
            _write_json(ws / ".auditooor" / "live_topology_proof_readiness.json", readiness)

            _run(sys.executable, TOOL, "--workspace", ws, "--no-write-bundles")

            payload = json.loads((ws / ".auditooor" / "live_topology_proof_input_bridge.json").read_text())
            pair = payload["proof_pairs"][0]
            self.assertEqual(payload["summary"]["proof_pairs_not_bridged"], 1)
            self.assertFalse(pair["proof_input_bridge"]["bridged"])
            self.assertIn("missing_current_workspace_source_refs", pair["bridge_reasons"])
            self.assertIn("missing_current_workspace_source_refs", pair["rows"][0]["bridge_reasons"])

    def test_does_not_bridge_when_source_refs_are_stale(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_input_bridge_stale_refs_") as tmp:
            ws = Path(tmp)
            _write_source_fixture(ws)
            readiness = _strict_readiness(
                rows=[
                    _strict_row("LTPR-900-edge", "Portal", "src/Missing.sol:1"),
                    _strict_row("LTPR-900-authority", "Registry", "src/Registry.sol:1"),
                ]
            )
            _write_json(ws / ".auditooor" / "live_topology_proof_readiness.json", readiness)

            _run(sys.executable, TOOL, "--workspace", ws, "--no-write-bundles")

            payload = json.loads((ws / ".auditooor" / "live_topology_proof_input_bridge.json").read_text())
            pair = payload["proof_pairs"][0]
            self.assertFalse(pair["proof_input_bridge"]["bridged"])
            self.assertIn("stale_workspace_source_refs", pair["bridge_reasons"])
            self.assertIn("stale_workspace_source_refs", pair["rows"][0]["bridge_reasons"])

    def test_does_not_bridge_when_topology_evidence_is_missing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_input_bridge_missing_topology_") as tmp:
            ws = Path(tmp)
            _write_source_fixture(ws)
            readiness = _strict_readiness(
                rows=[
                    _strict_row("LTPR-900-edge", "Portal", "src/Portal.sol:1", topology=False),
                    _strict_row("LTPR-900-authority", "Registry", "src/Registry.sol:1"),
                ]
            )
            _write_json(ws / ".auditooor" / "live_topology_proof_readiness.json", readiness)

            _run(sys.executable, TOOL, "--workspace", ws, "--no-write-bundles")

            payload = json.loads((ws / ".auditooor" / "live_topology_proof_input_bridge.json").read_text())
            pair = payload["proof_pairs"][0]
            self.assertFalse(pair["proof_input_bridge"]["bridged"])
            self.assertIn("missing_configured_topology_evidence", pair["bridge_reasons"])
            self.assertIn("missing_configured_topology_evidence", pair["rows"][0]["bridge_reasons"])

    def test_blocker_reasons_propagate_to_non_bridged_rows(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_input_bridge_blocker_") as tmp:
            ws = Path(tmp)
            _write_source_fixture(ws)
            readiness = _strict_readiness(
                rows=[
                    _strict_row("LTPR-900-edge", "Portal", "src/Portal.sol:1"),
                    _strict_row("LTPR-900-authority", "Registry", "src/Registry.sol:1"),
                ],
                blocker_class="manual_proof_required",
            )
            _write_json(ws / ".auditooor" / "live_topology_proof_readiness.json", readiness)

            _run(sys.executable, TOOL, "--workspace", ws, "--no-write-bundles")

            payload = json.loads((ws / ".auditooor" / "live_topology_proof_input_bridge.json").read_text())
            pair = payload["proof_pairs"][0]
            self.assertFalse(pair["proof_input_bridge"]["bridged"])
            self.assertIn("manual_proof_required", pair["bridge_reasons"])
            self.assertIn("missing_manual_proof", pair["bridge_reasons"])
            self.assertEqual(payload["summary"]["rows_not_bridged"], 2)
            self.assertTrue(all("manual_proof_required" in row["bridge_reasons"] for row in pair["rows"]))


if __name__ == "__main__":
    unittest.main()
