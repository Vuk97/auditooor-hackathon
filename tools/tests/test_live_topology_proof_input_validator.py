from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "live-topology-proof-input-validator.py"


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_source(path: Path, body: str = "contract Portal {}\ncontract Registry {}\n") -> None:
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


def _bridge_pair() -> dict:
    rows = []
    for suffix, contract in [("edge", "Portal"), ("authority", "Registry")]:
        row_id = f"LTPR-001-{suffix}"
        rows.append(
            {
                "row_id": row_id,
                "contract": contract,
                "network": "mainnet",
                "rpc_env_var": "MAINNET_RPC_URL",
                "candidate_address": None,
                "required_address": f"<resolved-{contract}-address>",
                "expected_value": "<expected-value>",
                "capture_command_template": f"python3 tools/live-state-checker.py --save-workspace-proof {row_id}",
                "capture_command_after_candidate_verification": None,
            }
        )
    return {
        "proof_pair_id": "LTPR-001-pair",
        "input_acquisition_class": "address_discovery_required",
        "row_ids": ["LTPR-001-edge", "LTPR-001-authority"],
        "rows": rows,
        "executor_command_after_import": "python3 tools/live-topology-proof-executor.py --workspace /tmp/ws",
    }


def _valid_manual_proof(ws: Path, row: dict, *, overrides: dict | None = None) -> dict:
    payload = {
        "id": row["row_id"],
        "row_id": row["row_id"],
        "proof_pair_id": "LTPR-001-pair",
        "evidence_class": "topology-relation",
        "contract": row["contract"],
        "status": "pass",
        "block": "123456",
        "workspace": str(ws),
        "source_refs": ["contracts/Topology.sol:1"],
        "configured_topology_evidence": [
            {
                "source_ref": "contracts/Topology.sol:1",
                "claim": "The checked contract participates in the configured topology.",
            }
        ],
        "proof_evidence": [
            {
                "harness": "live-state-checker",
                "transcript": f"PASS topology relation for {row['row_id']}",
            }
        ],
        "advisory_only": False,
    }
    if overrides:
        for key, value in overrides.items():
            if value is None:
                payload.pop(key, None)
            else:
                payload[key] = value
    return payload


class LiveTopologyProofInputValidatorTests(unittest.TestCase):
    def test_writes_samples_and_command_manifests_for_missing_manual_proofs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_input_validator_") as tmp:
            ws = Path(tmp)
            _write_json(
                ws / ".auditooor" / "live_topology_proof_input_bridge.json",
                {
                    "schema": "auditooor.live_topology_proof_input_bridge.v1",
                    "proof_pairs": [_bridge_pair()],
                },
            )

            _run(sys.executable, TOOL, "--workspace", ws)

            payload = json.loads((ws / ".auditooor" / "live_topology_proof_input_validator.json").read_text())
            self.assertEqual(payload["schema"], "auditooor.live_topology_proof_input_validator.v1")
            self.assertEqual(payload["summary"]["proof_pairs_total"], 1)
            self.assertEqual(payload["summary"]["proof_pairs_closed"], 0)
            self.assertEqual(payload["summary"]["import_ready_pairs"], 0)
            self.assertEqual(payload["summary"]["pair_validation_state_counts"], {"manual_proof_files_missing": 1})
            self.assertEqual(payload["summary"]["row_validation_state_counts"], {"missing_manual_proof_file": 2})
            sample = (
                ws
                / ".auditooor"
                / "live_topology_proof_input_validation"
                / "manual_proof_samples"
                / "LTPR-001-edge.json"
            )
            self.assertTrue(sample.is_file())
            self.assertTrue(
                (
                    ws
                    / ".auditooor"
                    / "live_topology_proof_input_validation"
                    / "network_command_manifests"
                    / "mainnet.json"
                ).is_file()
            )

    def test_detects_same_block_import_ready_pair_without_closing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_input_validator_ready_") as tmp:
            ws = Path(tmp)
            _write_source(ws / "contracts" / "Topology.sol")
            pair = _bridge_pair()
            _write_json(
                ws / ".auditooor" / "live_topology_proof_input_bridge.json",
                {
                    "schema": "auditooor.live_topology_proof_input_bridge.v1",
                    "proof_pairs": [pair],
                },
            )
            for row in pair["rows"]:
                _write_json(
                    ws / "manual_proofs" / f"{row['row_id']}.json",
                    _valid_manual_proof(ws, row),
                )

            _run(sys.executable, TOOL, "--workspace", ws, "--no-write-bundles")

            payload = json.loads((ws / ".auditooor" / "live_topology_proof_input_validator.json").read_text())
            self.assertEqual(payload["summary"]["import_ready_pairs"], 1)
            self.assertEqual(
                payload["summary"]["pair_validation_state_counts"],
                {"manual_proofs_same_block_import_ready": 1},
            )
            self.assertEqual(
                payload["summary"]["row_validation_state_counts"],
                {"manual_proof_ready_for_import": 2},
            )
            for row_validation in payload["pair_validations"][0]["row_validations"]:
                self.assertEqual(row_validation["invalid_reasons"], [])
                self.assertEqual(row_validation["source_ref_errors"], [])
                self.assertTrue(row_validation["configured_topology_evidence_present"])
                self.assertTrue(row_validation["concrete_proof_evidence_present"])
            self.assertEqual(payload["summary"]["proof_pairs_closed"], 0)
            self.assertFalse(payload["promotion_allowed"])

    def test_missing_source_refs_are_typed_invalid_reasons(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_input_validator_no_refs_") as tmp:
            ws = Path(tmp)
            _write_source(ws / "contracts" / "Topology.sol")
            pair = _bridge_pair()
            _write_json(
                ws / ".auditooor" / "live_topology_proof_input_bridge.json",
                {"schema": "auditooor.live_topology_proof_input_bridge.v1", "proof_pairs": [pair]},
            )
            for row in pair["rows"]:
                overrides = (
                    {
                        "source_refs": None,
                        "configured_topology_evidence": [
                            {"claim": "The topology claim is present but has no source citation."}
                        ],
                    }
                    if row["row_id"].endswith("edge")
                    else {}
                )
                _write_json(ws / "manual_proofs" / f"{row['row_id']}.json", _valid_manual_proof(ws, row, overrides=overrides))

            _run(sys.executable, TOOL, "--workspace", ws, "--no-write-bundles")

            payload = json.loads((ws / ".auditooor" / "live_topology_proof_input_validator.json").read_text())
            row_validation = payload["pair_validations"][0]["row_validations"][0]
            self.assertEqual(row_validation["validation_state"], "manual_proof_schema_invalid")
            self.assertIn("missing_source_refs", row_validation["invalid_reasons"])
            self.assertIn("missing_source_refs", row_validation["problems"])
            self.assertEqual(
                payload["summary"]["pair_validation_state_counts"],
                {"partial_manual_proofs_valid": 1},
            )

    def test_stale_workspace_refs_are_typed_invalid_reasons(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_input_validator_stale_ws_") as tmp:
            ws = Path(tmp)
            _write_source(ws / "contracts" / "Topology.sol")
            pair = _bridge_pair()
            stale_ws = ws.parent / "stale-workspace"
            _write_json(
                ws / ".auditooor" / "live_topology_proof_input_bridge.json",
                {"schema": "auditooor.live_topology_proof_input_bridge.v1", "proof_pairs": [pair]},
            )
            for row in pair["rows"]:
                overrides = {"workspace": str(stale_ws)} if row["row_id"].endswith("edge") else {}
                _write_json(ws / "manual_proofs" / f"{row['row_id']}.json", _valid_manual_proof(ws, row, overrides=overrides))

            _run(sys.executable, TOOL, "--workspace", ws, "--no-write-bundles")

            payload = json.loads((ws / ".auditooor" / "live_topology_proof_input_validator.json").read_text())
            row_validation = payload["pair_validations"][0]["row_validations"][0]
            self.assertEqual(row_validation["validation_state"], "manual_proof_schema_invalid")
            self.assertIn("stale_workspace_ref", row_validation["invalid_reasons"])

    def test_missing_topology_evidence_is_typed_invalid_reason(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_input_validator_no_topology_") as tmp:
            ws = Path(tmp)
            _write_source(ws / "contracts" / "Topology.sol")
            pair = _bridge_pair()
            _write_json(
                ws / ".auditooor" / "live_topology_proof_input_bridge.json",
                {"schema": "auditooor.live_topology_proof_input_bridge.v1", "proof_pairs": [pair]},
            )
            for row in pair["rows"]:
                overrides = {"configured_topology_evidence": None} if row["row_id"].endswith("edge") else {}
                _write_json(ws / "manual_proofs" / f"{row['row_id']}.json", _valid_manual_proof(ws, row, overrides=overrides))

            _run(sys.executable, TOOL, "--workspace", ws, "--no-write-bundles")

            payload = json.loads((ws / ".auditooor" / "live_topology_proof_input_validator.json").read_text())
            row_validation = payload["pair_validations"][0]["row_validations"][0]
            self.assertIn("missing_configured_topology_evidence", row_validation["invalid_reasons"])
            self.assertFalse(row_validation["configured_topology_evidence_present"])

    def test_blockers_remain_visible_and_block_import_readiness(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_input_validator_blockers_") as tmp:
            ws = Path(tmp)
            _write_source(ws / "contracts" / "Topology.sol")
            pair = _bridge_pair()
            _write_json(
                ws / ".auditooor" / "live_topology_proof_input_bridge.json",
                {"schema": "auditooor.live_topology_proof_input_bridge.v1", "proof_pairs": [pair]},
            )
            for row in pair["rows"]:
                overrides = {"blockers": ["oracle_unverified"]} if row["row_id"].endswith("edge") else {}
                _write_json(ws / "manual_proofs" / f"{row['row_id']}.json", _valid_manual_proof(ws, row, overrides=overrides))

            _run(sys.executable, TOOL, "--workspace", ws, "--no-write-bundles")

            payload = json.loads((ws / ".auditooor" / "live_topology_proof_input_validator.json").read_text())
            row_validation = payload["pair_validations"][0]["row_validations"][0]
            self.assertIn("proof_blockers_present", row_validation["invalid_reasons"])
            self.assertEqual(row_validation["proof_blockers"], ["oracle_unverified"])
            self.assertFalse(row_validation["ready_for_import"])

    def test_advisory_only_evidence_is_typed_invalid_reason(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_input_validator_advisory_") as tmp:
            ws = Path(tmp)
            _write_source(ws / "contracts" / "Topology.sol")
            pair = _bridge_pair()
            _write_json(
                ws / ".auditooor" / "live_topology_proof_input_bridge.json",
                {"schema": "auditooor.live_topology_proof_input_bridge.v1", "proof_pairs": [pair]},
            )
            for row in pair["rows"]:
                overrides = {"advisory_only": True} if row["row_id"].endswith("edge") else {}
                _write_json(ws / "manual_proofs" / f"{row['row_id']}.json", _valid_manual_proof(ws, row, overrides=overrides))

            _run(sys.executable, TOOL, "--workspace", ws, "--no-write-bundles")

            payload = json.loads((ws / ".auditooor" / "live_topology_proof_input_validator.json").read_text())
            row_validation = payload["pair_validations"][0]["row_validations"][0]
            self.assertIn("advisory_only_evidence", row_validation["invalid_reasons"])
            self.assertIn("advisory_only_evidence", row_validation["problems"])


if __name__ == "__main__":
    unittest.main()
