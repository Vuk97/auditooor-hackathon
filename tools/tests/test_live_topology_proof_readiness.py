from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "live-topology-proof-readiness.py"


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


def _requirements(pair_id: str = "LTPR-001-pair") -> dict:
    return {
        "requirements": [
            {
                "requirement_id": "LTPR-001",
                "required_proof_pair_id": pair_id,
                "required_contracts": ["Portal", "Registry"],
                "required_live_rows": [
                    {
                        "id": "LTPR-001-edge",
                        "contract": "Portal",
                        "proof_pair_id": pair_id,
                        "status": "required_not_collected",
                    },
                    {
                        "id": "LTPR-001-authority",
                        "contract": "Registry",
                        "proof_pair_id": pair_id,
                        "status": "required_not_collected",
                    },
                ],
            }
        ]
    }


def _write_source_fixture(ws: Path) -> None:
    src = ws / "src"
    src.mkdir(parents=True, exist_ok=True)
    (src / "Portal.sol").write_text("contract Portal {}\n", encoding="utf-8")
    (src / "Registry.sol").write_text("contract Registry {}\n", encoding="utf-8")


def _add_harness_evidence(requirements: dict) -> dict:
    requirements["requirements"][0]["harness_evidence"] = {
        "claim": "runnable_harness",
        "runnable": True,
        "pass_evidence": "Suite result: ok. 2 passed",
    }
    return requirements


def _template(
    row_id: str,
    contract: str,
    address: str,
    *,
    source_ref: str | None,
    topology_path: str | None,
) -> dict:
    payload = {
        "row_id": row_id,
        "contract": contract,
        "network": "mainnet",
        "rpc_env_var": "MAINNET_RPC_URL",
        "required_address": address,
        "required_same_block": "12345",
        "expect": "0x0000000000000000000000000000000000000000",
        "capture_command": f"capture {row_id}",
    }
    if source_ref is not None:
        payload["source_refs"] = [source_ref]
    if topology_path is not None:
        payload["topology_path"] = topology_path
        payload["configured_topology_evidence"] = f"{contract} deployment relation verified at {topology_path}"
    return payload


def _populate_imported_pair(
    ws: Path,
    *,
    source_refs: bool = True,
    stale_source_refs: bool = False,
    topology_evidence: bool = True,
    advisory_only: bool = False,
    harness_evidence: bool = True,
) -> None:
    _write_source_fixture(ws)
    (ws / ".env").write_text("MAINNET_RPC_URL=https://example.invalid\n", encoding="utf-8")
    aud = ws / ".auditooor"
    template_dir = aud / "live_topology_manual_proof_templates_fd"
    manual_dir = ws / "manual_proofs"
    requirements = _requirements()
    if harness_evidence:
        requirements = _add_harness_evidence(requirements)
    _write_json(aud / "live_topology_proof_requirements.json", requirements)
    row_ids = ["LTPR-001-edge", "LTPR-001-authority"]
    _write_json(
        ws / "live_topology_checks.json",
        {
            "results": [
                {
                    "id": row_id,
                    "status": "pass",
                    "block": "12345",
                    "proof_pair_id": "LTPR-001-pair",
                    "evidence_class": "topology-relation",
                    "advisory_only": advisory_only,
                }
                for row_id in row_ids
            ],
            "proof_pairs": [
                {
                    "id": "LTPR-001-pair",
                    "status": "proved",
                    "row_ids": row_ids,
                    "shared_block": "12345",
                    "pair_blocks": ["12345"],
                }
            ],
        },
    )
    row_specs = [
        ("LTPR-001-edge", "Portal", "0x1111111111111111111111111111111111111111", "src/Portal.sol:1"),
        ("LTPR-001-authority", "Registry", "0x2222222222222222222222222222222222222222", "src/Registry.sol:1"),
    ]
    for row_id, contract, address, ref in row_specs:
        source_ref = None
        if source_refs:
            source_ref = "src/Missing.sol:1" if stale_source_refs else ref
        topology_path = ref if topology_evidence else None
        _write_json(template_dir / f"{row_id}.json", _template(row_id, contract, address, source_ref=source_ref, topology_path=topology_path))
        _write_json(
            manual_dir / f"{row_id}.json",
            {
                "id": row_id,
                "status": "pass",
                "block": "12345",
                "proof_pair_id": "LTPR-001-pair",
                "evidence_class": "topology-relation",
                "advisory_only": advisory_only,
            },
        )


class LiveTopologyProofReadinessTests(unittest.TestCase):
    def test_classifies_full_pair_missing_local_inputs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_proof_readiness_") as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            template_dir = aud / "live_topology_manual_proof_templates_fd"
            _write_json(aud / "live_topology_proof_requirements.json", _requirements())
            _write_json(
                ws / "live_topology_checks.json",
                {
                    "results": [
                        {"id": "LTPR-001-edge", "status": "required_not_collected"},
                        {"id": "LTPR-001-authority", "status": "required_not_collected"},
                    ],
                    "proof_pairs": [
                        {
                            "id": "LTPR-001-pair",
                            "status": "required_not_collected",
                            "row_ids": ["LTPR-001-edge", "LTPR-001-authority"],
                        }
                    ],
                },
            )
            for row_id, contract in [
                ("LTPR-001-edge", "Portal"),
                ("LTPR-001-authority", "Registry"),
            ]:
                _write_json(
                    template_dir / f"{row_id}.json",
                    {
                        "row_id": row_id,
                        "contract": contract,
                        "network": "mainnet",
                        "rpc_env_var": "MAINNET_RPC_URL",
                        "required_address": f"<resolved-{contract}-address>",
                        "required_same_block": "<same-block-for-LTPR-001>",
                        "expect": "<expected-value>",
                        "capture_command": f"capture {row_id}",
                    },
                )

            _run(sys.executable, TOOL, "--workspace", ws)

            payload = json.loads((aud / "live_topology_proof_readiness.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "auditooor.live_topology_proof_readiness.v1")
            self.assertEqual(payload["after_counts"]["proof_pairs_total"], 1)
            self.assertEqual(payload["after_counts"]["closure_candidates"], 0)
            self.assertEqual(
                payload["after_counts"]["pair_status_counts"],
                {"terminal_missing_local_inputs": 1},
            )
            self.assertEqual(
                payload["after_counts"]["pair_blocker_class_counts"],
                {"address_resolution_required": 1},
            )
            self.assertEqual(payload["after_counts"]["row_missing_counts"]["missing_verified_address"], 2)
            self.assertEqual(payload["after_counts"]["row_missing_counts"]["missing_manual_proof"], 2)
            self.assertEqual(payload["after_counts"]["strict_missing_counts"]["missing_current_workspace_source_refs"], 2)
            self.assertEqual(payload["after_counts"]["strict_missing_counts"]["missing_topology_path"], 2)
            bundle = aud / "live_topology_full_pair_requirements" / "LTPR-001-pair.json"
            self.assertTrue(bundle.is_file())
            bundle_payload = json.loads(bundle.read_text(encoding="utf-8"))
            self.assertEqual(bundle_payload["proof_pair_id"], "LTPR-001-pair")
            self.assertIn("safe_execution_order", bundle_payload)
            self.assertFalse(bundle_payload["promotion_allowed"])

    def test_marks_manual_proofs_ready_for_import(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_proof_readiness_import_") as tmp:
            ws = Path(tmp)
            (ws / ".env").write_text("MAINNET_RPC_URL=https://example.invalid\n", encoding="utf-8")
            aud = ws / ".auditooor"
            template_dir = aud / "live_topology_manual_proof_templates_fd"
            manual_dir = ws / "manual_proofs"
            _write_json(aud / "live_topology_proof_requirements.json", _requirements())
            _write_json(ws / "live_topology_checks.json", {"results": [], "proof_pairs": []})
            for row_id, contract, address in [
                ("LTPR-001-edge", "Portal", "0x1111111111111111111111111111111111111111"),
                ("LTPR-001-authority", "Registry", "0x2222222222222222222222222222222222222222"),
            ]:
                _write_json(
                    template_dir / f"{row_id}.json",
                    {
                        "row_id": row_id,
                        "contract": contract,
                        "network": "mainnet",
                        "rpc_env_var": "MAINNET_RPC_URL",
                        "required_address": address,
                        "required_same_block": "12345",
                        "expect": "0x0000000000000000000000000000000000000000",
                        "capture_command": f"capture {row_id}",
                    },
                )
                _write_json(
                    manual_dir / f"{row_id}.json",
                    {
                        "results": [
                            {
                                "id": row_id,
                                "status": "pass",
                                "block": "12345",
                                "proof_pair_id": "LTPR-001-pair",
                                "evidence_class": "topology-relation",
                            }
                        ]
                    },
                )

            _run(sys.executable, TOOL, "--workspace", ws)

            payload = json.loads((aud / "live_topology_proof_readiness.json").read_text(encoding="utf-8"))
            self.assertEqual(
                payload["after_counts"]["pair_status_counts"],
                {"manual_proofs_ready_for_import": 1},
            )
            self.assertEqual(payload["after_counts"]["manual_proof_import_ready_pairs"], 1)
            pair = payload["proof_pairs"][0]
            self.assertEqual(pair["blocker_class"], "ready_to_import_manual_proofs")
            self.assertIn("--manual-proof-id LTPR-001-edge", pair["import_command_after_manual_proofs"])

    def test_marks_same_block_executor_ready_only_after_imported_proved_pair(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_proof_readiness_ready_") as tmp:
            ws = Path(tmp)
            _populate_imported_pair(ws)
            aud = ws / ".auditooor"

            _run(sys.executable, TOOL, "--workspace", ws)

            payload = json.loads((aud / "live_topology_proof_readiness.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["after_counts"]["closure_candidates"], 1)
            self.assertEqual(payload["after_counts"]["same_block_executor_ready_pairs"], 1)
            self.assertEqual(
                payload["after_counts"]["pair_status_counts"],
                {"same_block_executor_ready": 1},
            )
            self.assertEqual(payload["proof_pairs"][0]["strict_missing"], [])
            self.assertFalse(payload["promotion_allowed"])

    def test_imported_proved_pair_blocks_when_source_refs_missing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_proof_readiness_missing_refs_") as tmp:
            ws = Path(tmp)
            _populate_imported_pair(ws, source_refs=False)
            aud = ws / ".auditooor"

            _run(sys.executable, TOOL, "--workspace", ws)

            payload = json.loads((aud / "live_topology_proof_readiness.json").read_text(encoding="utf-8"))
            pair = payload["proof_pairs"][0]
            self.assertEqual(pair["status"], "blocked_strict_readiness_inputs")
            self.assertEqual(pair["blocker_class"], "source_refs_required")
            self.assertIn("missing_current_workspace_source_refs", pair["strict_missing"])
            self.assertEqual(payload["after_counts"]["closure_candidates"], 0)

    def test_imported_proved_pair_blocks_when_source_refs_stale(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_proof_readiness_stale_refs_") as tmp:
            ws = Path(tmp)
            _populate_imported_pair(ws, stale_source_refs=True)
            aud = ws / ".auditooor"

            _run(sys.executable, TOOL, "--workspace", ws)

            payload = json.loads((aud / "live_topology_proof_readiness.json").read_text(encoding="utf-8"))
            pair = payload["proof_pairs"][0]
            self.assertEqual(pair["status"], "blocked_strict_readiness_inputs")
            self.assertEqual(pair["blocker_class"], "stale_source_refs")
            self.assertIn("stale_workspace_source_refs", pair["strict_missing"])
            self.assertEqual(payload["after_counts"]["closure_candidates"], 0)

    def test_imported_proved_pair_blocks_when_topology_evidence_missing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_proof_readiness_missing_topology_") as tmp:
            ws = Path(tmp)
            _populate_imported_pair(ws, topology_evidence=False)
            aud = ws / ".auditooor"

            _run(sys.executable, TOOL, "--workspace", ws)

            payload = json.loads((aud / "live_topology_proof_readiness.json").read_text(encoding="utf-8"))
            pair = payload["proof_pairs"][0]
            self.assertEqual(pair["status"], "blocked_strict_readiness_inputs")
            self.assertEqual(pair["blocker_class"], "configured_topology_required")
            self.assertIn("missing_topology_path", pair["strict_missing"])
            self.assertIn("missing_configured_topology_evidence", pair["strict_missing"])
            self.assertEqual(payload["after_counts"]["closure_candidates"], 0)

    def test_imported_proved_pair_blocks_when_evidence_is_advisory_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_proof_readiness_advisory_") as tmp:
            ws = Path(tmp)
            _populate_imported_pair(ws, advisory_only=True)
            aud = ws / ".auditooor"

            _run(sys.executable, TOOL, "--workspace", ws)

            payload = json.loads((aud / "live_topology_proof_readiness.json").read_text(encoding="utf-8"))
            pair = payload["proof_pairs"][0]
            self.assertEqual(pair["status"], "blocked_strict_readiness_inputs")
            self.assertEqual(pair["blocker_class"], "advisory_only_evidence")
            self.assertIn("advisory_only_evidence", pair["strict_missing"])
            self.assertEqual(payload["after_counts"]["closure_candidates"], 0)


if __name__ == "__main__":
    unittest.main()
