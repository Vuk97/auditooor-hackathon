from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "live-topology-manual-proof-materializer.py"
LIVE_CHECK_RUNNER = ROOT / "tools" / "live-check-runner.py"
EXECUTOR_TOOL = ROOT / "tools" / "live-topology-proof-executor.py"


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


def _validator_payload() -> dict:
    rows = []
    for suffix, contract in [("edge", "Portal"), ("authority", "Registry")]:
        row_id = f"LTPR-001-{suffix}"
        rows.append(
            {
                "row_id": row_id,
                "contract": contract,
                "proof_path": f"/tmp/manual_proofs/{row_id}.json",
                "validation_state": "missing_manual_proof_file",
                "problems": ["missing_manual_proof_file"],
            }
        )
    return {
        "schema": "auditooor.live_topology_proof_input_validator.v1",
        "pair_validations": [
            {
                "proof_pair_id": "LTPR-001-pair",
                "row_ids": ["LTPR-001-edge", "LTPR-001-authority"],
                "row_validations": rows,
                "executor_command_after_import": "python3 tools/live-topology-proof-executor.py --workspace /tmp/ws",
            }
        ],
    }


def _provided_row(row_id: str, contract: str, *, block: str = "123456") -> dict:
    return {
        "id": row_id,
        "proof_pair_id": "LTPR-001-pair",
        "evidence_class": "topology-relation",
        "contract": contract,
        "network": "mainnet",
        "address": "0x" + ("1" if contract == "Portal" else "2") * 40,
        "status": "pass",
        "block": block,
        "expected": "owner=0xabc",
        "actual": "owner=0xabc",
        "live_result": {"sig": "owner()", "args": [], "actual_normalized": "0xabc", "expected_normalized": "0xabc"},
    }


def _write_requirements(ws: Path) -> None:
    _write_json(
        ws / ".auditooor" / "live_topology_proof_requirements.json",
        {
            "schema": "auditooor.live_topology_proof_requirements.v1",
            "requirements": [
                {
                    "requirement_id": "LTPR-001",
                    "required_proof_pair_id": "LTPR-001-pair",
                    "required_contracts": ["Portal", "Registry"],
                    "required_live_rows": [
                        {
                            "id": "LTPR-001-edge",
                            "contract": "Portal",
                            "evidence_class": "topology-relation",
                            "proof_pair_id": "LTPR-001-pair",
                        },
                        {
                            "id": "LTPR-001-authority",
                            "contract": "Registry",
                            "evidence_class": "topology-relation",
                            "proof_pair_id": "LTPR-001-pair",
                        },
                    ],
                    "submission_posture": "NOT_SUBMIT_READY",
                    "promotion_allowed": False,
                }
            ],
        },
    )


class LiveTopologyManualProofMaterializerTests(unittest.TestCase):
    def test_materializes_same_block_pair_as_importable_manual_proofs_without_closing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_manual_materializer_") as tmp:
            ws = Path(tmp)
            _write_json(ws / ".auditooor" / "live_topology_proof_input_validator.json", _validator_payload())
            _write_json(ws / ".auditooor" / "provided" / "LTPR-001-edge.json", _provided_row("LTPR-001-edge", "Portal"))
            _write_json(
                ws / ".auditooor" / "provided" / "LTPR-001-authority.json",
                {
                    "schema": "auditooor.manual_live_topology_proof.v1",
                    "results": [_provided_row("LTPR-001-authority", "Registry")],
                },
            )

            _run(sys.executable, TOOL, "--workspace", ws, "--provided-dir", ws / ".auditooor" / "provided")

            payload = json.loads((ws / ".auditooor" / "live_topology_manual_proof_materializer.json").read_text())
            self.assertEqual(payload["schema"], "auditooor.live_topology_manual_proof_materializer.v1")
            self.assertEqual(payload["summary"]["canonical_import_ready_pairs"], 1)
            self.assertEqual(payload["summary"]["canonical_rows_materialized"], 2)
            self.assertEqual(payload["summary"]["proof_pairs_closed"], 0)
            self.assertFalse(payload["promotion_allowed"])

            canonical = json.loads((ws / "manual_proofs" / "LTPR-001-edge.json").read_text())
            self.assertEqual(canonical["schema"], "auditooor.manual_live_topology_proof.v1")
            self.assertFalse(canonical["advisory_only"])
            self.assertEqual(canonical["results"][0]["id"], "LTPR-001-edge")
            self.assertTrue(canonical["results"][0]["same_block"])

            _run(
                sys.executable,
                LIVE_CHECK_RUNNER,
                ws,
                "--import-manual-proofs",
                "--manual-proof-id",
                "LTPR-001-edge",
                "--manual-proof-id",
                "LTPR-001-authority",
            )
            dossier = json.loads((ws / "live_topology_checks.json").read_text())
            self.assertEqual(dossier["manual_imports"]["imported_rows"], 2)
            self.assertEqual(dossier["proof_pair_summary"]["proved"], 1)

    def test_same_block_materialize_import_executor_chain_is_depth_ready_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_manual_materializer_chain_") as tmp:
            ws = Path(tmp)
            _write_requirements(ws)
            _write_json(ws / ".auditooor" / "live_topology_proof_input_validator.json", _validator_payload())
            _write_json(ws / ".auditooor" / "provided" / "LTPR-001-edge.json", _provided_row("LTPR-001-edge", "Portal"))
            _write_json(
                ws / ".auditooor" / "provided" / "LTPR-001-authority.json",
                _provided_row("LTPR-001-authority", "Registry"),
            )

            _run(sys.executable, TOOL, "--workspace", ws, "--provided-dir", ws / ".auditooor" / "provided")
            materializer = json.loads((ws / ".auditooor" / "live_topology_manual_proof_materializer.json").read_text())
            self.assertEqual(materializer["summary"]["canonical_import_ready_pairs"], 1)
            self.assertEqual(materializer["summary"]["canonical_rows_materialized"], 2)
            self.assertEqual(materializer["summary"]["proof_pairs_closed"], 0)

            _run(
                sys.executable,
                LIVE_CHECK_RUNNER,
                ws,
                "--import-manual-proofs",
                "--manual-proof-id",
                "LTPR-001-edge",
                "--manual-proof-id",
                "LTPR-001-authority",
            )
            _run(sys.executable, EXECUTOR_TOOL, "--workspace", ws)

            executor = json.loads((ws / ".auditooor" / "live_topology_proof_executor.json").read_text())
            self.assertEqual(executor["depth_closure_candidate_count"], 1)
            self.assertEqual(executor["status_counts"], {"closure_candidate_same_block_pair_validated": 1})
            row = executor["rows"][0]
            self.assertEqual(row["status"], "closure_candidate_same_block_pair_validated")
            self.assertEqual(row["closure_scope"], "semantic_live_topology_depth_only")
            self.assertEqual(row["validated_blocks"], ["123456"])
            self.assertCountEqual(row["validated_contracts"], ["Portal", "Registry"])
            self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")
            self.assertEqual(row["severity"], "none")
            self.assertFalse(row["promotion_allowed"])

    def test_cross_block_pair_does_not_materialize_or_become_executor_ready(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_manual_materializer_chain_badblock_") as tmp:
            ws = Path(tmp)
            _write_requirements(ws)
            _write_json(ws / ".auditooor" / "live_topology_proof_input_validator.json", _validator_payload())
            _write_json(ws / "provided" / "LTPR-001-edge.json", _provided_row("LTPR-001-edge", "Portal", block="123456"))
            _write_json(
                ws / "provided" / "LTPR-001-authority.json",
                _provided_row("LTPR-001-authority", "Registry", block="123457"),
            )

            _run(sys.executable, TOOL, "--workspace", ws, "--provided-dir", ws / "provided")
            materializer = json.loads((ws / ".auditooor" / "live_topology_manual_proof_materializer.json").read_text())
            self.assertEqual(materializer["summary"]["canonical_import_ready_pairs"], 0)
            self.assertEqual(materializer["summary"]["canonical_rows_materialized"], 0)

            _run(sys.executable, EXECUTOR_TOOL, "--workspace", ws)
            executor = json.loads((ws / ".auditooor" / "live_topology_proof_executor.json").read_text())
            self.assertEqual(executor["depth_closure_candidate_count"], 0)
            self.assertEqual(executor["status_counts"], {"terminal_missing_live_topology_checks": 1})
            self.assertEqual(executor["blocker_kind_counts"], {"missing_live_topology_artifact": 1})

    def test_rejects_pair_when_blocks_do_not_match(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_manual_materializer_badblock_") as tmp:
            ws = Path(tmp)
            _write_json(ws / ".auditooor" / "live_topology_proof_input_validator.json", _validator_payload())
            _write_json(ws / "provided" / "LTPR-001-edge.json", _provided_row("LTPR-001-edge", "Portal", block="123456"))
            _write_json(
                ws / "provided" / "LTPR-001-authority.json",
                _provided_row("LTPR-001-authority", "Registry", block="123457"),
            )

            _run(sys.executable, TOOL, "--workspace", ws, "--provided-dir", ws / "provided")

            payload = json.loads((ws / ".auditooor" / "live_topology_manual_proof_materializer.json").read_text())
            self.assertEqual(payload["summary"]["canonical_import_ready_pairs"], 0)
            self.assertEqual(payload["summary"]["canonical_rows_materialized"], 0)
            self.assertEqual(
                payload["summary"]["pair_materialization_state_counts"],
                {"partial_canonical_manual_proofs_ready": 1},
            )
            self.assertFalse((ws / "manual_proofs" / "LTPR-001-edge.json").exists())

    def test_rejects_placeholder_values(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_manual_materializer_placeholder_") as tmp:
            ws = Path(tmp)
            _write_json(ws / ".auditooor" / "live_topology_proof_input_validator.json", _validator_payload())
            bad = _provided_row("LTPR-001-edge", "Portal")
            bad["actual"] = "<observed-value>"
            _write_json(ws / "provided" / "LTPR-001-edge.json", bad)

            _run(sys.executable, TOOL, "--workspace", ws, "--provided-dir", ws / "provided")

            payload = json.loads((ws / ".auditooor" / "live_topology_manual_proof_materializer.json").read_text())
            row = payload["pair_materializations"][0]["row_materializations"][0]
            self.assertEqual(row["materialization_state"], "provided_manual_proof_invalid")
            self.assertIn("missing_or_placeholder_actual", row["problems"])


if __name__ == "__main__":
    unittest.main()
