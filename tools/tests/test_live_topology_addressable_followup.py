from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "live-topology-addressable-followup.py"


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_text(path: Path, text: str = "line 1\nline 2\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


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


class LiveTopologyAddressableFollowupTests(unittest.TestCase):
    def test_terminalizes_addressable_pair_when_counterpart_and_runtime_inputs_are_missing(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_addressable_followup_") as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            template_dir = aud / "live_topology_manual_proof_templates_fd"
            row_ids = ["LTPR-001-edge", "LTPR-001-authority"]
            _write_json(
                aud / "live_topology_manual_proof_command_groups_fj" / "addressable_candidate.json",
                {
                    "schema": "auditooor.live_topology_manual_proof_command_group.v1",
                    "pair_count": 1,
                    "row_count": 2,
                    "items": [
                        {
                            "proof_pair_id": "LTPR-001-pair",
                            "row_ids": row_ids,
                            "contracts": ["Portal", "Registry"],
                            "networks": ["mainnet"],
                        }
                    ],
                },
            )
            _write_json(
                aud / "live_topology_address_resolution_ew.json",
                {
                    "rows": [
                        {
                            "row_id": "LTPR-001-edge",
                            "requirement_id": "LTPR-001",
                            "contract": "Portal",
                            "network": "mainnet",
                            "proof_pair_id": "LTPR-001-pair",
                            "address_resolution_status": "unresolved_no_deterministic_address",
                            "candidate_addresses": [],
                        },
                        {
                            "row_id": "LTPR-001-authority",
                            "requirement_id": "LTPR-001",
                            "contract": "Registry",
                            "network": "mainnet",
                            "proof_pair_id": "LTPR-001-pair",
                            "address_resolution_status": "candidate_address_found_not_applied",
                            "candidate_addresses": ["0x00000000000076A84feF008CDAbe6409d2FE638B"],
                        },
                    ]
                },
            )
            _write_json(
                aud / "deployment_topology_ew_unresolved.json",
                {
                    "entries": [
                        {
                            "contract": "Registry",
                            "candidate_addresses": ["0x00000000000076A84feF008CDAbe6409d2FE638B"],
                        }
                    ]
                },
            )
            for rid, contract in zip(row_ids, ["Portal", "Registry"], strict=True):
                _write_json(
                    template_dir / f"{rid}.json",
                    {
                        "row_id": rid,
                        "contract": contract,
                        "network": "mainnet",
                        "required_same_block": "<same-block-for-LTPR-001>",
                        "expect": "<fill-from-deployment-topology>",
                        "capture_command": (
                            "python3 tools/live-state-checker.py --address "
                            f"'<resolved-{contract}-address>' --block '<same-block-for-LTPR-001>'"
                        ),
                    },
                )

            _run(sys.executable, TOOL, "--workspace", ws)

            payload = json.loads((aud / "live_topology_addressable_followup.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "auditooor.live_topology_addressable_followup.v1")
            self.assertEqual(payload["after_counts"]["pairs_total"], 1)
            self.assertEqual(payload["after_counts"]["capture_executable_pairs"], 0)
            self.assertEqual(payload["after_counts"]["same_block_executor_ready_pairs"], 0)
            self.assertEqual(payload["after_counts"]["candidate_bound_rows"], 1)
            self.assertEqual(
                payload["after_counts"]["pair_blocker_class_counts"],
                {"one_side_candidate_bound_missing_counterpart_address": 1},
            )
            self.assertEqual(payload["after_counts"]["missing_requirement_kind_counts"]["address"], 1)
            pair = payload["pairs"][0]
            self.assertEqual(pair["status"], "terminal_not_locally_executable")
            self.assertEqual(pair["blocker_class"], "one_side_candidate_bound_missing_counterpart_address")
            self.assertIn("missing_address", pair["missing"])
            self.assertIn("missing_rpc", pair["missing"])
            self.assertIn("missing_same_block", pair["missing"])
            self.assertIn("missing_expected_value", pair["missing"])
            self.assertIn("missing_manual_proof", pair["missing"])
            self.assertTrue(pair["missing_requirements"])
            authority = [row for row in pair["rows"] if row["row_id"] == "LTPR-001-authority"][0]
            self.assertIn("0x00000000000076A84feF008CDAbe6409d2FE638B", authority["capture_command_candidate_bound"])
            requirement_path = aud / "live_topology_addressable_pair_requirements" / "LTPR-001-pair.json"
            self.assertTrue(requirement_path.is_file())
            requirement_payload = json.loads(requirement_path.read_text(encoding="utf-8"))
            self.assertEqual(requirement_payload["proof_pair_id"], "LTPR-001-pair")
            self.assertEqual(
                requirement_payload["blocker_class"],
                "one_side_candidate_bound_missing_counterpart_address",
            )
            self.assertIn("safe_execution_order", requirement_payload)
            self.assertFalse(payload["promotion_allowed"])

    def test_marks_capture_executable_but_not_import_ready_when_runtime_inputs_exist(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_addressable_followup_ready_") as tmp:
            ws = Path(tmp)
            (ws / ".env").write_text("MAINNET_RPC_URL=https://example.invalid\n", encoding="utf-8")
            aud = ws / ".auditooor"
            template_dir = aud / "live_topology_manual_proof_templates_fd"
            row_ids = ["LTPR-002-edge", "LTPR-002-authority"]
            _write_json(
                aud / "live_topology_manual_proof_command_groups_fj" / "addressable_candidate.json",
                {
                    "items": [
                        {
                            "proof_pair_id": "LTPR-002-pair",
                            "row_ids": row_ids,
                            "contracts": ["Portal", "Registry"],
                            "networks": ["mainnet"],
                        }
                    ],
                },
            )
            _write_json(
                aud / "live_topology_address_resolution_ew.json",
                {
                    "rows": [
                        {
                            "row_id": rid,
                            "requirement_id": "LTPR-002",
                            "contract": contract,
                            "network": "mainnet",
                            "candidate_addresses": [address],
                            "address_resolution_status": "candidate_address_found_not_applied",
                        }
                        for rid, contract, address in [
                            ("LTPR-002-edge", "Portal", "0x1111111111111111111111111111111111111111"),
                            ("LTPR-002-authority", "Registry", "0x2222222222222222222222222222222222222222"),
                        ]
                    ]
                },
            )
            _write_json(aud / "deployment_topology_ew_unresolved.json", {"entries": []})
            for rid, contract in zip(row_ids, ["Portal", "Registry"], strict=True):
                _write_json(
                    template_dir / f"{rid}.json",
                    {
                        "row_id": rid,
                        "contract": contract,
                        "network": "mainnet",
                        "required_same_block": "12345",
                        "expect": "0x0000000000000000000000000000000000000000",
                        "capture_command": f"live-state --address <resolved-{contract}-address>",
                    },
                )

            _run(sys.executable, TOOL, "--workspace", ws)

            payload = json.loads((aud / "live_topology_addressable_followup.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["after_counts"]["capture_executable_pairs"], 1)
            self.assertEqual(payload["after_counts"]["same_block_executor_ready_pairs"], 0)
            self.assertEqual(payload["pairs"][0]["status"], "capture_executable_missing_manual_import")
            self.assertEqual(payload["pairs"][0]["blocker_class"], "capture_ready_waiting_for_manual_import")
            self.assertEqual(payload["pairs"][0]["missing"], ["candidate_address_requires_manual_verification", "missing_manual_proof"])

    def test_followup_ready_rows_require_current_source_topology_and_proof_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_addressable_followup_strict_ready_") as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            template_dir = aud / "live_topology_manual_proof_templates_fd"
            row_ids = ["LTPR-003-edge", "LTPR-003-authority"]
            _write_text(ws / "contracts" / "Portal.sol")
            _write_text(ws / "contracts" / "Registry.sol")
            _write_text(ws / "config" / "deployment-topology.json")
            _write_text(ws / "poc-tests" / "LiveTopologyProof.t.sol")
            _write_json(
                aud / "live_topology_manual_proof_command_groups_fj" / "addressable_candidate.json",
                {
                    "items": [
                        {
                            "proof_pair_id": "LTPR-003-pair",
                            "row_ids": row_ids,
                            "contracts": ["Portal", "Registry"],
                            "networks": ["mainnet"],
                        }
                    ],
                },
            )
            _write_json(
                aud / "live_topology_address_resolution_ew.json",
                {
                    "rows": [
                        {
                            "row_id": "LTPR-003-edge",
                            "contract": "Portal",
                            "network": "mainnet",
                            "source_refs": ["contracts/Portal.sol:1"],
                            "topology_required": True,
                            "topology_path": "config/deployment-topology.json:1",
                            "proof_ready": True,
                            "proof_artifact_path": "poc-tests/LiveTopologyProof.t.sol",
                            "pass_evidence_lines": ["Suite result: ok. 1 passed; 0 failed"],
                        },
                        {
                            "row_id": "LTPR-003-authority",
                            "contract": "Registry",
                            "network": "mainnet",
                            "source_refs": ["contracts/Registry.sol:1"],
                            "topology_required": True,
                            "configured_topology_evidence": "registry owner is configured in deployment-topology.json",
                            "proof_ready": True,
                            "harness_evidence": {"ran": True, "pass": True},
                        },
                    ]
                },
            )
            _write_json(aud / "deployment_topology_ew_unresolved.json", {"entries": []})
            for rid, contract in zip(row_ids, ["Portal", "Registry"], strict=True):
                _write_json(
                    template_dir / f"{rid}.json",
                    {
                        "row_id": rid,
                        "contract": contract,
                        "network": "mainnet",
                        "required_same_block": "12345",
                        "expect": "0x0000000000000000000000000000000000000000",
                    },
                )

            _run(sys.executable, TOOL, "--workspace", ws)

            payload = json.loads((aud / "live_topology_addressable_followup.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["after_counts"]["followup_ready_rows"], 2)
            self.assertEqual(payload["after_counts"]["followup_non_ready_rows"], 0)
            self.assertEqual(payload["after_counts"]["proof_ready_claimed_rows"], 2)
            self.assertTrue(payload["pairs"][0]["followup_pair_ready_now"])
            self.assertEqual(payload["pairs"][0]["followup_ready_row_ids"], row_ids)
            for row in payload["pairs"][0]["rows"]:
                self.assertTrue(row["followup_ready"])
                self.assertEqual(row["followup_non_ready_reasons"], [])
                self.assertTrue(row["source_refs"])
                self.assertTrue(row["topology_required"])
                self.assertTrue(row["concrete_proof_or_harness_evidence"])

    def test_non_ready_rows_remain_visible_with_typed_reasons(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_addressable_followup_strict_blocked_") as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            template_dir = aud / "live_topology_manual_proof_templates_fd"
            row_ids = ["LTPR-004-edge", "LTPR-004-authority"]
            _write_json(
                aud / "live_topology_manual_proof_command_groups_fj" / "addressable_candidate.json",
                {
                    "items": [
                        {
                            "proof_pair_id": "LTPR-004-pair",
                            "row_ids": row_ids,
                            "contracts": ["Portal", "Registry"],
                            "networks": ["mainnet"],
                        }
                    ],
                },
            )
            _write_json(
                aud / "live_topology_address_resolution_ew.json",
                {
                    "rows": [
                        {
                            "row_id": "LTPR-004-edge",
                            "contract": "Portal",
                            "network": "mainnet",
                            "topology_required": True,
                            "proof_ready": True,
                            "blockers": ["operator topology source missing"],
                            "advisory_only": True,
                        },
                        {
                            "row_id": "LTPR-004-authority",
                            "contract": "Registry",
                            "network": "mainnet",
                            "source_refs": ["contracts/MissingRegistry.sol:42"],
                        },
                    ]
                },
            )
            _write_json(aud / "deployment_topology_ew_unresolved.json", {"entries": []})
            for rid, contract in zip(row_ids, ["Portal", "Registry"], strict=True):
                _write_json(
                    template_dir / f"{rid}.json",
                    {
                        "row_id": rid,
                        "contract": contract,
                        "network": "mainnet",
                        "required_same_block": "12345",
                        "expect": "0x0000000000000000000000000000000000000000",
                    },
                )

            _run(sys.executable, TOOL, "--workspace", ws)

            payload = json.loads((aud / "live_topology_addressable_followup.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["after_counts"]["followup_ready_rows"], 0)
            self.assertEqual(payload["after_counts"]["followup_non_ready_rows"], 2)
            reason_counts = payload["after_counts"]["followup_non_ready_reason_counts"]
            for reason in [
                "advisory_only",
                "blocker_present",
                "missing_proof_evidence",
                "missing_source_refs",
                "missing_topology_evidence",
                "stale_source",
            ]:
                self.assertIn(reason, reason_counts)
            rows = {row["row_id"]: row for row in payload["pairs"][0]["rows"]}
            edge_reasons = rows["LTPR-004-edge"]["followup_non_ready_reasons"]
            self.assertIn("missing_source_refs", edge_reasons)
            self.assertIn("missing_topology_evidence", edge_reasons)
            self.assertIn("missing_proof_evidence", edge_reasons)
            self.assertIn("blocker_present", edge_reasons)
            self.assertIn("advisory_only", edge_reasons)
            self.assertIn("stale_source", rows["LTPR-004-authority"]["followup_non_ready_reasons"])
            self.assertEqual(len(payload["pairs"][0]["followup_non_ready_rows"]), 2)


if __name__ == "__main__":
    unittest.main()
