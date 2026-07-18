from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "live-topology-terminalization.py"


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


def _row(row_id: str, pair_id: str, contract: str, status: str) -> dict:
    return {
        "row_id": row_id,
        "requirement_id": pair_id.replace("-pair", ""),
        "proof_pair_id": pair_id,
        "contract": contract,
        "network": "hermetic",
        "address_resolution_status": status,
        "status_after_ew": "blocked_unresolved_address",
    }


def _fd_pair(pair_id: str, row_ids: list[str], contracts: list[str]) -> dict:
    return {
        "proof_pair_id": pair_id,
        "row_ids": row_ids,
        "contracts": contracts,
        "terminal_blockers": [
            f"manual_proof_missing:{row_id}" for row_id in row_ids
        ]
        + [f"same_block_unpinned:{pair_id}"],
        "import_command_after_capture": (
            "python3 tools/live-check-runner.py . --import-manual-proofs "
            + " ".join(f"--manual-proof-id {row_id}" for row_id in row_ids)
        ),
    }


class LiveTopologyTerminalizationTests(unittest.TestCase):
    def test_terminalizes_pairs_into_exact_groups_and_counts_real_imported_closure_only(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_terminalization_") as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            template_dir = aud / "live_topology_manual_proof_templates_fd"
            manual_dir = ws / "manual_proofs"
            template_dir.mkdir(parents=True)
            manual_dir.mkdir()
            (ws / "src").mkdir()
            (ws / "src" / "Topology.sol").write_text("contract Topology {}\n", encoding="utf-8")
            pairs = {
                "LTPR-001-pair": ["LTPR-001-edge", "LTPR-001-authority"],
                "LTPR-002-pair": ["LTPR-002-edge", "LTPR-002-authority"],
                "LTPR-003-pair": ["LTPR-003-edge", "LTPR-003-authority"],
                "LTPR-004-pair": ["LTPR-004-edge", "LTPR-004-authority"],
            }
            for row_ids in pairs.values():
                for rid in row_ids:
                    _write_json(template_dir / f"{rid}.json", {"row_id": rid})

            ew_rows = [
                _row("LTPR-001-edge", "LTPR-001-pair", "CandidatePortal", "candidate_address_found_not_applied"),
                _row("LTPR-001-authority", "LTPR-001-pair", "CandidateBridge", "unresolved_no_deterministic_address"),
                _row("LTPR-002-edge", "LTPR-002-pair", "FixturePortal", "terminal_fixture_or_corpus_only_no_live_address"),
                _row("LTPR-002-authority", "LTPR-002-pair", "FixtureBridgeTest", "terminal_test_or_script_label_no_live_address"),
                _row("LTPR-003-edge", "LTPR-003-pair", "IPortal", "terminal_interface_type_no_address"),
                _row("LTPR-003-authority", "LTPR-003-pair", "SemanticStage", "terminal_semantic_stage_not_contract"),
                _row("LTPR-004-edge", "LTPR-004-pair", "RealPortal", "unresolved_no_deterministic_address"),
                _row("LTPR-004-authority", "LTPR-004-pair", "RealBridge", "unresolved_no_deterministic_address"),
            ]
            _write_json(
                aud / "live_topology_address_resolution_ew.json",
                {
                    "schema": "auditooor.live_topology_address_resolution_ew.v1",
                    "requirements": [{"requirement_id": f"LTPR-{idx:03d}"} for idx in range(1, 5)],
                    "closed_rows": [],
                    "closed_requirements": [],
                    "rows": ew_rows,
                },
            )
            _write_json(
                aud / "live_topology_manual_proof_plan_fd.json",
                {
                    "schema": "auditooor.live_topology_manual_proof_plan.v1",
                    "before_counts": {"source_rows": 8, "source_proof_pairs": 4},
                    "after_counts": {"closure_candidates": 0, "terminal_proof_pairs": 4},
                    "proof_pairs": [
                        _fd_pair("LTPR-001-pair", pairs["LTPR-001-pair"], ["CandidatePortal", "CandidateBridge"]),
                        _fd_pair("LTPR-002-pair", pairs["LTPR-002-pair"], ["FixturePortal", "FixtureBridgeTest"]),
                        _fd_pair("LTPR-003-pair", pairs["LTPR-003-pair"], ["IPortal", "SemanticStage"]),
                        _fd_pair("LTPR-004-pair", pairs["LTPR-004-pair"], ["RealPortal", "RealBridge"]),
                    ],
                },
            )
            _write_json(
                aud / "live_topology_execution_closure_eo.json",
                {
                    "schema": "auditooor.live_topology_execution_closure.v1",
                    "closure": {"closed_requirement_count": 0, "reduced_requirement_count": 4, "row_attempt_count": 8},
                    "groups": {
                        "missing_address": {"row_count": 6},
                        "missing_block": {"requirement_count": 3},
                        "missing_manual_proof_id": {"row_count": 6},
                    },
                },
            )
            _write_json(
                manual_dir / "real_pair.json",
                {
                    "results": [
                        {"id": "LTPR-004-edge"},
                        {"id": "LTPR-004-authority"},
                    ]
                },
            )
            live_results = [
                {
                    "id": row["row_id"],
                    "contract": row["contract"],
                    "network": "hermetic",
                    "status": "required_not_collected",
                    "evidence_class": "topology-relation",
                    "proof_pair_id": row["proof_pair_id"],
                }
                for row in ew_rows[:6]
            ] + [
                {
                    "id": "LTPR-004-edge",
                    "contract": "RealPortal",
                    "network": "hermetic",
                    "block": "123",
                    "status": "pass",
                    "evidence_class": "topology-relation",
                    "proof_pair_id": "LTPR-004-pair",
                    "spec_source": "manual-proof-import",
                    "manual_proof_source": str(manual_dir / "real_pair.json"),
                    "block_source": "manual-proof-import",
                    "address_source": "manual-proof-import",
                    "source_refs": ["src/Topology.sol:1"],
                    "configured_topology_evidence": "RealPortal deployment address captured from current topology",
                    "proof_evidence": "go test ./... PASS",
                },
                {
                    "id": "LTPR-004-authority",
                    "contract": "RealBridge",
                    "network": "hermetic",
                    "block": "123",
                    "status": "pass",
                    "evidence_class": "topology-relation",
                    "proof_pair_id": "LTPR-004-pair",
                    "spec_source": "manual-proof-import",
                    "manual_proof_source": str(manual_dir / "real_pair.json"),
                    "block_source": "manual-proof-import",
                    "address_source": "manual-proof-import",
                    "source_refs": ["src/Topology.sol:1"],
                    "configured_topology_evidence": "RealBridge deployment address captured from current topology",
                    "proof_evidence": "go test ./... PASS",
                },
            ]
            _write_json(
                ws / "live_topology_checks.json",
                {
                    "schema": "auditooor.live_topology_checks.v1",
                    "summary": {"required_not_collected": 6, "pass": 2},
                    "proof_pair_summary": {"declared": 4, "required_not_collected": 3, "proved": 1},
                    "results": live_results,
                    "proof_pairs": [
                        {"id": "LTPR-001-pair", "status": "required_not_collected", "row_ids": pairs["LTPR-001-pair"]},
                        {"id": "LTPR-002-pair", "status": "required_not_collected", "row_ids": pairs["LTPR-002-pair"]},
                        {"id": "LTPR-003-pair", "status": "required_not_collected", "row_ids": pairs["LTPR-003-pair"]},
                        {
                            "id": "LTPR-004-pair",
                            "status": "proved",
                            "row_ids": pairs["LTPR-004-pair"],
                            "shared_block": "123",
                            "pair_blocks": ["123"],
                        },
                    ],
                },
            )

            _run(sys.executable, TOOL, "--workspace", ws)

            payload = json.loads((aud / "live_topology_terminalization_fl.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "auditooor.live_topology_terminalization_fl.v1")
            self.assertEqual(payload["after_counts"]["proof_pairs_total"], 4)
            self.assertEqual(payload["after_counts"]["terminal_pair_count"], 3)
            self.assertEqual(payload["after_counts"]["closure_candidates_real_imported_same_block"], 1)
            self.assertEqual(payload["after_counts"]["addressable_candidate_pairs"], 1)
            self.assertEqual(payload["after_counts"]["fixture_or_corpus_only_pairs"], 1)
            self.assertEqual(payload["after_counts"]["interface_or_non_contract_pairs"], 1)
            self.assertEqual(payload["after_counts"]["missing_rpc_pairs"], 3)
            self.assertEqual(payload["after_counts"]["missing_block_pairs"], 3)
            self.assertEqual(payload["after_counts"]["missing_manual_proof_pairs"], 3)
            self.assertEqual(payload["after_counts"]["proof_complete_row_count"], 2)
            self.assertEqual(payload["after_counts"]["non_terminal_row_count"], 6)
            self.assertTrue(payload["after_counts"]["all_pairs_accounted"])
            closure_item = payload["groups"]["closure_candidates_real_imported_same_block"]["items"][0]
            self.assertEqual(closure_item["proof_pair_id"], "LTPR-004-pair")
            self.assertEqual(closure_item["terminal_buckets"], [])
            self.assertTrue(all(row["proof_complete"] for row in closure_item["row_terminalization"]))
            self.assertFalse(payload["promotion_allowed"])

    def test_proved_pair_without_manual_import_is_not_a_closure_candidate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_terminalization_no_import_") as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            template_dir = aud / "live_topology_manual_proof_templates_fd"
            template_dir.mkdir(parents=True)
            (ws / "src").mkdir()
            (ws / "src" / "Topology.sol").write_text("contract Topology {}\n", encoding="utf-8")
            for rid in ("LTPR-001-edge", "LTPR-001-authority"):
                _write_json(template_dir / f"{rid}.json", {"row_id": rid})
            _write_json(
                aud / "live_topology_address_resolution_ew.json",
                {
                    "requirements": [{"requirement_id": "LTPR-001"}],
                    "rows": [
                        _row("LTPR-001-edge", "LTPR-001-pair", "Portal", "unresolved_no_deterministic_address"),
                        _row("LTPR-001-authority", "LTPR-001-pair", "Bridge", "unresolved_no_deterministic_address"),
                    ],
                },
            )
            _write_json(
                aud / "live_topology_manual_proof_plan_fd.json",
                {
                    "before_counts": {"source_rows": 2, "source_proof_pairs": 1},
                    "after_counts": {"closure_candidates": 0, "terminal_proof_pairs": 1},
                    "proof_pairs": [_fd_pair("LTPR-001-pair", ["LTPR-001-edge", "LTPR-001-authority"], ["Portal", "Bridge"])],
                },
            )
            _write_json(aud / "live_topology_execution_closure_eo.json", {"closure": {}, "groups": {}})
            _write_json(
                ws / "live_topology_checks.json",
                {
                    "results": [
                        {
                            "id": "LTPR-001-edge",
                            "contract": "Portal",
                            "network": "hermetic",
                            "block": "777",
                            "status": "pass",
                            "evidence_class": "topology-relation",
                            "proof_pair_id": "LTPR-001-pair",
                            "source_refs": ["src/Topology.sol:1"],
                            "configured_topology_evidence": "Portal configured in deployment topology",
                            "proof_evidence": "go test ./... PASS",
                        },
                        {
                            "id": "LTPR-001-authority",
                            "contract": "Bridge",
                            "network": "hermetic",
                            "block": "777",
                            "status": "pass",
                            "evidence_class": "topology-relation",
                            "proof_pair_id": "LTPR-001-pair",
                            "source_refs": ["src/Topology.sol:1"],
                            "configured_topology_evidence": "Bridge configured in deployment topology",
                            "proof_evidence": "go test ./... PASS",
                        },
                    ],
                    "proof_pairs": [
                        {
                            "id": "LTPR-001-pair",
                            "status": "proved",
                            "row_ids": ["LTPR-001-edge", "LTPR-001-authority"],
                            "shared_block": "777",
                            "pair_blocks": ["777"],
                        }
                    ],
                },
            )

            _run(sys.executable, TOOL, "--workspace", ws)

            payload = json.loads((aud / "live_topology_terminalization_fl.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["after_counts"]["closure_candidates_real_imported_same_block"], 0)
            self.assertEqual(payload["after_counts"]["not_real_imported_same_block_pairs"], 1)
            item = payload["pair_terminalization"][0]
            self.assertIn("not_real_imported_same_block", item["terminal_buckets"])
            self.assertTrue(any("not imported manual proofs" in blocker for blocker in item["closure_blockers"]))

    def test_non_terminal_rows_keep_typed_evidence_reasons(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_terminalization_reasons_") as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            template_dir = aud / "live_topology_manual_proof_templates_fd"
            manual_dir = ws / "manual_proofs"
            template_dir.mkdir(parents=True)
            manual_dir.mkdir()
            row_ids = ["LTPR-001-edge", "LTPR-001-authority"]
            for rid in row_ids:
                _write_json(template_dir / f"{rid}.json", {"row_id": rid})
            _write_json(
                manual_dir / "pair.json",
                {"results": [{"id": "LTPR-001-edge"}, {"id": "LTPR-001-authority"}]},
            )
            _write_json(
                aud / "live_topology_address_resolution_ew.json",
                {
                    "requirements": [{"requirement_id": "LTPR-001"}],
                    "rows": [
                        _row("LTPR-001-edge", "LTPR-001-pair", "Portal", "unresolved_no_deterministic_address"),
                        _row("LTPR-001-authority", "LTPR-001-pair", "Bridge", "unresolved_no_deterministic_address"),
                    ],
                },
            )
            _write_json(
                aud / "live_topology_manual_proof_plan_fd.json",
                {
                    "before_counts": {"source_rows": 2, "source_proof_pairs": 1},
                    "after_counts": {"closure_candidates": 0, "terminal_proof_pairs": 1},
                    "proof_pairs": [_fd_pair("LTPR-001-pair", row_ids, ["Portal", "Bridge"])],
                },
            )
            _write_json(aud / "live_topology_execution_closure_eo.json", {"closure": {}, "groups": {}})
            _write_json(
                ws / "live_topology_checks.json",
                {
                    "results": [
                        {
                            "id": "LTPR-001-edge",
                            "contract": "Portal",
                            "network": "hermetic",
                            "block": "888",
                            "status": "pass",
                            "evidence_class": "topology-relation",
                            "proof_pair_id": "LTPR-001-pair",
                            "spec_source": "manual-proof-import",
                            "manual_proof_source": str(manual_dir / "pair.json"),
                            "block_source": "manual-proof-import",
                            "address_source": "manual-proof-import",
                            "source_refs": ["src/Missing.sol:1"],
                            "blockers": ["operator required before proof promotion"],
                            "advisory_only": True,
                        },
                        {
                            "id": "LTPR-001-authority",
                            "contract": "Bridge",
                            "network": "hermetic",
                            "block": "888",
                            "status": "pass",
                            "evidence_class": "topology-relation",
                            "proof_pair_id": "LTPR-001-pair",
                            "spec_source": "manual-proof-import",
                            "manual_proof_source": str(manual_dir / "pair.json"),
                            "block_source": "manual-proof-import",
                            "address_source": "manual-proof-import",
                        },
                    ],
                    "proof_pairs": [
                        {
                            "id": "LTPR-001-pair",
                            "status": "proved",
                            "row_ids": row_ids,
                            "shared_block": "888",
                            "pair_blocks": ["888"],
                        }
                    ],
                },
            )

            _run(sys.executable, TOOL, "--workspace", ws)

            payload = json.loads((aud / "live_topology_terminalization_fl.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["after_counts"]["closure_candidates_real_imported_same_block"], 0)
            self.assertEqual(payload["after_counts"]["stale_source_pairs"], 1)
            self.assertEqual(payload["after_counts"]["missing_source_refs_pairs"], 1)
            self.assertEqual(payload["after_counts"]["missing_topology_evidence_pairs"], 1)
            self.assertEqual(payload["after_counts"]["missing_proof_evidence_pairs"], 1)
            self.assertEqual(payload["after_counts"]["blocker_present_pairs"], 1)
            self.assertEqual(payload["after_counts"]["advisory_only_pairs"], 1)
            reason_counts = payload["after_counts"]["non_terminal_row_reason_counts"]
            self.assertEqual(reason_counts["stale_source"], 1)
            self.assertEqual(reason_counts["missing_source_refs"], 1)
            self.assertEqual(reason_counts["missing_topology_evidence"], 2)
            self.assertEqual(reason_counts["missing_proof_evidence"], 2)
            self.assertEqual(reason_counts["blocker_present"], 1)
            self.assertEqual(reason_counts["advisory_only"], 1)
            item = payload["pair_terminalization"][0]
            self.assertIn("rows are not proof complete", " ".join(item["closure_blockers"]))
            rows = {row["row_id"]: row for row in item["row_terminalization"]}
            self.assertEqual(rows["LTPR-001-edge"]["proof_terminal_status"], "non_terminal")
            self.assertIn("stale_source", rows["LTPR-001-edge"]["proof_terminal_reasons"])
            self.assertIn("missing_source_refs", rows["LTPR-001-authority"]["proof_terminal_reasons"])


if __name__ == "__main__":
    unittest.main()
