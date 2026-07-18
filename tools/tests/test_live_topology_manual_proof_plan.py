from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "live-topology-manual-proof-plan.py"


class LiveTopologyManualProofPlanTests(unittest.TestCase):
    def _run_tool(self, ws: Path) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(TOOL), "--workspace", str(ws)],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

    def test_generates_templates_without_promoting_unresolved_rows(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_manual_plan_") as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            source = aud / "live_topology_address_resolution_ew.json"
            source.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.live_topology_address_resolution_ew.v1",
                        "requirements": [
                            {
                                "requirement_id": "LTPR-001",
                                "proof_pair_id": "LTPR-001-pair",
                            }
                        ],
                        "closed_rows": [],
                        "closed_requirements": [],
                        "rows": [
                            {
                                "row_id": "LTPR-001-edge",
                                "contract": "HermeticPortal",
                                "requirement_id": "LTPR-001",
                                "proof_pair_id": "LTPR-001-pair",
                                "requirement_role": "relation-edge",
                                "network": "hermetic",
                                "call": "owner()",
                                "expect": "<fill-from-deployment-topology>",
                                "address_resolution_status": "unresolved_no_deterministic_address",
                                "status_after_ew": "blocked_unresolved_address",
                            },
                            {
                                "row_id": "LTPR-001-authority",
                                "contract": "HermeticBridge",
                                "requirement_id": "LTPR-001",
                                "proof_pair_id": "LTPR-001-pair",
                                "requirement_role": "authority-or-wiring",
                                "network": "hermetic",
                                "call": "owner()",
                                "expect": "<fill-from-deployment-topology>",
                                "address_resolution_status": "unresolved_no_deterministic_address",
                                "status_after_ew": "blocked_unresolved_address",
                            },
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            proc = self._run_tool(ws)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads((aud / "live_topology_manual_proof_plan_fd.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], "auditooor.live_topology_manual_proof_plan.v1")
            self.assertEqual(payload["after_counts"]["manual_proof_templates"], 2)
            self.assertEqual(payload["after_counts"]["proof_pair_capture_plans"], 1)
            self.assertEqual(payload["after_counts"]["proof_plan_ready_rows"], 0)
            self.assertEqual(payload["after_counts"]["proof_plan_non_ready_rows"], 2)
            self.assertEqual(payload["after_counts"]["closure_candidates"], 0)
            self.assertFalse(payload["promotion_allowed"])
            self.assertEqual(payload["submission_posture"], "NOT_SUBMIT_READY")
            pair = payload["proof_pairs"][0]
            self.assertIn("address_unresolved:LTPR-001-edge:HermeticPortal", pair["terminal_blockers"])
            self.assertIn("manual_proof_missing:LTPR-001-authority", pair["terminal_blockers"])
            self.assertIn("same_block_unpinned:LTPR-001-pair", pair["terminal_blockers"])
            self.assertTrue(any("--proof-pair-id LTPR-001-pair" in command for command in pair["capture_commands"]))
            self.assertTrue(any("--manual-proof-id LTPR-001-edge" in pair["import_command_after_capture"] for _ in [0]))
            template = aud / "live_topology_manual_proof_templates_fd" / "LTPR-001-edge.json"
            self.assertTrue(template.is_file())
            template_payload = json.loads(template.read_text(encoding="utf-8"))
            self.assertEqual(template_payload["status"], "template_not_executed")
            self.assertEqual(template_payload["rpc_env_var"], "HERMETIC_RPC_URL")
            rows = {row["row_id"]: row for row in payload["row_readiness"]}
            self.assertIn("missing_source_refs", rows["LTPR-001-edge"]["non_ready_reasons"])
            self.assertIn("missing_topology_evidence", rows["LTPR-001-edge"]["non_ready_reasons"])
            self.assertIn("missing_proof_evidence", rows["LTPR-001-edge"]["non_ready_reasons"])
            self.assertIn("blocker_present", rows["LTPR-001-edge"]["non_ready_reasons"])

    def test_proof_plan_ready_requires_source_topology_proof_and_no_markers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_manual_ready_") as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            source_dir = ws / "contracts"
            source_dir.mkdir(parents=True)
            (source_dir / "HermeticPortal.sol").write_text("contract HermeticPortal {}\n", encoding="utf-8")
            (source_dir / "HermeticBridge.sol").write_text("contract HermeticBridge {}\n", encoding="utf-8")
            aud.mkdir(parents=True)
            (aud / "live_topology_address_resolution_ew.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.live_topology_address_resolution_ew.v1",
                        "requirements": [{"requirement_id": "LTPR-002", "proof_pair_id": "LTPR-002-pair"}],
                        "rows": [
                            {
                                "row_id": "LTPR-002-edge",
                                "contract": "HermeticPortal",
                                "requirement_id": "LTPR-002",
                                "proof_pair_id": "LTPR-002-pair",
                                "network": "hermetic",
                                "status_after_ew": "proof-plan-ready",
                                "source_refs": ["contracts/HermeticPortal.sol:1"],
                                "configured_topology_evidence": {
                                    "deployment": "HermeticPortal is wired to HermeticBridge"
                                },
                                "harness_evidence": {
                                    "command": "forge test --match-test testLiveTopology",
                                    "result": "PASS",
                                },
                            },
                            {
                                "row_id": "LTPR-002-authority",
                                "contract": "HermeticBridge",
                                "requirement_id": "LTPR-002",
                                "proof_pair_id": "LTPR-002-pair",
                                "network": "hermetic",
                                "proof_plan_ready": True,
                                "source_refs": ["contracts/HermeticBridge.sol:1-1"],
                                "deployment_topology_evidence": "deployment_topology.json confirms authority",
                                "proof_evidence": "manual proof transcript PASS at shared block",
                            },
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            proc = self._run_tool(ws)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads((aud / "live_topology_manual_proof_plan_fd.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["after_counts"]["proof_plan_ready_rows"], 2)
            self.assertEqual(payload["after_counts"]["proof_plan_non_ready_rows"], 0)
            self.assertEqual(payload["after_counts"]["proof_plan_ready_pairs"], 1)
            self.assertEqual(payload["proof_plan_ready_row_ids"], ["LTPR-002-edge", "LTPR-002-authority"])
            pair = payload["proof_pairs"][0]
            self.assertTrue(pair["proof_plan_ready"])
            self.assertEqual(pair["row_readiness"][0]["non_ready_reasons"], [])
            self.assertEqual(pair["row_readiness"][1]["non_ready_reasons"], [])
            self.assertEqual(payload["non_ready_reason_counts"], {})

    def test_non_ready_rows_report_typed_reasons(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lt_manual_reasons_") as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            source_dir = ws / "contracts"
            source_dir.mkdir(parents=True)
            (source_dir / "LiveSource.sol").write_text("contract LiveSource {}\n", encoding="utf-8")
            aud.mkdir(parents=True)

            base = {
                "contract": "LiveSource",
                "network": "hermetic",
                "status_after_ew": "proof-plan-ready",
                "source_refs": ["contracts/LiveSource.sol:1"],
                "configured_topology_evidence": "deployment topology captured",
                "proof_evidence": "go test PASS transcript",
            }
            rows = []
            cases = {
                "stale": {"source_refs": ["/tmp/outside/LiveSource.sol:1"]},
                "missing-source": {"source_refs": []},
                "missing-topology": {"configured_topology_evidence": ""},
                "missing-proof": {"proof_evidence": ""},
                "blocked": {"blockers": ["operator_rpc_unavailable"]},
                "advisory": {"advisory_only": True},
            }
            for name, override in cases.items():
                row = dict(base)
                row.update(
                    {
                        "row_id": f"LTPR-003-{name}",
                        "requirement_id": f"LTPR-003-{name}",
                        "proof_pair_id": f"LTPR-003-{name}-pair",
                    }
                )
                row.update(override)
                rows.append(row)

            (aud / "live_topology_address_resolution_ew.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.live_topology_address_resolution_ew.v1",
                        "requirements": [
                            {"requirement_id": row["requirement_id"], "proof_pair_id": row["proof_pair_id"]}
                            for row in rows
                        ],
                        "rows": rows,
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            proc = self._run_tool(ws)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads((aud / "live_topology_manual_proof_plan_fd.json").read_text(encoding="utf-8"))
            by_row = {row["row_id"]: row for row in payload["proof_plan_non_ready_rows"]}
            self.assertIn("stale_source_refs", by_row["LTPR-003-stale"]["non_ready_reasons"])
            self.assertIn("missing_source_refs", by_row["LTPR-003-missing-source"]["non_ready_reasons"])
            self.assertIn("missing_topology_evidence", by_row["LTPR-003-missing-topology"]["non_ready_reasons"])
            self.assertIn("missing_proof_evidence", by_row["LTPR-003-missing-proof"]["non_ready_reasons"])
            self.assertIn("blocker_present", by_row["LTPR-003-blocked"]["non_ready_reasons"])
            self.assertIn("advisory_only", by_row["LTPR-003-advisory"]["non_ready_reasons"])
            self.assertEqual(payload["non_ready_reason_counts"]["stale_source_refs"], 1)
            self.assertEqual(payload["non_ready_reason_counts"]["missing_source_refs"], 1)
            self.assertEqual(payload["non_ready_reason_counts"]["missing_topology_evidence"], 1)
            self.assertEqual(payload["non_ready_reason_counts"]["missing_proof_evidence"], 1)
            self.assertEqual(payload["non_ready_reason_counts"]["blocker_present"], 1)
            self.assertEqual(payload["non_ready_reason_counts"]["advisory_only"], 1)


if __name__ == "__main__":
    unittest.main()
