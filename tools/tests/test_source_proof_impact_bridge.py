from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "source-proof-impact-bridge.py"


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_bridge(ws: Path, *, min_items: int = 1, max_items: int = 20) -> dict:
    proc = subprocess.run(
        [
            sys.executable,
            str(TOOL),
            "--workspace",
            str(ws),
            "--min-items",
            str(min_items),
            "--max-items",
            str(max_items),
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    self_msg = proc.stdout + proc.stderr
    if proc.returncode not in (0, 2):
        raise AssertionError(self_msg)
    return json.loads((ws / ".auditooor" / "source_proof_impact_bridge.json").read_text(encoding="utf-8"))


class SourceProofImpactBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="spic_")
        self.addCleanup(self.tmp.cleanup)
        self.ws = Path(self.tmp.name)
        (self.ws / ".auditooor").mkdir(parents=True)
        self._write_source_file()

    def _write_source_file(self) -> None:
        path = self.ws / "src" / "Bridge.sol"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "\n".join(
                [
                    "pragma solidity ^0.8.20;",
                    "contract Bridge {",
                    "    function finalize(bytes calldata proof) external {}",
                    "}",
                ]
            )
            + "\n",
            encoding="utf-8",
        )

    def _write_contract(
        self,
        candidate: str = "C-BRIDGE",
        *,
        listed: bool = True,
        terminal_blockers: list[str] | None = None,
        advisory_only: bool = False,
    ) -> None:
        write_json(
            self.ws / ".auditooor" / "impact_contracts.json",
            {
                "contracts": [
                    {
                        "candidate_id": candidate,
                        "impact_contract_id": f"impact-{candidate}",
                        "route_family": "bridge",
                        "tier": "High",
                        "selected_impact": "Bridge state transition releases funds",
                        "exact_impact_row": True,
                        "listed_impact_proven": listed,
                        "terminal_blockers": terminal_blockers or [],
                        "advisory_only": advisory_only,
                    }
                ]
            },
        )

    def _write_impact_artifact(self, candidate: str = "C-BRIDGE") -> str:
        path = self.ws / ".auditooor" / "proofs" / f"{candidate}.json"
        write_json(
            path,
            {
                "candidate_id": candidate,
                "before_after_assertions": True,
                "state_transition": {
                    "before": "custody_balance=10",
                    "after": "custody_balance=0",
                },
            },
        )
        return str(path.relative_to(self.ws))

    def _write_execution_manifest(self, candidate: str = "C-BRIDGE") -> str:
        path = self.ws / "poc_execution" / candidate / "execution_manifest.json"
        write_json(
            path,
            {
                "candidate_id": candidate,
                "evidence_class": "executed_with_manifest",
                "final_result": "proved",
                "impact_assertion": "exploit_impact",
                "commands_attempted": [
                    {
                        "command": "forge test --match-test testBridgeImpact -vv",
                        "status": "pass",
                        "exit_code": 0,
                    }
                ],
            },
        )
        return str(path.relative_to(self.ws))

    def _write_source_proof(
        self,
        candidate: str = "C-BRIDGE",
        *,
        source_refs: list | None = None,
        impact_artifacts: list | None = None,
        impact_linked: bool = True,
        advisory_only: bool = False,
        workspace: str | None = None,
        final_verdict: str = "proved_source_only",
        blockers: list[str] | None = None,
    ) -> None:
        proof_dir = self.ws / "source_proofs" / f"{candidate}-source-proof"
        write_json(
            proof_dir / "source_proof.json",
            {
                "schema_version": "auditooor.source_proof.v1",
                "candidate_id": f"{candidate}-source-proof",
                "workspace": workspace if workspace is not None else str(self.ws.resolve()),
                "final_verdict": final_verdict,
                "valid_source_citation_count": 1,
                "impact_contract_linked": impact_linked,
                "oos_status": "in_scope",
                "advisory_only": advisory_only,
                "blockers": blockers or [],
                "source_citations": source_refs
                if source_refs is not None
                else [{"path": "src/Bridge.sol", "start_line": 2, "end_line": 3}],
                "impact_proof_artifacts": impact_artifacts if impact_artifacts is not None else [self._write_impact_artifact(candidate)],
            },
        )

    def _single_row(self) -> dict:
        payload = run_bridge(self.ws)
        self.assertEqual(payload["summary"]["row_count"], 1)
        return payload["rows"][0]

    def test_proof_linked_pass_requires_resolved_source_and_concrete_impact_artifact(self) -> None:
        self._write_contract()
        self._write_source_proof()

        row = self._single_row()

        self.assertEqual(row["status"], "attached_exact_contract_with_proof_linked_impact")
        self.assertEqual(row["proof_linkage"], "proof_linked_impact")
        self.assertTrue(row["proof_linked_impact"])
        self.assertEqual(row["non_proof_reasons"], [])
        self.assertTrue(row["concrete_impact_artifact_paths"])
        self.assertEqual(row["source_proof_evaluations"][0]["source_ref_resolution"][0]["status"], "resolved")

    def test_proved_execution_manifest_counts_as_concrete_harness_evidence(self) -> None:
        self._write_contract()
        self._write_source_proof(
            impact_artifacts=[self._write_execution_manifest()],
            final_verdict="proved_executed_poc",
        )

        row = self._single_row()

        self.assertEqual(row["status"], "attached_exact_contract_with_proof_linked_impact")
        self.assertTrue(row["proof_linked_impact"])
        self.assertEqual(
            row["source_proof_evaluations"][0]["impact_artifact_resolution"][0]["impact_evidence_kind"],
            "strict_execution_manifest",
        )

    def test_missing_source_refs_remain_visible_as_non_proof_reason(self) -> None:
        self._write_contract()
        self._write_source_proof(source_refs=[])

        row = self._single_row()

        self.assertEqual(row["status"], "attached_exact_contract_with_non_proof_source_record")
        self.assertFalse(row["proof_linked_impact"])
        self.assertIn("missing_source_refs", row["non_proof_reasons"])
        self.assertIn("source_proof_missing_source_refs", row["terminal_blockers"])

    def test_stale_workspace_source_refs_remain_visible_as_non_proof_reason(self) -> None:
        self._write_contract()
        other = Path(tempfile.mkdtemp(prefix="spic_stale_"))
        self.addCleanup(shutil.rmtree, other, ignore_errors=True)
        stale_source = other / "src" / "Bridge.sol"
        stale_source.parent.mkdir(parents=True)
        stale_source.write_text("contract Bridge {}\n", encoding="utf-8")
        self._write_source_proof(
            source_refs=[{"path": str(stale_source), "start_line": 1, "end_line": 1}],
            workspace=str(other.resolve()),
        )

        row = self._single_row()

        self.assertEqual(row["status"], "attached_exact_contract_with_non_proof_source_record")
        self.assertFalse(row["proof_linked_impact"])
        self.assertIn("stale_workspace_source_refs", row["non_proof_reasons"])
        self.assertIn("stale_source", row["non_proof_reasons"])
        self.assertEqual(
            row["source_proof_evaluations"][0]["source_ref_resolution"][0]["status"],
            "stale_workspace_source_ref",
        )

    def test_advisory_only_source_proof_remains_visible_as_non_proof_reason(self) -> None:
        self._write_contract()
        self._write_source_proof(advisory_only=True)

        row = self._single_row()

        self.assertEqual(row["status"], "attached_exact_contract_with_non_proof_source_record")
        self.assertFalse(row["proof_linked_impact"])
        self.assertIn("advisory_only_source_proof", row["non_proof_reasons"])
        self.assertIn("advisory_only", row["non_proof_reasons"])

    def test_source_proof_blocker_marker_blocks_bridge_ready_row(self) -> None:
        self._write_contract()
        self._write_source_proof(blockers=["human_review_required"])

        row = self._single_row()

        self.assertEqual(row["status"], "attached_exact_contract_with_non_proof_source_record")
        self.assertFalse(row["proof_linked_impact"])
        self.assertIn("blocker_present", row["non_proof_reasons"])
        self.assertIn("human_review_required", row["terminal_blockers"])
        self.assertIn("source_proof_blocker_present", row["terminal_blockers"])

    def test_contract_blocker_marker_blocks_bridge_ready_row(self) -> None:
        self._write_contract(terminal_blockers=["scope_review_required"])
        self._write_source_proof()

        row = self._single_row()

        self.assertEqual(row["status"], "attached_exact_contract_with_non_proof_source_record")
        self.assertFalse(row["proof_linked_impact"])
        self.assertIn("blocker_present", row["non_proof_reasons"])
        self.assertIn("scope_review_required", row["terminal_blockers"])

    def test_contract_advisory_marker_blocks_bridge_ready_row(self) -> None:
        self._write_contract(advisory_only=True)
        self._write_source_proof()

        row = self._single_row()

        self.assertEqual(row["status"], "attached_exact_contract_with_non_proof_source_record")
        self.assertFalse(row["proof_linked_impact"])
        self.assertIn("advisory_only", row["non_proof_reasons"])
        self.assertIn("advisory_only_marker", row["terminal_blockers"])

    def test_no_impact_linkage_remains_visible_as_non_proof_reason(self) -> None:
        self._write_contract()
        self._write_source_proof(impact_linked=False)

        row = self._single_row()

        self.assertEqual(row["status"], "attached_exact_contract_with_non_proof_source_record")
        self.assertFalse(row["proof_linked_impact"])
        self.assertIn("no_impact_linkage", row["non_proof_reasons"])
        self.assertIn("source_proof_not_linked_to_impact_contract", row["terminal_blockers"])

    def test_missing_concrete_impact_artifact_blocks_proof_linkage(self) -> None:
        self._write_contract()
        self._write_source_proof(impact_artifacts=[])

        row = self._single_row()

        self.assertEqual(row["status"], "attached_exact_contract_with_non_proof_source_record")
        self.assertFalse(row["proof_linked_impact"])
        self.assertIn("missing_concrete_impact_artifact", row["non_proof_reasons"])
        self.assertIn("missing_proof_evidence", row["non_proof_reasons"])

    def test_unmatched_source_proof_keeps_typed_non_proof_reasons(self) -> None:
        self._write_contract("OTHER")
        self._write_source_proof("C-BRIDGE", impact_linked=False, impact_artifacts=[])

        payload = run_bridge(self.ws)
        by_candidate = {row["candidate_id"]: row for row in payload["rows"]}
        row = by_candidate["C-BRIDGE-source-proof"]

        self.assertEqual(row["row_type"], "source_proof_terminal_blocker")
        self.assertFalse(row["proof_linked_impact"])
        self.assertIn("no_impact_linkage", row["non_proof_reasons"])
        self.assertIn("missing_concrete_impact_artifact", row["non_proof_reasons"])
        self.assertIn("missing_proof_evidence", row["non_proof_reasons"])

    def test_item_target_miss_is_hard_blocker(self) -> None:
        write_json(self.ws / ".auditooor" / "impact_contracts.json", {"contracts": []})

        payload = run_bridge(self.ws, min_items=300, max_items=500)

        self.assertEqual(payload["status"], "hard_blocker_item_target_out_of_range")


if __name__ == "__main__":
    unittest.main()
