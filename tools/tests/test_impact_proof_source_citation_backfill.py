from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "impact-proof-source-citation-backfill.py"


class ImpactProofSourceCitationBackfillTests(unittest.TestCase):
    def test_records_advisory_hint_without_promoting_missing_citation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ipscb_") as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            proof = ws / "source_proofs" / "imo-high-access-control-01-source-proof" / "source_proof.json"
            proof.parent.mkdir(parents=True)
            proof.write_text(
                json.dumps(
                    {
                        "candidate_id": "imo-high-access-control-01",
                        "final_verdict": "blocked_missing_project_source_citation",
                        "impact_contract_linked": True,
                        "valid_source_citation_count": 0,
                        "source_citations": [],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (aud / "impact_proof_requirement_execution.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "candidate_id": "imo-high-access-control-01",
                                "requirement_id": "IPR-001",
                                "tier": "High",
                                "route_family": "access_control",
                                "exact_impact_row": True,
                                "listed_impact_proven": False,
                                "decision": "terminal_blocker_source_proof_incomplete",
                                "terminal_blockers": ["source_proof_missing_project_source_citation"],
                                "source_proofs": [{"path": str(proof)}],
                            }
                        ]
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (aud / "semantic_graph.scoped.json").write_text(
                json.dumps(
                    {
                        "multi_hop_paths": [
                            {
                                "path_id": "SG-1",
                                "impact_family": "access_control",
                                "source_component": "Vault.withdraw",
                                "evidence_edges": [
                                    {
                                        "file": "src/Vault.sol",
                                        "line": 42,
                                        "stage": "authorization",
                                        "evidence": "onlyRole(WITHDRAWER)",
                                    }
                                ],
                            }
                        ]
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            proc = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws)],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads((aud / "impact_proof_source_citation_backfill.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["processed_target_rows"], 1)
            self.assertEqual(payload["summary"]["closure_candidate_count"], 0)
            row = payload["rows"][0]
            self.assertEqual(row["decision"], "terminal_source_citation_missing_with_advisory_hints")
            self.assertFalse(row["promotion_allowed"])
            self.assertTrue(row["semantic_graph_hints"])
            self.assertIn("semantic_graph_hints_advisory_not_exact_source_proof", row["terminal_blockers"])
            self.assertTrue(Path(row["resolution_manifest_path"]).is_file())

    def test_project_source_citation_is_backfilled_but_impact_stays_blocked(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ipscb_cited_") as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            source = ws / "src" / "Vault.sol"
            source.parent.mkdir(parents=True)
            source.write_text("contract Vault { function withdraw() external {} }\n", encoding="utf-8")
            proof = ws / "source_proofs" / "imo-low-asset-custody-01-source-proof" / "source_proof.json"
            proof.parent.mkdir(parents=True)
            proof.write_text(
                json.dumps(
                    {
                        "candidate_id": "imo-low-asset-custody-01",
                        "final_verdict": "proved_source_only",
                        "impact_contract_linked": True,
                        "valid_source_citation_count": 1,
                        "source_citations": [
                            {
                                "path": "src/Vault.sol",
                                "start_line": 1,
                                "end_line": 1,
                                "exists": True,
                                "valid_lines": True,
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (aud / "impact_proof_requirement_execution.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "candidate_id": "imo-low-asset-custody-01",
                                "requirement_id": "IPR-001",
                                "tier": "Low",
                                "route_family": "asset_custody",
                                "exact_impact_row": True,
                                "listed_impact_proven": False,
                                "decision": "terminal_blocker_source_proof_incomplete",
                                "terminal_blockers": ["listed_impact_not_proven"],
                                "source_proofs": [{"path": str(proof)}],
                            }
                        ]
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            proc = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws)],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads((aud / "impact_proof_source_citation_backfill.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["closure_candidate_count"], 1)
            row = payload["rows"][0]
            self.assertEqual(row["decision"], "source_citation_backfilled_impact_unproved")
            self.assertIn("source_citation_present_but_listed_impact_unproved", row["terminal_blockers"])
            self.assertEqual(row["source_proofs"][0]["project_source_citation_count"], 1)
            self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")


if __name__ == "__main__":
    unittest.main()
