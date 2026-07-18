from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "impact-proof-source-review-plan.py"


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")


def _strict_manifest(candidate_id: str) -> dict[str, object]:
    return {
        "candidate_id": candidate_id,
        "final_result": "proved",
        "impact_assertion": "exploit_impact",
        "evidence_class": "executed_with_manifest",
        "commands_attempted": [
            {
                "command": "forge test --match-test testImpact",
                "status": "pass",
                "exit_code": 0,
            }
        ],
    }


def _run_tool(ws: Path) -> dict[str, object]:
    proc = subprocess.run(
        [sys.executable, str(TOOL), "--workspace", str(ws)],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(proc.stdout + proc.stderr)
    return json.loads((ws / ".auditooor" / "impact_proof_source_review_plan.json").read_text(encoding="utf-8"))


def _seed_backfill(ws: Path, row: dict[str, object]) -> None:
    _write_json(ws / ".auditooor" / "impact_proof_source_citation_backfill_ex.json", {"rows": [row]})


def _seed_executor(ws: Path, row: dict[str, object]) -> None:
    _write_json(ws / ".auditooor" / "impact_proof_project_evidence_executor_ex.json", {"rows": [row]})


def _seed_strict_manifest(ws: Path, candidate_id: str) -> str:
    rel = f"poc_execution/{candidate_id}/execution_manifest.json"
    _write_json(ws / rel, _strict_manifest(candidate_id))
    return rel


class ImpactProofSourceReviewPlanTests(unittest.TestCase):
    def test_proof_review_ready_requires_current_source_and_concrete_proof(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ipsrp_ready_") as tmp:
            ws = Path(tmp)
            source = ws / "src" / "Vault.sol"
            source.parent.mkdir(parents=True)
            source.write_text("contract Vault { modifier onlyOwner() { _; } }\n", encoding="utf-8")
            candidate = "imo-high-access-control-ready"
            manifest = _seed_strict_manifest(ws, candidate)
            _seed_backfill(
                ws,
                {
                    "candidate_id": candidate,
                    "requirement_id": "IPR-READY",
                    "tier": "High",
                    "route_family": "access_control",
                    "source_refs": ["src/Vault.sol:1"],
                    "semantic_graph_hints": [
                        {
                            "source": "semantic_graph.evidence_edges",
                            "citations": [{"path": "src/Vault.sol", "line": 1}],
                        }
                    ],
                },
            )
            _seed_executor(
                ws,
                {
                    "candidate_id": candidate,
                    "execution_manifest": {"path": manifest},
                    "local_artifacts": {
                        "artifact_refs": [{"artifact": "poc_execution_manifest", "path": manifest, "exists": True}]
                    },
                },
            )

            row = _run_tool(ws)["rows"][0]

        self.assertEqual(row["decision"], "proof_review_ready")
        self.assertTrue(row["proof_review_ready"])
        self.assertEqual(row["proof_review_status"], "ready")
        self.assertEqual(row["proof_review_reasons"], [])
        self.assertEqual(row["current_workspace_source_refs"], ["src/Vault.sol:1"])
        self.assertTrue(row["has_concrete_proof_evidence"])
        self.assertTrue(row["strict_execution_manifest_proved"])
        self.assertEqual(row["terminal_blockers"], [])

    def test_missing_source_refs_blocks_proof_review_even_with_harness(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ipsrp_missing_src_") as tmp:
            ws = Path(tmp)
            source = ws / "src" / "Vault.sol"
            source.parent.mkdir(parents=True)
            source.write_text("contract Vault { modifier onlyOwner() { _; } }\n", encoding="utf-8")
            candidate = "imo-high-access-control-missing-source"
            harness = ws / "poc-tests" / candidate / "run_harness.sh"
            harness.parent.mkdir(parents=True)
            harness.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            _seed_backfill(
                ws,
                {
                    "candidate_id": candidate,
                    "requirement_id": "IPR-MISSING-SOURCE",
                    "tier": "High",
                    "route_family": "access_control",
                },
            )
            _seed_executor(
                ws,
                {
                    "candidate_id": candidate,
                    "local_artifacts": {
                        "artifact_refs": [
                            {"artifact": "replay_harness", "path": f"poc-tests/{candidate}/run_harness.sh", "exists": True}
                        ]
                    },
                },
            )

            row = _run_tool(ws)["rows"][0]

        self.assertEqual(row["decision"], "source_review_ready_from_family_grep_candidates")
        self.assertFalse(row["proof_review_ready"])
        self.assertIn("missing_current_workspace_source_refs", row["proof_review_reasons"])
        self.assertIn("missing_current_workspace_source_refs", row["terminal_blockers"])
        self.assertEqual(row["current_workspace_source_refs"], [])
        self.assertTrue(row["has_concrete_proof_evidence"])

    def test_stale_workspace_source_ref_stays_visible(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ipsrp_stale_src_") as tmp:
            ws = Path(tmp)
            candidate = "imo-high-access-control-stale-source"
            manifest = _seed_strict_manifest(ws, candidate)
            _seed_backfill(
                ws,
                {
                    "candidate_id": candidate,
                    "requirement_id": "IPR-STALE-SOURCE",
                    "tier": "High",
                    "route_family": "access_control",
                    "source_refs": ["src/Missing.sol:1"],
                },
            )
            _seed_executor(
                ws,
                {
                    "candidate_id": candidate,
                    "execution_manifest": {"path": manifest},
                    "local_artifacts": {
                        "artifact_refs": [{"artifact": "poc_execution_manifest", "path": manifest, "exists": True}]
                    },
                },
            )

            row = _run_tool(ws)["rows"][0]

        self.assertFalse(row["proof_review_ready"])
        self.assertIn("stale_workspace_source_ref", row["proof_review_reasons"])
        self.assertIn("stale_workspace_source_ref", row["terminal_blockers"])
        self.assertEqual(row["stale_workspace_source_refs"], ["src/Missing.sol:1"])

    def test_missing_proof_evidence_blocks_current_source_ref(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ipsrp_missing_proof_") as tmp:
            ws = Path(tmp)
            source = ws / "src" / "Vault.sol"
            source.parent.mkdir(parents=True)
            source.write_text("contract Vault { modifier onlyOwner() { _; } }\n", encoding="utf-8")
            candidate = "imo-high-access-control-missing-proof"
            _seed_backfill(
                ws,
                {
                    "candidate_id": candidate,
                    "requirement_id": "IPR-MISSING-PROOF",
                    "tier": "High",
                    "route_family": "access_control",
                    "source_refs": ["src/Vault.sol:1"],
                    "semantic_graph_hints": [
                        {
                            "source": "semantic_graph.evidence_edges",
                            "citations": [{"path": "src/Vault.sol", "line": 1}],
                        }
                    ],
                },
            )
            _seed_executor(ws, {"candidate_id": candidate})

            row = _run_tool(ws)["rows"][0]

        self.assertFalse(row["proof_review_ready"])
        self.assertIn("missing_concrete_proof_evidence", row["proof_review_reasons"])
        self.assertIn("missing_concrete_proof_evidence", row["terminal_blockers"])
        self.assertEqual(row["current_workspace_source_refs"], ["src/Vault.sol:1"])
        self.assertFalse(row["has_concrete_proof_evidence"])

    def test_blocker_and_advisory_markers_propagate_as_typed_reasons(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ipsrp_blocker_") as tmp:
            ws = Path(tmp)
            source = ws / "src" / "Vault.sol"
            source.parent.mkdir(parents=True)
            source.write_text("contract Vault { modifier onlyOwner() { _; } }\n", encoding="utf-8")
            candidate = "imo-high-access-control-blocked"
            manifest = _seed_strict_manifest(ws, candidate)
            _seed_backfill(
                ws,
                {
                    "candidate_id": candidate,
                    "requirement_id": "IPR-BLOCKED",
                    "tier": "High",
                    "route_family": "access_control",
                    "source_refs": ["src/Vault.sol:1"],
                },
            )
            _seed_executor(
                ws,
                {
                    "candidate_id": candidate,
                    "execution_manifest": {"path": manifest},
                    "advisory_only": True,
                    "terminal_blockers": ["manual_review_required"],
                    "local_artifacts": {
                        "artifact_refs": [{"artifact": "poc_execution_manifest", "path": manifest, "exists": True}]
                    },
                },
            )

            row = _run_tool(ws)["rows"][0]

        self.assertFalse(row["proof_review_ready"])
        self.assertIn("blocker_or_advisory_marker_present", row["proof_review_reasons"])
        self.assertIn("manual_review_required", row["blocker_advisory_markers"])
        self.assertIn("advisory_only_requirement", row["blocker_advisory_markers"])
        self.assertIn("manual_review_required", row["terminal_blockers"])
        self.assertIn("blocker_or_advisory_marker_present", row["terminal_blockers"])

    def test_routes_project_semantic_hint_to_review_command_without_promoting(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ipsrp_hint_") as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            source = ws / "src" / "Vault.sol"
            source.parent.mkdir(parents=True)
            source.write_text("contract Vault { modifier onlyOwner() { _; } }\n", encoding="utf-8")
            (aud / "impact_proof_source_citation_backfill_ex.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "candidate_id": "imo-high-access-control-01",
                                "requirement_id": "IPR-001",
                                "tier": "High",
                                "route_family": "access_control",
                                "terminal_blockers": ["source_proof_missing_project_source_citation"],
                                "semantic_graph_hints": [
                                    {
                                        "source": "semantic_graph.evidence_edges",
                                        "citations": [
                                            {
                                                "path": "src/Vault.sol",
                                                "line": 1,
                                                "stage": "authorization",
                                                "evidence": "onlyOwner",
                                            }
                                        ],
                                    }
                                ],
                            }
                        ]
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (aud / "impact_proof_project_evidence_executor_ex.json").write_text(
                json.dumps({"rows": [{"candidate_id": "imo-high-access-control-01", "terminal_blockers": []}]})
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
            payload = json.loads((aud / "impact_proof_source_review_plan.json").read_text(encoding="utf-8"))
            row = payload["rows"][0]
            self.assertEqual(row["decision"], "source_review_ready_from_project_semantic_hint")
            self.assertFalse(row["promotion_allowed"])
            self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")
            self.assertIn("src/Vault.sol:1", row["next_local_commands"][2])

    def test_fixture_only_hint_is_terminal_without_project_source(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ipsrp_fixture_") as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            fixture = ws / "patterns" / "fixtures" / "auto" / "Finding.sol"
            fixture.parent.mkdir(parents=True)
            fixture.write_text("contract Finding {}\n", encoding="utf-8")
            (aud / "impact_proof_source_citation_backfill_ex.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "candidate_id": "imo-critical-oracle-settlement-01",
                                "requirement_id": "IPR-001",
                                "tier": "Critical",
                                "route_family": "oracle_settlement",
                                "terminal_blockers": [],
                                "semantic_graph_hints": [
                                    {
                                        "source": "semantic_graph.evidence_edges",
                                        "citations": [
                                            {
                                                "path": "patterns/fixtures/auto/Finding.sol",
                                                "line": 1,
                                                "stage": "oracle",
                                                "evidence": "oracle",
                                            }
                                        ],
                                    }
                                ],
                            }
                        ]
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (aud / "impact_proof_project_evidence_executor_ex.json").write_text(json.dumps({"rows": []}) + "\n", encoding="utf-8")

            proc = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws)],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads((aud / "impact_proof_source_review_plan.json").read_text(encoding="utf-8"))
            row = payload["rows"][0]
            self.assertEqual(row["decision"], "terminal_semantic_hints_not_project_source")
            self.assertIn("semantic_hints_are_fixture_or_generated_only", row["terminal_blockers"])
            self.assertEqual(row["review_candidates"], [])

    def test_family_scan_candidates_make_review_ready(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ipsrp_scan_") as tmp:
            ws = Path(tmp)
            aud = ws / ".auditooor"
            aud.mkdir(parents=True)
            source = ws / "projects" / "demo" / "contracts" / "Gov.sol"
            source.parent.mkdir(parents=True)
            source.write_text("contract Gov { function vote(uint proposal) external {} }\n", encoding="utf-8")
            (aud / "impact_proof_source_citation_backfill_ex.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "candidate_id": "imo-medium-governance-integrity-01",
                                "requirement_id": "IPR-001",
                                "tier": "Medium",
                                "route_family": "governance_integrity",
                                "terminal_blockers": [],
                                "semantic_graph_hints": [],
                            }
                        ]
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (aud / "impact_proof_project_evidence_executor_ex.json").write_text(json.dumps({"rows": []}) + "\n", encoding="utf-8")

            proc = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws)],
                cwd=ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads((aud / "impact_proof_source_review_plan.json").read_text(encoding="utf-8"))
            row = payload["rows"][0]
            self.assertEqual(row["decision"], "source_review_ready_from_family_grep_candidates")
            self.assertIn("candidate_binding_required_before_source_proof_record", row["terminal_blockers"])
            self.assertEqual(row["review_candidates"][0]["raw"], "projects/demo/contracts/Gov.sol:1")


if __name__ == "__main__":
    unittest.main()
