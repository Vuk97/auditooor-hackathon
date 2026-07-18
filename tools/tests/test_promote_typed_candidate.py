#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "promote-typed-candidate.py"


def _candidate(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "schema_version": "deep_candidate.v1",
        "lane": "math",
        "candidate_id": "cand-1",
        "files": ["src/Vault.sol"],
        "claim": "Vault.deposit rounds shares against the first depositor.",
        "trigger": "Empty vault receives a small donation before the first deposit.",
        "impact": "A depositor can receive fewer shares than expected.",
        "reproduction": "forge test --match-test test_FirstDeposit -vv",
        "confidence": "low",
        "blocking_questions": ["needs replay"],
        "promotion_status": "investigate",
    }
    base.update(overrides)
    return base


class PromoteTypedCandidateTest(unittest.TestCase):
    def _run(
        self,
        ws: Path,
        *paths: Path,
        require_line_cite: bool = False,
        require_production_path: bool = False,
    ) -> dict[str, Any]:
        extra = ["--require-line-cite"] if require_line_cite else []
        if require_production_path:
            extra.append("--require-production-path")
        proc = subprocess.run(
            [sys.executable, str(TOOL), "--workspace", str(ws), *extra, *map(str, paths)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)

    def test_high_confidence_poc_ready_with_present_file_promotes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
            path = ws / "deep_candidates" / "cand.json"
            path.parent.mkdir()
            path.write_text(
                json.dumps(
                    _candidate(
                        confidence="high",
                        promotion_status="poc_ready",
                        blocking_questions=[],
                    )
                ),
                encoding="utf-8",
            )
            payload = self._run(ws, path)
            self.assertEqual(payload["schema_version"], "auditooor.promote_typed_candidate.v1")
            self.assertEqual(payload["decision_counts"]["poc_ready"], 1)
            self.assertEqual(payload["blocker_counts"], {})
            self.assertEqual(payload["work_items"], [])
            self.assertEqual(payload["verdicts"][0]["decision"], "poc_ready")
            self.assertEqual(payload["verdicts"][0]["blocker_categories"], [])
            self.assertTrue(payload["verdicts"][0]["checks"]["reproduction_looks_runnable"])

    def test_investigate_candidate_needs_poc(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
            path = ws / "deep_candidates" / "cand.json"
            path.parent.mkdir()
            path.write_text(json.dumps(_candidate()), encoding="utf-8")
            payload = self._run(ws, path)
            self.assertEqual(payload["decision_counts"]["needs_poc"], 1)
            self.assertIn("promotion_status", payload["verdicts"][0]["reasons"][0])

    def test_missing_source_file_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            path = ws / "cand.json"
            path.write_text(json.dumps(_candidate()), encoding="utf-8")
            payload = self._run(ws, path)
            verdict = payload["verdicts"][0]
            self.assertEqual(verdict["decision"], "rejected")
            self.assertEqual(verdict["missing_files"], ["src/Vault.sol"])

    def test_line_suffixed_file_citation_counts_as_existing_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
            path = ws / "cand.json"
            path.write_text(
                json.dumps(
                    _candidate(
                        files=["src/Vault.sol:12-20"],
                        confidence="high",
                        promotion_status="poc_ready",
                        blocking_questions=[],
                    )
                ),
                encoding="utf-8",
            )
            payload = self._run(ws, path, require_line_cite=True)
            verdict = payload["verdicts"][0]
            self.assertEqual(verdict["decision"], "poc_ready")
            self.assertEqual(verdict["missing_files"], [])

    def test_require_production_path_missing_stays_needs_poc(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
            path = ws / "cand.json"
            path.write_text(
                json.dumps(
                    _candidate(
                        confidence="high",
                        promotion_status="poc_ready",
                        blocking_questions=[],
                    )
                ),
                encoding="utf-8",
            )
            payload = self._run(ws, path, require_production_path=True)
            verdict = payload["verdicts"][0]
            self.assertEqual(verdict["decision"], "needs_poc")
            self.assertEqual(verdict["checks"]["production_path_verdict"], "")
            self.assertEqual(payload["blocker_counts"]["production_path_missing"], 1)
            self.assertEqual(payload["work_items"][0]["blocker_categories"], ["production_path_missing"])
            self.assertTrue(payload["work_items"][0]["next_actions"])
            self.assertTrue(any("production path not proven" in reason for reason in verdict["reasons"]))

    def test_task_outputs_are_written_for_needs_poc(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
            path = ws / "cand.json"
            path.write_text(
                json.dumps(
                    _candidate(
                        confidence="high",
                        promotion_status="poc_ready",
                        blocking_questions=[],
                    )
                ),
                encoding="utf-8",
            )
            tasks_json = ws / "tasks.json"
            tasks_md = ws / "tasks.md"
            brief_dir = ws / "briefs"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--require-production-path",
                    "--out-tasks-json",
                    str(tasks_json),
                    "--out-tasks-md",
                    str(tasks_md),
                    "--out-brief-dir",
                    str(brief_dir),
                    str(path),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            tasks = json.loads(tasks_json.read_text(encoding="utf-8"))
            self.assertEqual(tasks[0]["candidate_id"], "cand-1")
            self.assertIn("production_path_missing", tasks[0]["blocker_categories"])
            self.assertIn("Candidate PoC Task Queue", tasks_md.read_text(encoding="utf-8"))
            briefs = sorted(brief_dir.glob("*.md"))
            self.assertEqual(len(briefs), 1)
            brief_text = briefs[0].read_text(encoding="utf-8")
            self.assertIn("PoC Dispatch Brief", brief_text)
            self.assertIn("Claude:", brief_text)
            self.assertIn("Kimi:", brief_text)
            self.assertIn("Minimax:", brief_text)
            self.assertIn("UNSAFE_TO_SUBMIT", brief_text)

    def test_require_production_path_proven_allows_poc_ready(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
            path = ws / "cand.json"
            path.write_text(
                json.dumps(
                    _candidate(
                        confidence="high",
                        promotion_status="poc_ready",
                        blocking_questions=[],
                        lane_payload={"production_path": {"verdict": "PROVEN"}},
                    )
                ),
                encoding="utf-8",
            )
            payload = self._run(ws, path, require_production_path=True)
            verdict = payload["verdicts"][0]
            self.assertEqual(verdict["decision"], "poc_ready")
            self.assertEqual(verdict["checks"]["production_path_verdict"], "PROVEN")

    def test_workspace_impact_contract_summary_unlocks_direct_submit_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
            (ws / "SEVERITY.md").write_text(
                "# Test Severity\n\n"
                "## High-tier listed impacts\n"
                "- Temporary freezing of user funds (recoverable within a finalization window)\n",
                encoding="utf-8",
            )
            (ws / ".auditooor").mkdir()
            (ws / ".auditooor" / "impact_contracts.json").write_text(
                json.dumps(
                    {
                        "contracts": [
                            {
                                "impact_contract_id": "impact-contract-cand-1",
                                "candidate_id": "cand-1",
                                "selected_impact": (
                                    "Temporary freezing of user funds "
                                    "(recoverable within a finalization window)"
                                ),
                                "severity_tier": "High",
                                "listed_impact_proven": True,
                                "evidence_class": "executed_with_manifest",
                                "oos_traps": ["admin-only path"],
                                "stop_condition": "Stop if the replay does not freeze funds.",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            path = ws / "cand.json"
            path.write_text(
                json.dumps(
                    _candidate(
                        confidence="high",
                        promotion_status="poc_ready",
                        blocking_questions=[],
                        claim="direct submit candidate after local verification",
                    )
                ),
                encoding="utf-8",
            )
            payload = self._run(ws, path)
            verdict = payload["verdicts"][0]
            self.assertEqual(verdict["decision"], "poc_ready")
            self.assertEqual(verdict["checks"]["impact_contract_status"], "missing_mapping")

    def test_require_production_path_plain_source_only_prose_does_not_promote(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
            path = ws / "cand.json"
            path.write_text(
                json.dumps(
                    _candidate(
                        confidence="high",
                        promotion_status="poc_ready",
                        blocking_questions=[],
                        trigger="This is a pre-deployment source-only issue with no live deployment.",
                    )
                ),
                encoding="utf-8",
            )
            payload = self._run(ws, path, require_production_path=True)
            verdict = payload["verdicts"][0]
            self.assertEqual(verdict["decision"], "needs_poc")
            self.assertIn("production_path_missing", verdict["blocker_categories"])

    def test_require_production_path_structured_source_only_allows_poc_ready(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
            path = ws / "cand.json"
            path.write_text(
                json.dumps(
                    _candidate(
                        confidence="high",
                        promotion_status="poc_ready",
                        blocking_questions=[],
                        trigger="Pre-deployment source-only issue; no live deployment exists.",
                        lane_payload={"production_path_verdict": "PRE_DEPLOYMENT_SOURCE_ONLY"},
                    )
                ),
                encoding="utf-8",
            )
            payload = self._run(ws, path, require_production_path=True)
            verdict = payload["verdicts"][0]
            self.assertEqual(verdict["decision"], "poc_ready")

    def test_source_mine_candidate_needs_source_or_replay_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
            path = ws / "cand.json"
            path.write_text(
                json.dumps(
                    _candidate(
                        lane="source_mine",
                        files=["src/Vault.sol:12-20"],
                        confidence="high",
                        promotion_status="poc_ready",
                        blocking_questions=[],
                        trigger="Pre-deployment source-only issue; no live deployment exists.",
                        lane_payload={"production_path_verdict": "PRE_DEPLOYMENT_SOURCE_ONLY"},
                    )
                ),
                encoding="utf-8",
            )
            payload = self._run(ws, path, require_line_cite=True, require_production_path=True)
            verdict = payload["verdicts"][0]
            self.assertEqual(verdict["decision"], "needs_poc")
            self.assertIn("source_or_replay_evidence_missing", verdict["blocker_categories"])
            proof = verdict["checks"]["proof_evidence"]
            self.assertFalse(proof["source_proof_ok"])
            self.assertFalse(proof["execution_manifest_ok"])

    def test_source_mine_candidate_with_proved_source_proof_can_be_poc_ready(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
            proof_dir = ws / "source_proofs" / "cand-1"
            proof_dir.mkdir(parents=True)
            (proof_dir / "source_proof.json").write_text(
                json.dumps(
                    {
                        "schema_version": "auditooor.source_proof.v1",
                        "candidate_id": "cand-1",
                        "impact_contract_linked": True,
                        "valid_source_citation_count": 1,
                        "oos_status": "in_scope",
                        "final_verdict": "proved_source_only",
                        "evidence_class": "human_verified",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            path = ws / "cand.json"
            path.write_text(
                json.dumps(
                    _candidate(
                        lane="source_mine",
                        files=["src/Vault.sol:12-20"],
                        confidence="high",
                        promotion_status="poc_ready",
                        blocking_questions=[],
                        trigger="Pre-deployment source-only issue; no live deployment exists.",
                        lane_payload={"production_path_verdict": "PRE_DEPLOYMENT_SOURCE_ONLY"},
                    )
                ),
                encoding="utf-8",
            )
            payload = self._run(ws, path, require_line_cite=True, require_production_path=True)
            verdict = payload["verdicts"][0]
            self.assertEqual(verdict["decision"], "poc_ready")
            proof = verdict["checks"]["proof_evidence"]
            self.assertTrue(proof["source_proof_ok"])
            self.assertEqual(verdict["checks"]["production_path_verdict"], "PRE_DEPLOYMENT_SOURCE_ONLY")

    def test_require_production_path_contradicted_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
            path = ws / "cand.json"
            path.write_text(
                json.dumps(
                    _candidate(
                        confidence="high",
                        promotion_status="poc_ready",
                        blocking_questions=[],
                        lane_payload={"production_path_verdict": "CONTRADICTED"},
                    )
                ),
                encoding="utf-8",
            )
            payload = self._run(ws, path, require_production_path=True)
            verdict = payload["verdicts"][0]
            self.assertEqual(verdict["decision"], "rejected")
            self.assertIn("external_actor_path_contradicted", verdict["blocker_categories"])
            self.assertIn("production_path_contradicted", verdict["blocker_categories"])
            self.assertEqual(payload["blocker_counts"]["production_path_contradicted"], 1)
            self.assertTrue(any("CONTRADICTED" in reason for reason in verdict["reasons"]))

    def test_require_production_path_privileged_dossier_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "Game.sol").write_text(
                "contract Game { function resolve() external {} }\n",
                encoding="utf-8",
            )
            path = ws / "cand.json"
            path.write_text(
                json.dumps(
                    _candidate(
                        files=["src/Game.sol:1"],
                        claim="resolve takes the parent-loss branch.",
                        trigger="G0 reaches CHALLENGER_WINS via guardian blacklistDisputeGame.",
                        impact="Challenge-system bond reward is misrouted.",
                        confidence="high",
                        promotion_status="poc_ready",
                        blocking_questions=[],
                    )
                ),
                encoding="utf-8",
            )
            payload = self._run(ws, path, require_production_path=True)
            verdict = payload["verdicts"][0]
            self.assertEqual(verdict["decision"], "rejected")
            self.assertIn("external_actor_path_privileged_only", verdict["blocker_categories"])
            self.assertEqual(
                verdict["checks"]["production_path_dossier"]["submit_verdict"],
                "unsafe_to_submit",
            )

    def test_source_mine_without_line_citation_stays_needs_poc(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
            path = ws / "cand.json"
            path.write_text(
                json.dumps(
                    _candidate(
                        lane="source_mine",
                        confidence="high",
                        promotion_status="poc_ready",
                        blocking_questions=[],
                        lane_payload={"snippet": "deposit rounds shares"},
                    )
                ),
                encoding="utf-8",
            )
            payload = self._run(ws, path)
            verdict = payload["verdicts"][0]
            self.assertEqual(verdict["decision"], "needs_poc")
            self.assertFalse(verdict["has_line_citation"])
            self.assertTrue(any("line citation" in reason for reason in verdict["reasons"]))

    def test_require_line_cite_rejects_when_absent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
            path = ws / "cand.json"
            path.write_text(
                json.dumps(
                    _candidate(
                        lane="source_mine",
                        confidence="high",
                        promotion_status="poc_ready",
                        blocking_questions=[],
                    )
                ),
                encoding="utf-8",
            )
            payload = self._run(ws, path, require_line_cite=True)
            self.assertEqual(payload["verdicts"][0]["decision"], "rejected")
            self.assertTrue(any("line citation required" in reason for reason in payload["verdicts"][0]["reasons"]))

    def test_require_line_cite_accepts_payload_line(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
            path = ws / "cand.json"
            path.write_text(
                json.dumps(
                    _candidate(
                        lane="source_mine",
                        confidence="high",
                        promotion_status="poc_ready",
                        blocking_questions=[],
                        lane_payload={"source_files": [{"path": "src/Vault.sol", "line_start": 12}]},
                    )
                ),
                encoding="utf-8",
            )
            payload = self._run(ws, path, require_line_cite=True)
            verdict = payload["verdicts"][0]
            self.assertEqual(verdict["decision"], "needs_poc")
            self.assertTrue(verdict["has_line_citation"])
            self.assertIn("source_or_replay_evidence_missing", verdict["blocker_categories"])

    def test_precondition_risk_blocks_poc_ready(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
            path = ws / "cand.json"
            path.write_text(
                json.dumps(
                    _candidate(
                        confidence="high",
                        promotion_status="poc_ready",
                        blocking_questions=[],
                        trigger="Guardian blacklist happens after the child resolves.",
                    )
                ),
                encoding="utf-8",
            )
            payload = self._run(ws, path)
            verdict = payload["verdicts"][0]
            self.assertEqual(verdict["decision"], "needs_poc")
            self.assertIn("guardian", verdict["precondition_risks"])
            self.assertIn("precondition_risk", verdict["blocker_categories"])
            self.assertEqual(payload["blocker_counts"]["precondition_risk"], 1)

    def test_explicit_oos_marker_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "src").mkdir()
            (ws / "src" / "Vault.sol").write_text("contract Vault {}\n", encoding="utf-8")
            path = ws / "cand.json"
            path.write_text(
                json.dumps(
                    _candidate(
                        confidence="high",
                        promotion_status="poc_ready",
                        blocking_questions=[],
                        claim="This is an out-of-scope best practice note.",
                    )
                ),
                encoding="utf-8",
            )
            payload = self._run(ws, path)
            verdict = payload["verdicts"][0]
            self.assertEqual(verdict["decision"], "rejected")
            self.assertTrue(verdict["checks"]["explicit_reject_markers"])

    def test_invalid_schema_rejects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            path = ws / "bad.json"
            path.write_text(textwrap.dedent('{"lane": "math"}\n'), encoding="utf-8")
            payload = self._run(ws, path)
            self.assertEqual(payload["decision_counts"]["rejected"], 1)
            self.assertTrue(payload["verdicts"][0]["reasons"][0].startswith("schema-invalid"))


if __name__ == "__main__":
    unittest.main()
