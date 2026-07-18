from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "source-scope-live-proof-guard.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("source_scope_live_proof_guard", TOOL_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class SourceScopeLiveProofGuardTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = load_tool()

    def _write_scope(self, ws: Path) -> None:
        (ws / "SCOPE.md").write_text(
            "In scope: https://github.com/example/protocol source code\n",
            encoding="utf-8",
        )

    def _write_source(self, ws: Path, rel: str = "contracts/Protocol.sol") -> Path:
        path = ws / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("contract Protocol {}\nfunction f() external {}\n", encoding="utf-8")
        return path

    def _write_harness(self, ws: Path, rel: str = "poc/Protocol.t.sol") -> Path:
        path = ws / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("contract ProtocolTest {}\n", encoding="utf-8")
        return path

    def _write_queue(self, ws: Path, row: dict) -> None:
        aud = ws / ".auditooor"
        aud.mkdir(exist_ok=True)
        (aud / "exploit_queue.source_mined.json").write_text(
            json.dumps({"rows": [row]}),
            encoding="utf-8",
        )

    def _only_violation(self, report: dict) -> dict:
        self.assertEqual(report["status"], "fail")
        self.assertEqual(report["violation_count"], 1)
        return report["violations"][0]

    def test_pass_requires_current_source_refs_and_concrete_proof(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._write_scope(ws)
            self._write_source(ws)
            self._write_harness(ws)
            self._write_queue(
                ws,
                {
                    "lead_id": "PASS-1",
                    "proof_status": "proof_ready",
                    "source_refs": ["contracts/Protocol.sol:1"],
                    "poc_path": "poc/Protocol.t.sol",
                    "pass_evidence_lines": ["Suite result: ok. 1 passed; 0 failed"],
                },
            )

            report = self.tool.build_report(ws)
            self.assertEqual(report["status"], "pass")
            self.assertEqual(report["violation_count"], 0)

    def test_passlike_row_without_source_refs_fails_typed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._write_scope(ws)
            self._write_harness(ws)
            self._write_queue(
                ws,
                {
                    "lead_id": "NO-SRC",
                    "proof_status": "proof_ready",
                    "poc_path": "poc/Protocol.t.sol",
                    "pass_evidence_lines": ["--- PASS: TestExploit"],
                },
            )

            violation = self._only_violation(self.tool.build_report(ws))
            self.assertEqual(violation["candidate_id"], "NO-SRC")
            self.assertIn("missing_current_workspace_source_refs", violation["typed_reasons"])

    def test_stale_workspace_source_ref_fails_typed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._write_scope(ws)
            self._write_source(ws)
            self._write_harness(ws)
            self._write_queue(
                ws,
                {
                    "lead_id": "STALE-SRC",
                    "proof_status": "proof_ready",
                    "source_refs": ["contracts/Protocol.sol:99"],
                    "poc_path": "poc/Protocol.t.sol",
                    "pass_evidence_lines": ["PASS"],
                },
            )

            violation = self._only_violation(self.tool.build_report(ws))
            self.assertTrue(
                any(reason.startswith("stale_workspace_source_ref:") for reason in violation["typed_reasons"])
            )

    def test_passlike_row_without_concrete_proof_fails_typed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._write_scope(ws)
            self._write_source(ws)
            self._write_queue(
                ws,
                {
                    "lead_id": "NO-PROOF",
                    "proof_status": "proof_ready",
                    "source_refs": ["contracts/Protocol.sol:1"],
                },
            )

            violation = self._only_violation(self.tool.build_report(ws))
            self.assertIn("missing_concrete_live_or_harness_evidence", violation["typed_reasons"])

    def test_out_of_scope_advisory_only_evidence_fails_typed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._write_scope(ws)
            prior = ws / "prior_audits" / "Report.sol"
            prior.parent.mkdir()
            prior.write_text("contract Report {}\n", encoding="utf-8")
            self._write_harness(ws)
            self._write_queue(
                ws,
                {
                    "lead_id": "ADVISORY-ONLY",
                    "proof_status": "proof_ready",
                    "source_refs": ["prior_audits/Report.sol:1"],
                    "advisory_only": True,
                    "poc_path": "poc/Protocol.t.sol",
                    "pass_evidence_lines": ["Suite result: ok"],
                },
            )

            violation = self._only_violation(self.tool.build_report(ws))
            self.assertTrue(
                any(
                    reason.startswith("out_of_scope_or_advisory_source_ref:")
                    for reason in violation["typed_reasons"]
                )
            )
            self.assertIn("out_of_scope_or_advisory_only_evidence", violation["typed_reasons"])

    def test_blocker_propagates_even_with_source_and_harness_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._write_scope(ws)
            self._write_source(ws)
            self._write_harness(ws)
            self._write_queue(
                ws,
                {
                    "lead_id": "BLOCKED-PASS",
                    "proof_status": "proof_ready",
                    "source_refs": ["contracts/Protocol.sol:1"],
                    "poc_path": "poc/Protocol.t.sol",
                    "pass_evidence_lines": ["--- PASS: TestExploit"],
                    "blockers": ["blocked_by_scope: manager-only entrypoint"],
                },
            )

            violation = self._only_violation(self.tool.build_report(ws))
            self.assertTrue(any(reason.startswith("blocker_present:blockers:") for reason in violation["typed_reasons"]))

    def test_flags_live_state_terminal_blocker_for_github_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "SCOPE.md").write_text(
                "In scope: https://github.com/example/protocol runtime and smart contracts\n",
                encoding="utf-8",
            )
            aud = ws / ".auditooor"
            aud.mkdir()
            (aud / "exploit_queue.source_mined.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "lead_id": "B-1",
                                "proof_status": "live_state_currently_blocked",
                                "blockers": ["Sampled live managers have tierPrice(1..4)=0"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            report = self.tool.build_report(ws)
            self.assertEqual(report["status"], "fail")
            self.assertEqual(report["violation_count"], 1)
            self.assertEqual(report["violations"][0]["candidate_id"], "B-1")

    def test_allows_optional_live_witness_without_terminal_status(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "SCOPE.md").write_text("github.com/example/protocol source scope\n", encoding="utf-8")
            aud = ws / ".auditooor"
            aud.mkdir()
            (aud / "exploit_queue.source_mined.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "lead_id": "B-2",
                                "proof_status": "needs_harness",
                                "notes": "live state may be useful as optional materiality evidence",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            report = self.tool.build_report(ws)
            self.assertEqual(report["status"], "pass")
            self.assertEqual(report["violation_count"], 0)

    def test_policy_can_mark_live_required(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "SCOPE.md").write_text("github.com/example/protocol source scope\n", encoding="utf-8")
            aud = ws / ".auditooor"
            aud.mkdir()
            (aud / "scope_live_proof_policy.json").write_text(
                json.dumps({"requires_live_proof": True}),
                encoding="utf-8",
            )
            (aud / "impact_contracts.json").write_text(
                json.dumps(
                    {
                        "contracts": [
                            {
                                "candidate_id": "LIVE-1",
                                "submission_posture": "NOT_SUBMIT_READY",
                                "stop_condition": "Stop if live tier prices are uniform",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            report = self.tool.build_report(ws)
            self.assertEqual(report["status"], "pass")
            self.assertEqual(report["scope"]["requires_live_proof"], True)

    def test_generic_smart_contract_scope_does_not_imply_source_scope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "SCOPE.md").write_text(
                "Focus area: IN SCOPE VULNERABILITIES: Runtime, Pallets and Smart Contracts\n",
                encoding="utf-8",
            )
            aud = ws / ".auditooor"
            aud.mkdir()
            (aud / "exploit_queue.source_mined.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "lead_id": "LIVE-ONLY",
                                "proof_status": "live_state_currently_blocked",
                                "blockers": ["No current live deployment witness"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            report = self.tool.build_report(ws)
            self.assertEqual(report["status"], "pass")
            self.assertFalse(report["scope"]["source_scoped"])
            self.assertEqual(report["violation_count"], 0)

    def test_policy_source_scoped_override_controls_guard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "SCOPE.md").write_text("Smart contracts in scope\n", encoding="utf-8")
            aud = ws / ".auditooor"
            aud.mkdir()
            (aud / "scope_live_proof_policy.json").write_text(
                json.dumps({"source_scoped": True, "requires_live_proof": False}),
                encoding="utf-8",
            )
            (aud / "exploit_queue.source_mined.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "lead_id": "SRC-1",
                                "proof_status": "live_state_currently_blocked",
                                "blockers": ["No current live state proof"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            report = self.tool.build_report(ws)
            self.assertEqual(report["status"], "fail")
            self.assertTrue(report["scope"]["source_scoped"])
            self.assertEqual(report["violations"][0]["candidate_id"], "SRC-1")

        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "SCOPE.md").write_text("github.com/example/protocol\n", encoding="utf-8")
            aud = ws / ".auditooor"
            aud.mkdir()
            (aud / "scope_live_proof_policy.json").write_text(
                json.dumps({"source_scoped": False}),
                encoding="utf-8",
            )
            (aud / "exploit_queue.source_mined.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {
                                "lead_id": "LIVE-1",
                                "proof_status": "live_state_currently_blocked",
                                "blockers": ["No current live state proof"],
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            report = self.tool.build_report(ws)
            self.assertEqual(report["status"], "pass")
            self.assertFalse(report["scope"]["source_scoped"])


if __name__ == "__main__":
    unittest.main()
