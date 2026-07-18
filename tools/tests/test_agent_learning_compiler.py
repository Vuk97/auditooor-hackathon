"""Tests for agent-learning-compiler.py."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "agent-learning-compiler.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("agent_learning_compiler", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["agent_learning_compiler"] = module
    spec.loader.exec_module(module)
    return module


def write_report(path: Path, artifacts: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema_version": "auditooor.agent_artifact_mining.v2",
                "total_artifacts": len(artifacts),
                "artifact_type_counts": {},
                "artifacts": artifacts,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


class AgentLearningCompilerTests(unittest.TestCase):
    def test_compiles_each_artifact_to_proposition_scoped_terminal_row(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            report = ws / "agent_artifact_mining_report.json"
            ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            write_report(
                report,
                [
                    {
                        "artifact_id": "hq1",
                        "artifact_type": "candidate_hacker_question",
                        "title": "Can attacker bypass the withdrawal guard?",
                        "content": "harness required before proof",
                        "provenance_ref": "agent_outputs/REPORT.md",
                        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                    },
                    {
                        "artifact_id": "proof1",
                        "artifact_type": "proof_artifact_mapping_candidate",
                        "title": "Passing local PoC transcript",
                        "content": "go test ./... PASS",
                        # K3 - a proof_artifact promotion needs a primary signal:
                        # command transcript + source refs + proof status.
                        "source_has_local_proof": True,
                        "command_transcript": "go test ./... -run TestPoC -> ok",
                        "proof_status": "pass",
                        "source_refs": ["poc-tests/poc_test.go"],
                        "provenance_ref": "poc-tests/poc_test.go",
                        "verification_tier": "tier-2-verified-public-archive",
                    },
                    {
                        "artifact_id": "provider1",
                        "artifact_type": "rejection_pattern",
                        "title": "Provider-only OOS note",
                        "provider_only": True,
                        "verification_tier": "tier-5-quarantine",
                        "provenance_ref": "agent_outputs/provider.txt",
                    },
                ],
            )

            payload = tool.compile_learning(ws, report, ledger)
            again = tool.compile_learning(ws, report, ledger)
            rows = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines()]

        self.assertEqual(payload["artifacts_seen"], 3)
        self.assertEqual(payload["terminal_rows_compiled"], 3)
        self.assertEqual(payload["rows_appended"], 3)
        self.assertEqual(again["rows_appended"], 0)
        self.assertEqual(len(rows), 3)
        by_id = {row["artifact_id"]: row for row in rows}
        self.assertEqual(by_id["hq1"]["terminal_kind"], "hacker_question")
        self.assertEqual(by_id["proof1"]["terminal_kind"], "proof_artifact")
        self.assertEqual(by_id["provider1"]["terminal_kind"], "NO_ACTION")
        self.assertEqual(by_id["provider1"]["reason"], "provider_only")
        for row in rows:
            self.assertEqual(row["schema"], "auditooor.agent_learning_ledger.v1")
            self.assertTrue(row["proposition"])
            self.assertIn(row["evidence_polarity"], {"supports", "contradicts", "limits", "context_only"})
            self.assertIn(
                row["primary_for"],
                {
                    "proof",
                    "dupe",
                    "OOS",
                    "economics",
                    "severity_cap",
                    "team_position",
                    "source_reachability",
                    "harness_gap",
                    "methodology",
                },
            )
            self.assertEqual(row["evidence_tier"], "secondary")
            self.assertTrue(row["quarantine"])
            self.assertFalse(row["promotion_authority"])
            self.assertFalse(row["submit_ready"])
            self.assertEqual(row["severity"], "none")

    def test_compiler_output_satisfies_strict_gate(self) -> None:
        compiler = load_tool()
        gate_spec = importlib.util.spec_from_file_location(
            "agent_learning_gate_for_compiler_test",
            REPO_ROOT / "tools" / "agent-learning-gate.py",
        )
        assert gate_spec is not None and gate_spec.loader is not None
        gate = importlib.util.module_from_spec(gate_spec)
        sys.modules["agent_learning_gate_for_compiler_test"] = gate
        gate_spec.loader.exec_module(gate)
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            report = ws / "agent_artifact_mining_report.json"
            ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            write_report(
                report,
                [
                    {
                        "artifact_id": "proof1",
                        "artifact_type": "proof_artifact_mapping_candidate",
                        "title": "Passing local proof transcript",
                        "source_has_local_proof": True,
                        "command_transcript": "forge test -> Suite result: ok",
                        "proof_status": "pass",
                        "source_refs": ["poc-tests/poc.t.sol"],
                    },
                    {
                        "artifact_id": "gap1",
                        "artifact_type": "harness_template_request",
                        "title": "Harness blocker",
                    },
                ],
            )

            compiler.compile_learning(ws, report, ledger)
            payload = gate.evaluate(ws, strict=True)

        self.assertEqual(payload["status"], "pass")
        self.assertEqual(payload["learning_ledger_covered_count"], 2)
        self.assertEqual(payload["terminal_scope_violation_count"], 0)

    def test_check_mode_does_not_write_ledger(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            report = ws / "agent_artifact_mining_report.json"
            ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            write_report(
                report,
                [
                    {
                        "artifact_id": "gap1",
                        "artifact_type": "roadmap_gap",
                        "title": "Missing source closure",
                    }
                ],
            )

            payload = tool.compile_learning(ws, report, ledger, check=True)

        self.assertEqual(payload["rows_would_append"], 1)
        self.assertEqual(payload["rows_appended"], 0)
        self.assertFalse(ledger.exists())


    # K3 acceptance: compiler must report provider_only_promotion_escape_count = 0
    # even when an artifact has source_has_local_proof = True but provider_only = True.
    def test_provider_only_escape_count_always_zero(self) -> None:
        """K3: compiler hard-clamps provider-only rows; escape count must be 0."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            report = ws / "agent_artifact_mining_report.json"
            ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            # A provider-only artifact that claims a proof transcript should be
            # demoted - the compiler MUST NOT let it reach proof_artifact.
            write_report(
                report,
                [
                    {
                        "artifact_id": "ponly_proof",
                        "artifact_type": "proof_artifact_mapping_candidate",
                        "title": "Provider claimed proof",
                        "provider_only": True,
                        "source_has_local_proof": True,
                        "command_transcript": "go test ./... -> ok",
                        "proof_status": "pass",
                        "source_refs": ["poc-tests/poc_test.go"],
                        "provenance_ref": "poc-tests/poc_test.go",
                        "verification_tier": "tier-5-quarantine",
                    }
                ],
            )
            payload = tool.compile_learning(ws, report, ledger)

            # K3 hard gate: provider-only rows cannot escape to proof_artifact.
            self.assertEqual(
                payload["provider_only_promotion_escape_count"],
                0,
                "K3: provider_only_promotion_escape_count must be 0 on compiler output",
            )
            rows = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(len(rows), 1)
            row = rows[0]
            # Must be demoted away from proof_artifact.
            self.assertNotEqual(
                row["terminal_kind"],
                "proof_artifact",
                "K3: provider_only artifact must not reach proof_artifact terminal kind",
            )
            self.assertIn(
                row["promotion_class"],
                {"provider_only_demoted", "suggest_only"},
                "K3: promotion_class must reflect demotion",
            )

    # K3a: a negative-polarity row (contradicts/limits) must not carry
    # primary_for='proof' - negative outcomes cannot be reused as positive proof.
    def test_negative_polarity_row_not_primary_for_proof(self) -> None:
        """K3a: negative outcome rows must not be labeled primary_for='proof'."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            report = ws / "agent_artifact_mining_report.json"
            ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            write_report(
                report,
                [
                    {
                        "artifact_id": "kill1",
                        "artifact_type": "kill_rubric_entry",
                        "title": "OOS rejection - not reachable via external call",
                        "verdict": "NEGATIVE kill",
                        "provenance_ref": "agent_outputs/REPORT.md",
                        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                    }
                ],
            )
            tool.compile_learning(ws, report, ledger)
            rows = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines()]

        self.assertEqual(len(rows), 1)
        row = rows[0]
        # K3a: evidence_polarity for a kill_reason should be contradicts or limits, not supports.
        self.assertIn(row["evidence_polarity"], {"contradicts", "limits", "context_only"})
        # K3a: a kill / rejection row must NOT be primary_for='proof'.
        self.assertNotEqual(
            row["primary_for"],
            "proof",
            "K3a: negative-outcome kill_reason row must not be primary_for='proof'",
        )

    # K4: every compiled row must carry a valid K4 reuse_action.
    def test_every_compiled_row_carries_valid_k4_reuse_action(self) -> None:
        """K4: compiled rows must declare a reuse_action from the K4 enum."""
        tool = load_tool()
        K4_REUSE_ACTIONS = {
            "add_detector",
            "add_kill_rubric",
            "add_pre_submit_gate",
            "add_originality_check",
            "add_provider_prompt_constraint",
            "add_harness_template",
            "add_hacker_question",
            "none",
        }
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            report = ws / "agent_artifact_mining_report.json"
            ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            write_report(
                report,
                [
                    {
                        "artifact_id": "hq1",
                        "artifact_type": "candidate_hacker_question",
                        "title": "Can attacker bypass guard?",
                        "provenance_ref": "agent_outputs/REPORT.md",
                        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                    },
                    {
                        "artifact_id": "det1",
                        "artifact_type": "candidate_detector_pattern",
                        "title": "Reentrancy pattern candidate",
                        "provenance_ref": "agent_outputs/REPORT.md",
                        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                    },
                    {
                        "artifact_id": "kill1",
                        "artifact_type": "kill_rubric_entry",
                        "title": "OOS kill - funds not at risk",
                        "provenance_ref": "agent_outputs/REPORT.md",
                        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                    },
                    {
                        "artifact_id": "tri1",
                        "artifact_type": "triager_pattern",
                        "title": "Triager objection on severity",
                        "provenance_ref": "agent_outputs/REPORT.md",
                        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                    },
                    {
                        "artifact_id": "gap1",
                        "artifact_type": "harness_template_request",
                        "title": "Harness missing for poc execution",
                        "provenance_ref": "agent_outputs/REPORT.md",
                        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                    },
                ],
            )
            tool.compile_learning(ws, report, ledger)
            rows = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines()]

        self.assertEqual(len(rows), 5)
        for row in rows:
            reuse_action = row.get("reuse_action", "")
            self.assertIn(
                reuse_action,
                K4_REUSE_ACTIONS,
                f"K4: artifact {row['artifact_id']!r} carries invalid reuse_action {reuse_action!r}",
            )

    # K3: the by_promotion_class summary in compiler output must not contain
    # 'primary_promoted' for any provider-only artifact.
    def test_compiler_by_promotion_class_no_primary_promoted_for_provider_only(self) -> None:
        """K3: provider-only artifacts must not appear in by_promotion_class as primary_promoted."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            report = ws / "agent_artifact_mining_report.json"
            ledger = ws / ".auditooor" / "agent_artifacts" / "learning_ledger.jsonl"
            # Mix: one real primary-signal artifact + one provider-only claimant.
            write_report(
                report,
                [
                    {
                        "artifact_id": "real_proof",
                        "artifact_type": "proof_artifact_mapping_candidate",
                        "title": "Real local PoC",
                        "source_has_local_proof": True,
                        "command_transcript": "forge test -> Suite result: ok",
                        "proof_status": "pass",
                        "source_refs": ["poc-tests/poc.t.sol"],
                        "provenance_ref": "poc-tests/poc.t.sol",
                        "verification_tier": "tier-2-verified-public-archive",
                    },
                    {
                        "artifact_id": "fake_proof",
                        "artifact_type": "proof_artifact_mapping_candidate",
                        "title": "Provider claimed proof without local run",
                        "provider_only": True,
                        "source_has_local_proof": True,
                        "command_transcript": "forge test -> Suite result: ok",
                        "proof_status": "pass",
                        "source_refs": ["poc-tests/fake.t.sol"],
                        "provenance_ref": "poc-tests/fake.t.sol",
                        "verification_tier": "tier-5-quarantine",
                    },
                ],
            )
            payload = tool.compile_learning(ws, report, ledger)

            # Real proof should be primary_promoted; provider-only must NOT be.
            by_class = payload["by_promotion_class"]
            self.assertEqual(by_class.get("primary_promoted", 0), 1, "Only one real primary-promoted row")
            self.assertEqual(
                payload["provider_only_promotion_escape_count"],
                0,
                "K3: compiler escape count must be 0",
            )
            rows = [json.loads(line) for line in ledger.read_text(encoding="utf-8").splitlines()]
            by_id = {r["artifact_id"]: r for r in rows}
            self.assertEqual(by_id["real_proof"]["terminal_kind"], "proof_artifact")
            self.assertNotEqual(by_id["fake_proof"]["terminal_kind"], "proof_artifact")


if __name__ == "__main__":
    unittest.main()
