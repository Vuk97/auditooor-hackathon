#!/usr/bin/env python3
"""Tests for agent-artifact-miner.py - Lane 6 capability engineering."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "agent-artifact-miner.py"


def load_tool():
    """Load the agent-artifact-miner module."""
    spec = importlib.util.spec_from_file_location("agent_artifact_miner", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["agent_artifact_miner"] = module
    spec.loader.exec_module(module)
    return module


class TestEmptyWorkspace(unittest.TestCase):
    """Empty workspace emits NO_LEARNING_REASON."""

    def test_empty_workspace_no_learning_reason(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            report = tool.mine_workspace(ws)
            self.assertTrue(
                report["no_learning_reason"],
                "Empty workspace should set no_learning_reason=True",
            )
            self.assertEqual(report["total_artifacts"], 0)
            self.assertEqual(report["artifacts"], [])
            self.assertEqual(report["schema_version"], "auditooor.agent_artifact_mining.v2")

    def test_empty_workspace_has_required_fields(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            report = tool.mine_workspace(ws)
            for field in ("schema_version", "workspace", "generated_at",
                          "total_artifacts", "no_learning_reason",
                          "artifact_type_counts", "artifacts"):
                self.assertIn(field, report, f"Missing required field: {field}")


class TestKilledLeadArtifact(unittest.TestCase):
    """Killed leads emit rejection/kill-reason learning artifacts."""

    def _make_kill_report(self, ws: Path, verdict: str = "NEGATIVE", has_kill_reason: bool = True) -> Path:
        agent_dir = ws / "agent_outputs" / "round1_test_lane"
        agent_dir.mkdir(parents=True)
        report_path = agent_dir / "REPORT.md"
        kill_line = (
            "KILL: privileged-required, non-privileged actor cannot reach the vault"
            if has_kill_reason else ""
        )
        report_path.write_text(
            f"# Test Lane Report\n\n"
            f"**VERDICT: {verdict}** - No fileable finding.\n\n"
            f"## Candidate verdicts\n\n"
            f"- C1 DoS candidate: {kill_line}\n"
            f"- C2 Reentrancy: KILL: guarded by nonReentrant modifier.\n",
            encoding="utf-8",
        )
        return report_path

    def test_killed_lead_emits_rejection_pattern(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._make_kill_report(ws)
            report = tool.mine_workspace(ws)
            types = [a["artifact_type"] for a in report["artifacts"]]
            self.assertIn("rejection_pattern", types,
                          "Killed lead must produce a rejection_pattern artifact")

    def test_killed_lead_has_required_fields(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._make_kill_report(ws)
            report = tool.mine_workspace(ws)
            for artifact in report["artifacts"]:
                for field in ("artifact_id", "artifact_type", "title", "content",
                              "provenance_ref", "verdict", "verification_tier",
                              "source_has_local_proof"):
                    self.assertIn(field, artifact, f"Artifact missing field: {field}")

    def test_killed_lead_has_tier(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._make_kill_report(ws)
            report = tool.mine_workspace(ws)
            valid_tiers = {
                "tier-1-verified-realtime-api",
                "tier-1-officially-disclosed",
                "tier-2-verified-public-archive",
                "tier-3-synthetic-taxonomy-anchored",
                "tier-4-bundled-fixture",
                "tier-5-quarantine",
            }
            for artifact in report["artifacts"]:
                self.assertIn(
                    artifact["verification_tier"],
                    valid_tiers,
                    f"Invalid verification_tier: {artifact['verification_tier']}",
                )

    def test_negative_no_local_proof_is_tier3_not_tier2(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._make_kill_report(ws, verdict="NEGATIVE", has_kill_reason=True)
            report = tool.mine_workspace(ws)
            rejection_artifacts = [a for a in report["artifacts"] if a["artifact_type"] == "rejection_pattern"]
            self.assertGreater(len(rejection_artifacts), 0)
            for a in rejection_artifacts:
                # No local proof -> must be tier-3 or tier-5
                self.assertIn(
                    a["verification_tier"],
                    {"tier-3-synthetic-taxonomy-anchored", "tier-5-quarantine"},
                    f"No-local-proof artifact should be tier-3 or tier-5, got {a['verification_tier']}",
                )


class TestProviderOnlyNotPromoted(unittest.TestCase):
    """Provider-only artifacts without local verification are NOT promoted."""

    def test_verdict_extraction_preserves_provider_only_class(self) -> None:
        tool = load_tool()
        self.assertEqual(
            tool._extract_verdict("**VERDICT: NEGATIVE-PROVIDER-ONLY**"),
            "NEGATIVE-PROVIDER-ONLY",
        )

    def test_verdict_extraction_requires_complete_token(self) -> None:
        tool = load_tool()
        self.assertIsNone(tool._extract_verdict("VERDICT: KILLED by invariant"))
        self.assertIsNone(tool._extract_verdict("VERDICT: NEGATIVE-PROVIDER-ONLY-EXTRA"))

    def test_raw_provider_txt_no_local_proof_not_promoted(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            # Create a raw provider text file with no local proof signal
            prov_dir = ws / "agent_outputs" / "provider_outputs"
            prov_dir.mkdir(parents=True)
            (prov_dir / "kimi_analysis.txt").write_text(
                "This is a provider-only analysis from Kimi.\n"
                "local_verification_required: false\n"
                "The contract might have a reentrancy issue.\n",
                encoding="utf-8",
            )
            report = tool.mine_workspace(ws)
            # The raw provider-only txt with no local proof should not appear
            # as a tier-2 or higher learning artifact
            for a in report["artifacts"]:
                if "kimi_analysis" in a.get("provenance_ref", ""):
                    self.assertNotIn(
                        a["verification_tier"],
                        {"tier-1-verified-realtime-api", "tier-1-officially-disclosed",
                         "tier-2-verified-public-archive"},
                        f"Provider-only artifact was promoted to {a['verification_tier']}",
                    )

    def test_proof_hardening_without_local_proof_is_not_mapping_candidate(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            agent_dir = ws / "agent_outputs" / "round1_proof_hardening"
            agent_dir.mkdir(parents=True)
            (agent_dir / "REPORT.md").write_text(
                "# Report\n\n"
                "VERDICT: NEEDS-VERIFY\n\n"
                "This needs production-profile evidence and Rule 18 proof hardening, "
                "but there is no local proof or passing test transcript yet.\n",
                encoding="utf-8",
            )
            report = tool.mine_workspace(ws)
            for artifact in report["artifacts"]:
                self.assertFalse(
                    artifact["artifact_type"] == "proof_artifact_mapping_candidate"
                    and artifact.get("source_has_local_proof") is not True,
                    "Unproved proof-hardening prose must not become a proof mapping candidate",
                )

    def test_provider_only_report_artifacts_are_quarantined(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            agent_dir = ws / "agent_outputs" / "round_provider_only"
            agent_dir.mkdir(parents=True)
            (agent_dir / "REPORT.md").write_text(
                "# Provider-only Report\n\n"
                "**VERDICT: NEGATIVE-PROVIDER-ONLY**\n\n"
                "KILL: provider-only objection without repository-backed evidence.\n"
                "This needs production-profile evidence and Rule 18 proof hardening, "
                "but there is no executed test transcript yet.\n",
                encoding="utf-8",
            )
            report = tool.mine_workspace(ws)
            provider_artifacts = [
                a for a in report["artifacts"]
                if "round_provider_only" in a.get("provenance_ref", "")
            ]
            self.assertGreater(len(provider_artifacts), 0)
            for artifact in provider_artifacts:
                self.assertEqual(artifact["verdict"], "NEGATIVE-PROVIDER-ONLY")
                self.assertEqual(artifact["verification_tier"], "tier-5-quarantine")
                self.assertTrue(artifact.get("provider_only", False))

    def test_unrelated_test_command_does_not_count_as_local_proof(self) -> None:
        tool = load_tool()
        self.assertFalse(
            tool._has_local_proof(
                "VERDICT: NEEDS-VERIFY\n"
                "The dependency baseline ran go test successfully, but this is "
                "not the PoC and no local verification was executed.\n"
            )
        )

    def test_unrelated_pass_output_does_not_count_as_local_proof(self) -> None:
        tool = load_tool()
        self.assertFalse(
            tool._has_local_proof(
                "VERDICT: NEEDS-VERIFY\n"
                "Provider notes: dependency smoke tests PASS.\n"
                "--- PASS: TestDependencyBaseline\n"
                "This is not this PoC and no local proof was executed.\n"
            )
        )

    def test_test_command_near_poc_context_counts_as_local_proof(self) -> None:
        tool = load_tool()
        self.assertTrue(
            tool._has_local_proof(
                "VERDICT: POSITIVE\n"
                "PoC proof transcript:\n"
                "go test ./x/vault/keeper -run TestInterestOverflow -v\n"
                "--- PASS: TestInterestOverflow\n"
            )
        )

    def test_failed_reproduction_attempt_has_distinct_artifact_type(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            agent_dir = ws / "agent_outputs" / "round_repro_fail"
            agent_dir.mkdir(parents=True)
            (agent_dir / "REPORT.md").write_text(
                "# Report\n\n"
                "VERDICT: NEEDS-VERIFY\n\n"
                "PoC could not reproduce on the pinned commit after running the "
                "documented exploit command.\n",
                encoding="utf-8",
            )
            report = tool.mine_workspace(ws)
            types = [artifact["artifact_type"] for artifact in report["artifacts"]]
            self.assertIn("failed_reproduction_attempt", types)

    def test_provider_kill_json_with_no_local_required_is_tier5(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            prov_dir = ws / "agent_outputs" / "provider_outputs"
            prov_dir.mkdir(parents=True)
            kill_json = [
                {
                    "id": "XCHAIN-2",
                    "verdict": "Kill",
                    "local_verification_required": False,
                    "notes": "Fee miscalculation can cause user fund loss.",
                    "minimum_followup_check": "Confirm feeArgs matches normalized amount.",
                    "contradiction_citation": None,
                }
            ]
            (prov_dir / "minimax_kills.txt").write_text(
                json.dumps(kill_json), encoding="utf-8"
            )
            report = tool.mine_workspace(ws)
            provider_artifacts = [
                a for a in report["artifacts"]
                if "minimax_kills" in a.get("provenance_ref", "")
            ]
            for a in provider_artifacts:
                self.assertEqual(
                    a["verification_tier"],
                    "tier-5-quarantine",
                    f"Provider-only kill must be tier-5-quarantine, got {a['verification_tier']}",
                )
                self.assertTrue(a.get("provider_only", False))

    def test_provider_kill_json_with_local_required_is_candidate_hacker_question(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            prov_dir = ws / "agent_outputs" / "provider_outputs"
            prov_dir.mkdir(parents=True)
            kill_json = [
                {
                    "id": "PRIME-1",
                    "verdict": "Kill",
                    "local_verification_required": True,
                    "notes": "Premature deletion of proxy mapping orphans assets.",
                    "minimum_followup_check": "Ensure Keeper zero-sweep does not delete proxy before async payout.",
                    "contradiction_citation": None,
                }
            ]
            (prov_dir / "minimax_verified_kills.txt").write_text(
                json.dumps(kill_json), encoding="utf-8"
            )
            report = tool.mine_workspace(ws)
            candidate_artifacts = [
                a for a in report["artifacts"]
                if a.get("artifact_type") == "candidate_hacker_question"
                and "minimax_verified_kills" in a.get("provenance_ref", "")
            ]
            self.assertGreater(
                len(candidate_artifacts), 0,
                "local_verification_required=True kill should produce candidate_hacker_question",
            )


class TestOutputSchema(unittest.TestCase):
    """Output schema field presence and deterministic ordering."""

    def test_schema_version_correct(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            report = tool.mine_workspace(ws)
            self.assertEqual(report["schema_version"], "auditooor.agent_artifact_mining.v2")

    def test_artifact_ids_are_unique(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            # Add two different REPORT.md files
            for i in range(2):
                rd = ws / "agent_outputs" / f"round{i}_lane" / "REPORT.md"
                rd.parent.mkdir(parents=True)
                rd.write_text(
                    f"# Round {i}\n\n**VERDICT: NEGATIVE** - no finding.\n"
                    f"KILL: candidate {i} is privileged-only, non-fileable.\n",
                    encoding="utf-8",
                )
            report = tool.mine_workspace(ws)
            ids = [a["artifact_id"] for a in report["artifacts"]]
            self.assertEqual(len(ids), len(set(ids)), "artifact_ids must be unique")

    def test_deterministic_ordering(self) -> None:
        """Running mine_workspace twice on the same workspace returns the same order."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            for i in range(3):
                rd = ws / "agent_outputs" / f"round{i}_lane" / "REPORT.md"
                rd.parent.mkdir(parents=True)
                rd.write_text(
                    f"# Round {i}\n\n**VERDICT: NEGATIVE**\n"
                    f"KILL: reason {i} - privileged.\n",
                    encoding="utf-8",
                )
            r1 = tool.mine_workspace(ws)
            r2 = tool.mine_workspace(ws)
            ids1 = [a["artifact_id"] for a in r1["artifacts"]]
            ids2 = [a["artifact_id"] for a in r2["artifacts"]]
            self.assertEqual(ids1, ids2, "Artifact ordering must be deterministic across runs")

    def test_no_learning_reason_false_when_artifacts_present(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            rd = ws / "agent_outputs" / "round1_test" / "REPORT.md"
            rd.parent.mkdir(parents=True)
            rd.write_text(
                "# Test\n\n**VERDICT: NEGATIVE**\nKILL: privileged path, OOS.\n",
                encoding="utf-8",
            )
            report = tool.mine_workspace(ws)
            if report["total_artifacts"] > 0:
                self.assertFalse(
                    report["no_learning_reason"],
                    "no_learning_reason must be False when artifacts are present",
                )


class TestCapabilityLesson(unittest.TestCase):
    """Capability lesson blocks in REPORT.md are extracted as known_limitation."""

    def test_capability_lesson_extracted(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            rd = ws / "agent_outputs" / "round_backfill" / "REPORT.md"
            rd.parent.mkdir(parents=True)
            rd.write_text(
                "# Backfill Report\n\n"
                "## Filed finding\n\nStatus: SUBMITTED.\n\n"
                "## Capability Lesson\n\n"
                "For Critical Cosmos app-chain reports, a keeper-level proof is not enough. "
                "Real message path + production ABCI path + persistent backend + restart behavior "
                "and multi-validator evidence are required for network-wide liveness claims.\n\n"
                "## Another section\n\nfoo bar.\n",
                encoding="utf-8",
            )
            report = tool.mine_workspace(ws)
            lesson_artifacts = [
                a for a in report["artifacts"] if a["artifact_type"] == "known_limitation"
            ]
            self.assertGreater(len(lesson_artifacts), 0,
                               "Capability lesson block should produce known_limitation artifact")
            self.assertIn(
                "keeper-level proof",
                lesson_artifacts[0]["content"],
            )


class TestPassingPocArtifact(unittest.TestCase):
    """Passing PoC files are mapped to proof_artifact_mapping_candidate."""

    def test_passing_poc_go_txt(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            poc_dir = ws / "agent_outputs" / "round9_nav_overflow"
            poc_dir.mkdir(parents=True)
            (poc_dir / "poc_test.go.txt").write_text(
                "func TestRound9_Overflow(t *testing.T) {\n"
                "    // ... test body ...\n"
                "}\n"
                "--- PASS: TestRound9_Overflow (0.42s)\n"
                "ok  github.com/example/vault/keeper\n",
                encoding="utf-8",
            )
            report = tool.mine_workspace(ws)
            pass_artifacts = [
                a for a in report["artifacts"]
                if a.get("artifact_type") == "proof_artifact_mapping_candidate"
                and a.get("verdict") == "POC_PASS"
            ]
            self.assertGreater(len(pass_artifacts), 0,
                               "Passing PoC should produce proof_artifact_mapping_candidate")
            self.assertTrue(pass_artifacts[0]["source_has_local_proof"])
            self.assertEqual(pass_artifacts[0]["verification_tier"], "tier-2-verified-public-archive")


class TestMainCLI(unittest.TestCase):
    """CLI smoke test: --workspace with empty dir exits 0."""

    def test_cli_empty_workspace_exit_0(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = tmp
            rc = tool.main(["--workspace", ws])
            self.assertEqual(rc, 0)

    def test_cli_missing_workspace_exit_2(self) -> None:
        tool = load_tool()
        rc = tool.main(["--workspace", "/nonexistent/path/xyz_12345"])
        self.assertEqual(rc, 2)

    def test_cli_out_file_written(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            out_path = ws / "report.json"
            rc = tool.main(["--workspace", str(ws), "--out", str(out_path)])
            self.assertEqual(rc, 0)
            self.assertTrue(out_path.is_file(), "--out file must be written")
            data = json.loads(out_path.read_text())
            self.assertEqual(data["schema_version"], "auditooor.agent_artifact_mining.v2")


class TestProviderNormalizedWorkQueue(unittest.TestCase):
    """provider_normalized_work_queue.jsonl is mined into calibration rows + enrichments."""

    def _make_work_queue(self, ws: Path, rows: list[dict]) -> Path:
        reports_dir = ws / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        path = reports_dir / "provider_normalized_work_queue.jsonl"
        path.write_text(
            "\n".join(json.dumps(r) for r in rows) + "\n",
            encoding="utf-8",
        )
        return path

    def test_keep_row_produces_exploit_queue_enrichment(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._make_work_queue(ws, [
                {
                    "schema": "auditooor.provider_normalized_work_queue.v1",
                    "dedup_key": "aaa111",
                    "disposition": "KEEP",
                    "normalized_type": "candidate_detector_generalization",
                    "provider": "kimi",
                    "model": "kimi-for-coding",
                    "task_type": "source-extract",
                    "attack_class": "admin-bypass",
                    "output_path": "agent_outputs/slice2_kimi_admin_bypass_output.md",
                    "local_verification_command": "rg 'onlyOwner.*rescue' --glob '*.sol'",
                    "local_verification_run": False,
                },
            ])
            report = tool.mine_workspace(ws)
            types = [a["artifact_type"] for a in report["artifacts"]]
            self.assertIn("exploit_queue_enrichment", types,
                          "KEEP row with local_verification_command must produce exploit_queue_enrichment")

    def test_kill_row_produces_kill_rubric_entry(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._make_work_queue(ws, [
                {
                    "schema": "auditooor.provider_normalized_work_queue.v1",
                    "dedup_key": "bbb222",
                    "disposition": "KILL",
                    "normalized_type": "kill_reason_pending_local_check",
                    "provider": "minimax",
                    "model": "MiniMax-M2.7",
                    "task_type": "adversarial-kill",
                    "attack_class": "reentrancy",
                    "output_path": "agent_outputs/slice2_minimax_kill_output.md",
                    "local_verification_command": "rg 'nonReentrant' --glob '*.sol'",
                    "local_verification_run": False,
                },
            ])
            report = tool.mine_workspace(ws)
            types = [a["artifact_type"] for a in report["artifacts"]]
            self.assertIn("kill_rubric_entry", types,
                          "KILL row must produce kill_rubric_entry")

    def test_every_row_produces_provider_calibration_row(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._make_work_queue(ws, [
                {
                    "schema": "auditooor.provider_normalized_work_queue.v1",
                    "dedup_key": "ccc333",
                    "disposition": "KEEP",
                    "normalized_type": "candidate_detector_generalization",
                    "provider": "kimi",
                    "model": "kimi-for-coding",
                    "task_type": "source-extract",
                    "output_path": "agent_outputs/x.md",
                    "local_verification_command": "rg 'foo' --glob '*.sol'",
                    "local_verification_run": False,
                },
                {
                    "schema": "auditooor.provider_normalized_work_queue.v1",
                    "dedup_key": "ddd444",
                    "disposition": "KILL",
                    "normalized_type": "kill_reason_pending_local_check",
                    "provider": "minimax",
                    "model": "MiniMax-M2.7",
                    "task_type": "adversarial-kill",
                    "output_path": "agent_outputs/y.md",
                    "local_verification_command": "# review manually",
                    "local_verification_run": False,
                },
            ])
            report = tool.mine_workspace(ws)
            calibration_rows = [
                a for a in report["artifacts"]
                if a["artifact_type"] == "provider_calibration_row"
            ]
            # Two rows in the JSONL -> at least 2 calibration rows
            self.assertGreaterEqual(
                len(calibration_rows), 2,
                "Each JSONL row must produce at least one provider_calibration_row",
            )

    def test_provider_calibration_row_is_tier5_quarantine(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._make_work_queue(ws, [
                {
                    "dedup_key": "eee555",
                    "disposition": "KEEP",
                    "normalized_type": "candidate_detector_generalization",
                    "provider": "kimi",
                    "model": "kimi-for-coding",
                    "task_type": "source-extract",
                    "output_path": "agent_outputs/z.md",
                    "local_verification_command": "rg 'x' --glob '*.sol'",
                },
            ])
            report = tool.mine_workspace(ws)
            calibration_rows = [
                a for a in report["artifacts"]
                if a["artifact_type"] == "provider_calibration_row"
            ]
            self.assertGreater(len(calibration_rows), 0)
            for row in calibration_rows:
                self.assertEqual(
                    row["verification_tier"],
                    "tier-5-quarantine",
                    "Provider calibration rows must be tier-5-quarantine",
                )
                self.assertTrue(row.get("provider_only", False))

    def test_empty_work_queue_file_no_artifacts(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._make_work_queue(ws, [])
            report = tool.mine_workspace(ws)
            # Empty JSONL should not crash; may produce 0 artifacts
            self.assertIsInstance(report["artifacts"], list)
            self.assertIsInstance(report["total_artifacts"], int)


class TestFinalizationManifest(unittest.TestCase):
    """slice_finalization_*.json manifests are mined for provider calibration + roadmap."""

    def _make_manifest(self, ws: Path, data: dict, name: str = "slice_finalization_test.json") -> Path:
        reports_dir = ws / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        path = reports_dir / name
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return path

    def test_provider_jobs_produce_calibration_rows(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._make_manifest(ws, {
                "slice_id": "test-slice-1",
                "date": "2026-05-19",
                "provider_jobs": [
                    {
                        "provider": "kimi",
                        "model": "kimi-for-coding",
                        "task_type": "source-extract",
                        "status": "success",
                        "normalized_type": "candidate_detector_generalization",
                        "output_path": "agent_outputs/kimi_output.md",
                    },
                    {
                        "provider": "minimax",
                        "model": "MiniMax-M2.7",
                        "task_type": "adversarial-kill",
                        "status": "success",
                        "normalized_type": "kill_reason_pending_local_check",
                        "verdict": "KILL Proposal A",
                        "output_path": "agent_outputs/minimax_kill_output.md",
                    },
                ],
            })
            report = tool.mine_workspace(ws)
            calibration_rows = [
                a for a in report["artifacts"]
                if a["artifact_type"] == "provider_calibration_row"
            ]
            self.assertGreaterEqual(len(calibration_rows), 2,
                                    "Each provider_job must produce a provider_calibration_row")

    def test_kill_verdict_produces_kill_rubric_entry(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._make_manifest(ws, {
                "slice_id": "test-slice-2",
                "provider_jobs": [
                    {
                        "provider": "minimax",
                        "model": "MiniMax-M2.7",
                        "task_type": "adversarial-kill",
                        "status": "success",
                        "normalized_type": "kill_reason_pending_local_check",
                        "verdict": "KILL (FP: guarded by nonReentrant)",
                        "output_path": "agent_outputs/kill_output.md",
                    },
                ],
            })
            report = tool.mine_workspace(ws)
            kill_entries = [
                a for a in report["artifacts"]
                if a["artifact_type"] == "kill_rubric_entry"
            ]
            self.assertGreater(len(kill_entries), 0,
                               "Kill verdict in manifest must produce kill_rubric_entry")

    def test_provider_failure_produces_roadmap_gap(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._make_manifest(ws, {
                "slice_id": "test-slice-3",
                "provider_jobs": [
                    {
                        "provider": "minimax",
                        "model": "minimax-text-01",
                        "task_type": "adversarial-kill",
                        "status": "provider_failure",
                        "normalized_type": "provider_failure",
                        "error": "rc=3 empty output",
                        "output_path": "agent_outputs/failed_output.md",
                    },
                ],
            })
            report = tool.mine_workspace(ws)
            roadmap_gaps = [
                a for a in report["artifacts"]
                if a["artifact_type"] == "roadmap_gap"
            ]
            self.assertGreater(len(roadmap_gaps), 0,
                               "Provider failure must produce roadmap_gap (retry opportunity)")

    def test_dsl_pattern_artifact_produces_candidate_detector_pattern(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._make_manifest(ws, {
                "slice_id": "test-slice-4",
                "provider_jobs": [],
                "artifacts": [
                    {
                        "type": "dsl_pattern",
                        "path": "reference/patterns.dsl/test-pattern.yaml",
                        "description": "Test umbrella pattern for reentrancy",
                        "attack_classes": ["reentrancy"],
                        "confidence": "MEDIUM",
                    },
                ],
            })
            report = tool.mine_workspace(ws)
            detector_patterns = [
                a for a in report["artifacts"]
                if a["artifact_type"] == "candidate_detector_pattern"
            ]
            self.assertGreater(len(detector_patterns), 0,
                               "DSL pattern artifact must produce candidate_detector_pattern")

    def test_open_blockers_produce_roadmap_gap(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._make_manifest(ws, {
                "slice_id": "test-slice-5",
                "provider_jobs": [],
                "open_blockers": [
                    "Recall scoreboard not regenerated",
                    "Bridge pattern has LOW confidence only",
                ],
            })
            report = tool.mine_workspace(ws)
            roadmap_gaps = [
                a for a in report["artifacts"]
                if a["artifact_type"] == "roadmap_gap"
            ]
            self.assertGreater(len(roadmap_gaps), 0,
                               "open_blockers must produce roadmap_gap")
            gap_content = " ".join(a["content"] for a in roadmap_gaps)
            self.assertIn("scoreboard", gap_content.lower())

    def test_passing_tests_produce_proof_artifact(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._make_manifest(ws, {
                "slice_id": "test-slice-6",
                "provider_jobs": [],
                "tests": [
                    {
                        "name": "test_realworld_recall_scoreboard",
                        "command": "python3 -m unittest tools.tests.test_realworld_recall_scoreboard -v",
                        "result": "19 tests OK",
                    },
                ],
            })
            report = tool.mine_workspace(ws)
            proof_artifacts = [
                a for a in report["artifacts"]
                if a["artifact_type"] == "proof_artifact_mapping_candidate"
                and a.get("verdict") == "TEST_PASS"
            ]
            self.assertGreater(len(proof_artifacts), 0,
                               "Passing test in manifest must produce proof_artifact_mapping_candidate")
            self.assertTrue(proof_artifacts[0]["source_has_local_proof"])

    def test_no_learning_reason_false_for_non_empty_manifest(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._make_manifest(ws, {
                "slice_id": "test-slice-7",
                "provider_jobs": [
                    {
                        "provider": "kimi",
                        "model": "kimi-for-coding",
                        "task_type": "source-extract",
                        "status": "success",
                        "normalized_type": "candidate_detector_generalization",
                        "output_path": "agent_outputs/kimi_output.md",
                    },
                ],
            })
            report = tool.mine_workspace(ws)
            if report["total_artifacts"] > 0:
                self.assertFalse(
                    report["no_learning_reason"],
                    "no_learning_reason must be False when manifest produces artifacts",
                )


class TestSliceSubagentOutputMining(unittest.TestCase):
    """Slice subagent output MDs (kimi/minimax) are mined for kill rubric + detector patterns."""

    def _make_slice_output(
        self,
        ws: Path,
        name: str,
        content: str,
    ) -> Path:
        agent_dir = ws / "agent_outputs"
        agent_dir.mkdir(parents=True, exist_ok=True)
        path = agent_dir / name
        path.write_text(content, encoding="utf-8")
        return path

    def test_adversarial_kill_output_produces_kill_rubric_entry(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._make_slice_output(
                ws,
                "slice2_minimax_state_change_kill_output.md",
                "# Detector Challenge: False Positive Analysis\n\n"
                "## Proposal A: CEI violation\n\n"
                "**Verdict: KILL**\n\n"
                "False Positive 1: Internal helper pattern.\n\n"
                "## Proposal B: Oracle staleness\n\n"
                "**Verdict: KEEP-NARROW**\n",
            )
            report = tool.mine_workspace(ws)
            kill_entries = [
                a for a in report["artifacts"]
                if a["artifact_type"] == "kill_rubric_entry"
            ]
            self.assertGreater(len(kill_entries), 0,
                               "Adversarial kill output must produce kill_rubric_entry")

    def test_source_extract_output_produces_candidate_detector(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._make_slice_output(
                ws,
                "slice2_kimi_admin_bypass_output.md",
                "# Admin Bypass Patterns\n\n"
                "```yaml\n"
                "miss_pattern_id: admin-rescue-drain-no-whitelist\n"
                "vulnerability_subtype: admin-rescue-missing-token-whitelist\n"
                "attacker_capability: Admin can drain user funds.\n"
                "source_backed: true\n"
                "confidence: HIGH\n"
                "```\n",
            )
            report = tool.mine_workspace(ws)
            detector_patterns = [
                a for a in report["artifacts"]
                if a["artifact_type"] == "candidate_detector_pattern"
                and "admin_bypass_output" in a.get("provenance_ref", "")
            ]
            self.assertGreater(len(detector_patterns), 0,
                               "Source-extract output must produce candidate_detector_pattern")

    def test_source_extract_with_multiple_patterns_counts_correctly(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._make_slice_output(
                ws,
                "slice2_kimi_fund_loss_output.md",
                "# Fund Loss Patterns\n\n"
                "```yaml\n"
                "miss_pattern_id: pattern-one\n"
                "source_backed: true\n"
                "```\n\n"
                "```yaml\n"
                "miss_pattern_id: pattern-two\n"
                "source_backed: false\n"
                "```\n\n"
                "```yaml\n"
                "miss_pattern_id: pattern-three\n"
                "source_backed: true\n"
                "```\n",
            )
            report = tool.mine_workspace(ws)
            pattern_artifacts = [
                a for a in report["artifacts"]
                if a["artifact_type"] == "candidate_detector_pattern"
                and "fund_loss_output" in a.get("provenance_ref", "")
            ]
            self.assertGreater(len(pattern_artifacts), 0)
            # The content should mention the count
            all_content = " ".join(a["content"] for a in pattern_artifacts)
            self.assertIn("3", all_content,
                          "Content should mention count of 3 pattern blocks")

    def test_kill_output_tier3_not_tier2(self) -> None:
        """Provider kill outputs without local proof are tier-3, not tier-2."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._make_slice_output(
                ws,
                "slice2_minimax_liquidation_kill_output.md",
                "## Proposal A: Floor division in liquidation\n\n"
                "**Verdict: KILL**\n\n"
                "FP: EIP-4626 mandates floor division, so this fires on all vaults.\n",
            )
            report = tool.mine_workspace(ws)
            kill_entries = [
                a for a in report["artifacts"]
                if a["artifact_type"] == "kill_rubric_entry"
            ]
            self.assertGreater(len(kill_entries), 0)
            for entry in kill_entries:
                self.assertNotEqual(
                    entry["verification_tier"],
                    "tier-1-verified-realtime-api",
                    "Provider-only kill output must not be tier-1",
                )
                self.assertNotEqual(
                    entry["verification_tier"],
                    "tier-2-verified-public-archive",
                    "Provider-only kill output must not be tier-2",
                )


class TestHandoffDocMining(unittest.TestCase):
    """Claude/Codex handoff docs are mined for hacker questions and roadmap gaps."""

    def _make_handoff(self, ws: Path, content: str, subdir: str = "docs/archive/handoffs",
                      name: str = "OPERATOR_HANDOFF_ITER10.md") -> Path:
        doc_dir = ws / subdir
        doc_dir.mkdir(parents=True, exist_ok=True)
        path = doc_dir / name
        path.write_text(content, encoding="utf-8")
        return path

    def test_handoff_doc_roadmap_gap(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._make_handoff(ws,
                "# Operator Handoff Iter 10\n\n"
                "## Next session\n\n"
                "- Follow-up: verify the token whitelist guard is not bypassed via delegate.\n"
                "- Next loop: re-run commit mining with backward=90 on spark/watchchain.\n"
                "- TODO: build harness for LEAD COMMIT-RESUME.\n"
            )
            report = tool.mine_workspace(ws)
            roadmap_gaps = [
                a for a in report["artifacts"]
                if a["artifact_type"] == "roadmap_gap"
            ]
            self.assertGreater(len(roadmap_gaps), 0,
                               "Handoff doc with TODO/next-loop should produce roadmap_gap")

    def test_handoff_doc_hacker_question(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            self._make_handoff(ws,
                "# Handover Doc\n\n"
                "## Verification Followups\n\n"
                "Needs local verification: confirm that the admin rescue path\n"
                "is not guarded by a timelock in production deployment.\n"
                "Local verify cmd: rg 'timelock' src/*.sol\n"
            )
            report = tool.mine_workspace(ws)
            hacker_qs = [
                a for a in report["artifacts"]
                if a["artifact_type"] == "candidate_hacker_question"
            ]
            self.assertGreater(len(hacker_qs), 0,
                               "Handoff doc with local verification followups should produce "
                               "candidate_hacker_question")

    def test_agent_outputs_handoff_doc_mined(self) -> None:
        """Handoff docs directly in agent_outputs/ are also picked up."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            ao = ws / "agent_outputs"
            ao.mkdir(parents=True, exist_ok=True)
            (ao / "r113_hacker_handoff_advisory.md").write_text(
                "# R113 Handoff\n\n"
                "## Next iteration\n\n"
                "- TODO: pass hacker_question_seeds back to the exploit queue.\n"
                "- Follow-up: check if the bridge proof domain can be replayed.\n",
                encoding="utf-8",
            )
            report = tool.mine_workspace(ws)
            gap_artifacts = [
                a for a in report["artifacts"]
                if a["artifact_type"] in ("roadmap_gap", "candidate_hacker_question")
                and "handoff" in a.get("provenance_ref", "").lower()
            ]
            self.assertGreater(len(gap_artifacts), 0,
                               "agent_outputs/ handoff doc should produce roadmap_gap or "
                               "candidate_hacker_question")


class TestNewOutputTypes(unittest.TestCase):
    """All new normalized output types are producible."""

    def test_kill_rubric_entry_type_exists_in_schema(self) -> None:
        """kill_rubric_entry is a valid output type (produced by kill output mining)."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            ao = ws / "agent_outputs"
            ao.mkdir(parents=True, exist_ok=True)
            (ao / "slice1_minimax_test_kill_output.md").write_text(
                "## Proposal A\n\n**Verdict: KILL**\nFP: guarded internally.\n",
                encoding="utf-8",
            )
            report = tool.mine_workspace(ws)
            types_present = {a["artifact_type"] for a in report["artifacts"]}
            self.assertIn("kill_rubric_entry", types_present)

    def test_triager_pattern_type_from_report_md(self) -> None:
        """triager_pattern is produced when a REPORT.md has triager feedback language."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            rd = ws / "agent_outputs" / "round5_cantina_resubmit" / "REPORT.md"
            rd.parent.mkdir(parents=True)
            rd.write_text(
                "# Resubmit Report\n\n"
                "**VERDICT: NEGATIVE** - Triager closed as OOS.\n\n"
                "## Triager feedback\n\n"
                'The triager comment: "unsophisticated/generic DoS without '
                'demonstrated production impact".\n'
                "Triager closed for generic DoS, no in-scope production impact.\n",
                encoding="utf-8",
            )
            report = tool.mine_workspace(ws)
            types_present = {a["artifact_type"] for a in report["artifacts"]}
            self.assertIn("triager_pattern", types_present,
                          "REPORT.md with triager feedback must produce triager_pattern")

    def test_provider_calibration_row_type_from_work_queue(self) -> None:
        """provider_calibration_row is produced from provider_normalized_work_queue.jsonl."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            rd = ws / "reports"
            rd.mkdir(parents=True, exist_ok=True)
            (rd / "provider_normalized_work_queue.jsonl").write_text(
                json.dumps({
                    "dedup_key": "abc123",
                    "disposition": "KEEP",
                    "normalized_type": "candidate_detector_generalization",
                    "provider": "kimi",
                    "model": "kimi-for-coding",
                    "task_type": "source-extract",
                    "output_path": "agent_outputs/x.md",
                    "local_verification_command": "rg 'foo' --glob '*.sol'",
                }) + "\n",
                encoding="utf-8",
            )
            report = tool.mine_workspace(ws)
            types_present = {a["artifact_type"] for a in report["artifacts"]}
            self.assertIn("provider_calibration_row", types_present)

    def test_exploit_queue_enrichment_type_from_work_queue(self) -> None:
        """exploit_queue_enrichment is produced from KEEP rows in normalized work queue."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            rd = ws / "reports"
            rd.mkdir(parents=True, exist_ok=True)
            (rd / "provider_normalized_work_queue.jsonl").write_text(
                json.dumps({
                    "dedup_key": "abc456",
                    "disposition": "SOURCE_NEEDED",
                    "normalized_type": "verified_source_fact_pending_local_check",
                    "provider": "kimi",
                    "model": "kimi-for-coding",
                    "task_type": "source-extract",
                    "attack_class": "bridge-proof-domain-bypass",
                    "output_path": "agent_outputs/kimi_bridge_output.md",
                    "local_verification_command": "rg 'processMessage' --glob '*.sol'",
                }) + "\n",
                encoding="utf-8",
            )
            report = tool.mine_workspace(ws)
            types_present = {a["artifact_type"] for a in report["artifacts"]}
            self.assertIn("exploit_queue_enrichment", types_present)

    def test_all_7_output_types_producible(self) -> None:
        """All 7 normalized output types can be produced by mine_workspace."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            ao = ws / "agent_outputs"
            ao.mkdir(parents=True, exist_ok=True)
            rd = ws / "reports"
            rd.mkdir(parents=True, exist_ok=True)

            # 1. candidate_detector_pattern + 2. falsification_template + 3. triager_pattern
            #    + known_limitation from REPORT.md
            report_md = ao / "round1_test_lane" / "REPORT.md"
            report_md.parent.mkdir(parents=True)
            report_md.write_text(
                "# Test Lane Report\n\n"
                "**VERDICT: NEGATIVE** - no finding.\n\n"
                "KILL: candidate 1 is OOS - no direct fund loss.\n"
                "FAIL: assertion failed - negative control confirmed.\n"
                "detector pattern: missing reentrancy guard on withdraw.\n"
                "## Triager feedback\n\n"
                'Triager closed for generic DoS.\n'
                "## Capability Lesson\n\n"
                "For keeper-level bugs, always exercise FinalizeBlock path.\n",
                encoding="utf-8",
            )

            # 4. kill_rubric_entry from slice subagent kill output
            (ao / "slice1_minimax_reentrancy_kill_output.md").write_text(
                "## Proposal A\n\n**Verdict: KILL**\nFP: guarded by nonReentrant.\n",
                encoding="utf-8",
            )

            # 5. provider_calibration_row + 6. exploit_queue_enrichment from work queue
            (rd / "provider_normalized_work_queue.jsonl").write_text(
                json.dumps({
                    "dedup_key": "abc789",
                    "disposition": "KEEP",
                    "normalized_type": "candidate_detector_generalization",
                    "provider": "kimi",
                    "model": "kimi-for-coding",
                    "task_type": "source-extract",
                    "attack_class": "admin-bypass",
                    "output_path": "agent_outputs/kimi_output.md",
                    "local_verification_command": "rg 'onlyOwner' --glob '*.sol'",
                }) + "\n",
                encoding="utf-8",
            )

            # 7. candidate_hacker_question from provider text with local_verification_required
            prov_dir = ao / "provider_outputs"
            prov_dir.mkdir(parents=True)
            (prov_dir / "hacker_question_fixture.txt").write_text(
                json.dumps([{
                    "id": "HQ-1",
                    "verdict": "Kill",
                    "local_verification_required": True,
                    "notes": "Admin can drain user deposits via rescue without whitelist.",
                    "minimum_followup_check": "Confirm no token whitelist in rescue path.",
                }]),
                encoding="utf-8",
            )

            report = tool.mine_workspace(ws)
            types_present = {a["artifact_type"] for a in report["artifacts"]}

            expected_types = {
                "candidate_detector_pattern",  # from REPORT.md detector signal + kill output
                "falsification_template",      # from REPORT.md PoC-fail signal
                "kill_rubric_entry",           # from slice kill output
                "triager_pattern",             # from REPORT.md triager feedback
                "provider_calibration_row",    # from work queue
                "exploit_queue_enrichment",    # from work queue KEEP row
                "candidate_hacker_question",   # from provider text local_verification_required
            }
            for expected_type in expected_types:
                self.assertIn(
                    expected_type,
                    types_present,
                    f"Expected output type '{expected_type}' not produced",
                )

    def test_schema_version_is_v2(self) -> None:
        """Schema version must be v2 after Lane 13 extension."""
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            report = tool.mine_workspace(ws)
            self.assertEqual(report["schema_version"], "auditooor.agent_artifact_mining.v2")


class TestNoLearningReasonOnTrulyEmptyWorkspace(unittest.TestCase):
    """NO_LEARNING_REASON=True only on a workspace with literally no artifacts."""

    def test_truly_empty_workspace(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            # Only create the directory structure with no content
            (ws / "agent_outputs").mkdir()
            (ws / "reports").mkdir()
            report = tool.mine_workspace(ws)
            self.assertTrue(
                report["no_learning_reason"],
                "A workspace with empty dirs and no files should set no_learning_reason=True",
            )
            self.assertEqual(report["total_artifacts"], 0)


class TestAuditooorSourceFamilyMining(unittest.TestCase):
    """Planned .auditooor sidecar families are inventoried and mined."""

    def test_auditooor_source_families_are_inventoried_and_mined(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            auditooor = ws / ".auditooor"
            finalization = auditooor / "finalization"
            source_artifacts = auditooor / "source_artifacts"
            finalization.mkdir(parents=True)
            source_artifacts.mkdir(parents=True)

            (finalization / "current_manifest.json").write_text(
                json.dumps(
                    {
                        "status": "blocked",
                        "open_blockers": ["missing production path proof"],
                        "artifacts": [],
                    }
                ),
                encoding="utf-8",
            )
            (auditooor / "exploit_conversion_loop.json").write_text(
                json.dumps(
                    {
                        "strict_stop_reason": "blocked on harness",
                        "steps": [
                            {"name": "source", "status": "pass"},
                            {"name": "harness", "status": "blocked"},
                            {"name": "provider", "status": "skipped"},
                        ],
                        "hard_failures": ["no execution manifest"],
                    }
                ),
                encoding="utf-8",
            )
            (auditooor / "harness_execution_queue.json").write_text(
                json.dumps(
                    {
                        "rows": [
                            {"candidate_id": "C-1", "status": "ready"},
                            {"candidate_id": "C-2", "status": "blocked"},
                        ]
                    }
                ),
                encoding="utf-8",
            )
            (source_artifacts / "complete.json").write_text(
                json.dumps({"source_artifacts_complete": True, "test_command": "go test ./..."}),
                encoding="utf-8",
            )
            (source_artifacts / "blocked.md").write_text(
                "needs-source: missing production call path\nsource_artifacts_complete: false\n",
                encoding="utf-8",
            )

            summary = tool.artifact_input_summary(ws)
            self.assertEqual(summary["input_file_count"], 5)
            self.assertEqual(summary["source_counts"][".auditooor/finalization"], 1)
            self.assertEqual(summary["source_counts"][".auditooor/exploit_conversion_loop"], 1)
            self.assertEqual(summary["source_counts"][".auditooor/harness_execution_queue"], 1)
            self.assertEqual(summary["source_counts"][".auditooor/source_artifacts"], 2)
            self.assertEqual(summary["scanner_counts"]["finalization_manifest"], 1)
            self.assertEqual(summary["scanner_counts"]["exploit_conversion_loop"], 1)
            self.assertEqual(summary["scanner_counts"]["harness_execution_queue"], 1)
            self.assertEqual(summary["scanner_counts"]["source_artifact"], 2)

            report = tool.mine_workspace(ws)
            artifacts_by_type = {}
            for artifact in report["artifacts"]:
                artifacts_by_type.setdefault(artifact["artifact_type"], []).append(artifact)

            self.assertIn("roadmap_gap", artifacts_by_type)
            self.assertIn("known_limitation", artifacts_by_type)
            self.assertIn("proof_artifact_mapping_candidate", artifacts_by_type)
            self.assertIn("harness_template_request", artifacts_by_type)
            self.assertTrue(
                any(a["verdict"] == "EXPLOIT_CONVERSION_BLOCKED" for a in report["artifacts"])
            )
            self.assertTrue(any(a["verdict"] == "HARNESS_READY" for a in report["artifacts"]))
            self.assertTrue(
                any(a["verdict"] == "SOURCE_ARTIFACT_COMPLETE" for a in report["artifacts"])
            )
            self.assertTrue(
                any(a["verdict"] == "SOURCE_ARTIFACT_BLOCKED" for a in report["artifacts"])
            )


if __name__ == "__main__":
    unittest.main()
