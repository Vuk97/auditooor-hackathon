from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "agent-artifact-lesson-candidates.py"


def load_tool():
    spec = importlib.util.spec_from_file_location("agent_artifact_lesson_candidates", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["agent_artifact_lesson_candidates"] = module
    spec.loader.exec_module(module)
    return module


def write_report(ws: Path, artifacts: list[dict]) -> Path:
    report = ws / "agent_artifact_mining_report.json"
    report.write_text(
        json.dumps(
            {
                "schema_version": "auditooor.agent_artifact_mining.v2",
                "workspace": str(ws),
                "total_artifacts": len(artifacts),
                "artifacts": artifacts,
            }
        ),
        encoding="utf-8",
    )
    return report


class AgentArtifactLessonCandidateTest(unittest.TestCase):
    def test_actual_exploit_or_proof_outcome_precedes_generic_agent_note(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory(prefix="aalc_primary_") as td:
            ws = Path(td)
            agent_outputs = ws / "agent_outputs"
            agent_outputs.mkdir()
            (agent_outputs / "capability_summary.md").write_text(
                "# Generic Agent Note\n\n"
                "Capability lesson: strict execution manifests are useful, but this note has no proof transcript.\n",
                encoding="utf-8",
            )
            write_report(
                ws,
                [
                    {
                        "artifact_id": "aam-primary",
                        "artifact_type": "proof_artifact_mapping_candidate",
                        "title": "Passing PoC artifact for strict execution manifest",
                        "content": "PoC transcript has final_result=proved and evidence_class=executed_with_manifest.",
                        "provenance_ref": "poc_execution/strict_manifest/execution_manifest.json",
                        "verdict": "POC_PASS",
                        "verification_tier": "tier-2-verified-public-archive",
                        "source_has_local_proof": True,
                    },
                    {
                        "artifact_id": "aam-note",
                        "artifact_type": "known_limitation",
                        "title": "Generic strict execution manifest note",
                        "content": "Worker note says strict manifests may be useful.",
                        "provenance_ref": "agent_outputs/capability_summary.md",
                        "verdict": "HANDOFF_LESSON",
                        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                        "source_has_local_proof": False,
                    },
                ],
            )

            payload = tool.extract_lesson_candidates(ws, limit=10)

            self.assertGreaterEqual(payload["total_candidates"], 2)
            first = payload["candidates"][0]
            self.assertEqual(first["evidence_tier"], "primary")
            self.assertEqual(first["lesson_kind"], "proof_artifact")
            self.assertEqual(first["confidence"], "high")
            self.assertTrue(first["required_human_review"])
            self.assertFalse(first["candidate_truth_claim"])

    def test_agent_output_summary_proof_words_remain_secondary(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory(prefix="aalc_summary_secondary_") as td:
            ws = Path(td)
            agent_outputs = ws / "agent_outputs"
            agent_outputs.mkdir()
            (agent_outputs / "final_report.md").write_text(
                "# Worker Final\n\n"
                "Lesson: final_result=proved in a worker note is not primary proof by itself.\n",
                encoding="utf-8",
            )

            payload = tool.extract_lesson_candidates(ws, limit=10)

            self.assertEqual(payload["total_candidates"], 1)
            candidate = payload["candidates"][0]
            self.assertEqual(candidate["evidence_tier"], "secondary")
            self.assertEqual(candidate["confidence"], "low")
            self.assertTrue(candidate["provenance"][0]["primary_signal_unverified"])
            self.assertFalse(candidate["candidate_truth_claim"])

    def test_unsupported_agent_artifact_is_low_confidence_and_review_required(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory(prefix="aalc_unsupported_") as td:
            ws = Path(td)
            write_report(
                ws,
                [
                    {
                        "artifact_id": "aam-unsupported",
                        "artifact_type": "candidate_detector_pattern",
                        "title": "Provider-only detector hunch",
                        "content": "Provider-only text suggests a missing guard, with no local proof binding.",
                        "provenance_ref": "agent_outputs/provider_outputs/minimax.txt",
                        "verdict": "PROVIDER_DETECTOR_SIGNAL",
                        "verification_tier": "tier-5-quarantine",
                        "source_has_local_proof": False,
                        "provider_only": True,
                    }
                ],
            )

            payload = tool.extract_lesson_candidates(ws, limit=10)

            self.assertEqual(payload["total_candidates"], 1)
            candidate = payload["candidates"][0]
            self.assertEqual(candidate["evidence_tier"], "quarantine")
            self.assertEqual(candidate["confidence"], "low")
            self.assertLess(candidate["confidence_score"], 0.3)
            self.assertTrue(candidate["required_human_review"])
            self.assertTrue(candidate["advisory_only"])
            self.assertFalse(candidate["promotion_authority"])

    def test_output_is_bounded_by_limit(self) -> None:
        tool = load_tool()
        with tempfile.TemporaryDirectory(prefix="aalc_bounded_") as td:
            ws = Path(td)
            artifacts = []
            for idx in range(12):
                artifacts.append(
                    {
                        "artifact_id": f"aam-{idx}",
                        "artifact_type": "known_limitation",
                        "title": f"Workflow lesson {idx}",
                        "content": f"Agent summary found follow-up workflow blocker {idx}.",
                        "provenance_ref": f"agent_outputs/summary_{idx}.md",
                        "verdict": "HANDOFF_LESSON",
                        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                        "source_has_local_proof": False,
                    }
                )
            write_report(ws, artifacts)

            payload = tool.extract_lesson_candidates(ws, limit=5)

            self.assertEqual(payload["total_candidates"], 5)
            self.assertEqual(payload["total_candidates_unbounded"], 12)
            self.assertTrue(payload["bounded"])


if __name__ == "__main__":
    unittest.main()
