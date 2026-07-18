#!/usr/bin/env python3
"""Tests for agent-recall-replay.py.

Covers:
  1. All agent-found behaviors detectorized  -> recall_rate 1.0
  2. Mixed workspace with a recall gap       -> gap behavior listed with durable_route
  3. Empty workspace                         -> graceful zeroed result
  4. Required schema fields present
  5. Attention-metric disclaimer present
  6. Durable route classification (detector_gap vs source_review)
  7. Provider-only / quarantine artifacts excluded from agent-found count
  8. Pre-existing mining report loaded instead of re-running miner
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "agent-recall-replay.py"


def _load_module():
    """Load agent-recall-replay as a module."""
    spec = importlib.util.spec_from_file_location("agent_recall_replay", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    # Avoid polluting sys.modules across tests
    sys.modules["agent_recall_replay"] = module
    spec.loader.exec_module(module)
    return module


def _write_mining_report(ws: Path, artifacts: list[dict]) -> None:
    """Write a pre-built agent_artifact_mining.json into the workspace."""
    reports = ws / "reports"
    reports.mkdir(parents=True, exist_ok=True)
    (reports / "agent_artifact_mining.json").write_text(
        json.dumps(
            {
                "schema_version": "auditooor.agent_artifact_mining.v1",
                "workspace": str(ws),
                "generated_at": "2026-05-19T00:00:00+00:00",
                "total_artifacts": len(artifacts),
                "no_learning_reason": len(artifacts) == 0,
                "artifact_type_counts": {},
                "artifacts": artifacts,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------


class TestEmptyWorkspace(unittest.TestCase):
    """Empty workspace returns a valid zeroed report without crashing."""

    def test_empty_workspace_zeroed_result(self) -> None:
        m = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            report = m.replay(ws)
            self.assertEqual(report["total_agent_found_behaviors"], 0)
            self.assertEqual(report["detectorized_count"], 0)
            self.assertEqual(report["non_detectorized_count"], 0)
            self.assertEqual(report["recall_rate"], 0.0)
            self.assertEqual(report["recall_gap_behaviors"], [])
            self.assertEqual(report["detectorized_behaviors"], [])

    def test_empty_workspace_schema_fields(self) -> None:
        m = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            report = m.replay(ws)
            required_fields = [
                "schema_version",
                "workspace",
                "generated_at",
                "attention_metric_only",
                "total_agent_found_behaviors",
                "detectorized_count",
                "non_detectorized_count",
                "recall_rate",
                "recall_rate_pct",
                "detector_artifacts_present",
                "recall_gap_behaviors",
                "detectorized_behaviors",
                "gap_rows_truncated",
                "gap_rows_total",
            ]
            for field in required_fields:
                self.assertIn(field, report, f"Missing required field: {field}")

    def test_schema_version(self) -> None:
        m = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            report = m.replay(Path(tmp))
            self.assertEqual(report["schema_version"], "auditooor.agent_recall_replay.v1")

    def test_attention_metric_disclaimer_present(self) -> None:
        m = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            report = m.replay(Path(tmp))
            disclaimer = report.get("attention_metric_only", "")
            self.assertIn("proof signal", disclaimer.lower(),
                          "attention_metric_only disclaimer must mention 'proof signal'")
            self.assertIn("recall", disclaimer.lower())


class TestAllDetectorized(unittest.TestCase):
    """When every agent-found behavior has a detector hit, recall_rate is 1.0."""

    def _make_detectorized_artifact(self, idx: int) -> dict:
        return {
            "artifact_id": f"aam-detectorized-{idx:04d}",
            "artifact_type": "candidate_detector_pattern",
            "title": f"Detectorized behavior {idx}",
            "content": (
                f"Agent claude found a missing-guard at foo.go:{idx}. "
                f"Detector scanner slither fired on this pattern."
            ),
            "provenance_ref": f"agent_outputs/lane{idx}/REPORT.md",
            "verdict": "NEGATIVE",
            "verification_tier": "tier-2-verified-public-archive",
            "source_has_local_proof": True,
            # Explicit detector hit field
            "detector_hits": ["slither:missing-guard"],
        }

    def test_all_detectorized_recall_rate_1(self) -> None:
        m = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            artifacts = [self._make_detectorized_artifact(i) for i in range(5)]
            _write_mining_report(ws, artifacts)
            report = m.replay(ws)
            self.assertEqual(report["total_agent_found_behaviors"], 5)
            self.assertEqual(report["detectorized_count"], 5)
            self.assertEqual(report["non_detectorized_count"], 0)
            self.assertEqual(report["recall_rate"], 1.0)
            self.assertEqual(report["recall_rate_pct"], 100.0)
            self.assertEqual(report["recall_gap_behaviors"], [])

    def test_detectorized_behaviors_list_populated(self) -> None:
        m = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            artifacts = [self._make_detectorized_artifact(i) for i in range(3)]
            _write_mining_report(ws, artifacts)
            report = m.replay(ws)
            self.assertEqual(len(report["detectorized_behaviors"]), 3)
            for row in report["detectorized_behaviors"]:
                self.assertEqual(row["detector_status"], "found")


class TestRecallGap(unittest.TestCase):
    """When an agent-found behavior has no detector hit, it appears in recall_gap_behaviors."""

    def _make_gap_artifact(
        self,
        idx: int,
        artifact_type: str = "candidate_hacker_question",
    ) -> dict:
        return {
            "artifact_id": f"aam-gap-{idx:04d}",
            "artifact_type": artifact_type,
            "title": f"Gap behavior {idx}",
            "content": (
                f"Claude source-reader found that foo.go:{idx} is missing "
                f"a bounds check. No detector fired on this path."
            ),
            "provenance_ref": f"agent_outputs/lane{idx}/REPORT.md",
            "verdict": "NEGATIVE",
            "verification_tier": "tier-3-synthetic-taxonomy-anchored",
            "source_has_local_proof": False,
        }

    def _make_detectorized_artifact(self, idx: int) -> dict:
        return {
            "artifact_id": f"aam-det-{idx:04d}",
            "artifact_type": "candidate_detector_pattern",
            "title": f"Detectorized {idx}",
            "content": "Agent found; scanner semgrep also found this.",
            "provenance_ref": f"agent_outputs/lane{idx}/REPORT.md",
            "verdict": "CANDIDATE",
            "verification_tier": "tier-2-verified-public-archive",
            "source_has_local_proof": True,
            "detector_hits": ["semgrep:no-overflow-guard"],
        }

    def test_recall_gap_behavior_listed(self) -> None:
        m = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            artifacts = [
                self._make_detectorized_artifact(0),
                self._make_gap_artifact(1),
                self._make_gap_artifact(2),
            ]
            _write_mining_report(ws, artifacts)
            report = m.replay(ws)
            self.assertEqual(report["total_agent_found_behaviors"], 3)
            self.assertEqual(report["detectorized_count"], 1)
            self.assertEqual(report["non_detectorized_count"], 2)
            self.assertAlmostEqual(report["recall_rate"], 1 / 3, places=3)
            self.assertEqual(len(report["recall_gap_behaviors"]), 2)

    def test_gap_row_has_required_fields(self) -> None:
        m = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_mining_report(ws, [self._make_gap_artifact(0)])
            report = m.replay(ws)
            self.assertEqual(len(report["recall_gap_behaviors"]), 1)
            row = report["recall_gap_behaviors"][0]
            for field in (
                "behavior_id",
                "artifact_type",
                "impact_family",
                "provenance_ref",
                "verification_tier",
                "durable_route",
                "detector_status",
                "content_summary",
            ):
                self.assertIn(field, row, f"Gap row missing field: {field}")
            self.assertEqual(row["detector_status"], "not_found")

    def test_gap_row_durable_route_source_review_for_hacker_question(self) -> None:
        m = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_mining_report(ws, [self._make_gap_artifact(0, "candidate_hacker_question")])
            report = m.replay(ws)
            row = report["recall_gap_behaviors"][0]
            self.assertEqual(row["durable_route"], "source_review")

    def test_gap_row_durable_route_detector_gap_for_pattern_artifact(self) -> None:
        m = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            # candidate_detector_pattern without detector_hits -> recall gap, detector_gap route.
            # Title and content deliberately omit 'detector'/'scanner'/'semgrep'
            # keywords so the regex path does not misclassify this as detectorized.
            art = {
                "artifact_id": "aam-seed-gap-0001",
                "artifact_type": "candidate_detector_pattern",
                "title": "Pattern seed from claude source-reader - not yet fired",
                "content": (
                    "Claude source-reader found missing bounds check at foo.go:42. "
                    "No automated tool fired on this path. Seed queued for instrumentation."
                ),
                "provenance_ref": "agent_outputs/lane0/REPORT.md",
                "verdict": "NEGATIVE",
                "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                "source_has_local_proof": False,
                # No detector_hits / scanner_hits / scan_hits field
            }
            _write_mining_report(ws, [art])
            report = m.replay(ws)
            self.assertEqual(len(report["recall_gap_behaviors"]), 1)
            row = report["recall_gap_behaviors"][0]
            self.assertEqual(row["durable_route"], "detector_gap")


class TestProviderOnlyExclusion(unittest.TestCase):
    """Provider-only / quarantine artifacts should NOT register as agent-found behaviors."""

    def test_quarantine_artifact_not_counted(self) -> None:
        m = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            # tier-5-quarantine artifact with no agent hint signal
            art = {
                "artifact_id": "aam-quarantine-0001",
                "artifact_type": "rejection_pattern",
                "title": "Provider kill verdict (provider-only)",
                "content": (
                    "Kill verdict: KILL. Notes: OOS. "
                    "IMPORTANT: local_verification_required=false; "
                    "this is a PROVIDER-ONLY artifact."
                ),
                "provenance_ref": "agent_outputs/provider_outputs/kill.txt",
                "verdict": "PROVIDER_ONLY",
                "verification_tier": "tier-5-quarantine",
                "source_has_local_proof": False,
                "provider_only": True,
                # No 'agent', 'claude', 'codex' etc. mention - not agent-found
            }
            _write_mining_report(ws, [art])
            report = m.replay(ws)
            # Quarantine artifact has no AGENT_HINT_RE signal -> not counted
            self.assertEqual(report["total_agent_found_behaviors"], 0)


class TestPreExistingMiningReport(unittest.TestCase):
    """A pre-existing mining report is loaded without re-running the miner."""

    def test_reports_subdir_loaded(self) -> None:
        m = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            art = {
                "artifact_id": "aam-preexisting-0001",
                "artifact_type": "known_limitation",
                "title": "Pre-existing mining result",
                "content": "Claude agent found a known limitation in the harness.",
                "provenance_ref": "agent_outputs/lane0/REPORT.md",
                "verdict": "NEGATIVE",
                "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                "source_has_local_proof": False,
            }
            _write_mining_report(ws, [art])
            # Should load from reports/agent_artifact_mining.json, not re-run miner
            report = m.replay(ws)
            self.assertEqual(report["total_agent_found_behaviors"], 1)

    def test_auditooor_subdir_fallback(self) -> None:
        m = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            art = {
                "artifact_id": "aam-auditooor-0001",
                "artifact_type": "harness_template_request",
                "title": "Harness request from agent output",
                "content": "Claude agent blocked on harness for go test.",
                "provenance_ref": "agent_outputs/lane0/REPORT.md",
                "verdict": "BLOCKED",
                "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                "source_has_local_proof": False,
            }
            # Write to .auditooor/ instead of reports/
            auditooor_dir = ws / ".auditooor"
            auditooor_dir.mkdir(parents=True, exist_ok=True)
            (auditooor_dir / "agent_artifact_mining.json").write_text(
                json.dumps(
                    {
                        "schema_version": "auditooor.agent_artifact_mining.v1",
                        "workspace": str(ws),
                        "generated_at": "2026-05-19T00:00:00+00:00",
                        "total_artifacts": 1,
                        "no_learning_reason": False,
                        "artifact_type_counts": {},
                        "artifacts": [art],
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            report = m.replay(ws)
            self.assertEqual(report["total_agent_found_behaviors"], 1)


class TestGapRowsTruncation(unittest.TestCase):
    """Gap rows list is bounded at MAX_GAP_ROWS."""

    def test_large_gap_list_is_truncated(self) -> None:
        m = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            # 60 gap artifacts (> MAX_GAP_ROWS=50)
            artifacts = []
            for i in range(60):
                artifacts.append(
                    {
                        "artifact_id": f"aam-gap-{i:04d}",
                        "artifact_type": "candidate_hacker_question",
                        "title": f"Gap {i}",
                        "content": f"Claude source-reader found an issue at line {i}.",
                        "provenance_ref": f"agent_outputs/lane{i}/REPORT.md",
                        "verdict": "NEGATIVE",
                        "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                        "source_has_local_proof": False,
                    }
                )
            _write_mining_report(ws, artifacts)
            report = m.replay(ws)
            self.assertEqual(report["non_detectorized_count"], 60)
            self.assertEqual(report["gap_rows_total"], 60)
            self.assertTrue(report["gap_rows_truncated"])
            self.assertLessEqual(len(report["recall_gap_behaviors"]), 50)


class TestRecallRateArithmetic(unittest.TestCase):
    """Recall rate arithmetic is correct and rounded consistently."""

    def test_recall_rate_two_thirds(self) -> None:
        m = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            artifacts = [
                {
                    "artifact_id": "aam-det-0001",
                    "artifact_type": "candidate_detector_pattern",
                    "content": "Agent claude found; scanner semgrep fired.",
                    "provenance_ref": "agent_outputs/a/REPORT.md",
                    "verdict": "CANDIDATE",
                    "verification_tier": "tier-2-verified-public-archive",
                    "source_has_local_proof": True,
                    "detector_hits": ["semgrep:foo"],
                },
                {
                    "artifact_id": "aam-det-0002",
                    "artifact_type": "candidate_detector_pattern",
                    "content": "Agent codex found; scanner slither fired.",
                    "provenance_ref": "agent_outputs/b/REPORT.md",
                    "verdict": "CANDIDATE",
                    "verification_tier": "tier-2-verified-public-archive",
                    "source_has_local_proof": True,
                    "detector_hits": ["slither:bar"],
                },
                {
                    "artifact_id": "aam-gap-0003",
                    "artifact_type": "candidate_hacker_question",
                    "content": "Claude source-reader found a gap. No scanner fired.",
                    "provenance_ref": "agent_outputs/c/REPORT.md",
                    "verdict": "NEGATIVE",
                    "verification_tier": "tier-3-synthetic-taxonomy-anchored",
                    "source_has_local_proof": False,
                },
            ]
            _write_mining_report(ws, artifacts)
            report = m.replay(ws)
            self.assertEqual(report["total_agent_found_behaviors"], 3)
            self.assertEqual(report["detectorized_count"], 2)
            self.assertEqual(report["non_detectorized_count"], 1)
            self.assertAlmostEqual(report["recall_rate"], 2 / 3, places=3)
            self.assertAlmostEqual(report["recall_rate_pct"], 66.67, places=1)


if __name__ == "__main__":
    unittest.main()
