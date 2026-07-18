#!/usr/bin/env python3
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tools.control.gaps import SCHEMA, score_known_capability_gaps


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


class ControlGapScoringTests(unittest.TestCase):
    def test_scores_known_gap_categories_from_explicit_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            status = {
                "workspace": str(ws),
                "rust_workspace": True,
                "high_impact_workspace": True,
                "readiness": {"severity": {"status": "missing"}},
                "artifacts": {
                    "scan_report": {"exists": False, "status": "missing"},
                    "static_analysis_summary": {"exists": False, "status": "missing"},
                    "rust_scan_summary": {"exists": False, "status": "missing"},
                    "invariant_ledger": {"exists": False, "status": "missing"},
                },
                "provider_routing": {"kimi": "unverified"},
            }
            candidates = [
                {
                    "id": "C-HIGH",
                    "status": "paste_ready",
                    "severity": "High",
                    "impact": "",
                    "proof_state": "scaffolded",
                    "paste_ready_blockers": ["missing_poc_result", "missing_recommended_fix"],
                    "source": "kimi provider packet",
                }
            ]
            runs = [
                {
                    "tool": "rust-scan",
                    "artifact_path": "scanners/rust/SCAN_RUST_SUMMARY.json",
                    "execution_state": "blocked",
                    "blockers": ["missing_semgrep"],
                    "warnings": [],
                },
                {
                    "tool": "poc-execution",
                    "artifact_path": "poc_execution/C-HIGH/execution_manifest.json",
                    "execution_state": "blocked",
                    "proof_counted": False,
                    "blockers": ["final_result_blocked_path"],
                    "warnings": [],
                },
            ]
            actions = [
                {"reason": "Rust/DLT workspace is missing the canonical Rust scan summary", "command": "scan-rust"},
                {"reason": "candidate C-HIGH is missing executed test output", "command": "record-poc"},
            ]
            dirty = [
                {
                    "path": "tools/control/status.py",
                    "status": "tracked_modified",
                    "role": "source_code",
                }
            ]

            report = score_known_capability_gaps(
                ws,
                status=status,
                candidates=candidates,
                runs=runs,
                next_actions=actions,
                dirty_files=dirty,
            )

        self.assertEqual(report["schema"], SCHEMA)
        by_category = {row["category"]: row for row in report["rows"]}
        self.assertEqual(by_category["scanner_recall"]["priority"], "P0")
        self.assertIn("missing_semgrep", "\n".join(by_category["scanner_recall"]["evidence"]))
        self.assertEqual(by_category["invariant_autoseeding"]["priority"], "P1")
        self.assertEqual(by_category["impact_contract_gating"]["priority"], "P0")
        self.assertEqual(by_category["provider_routing"]["priority"], "P2")
        self.assertEqual(by_category["dirty_workspace_hygiene"]["priority"], "P1")

        row_ids = {row["id"] for row in report["rows"]}
        self.assertIn("harness_execution_replay:C-HIGH", row_ids)
        self.assertIn("harness_execution_replay:blocked-runs", row_ids)
        self.assertIn("submission_paste_readiness:C-HIGH", row_ids)
        self.assertGreaterEqual(report["counts_by_priority"]["P0"], 4)

    def test_workspace_discovery_stays_evidence_based(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            for name in ("SCOPE.md", "OOS_PASTED.md", "SEVERITY.md", "RUBRIC_COVERAGE.md"):
                (ws / name).write_text("real content\n", encoding="utf-8")
            (ws / "scan_report.md").write_text("DONE\n", encoding="utf-8")
            (ws / "static-analysis-summary.md").write_text("DONE\n", encoding="utf-8")
            (ws / ".auditooor").mkdir()
            (ws / ".auditooor" / "semantic_graph.json").write_text("{}", encoding="utf-8")
            control_dir = ws / ".auditooor" / "control" / "candidates"
            control_dir.mkdir(parents=True)
            _write_json(
                control_dir / "ready.json",
                {
                    "id": "ready",
                    "title": "Ready candidate",
                    "status": "candidate",
                    "severity": "Medium",
                    "likelihood": "High",
                    "impact": "temporary denial of service",
                    "oos_checked": True,
                    "inline_poc_ready": True,
                    "poc_command": "forge test --match-test testReady",
                    "poc_result": "1 passed, 0 failed, 0 skipped",
                    "recommended_fix": "validate inputs",
                },
            )
            _write_json(
                ws / "poc_execution" / "ready" / "execution_manifest.json",
                {
                    "candidate_id": "ready",
                    "final_result": "proved",
                    "impact_assertion": "exploit_impact",
                    "evidence_class": "executed_with_manifest",
                    "commands_attempted": [
                        {
                            "command": "forge test --match-test testReady",
                            "status": "pass",
                            "exit_code": 0,
                        }
                    ],
                },
            )

            report = score_known_capability_gaps(ws)

        self.assertEqual(report["gap_count"], 0)
        self.assertEqual(report["counts_by_priority"], {"P0": 0, "P1": 0, "P2": 0})
        self.assertEqual(report["rows"], [])

    def test_does_not_invent_provider_or_dirty_gaps_without_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            report = score_known_capability_gaps(
                ws,
                status={"artifacts": {}, "readiness": {}},
                candidates=[],
                runs=[],
                next_actions=[],
            )

        self.assertEqual(report["gap_count"], 0)


if __name__ == "__main__":
    unittest.main()
