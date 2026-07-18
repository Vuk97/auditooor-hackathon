#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "auditooorctl.py"
SCHEMA = ROOT / "docs" / "schemas" / "auditooor_control_state_v1.json"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.control.gaps import render_human as render_gap_report  # noqa: E402
from tools.control.gaps import score_known_capability_gaps  # noqa: E402
from tools.control.providers import build_provider_tasks, calibrate_provider_tasks  # noqa: E402
from tools.control.runner import (  # noqa: E402
    CLASS_BLOCKED,
    CLASS_PROOF_RECORDING,
    CLASS_SAFE_LOCAL,
    build_execution_plan,
)


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _write_json(path: Path, payload: Any) -> None:
    _write(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def _ctl(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _load_json(stdout: str) -> dict[str, Any]:
    payload = json.loads(stdout)
    if not isinstance(payload, dict):
        raise AssertionError("expected JSON object")
    return payload


def _required_top_level_keys(schema_path: Path) -> set[str]:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    return set(schema["required"])


class ControlIntegrationTests(unittest.TestCase):
    def test_synthetic_workspace_exercises_control_plane_end_to_end_offline(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "synthetic-audit"
            ws.mkdir()
            _populate_synthetic_workspace(ws)

            status_human = _ctl("status", str(ws)).stdout
            status = _load_json(_ctl("status", str(ws), "--json").stdout)
            candidates_payload = _load_json(_ctl("candidates", str(ws), "--json").stdout)
            runs = _load_json(_ctl("runs", str(ws), "--json").stdout)
            next_payload = _load_json(_ctl("next", str(ws), "--json").stdout)
            snapshot = _load_json(_ctl("snapshot", str(ws)).stdout)

            out = ws / ".auditooor" / "control" / "state.json"
            persisted_snapshot = _load_json(_ctl("snapshot", str(ws), "--out", str(out)).stdout)
            handoff = _ctl("handoff", str(ws), "--audience", "codex").stdout

            self.assertIn("scope", status_human)
            self.assertEqual(status["schema"], "auditooor.control.status.v1")
            self.assertEqual(status["readiness"]["scope"]["status"], "ready")
            self.assertEqual(status["readiness"]["severity"]["status"], "ready")
            self.assertEqual(status["artifacts"]["semantic_graph"]["status"], "present")

            by_candidate = {row["id"]: row for row in candidates_payload["candidates"]}
            self.assertEqual(by_candidate["amp-zero"]["paste_ready_blockers"], [])
            self.assertIn("missing_poc_command", by_candidate["oracle-lag"]["paste_ready_blockers"])
            self.assertIn("missing_poc_result", by_candidate["oracle-lag"]["paste_ready_blockers"])
            self.assertIn("provider packet: kimi source-extract", json.dumps(by_candidate["oracle-lag"]))

            self.assertGreaterEqual(runs["artifact_count"], 5)
            self.assertEqual(runs["proof_counted"]["true"], 1)
            self.assertGreaterEqual(runs["counts_by_tool"]["live-topology"], 1)
            self.assertGreaterEqual(runs["counts_by_tool"]["poc-execution"], 1)

            reasons = "\n".join(row["reason"] for row in next_payload["actions"])
            self.assertIn("candidate oracle-lag is missing an inline PoC", reasons)
            self.assertIn("candidate oracle-lag is missing executed test output", reasons)
            self.assertNotIn("candidate amp-zero is missing executed test output", reasons)

            self.assertEqual(snapshot["schema"], "auditooor.control.state.v1")
            self.assertTrue(_required_top_level_keys(SCHEMA).issubset(snapshot))
            self.assertEqual(snapshot["runs"]["proof_counted"]["true"], 1)
            self.assertEqual(persisted_snapshot, json.loads(out.read_text(encoding="utf-8")))

            gaps = score_known_capability_gaps(
                ws,
                status=snapshot["status"],
                candidates=snapshot["candidates"],
                runs=snapshot["runs"]["rows"],
                next_actions=snapshot["next_actions"],
            )
            gap_report = render_gap_report(gaps)
            gap_categories = {row["category"] for row in gaps["rows"]}
            self.assertIn("harness_execution_replay", gap_categories)
            self.assertIn("provider_routing", gap_categories)
            self.assertIn("submission_paste_readiness", gap_categories)
            self.assertIn("known capability gaps:", gap_report)

            provider_tasks = calibrate_provider_tasks(
                build_provider_tasks(
                    ws,
                    candidates=snapshot["candidates"],
                    runs=snapshot["runs"]["rows"],
                    next_actions=snapshot["next_actions"],
                )
            )
            provider_kinds = {(task["provider"], task["task_kind"], task["subject_id"]) for task in provider_tasks}
            self.assertIn(("codex", "proof-gate", "amp-zero"), provider_kinds)
            self.assertIn(("kimi", "source-extract", "oracle-lag"), provider_kinds)
            self.assertIn(("minimax", "adversarial-kill", "oracle-lag"), provider_kinds)
            self.assertIn(("claude", "harness-plan", "oracle-lag"), provider_kinds)
            self.assertTrue(
                any(
                    task["provider"] == "kimi"
                    and task["calibration_status"] == "blocked"
                    and "provider_output_advisory_only" in task["calibration_blockers"]
                    for task in provider_tasks
                )
            )

            runner_plan = build_execution_plan(ws, snapshot["next_actions"], cwd=ROOT)
            self.assertEqual(runner_plan["schema"], "auditooor.control.execution_plan.v1")
            self.assertTrue(runner_plan["dry_run"])
            self.assertFalse(runner_plan["would_execute"])
            self.assertGreaterEqual(runner_plan["counts_by_classification"][CLASS_SAFE_LOCAL], 1)
            self.assertGreaterEqual(runner_plan["counts_by_classification"][CLASS_PROOF_RECORDING], 1)

            blocked_plan = build_execution_plan(
                ws,
                [{"priority": 99, "reason": "blocked smoke", "command": "git push origin HEAD"}],
                cwd=ROOT,
            )
            self.assertEqual(blocked_plan["counts_by_classification"][CLASS_BLOCKED], 1)
            self.assertEqual(blocked_plan["commands"][0]["blockers"], ["git_push_blocked"])

            self.assertIn("Audience: codex", handoff)
            self.assertIn("amp-zero: Medium, submitted; gates present", handoff)
            self.assertIn("oracle-lag: High, candidate; missing inline PoC, test output", handoff)
            self.assertIn("WS=<workspace>", handoff)


def _populate_synthetic_workspace(ws: Path) -> None:
    _write(ws / "SCOPE.md", "# Scope\nSynthetic contracts are in scope.\n")
    _write(ws / "OOS.md", "# OOS\nFrontend-only issues are out of scope.\n")
    _write(ws / "OOS_PASTED.md", "# OOS\nFrontend-only issues are out of scope.\n")
    _write(ws / "SEVERITY.md", "# Severity\nHigh: fund loss. Medium: pool liveness.\n")
    _write(ws / "RUBRIC_COVERAGE.md", "# Coverage\nListed impacts are mapped.\n")
    _write(ws / "engage_report.md", "DONE WITH WARNINGS\n")
    _write(ws / "scan_report.md", "DONE\n")
    _write(ws / "static-analysis-summary.md", "DONE\n")
    _write_json(ws / ".auditooor" / "semantic_graph.json", {"entrypoints": ["swap", "updateOracle"]})
    _write_json(ws / ".auditooor" / "invariant_ledger.json", {"rows": []})
    _write_json(
        ws / "scanners" / "rust" / "SCAN_RUST_SUMMARY.json",
        {"status": "success", "missing_tools": []},
    )
    _write_json(
        ws / ".audit_logs" / "audit_deep_all_manifest.json",
        {"profiles": [{"profile": "default", "status": "success", "exit_code": 0}]},
    )
    _write_json(
        ws / "live_topology_checks.json",
        {
            "rows": [
                {
                    "id": "live-1",
                    "execution_state": "executed",
                    "result": "pass",
                    "block_number": 123,
                }
            ]
        },
    )
    (ws / "submissions").mkdir()
    _write_json(
        ws / ".auditooor" / "control" / "candidates" / "amp-zero.json",
        {
            "schema": "auditooor.candidate.v1",
            "id": "amp-zero",
            "title": "Zero amplification blocks swaps",
            "status": "submitted",
            "severity": "Medium",
            "likelihood": "Medium",
            "impact": "pool liveness failure",
            "inline_poc_ready": True,
            "poc_command": "forge test --match-path test/AmpZero.t.sol -vv",
            "poc_result": "1 passed, 0 failed, 0 skipped",
            "oos_checked": True,
            "proof_state": "proved",
            "recommended_fix": "reject baseAmp == 0",
            "source_paths": ["src/AmpPool.sol"],
        },
    )
    _write_json(
        ws / ".auditooor" / "control" / "candidates" / "oracle-lag.json",
        {
            "schema": "auditooor.candidate.v1",
            "id": "oracle-lag",
            "title": "Oracle lag can stale liquidations",
            "status": "candidate",
            "severity": "High",
            "likelihood": "Medium",
            "impact": "incorrect liquidation at stale price",
            "oos_checked": True,
            "proof_state": "planned",
            "recommended_fix": "bound oracle staleness",
            "source_paths": ["src/Oracle.sol", "provider packet: kimi source-extract"],
            "blockers": ["kimi_provider_packet_unverified"],
        },
    )
    _write_json(
        ws / "poc_execution" / "amp-zero" / "execution_manifest.json",
        {
            "candidate_id": "amp-zero",
            "final_result": "proved",
            "impact_assertion": "exploit_impact",
            "evidence_class": "executed_with_manifest",
            "commands_attempted": [
                {
                    "command": "forge test --match-path test/AmpZero.t.sol -vv",
                    "status": "pass",
                    "exit_code": 0,
                }
            ],
        },
    )


if __name__ == "__main__":
    unittest.main()
