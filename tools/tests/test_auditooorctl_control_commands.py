#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "auditooorctl.py"
MAKEFILE = ROOT / "Makefile"


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _run(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _run_make(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["make", "-f", str(MAKEFILE), *args],
        cwd=ROOT,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


class TestAuditooorctlControlCommands(unittest.TestCase):
    def test_candidates_runs_next_and_handoff_share_normalized_state(self) -> None:
        with TemporaryDirectory() as td:
            ws = Path(td) / "demo"
            ws.mkdir()
            _write(ws / "SCOPE.md", "# Scope\nsrc only\n")
            _write(ws / "OOS.md", "# OOS\nfrontend\n")
            _write(ws / "SEVERITY.md", "# Severity\nMedium: pool liveness\n")
            _write(ws / "RUBRIC_COVERAGE.md", "# Coverage\nmapped\n")
            _write(
                ws / ".auditooor" / "control" / "candidates" / "amp-zero.json",
                json.dumps(
                    {
                        "id": "amp-zero",
                        "title": "zero amp blocks swaps",
                        "status": "submitted",
                        "severity": "Medium",
                        "likelihood": "Medium",
                        "impact": "pool liveness failure",
                        "inline_poc_ready": True,
                        "poc_command": "forge test --match-path test/AmpZero.t.sol -vv",
                        "poc_result": "PASS",
                        "oos_checked": True,
                        "recommended_fix": "reject baseAmp == 0",
                    }
                ),
            )
            _write(
                ws / "poc_execution" / "amp-zero" / "execution_manifest.json",
                json.dumps(
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
                    }
                ),
            )

            candidate_payload = json.loads(_run("candidates", str(ws), "--json").stdout)
            self.assertEqual(candidate_payload["candidates"][0]["id"], "amp-zero")
            self.assertEqual(candidate_payload["candidates"][0]["paste_ready_blockers"], [])

            runs_payload = json.loads(_run("runs", str(ws), "--json").stdout)
            self.assertEqual(runs_payload["proof_counted"]["true"], 1)

            next_payload = json.loads(_run("next", str(ws), "--json").stdout)
            reasons = "\n".join(action["reason"] for action in next_payload["actions"])
            self.assertNotIn("candidate amp-zero is missing an inline PoC", reasons)
            self.assertNotIn("candidate amp-zero is missing executed test output", reasons)

            snapshot_payload = json.loads(_run("snapshot", str(ws)).stdout)
            self.assertEqual(snapshot_payload["schema"], "auditooor.control.state.v1")
            self.assertEqual(snapshot_payload["candidates"][0]["paste_ready_blockers"], [])
            self.assertEqual(snapshot_payload["runs"]["proof_counted"]["true"], 1)

            out = ws / ".auditooor" / "control" / "state.json"
            self.assertFalse(out.exists())
            out_payload = json.loads(_run("snapshot", str(ws), "--out", str(out)).stdout)
            self.assertEqual(out_payload["schema"], "auditooor.control.state.v1")
            self.assertEqual(json.loads(out.read_text(encoding="utf-8"))["schema"], "auditooor.control.state.v1")

            handoff = _run("handoff", str(ws), "--audience", "claude").stdout
            self.assertIn("Audience: claude", handoff)
            self.assertIn("amp-zero: Medium, submitted; gates present", handoff)

    def test_dirty_command_is_read_only_and_reports_untracked_files(self) -> None:
        with TemporaryDirectory() as td:
            repo = Path(td) / "repo"
            repo.mkdir()
            subprocess.run(["git", "init"], cwd=repo, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            _write(repo / "agent_outputs" / "lane.md", "done\n")

            payload = json.loads(_run("dirty", str(repo), "--json").stdout)
            self.assertEqual(payload["schema"], "auditooor.control.dirty.v1")
            self.assertEqual(payload["dirty_files"][0]["path"], "agent_outputs/lane.md")
            self.assertEqual(payload["dirty_files"][0]["role"], "agent_output")

    def test_gaps_providers_and_plan_are_snapshot_backed_and_read_only_by_default(self) -> None:
        with TemporaryDirectory() as td:
            ws = Path(td) / "demo"
            ws.mkdir()
            _write(ws / "SCOPE.md", "# Scope\nsrc only\n")
            _write(ws / "OOS_PASTED.md", "# OOS\nfrontend\n")
            _write(ws / "SEVERITY.md", "# Severity\nHigh: permanent funds locked\n")
            _write(ws / "RUBRIC_COVERAGE.md", "# Coverage\nmapped\n")
            _write(
                ws / ".auditooor" / "control" / "candidates" / "oracle-stale.json",
                json.dumps(
                    {
                        "id": "oracle-stale",
                        "title": "oracle stale price path",
                        "status": "candidate",
                        "severity": "High",
                        "impact": "permanent funds locked",
                        "proof_state": "planned",
                        "source_paths": ["src/Oracle.sol", "provider-packets/kimi/oracle-stale.md"],
                    }
                ),
            )
            default_plan_out = ws / ".auditooor" / "control" / "plan.json"
            self.assertFalse(default_plan_out.exists())

            gaps_payload = json.loads(_run("gaps", str(ws), "--json").stdout)
            self.assertEqual(gaps_payload["schema"], "auditooor.control.gaps.v1")
            gap_ids = {row["id"] for row in gaps_payload["rows"]}
            self.assertIn("harness_execution_replay:oracle-stale", gap_ids)
            self.assertIn("provider_routing", gap_ids)

            providers_payload = json.loads(_run("providers", str(ws), "--json").stdout)
            self.assertEqual(providers_payload["schema"], "auditooor.control.providers.v1")
            provider_kinds = {(row["provider"], row["task_kind"]) for row in providers_payload["tasks"]}
            self.assertIn(("kimi", "source-extract"), provider_kinds)
            self.assertIn(("minimax", "adversarial-kill"), provider_kinds)
            self.assertIn(("claude", "harness-plan"), provider_kinds)
            kimi_task = [row for row in providers_payload["tasks"] if row["provider"] == "kimi"][0]
            self.assertEqual(kimi_task["calibration_status"], "blocked")
            self.assertIn("provider_output_advisory_only", kimi_task["calibration_blockers"])

            plan_payload = json.loads(_run("plan", str(ws), "--json").stdout)
            self.assertEqual(plan_payload["schema"], "auditooor.control.execution_plan.v1")
            self.assertTrue(plan_payload["dry_run"])
            self.assertFalse(plan_payload["would_execute"])
            self.assertGreater(plan_payload["command_count"], 0)
            self.assertFalse(default_plan_out.exists())

            explicit_out = ws / ".auditooor" / "control" / "dry-run-plan.json"
            out_payload = json.loads(_run("plan", str(ws), "--out", str(explicit_out), "--json").stdout)
            self.assertEqual(out_payload["schema"], "auditooor.control.execution_plan.v1")
            self.assertEqual(json.loads(explicit_out.read_text(encoding="utf-8"))["schema"], "auditooor.control.execution_plan.v1")

            human_gaps = _run("gaps", str(ws)).stdout
            human_providers = _run("providers", str(ws)).stdout
            human_plan = _run("plan", str(ws)).stdout
            self.assertIn("known capability gaps:", human_gaps)
            self.assertIn("provider tasks:", human_providers)
            self.assertIn("dry-run commands:", human_plan)

            report_payload = json.loads(_run("report", str(ws), "--json").stdout)
            report_markdown = _run("report", str(ws)).stdout
            self.assertEqual(report_payload["schema"], "auditooor.control.report.v1")
            self.assertIn("# Control Takeover Packet: demo", report_markdown)
            self.assertIn("## Proof Boundary", report_markdown)

    def test_workpacks_command_and_make_target_are_snapshot_backed(self) -> None:
        with TemporaryDirectory() as td:
            ws = Path(td) / "demo"
            ws.mkdir()
            _write(ws / "SCOPE.md", "# Scope\nsrc only\n")
            _write(ws / "OOS_PASTED.md", "# OOS\nfrontend\n")
            _write(ws / "SEVERITY.md", "# Severity\nHigh: permanent funds locked\n")
            _write(ws / "RUBRIC_COVERAGE.md", "# Coverage\nmapped\n")
            _write(
                ws / ".auditooor" / "control" / "candidates" / "oracle-stale.json",
                json.dumps(
                    {
                        "id": "oracle-stale",
                        "title": "oracle stale price path",
                        "status": "candidate",
                        "severity": "High",
                        "impact": "permanent funds locked",
                        "proof_state": "planned",
                        "source_paths": ["src/Oracle.sol", "provider-packets/kimi/oracle-stale.md"],
                    }
                ),
            )
            default_out = ws / "provider_workpacks"
            explicit_out = ws / ".auditooor" / "control" / "workpacks.json"
            self.assertFalse(default_out.exists())

            payload = json.loads(_run("workpacks", str(ws), "--json").stdout)
            self.assertEqual(payload["schema"], "auditooor.control.workpacks.v1")
            self.assertGreater(payload["workpack_count"], 0)
            self.assertIn("kimi", payload["counts_by_provider"])
            self.assertFalse(default_out.exists())
            first_prompt = payload["workpacks"][0]["prompt"]
            self.assertIn("Do not launch workers", first_prompt)
            self.assertIn("Do not promote advisory model text as proof", first_prompt)

            markdown = _run("workpacks", str(ws)).stdout
            self.assertIn("# Control Workpacks", markdown)
            self.assertIn("## workpack:", markdown)
            self.assertFalse(explicit_out.exists())

            make_payload = json.loads(
                _run_make(f"control-workpacks", f"WS={ws}", "JSON=1", f"OUT={explicit_out}").stdout
            )
            self.assertEqual(make_payload["schema"], "auditooor.control.workpacks.v1")
            self.assertEqual(
                json.loads(explicit_out.read_text(encoding="utf-8"))["schema"],
                "auditooor.control.workpacks.v1",
            )
            self.assertFalse(default_out.exists())

    def test_followup_commands_are_safe_local_planners(self) -> None:
        with TemporaryDirectory() as td:
            ws = Path(td) / "demo"
            ws.mkdir()
            _write(ws / "SCOPE.md", "# Scope\nsrc only\n")
            _write(ws / "OOS_PASTED.md", "# OOS\nfrontend\n")
            _write(ws / "SEVERITY.md", "# Severity\nHigh: chain split\n")
            _write(ws / "RUBRIC_COVERAGE.md", "# Coverage\nmapped\n")
            candidate_file = ws / ".auditooor" / "wave-l1" / "promotion_candidates.json"
            _write(
                candidate_file,
                json.dumps(
                    {
                        "schema": "auditooor.upstream_equivalent_gate.v1",
                        "candidate_id": "L1-HARDFORK-PRECOMPILE-MISMATCH-56381928",
                        "title": "P256VERIFY zkVM/EL divergence",
                        "severity": "High",
                        "impact": "Chain-level fork or CL/EL state divergence",
                        "gate": {"status": "pass", "checks_passed": 5},
                        "source_paths": ["crates/succinct/utils/client/src/precompiles/mod.rs"],
                    }
                ),
            )

            normalized = json.loads(_run("candidates", str(ws), "--normalize", "--json").stdout)
            self.assertEqual(normalized["schema"], "auditooor.control.normalized_candidates.v1")
            self.assertEqual(normalized["candidate_count"], 1)
            self.assertEqual(normalized["candidates"][0]["id"], "l1-hardfork-precompile-mismatch-56381928")
            self.assertEqual(normalized["candidates"][0]["status"], "pass")
            self.assertEqual(normalized["candidates"][0]["gate"]["gate"]["status"], "pass")
            self.assertIn("normalized candidates:", _run("candidates", str(ws), "--normalize").stdout)

            open_state_path = ws / ".auditooor" / "control" / "state.json"
            open_preview = json.loads(_run("open", str(ws), "--json").stdout)
            self.assertIsNone(open_preview["path"])
            self.assertEqual(open_preview["state"]["schema"], "auditooor.control.open_state.v1")
            self.assertFalse(open_state_path.exists())
            open_written = json.loads(_run("open", str(ws), "--write", "--json").stdout)
            self.assertEqual(open_written["state"]["schema"], "auditooor.control.open_state.v1")
            self.assertTrue(open_state_path.exists())

            gate_out = ws / ".auditooor" / "control" / "run_gate" / "plan.json"
            gate = json.loads(
                _run("run-gate", str(ws), "--candidate-file", str(candidate_file), "--out", str(gate_out), "--json").stdout
            )
            self.assertEqual(gate["schema"], "auditooor.control.run_gate.v1")
            self.assertTrue(gate["dry_run"])
            self.assertFalse(gate["would_execute"])
            self.assertEqual(gate["candidate_id"], "L1-HARDFORK-PRECOMPILE-MISMATCH-56381928")
            self.assertEqual(json.loads(gate_out.read_text(encoding="utf-8"))["schema"], "auditooor.control.run_gate.v1")

            timeline_out = ws / ".auditooor" / "control" / "timeline.json"
            timeline = json.loads(
                _run(
                    "deployment-timeline",
                    str(ws),
                    "--repo",
                    str(ws / "missing-repo"),
                    "--bug-commit",
                    "162f87c5",
                    "--out",
                    str(timeline_out),
                    "--json",
                ).stdout
            )
            self.assertEqual(timeline["schema"], "auditooor.control.deployment_timeline.v1")
            self.assertIn("asset_repo_not_found", timeline["uncertainty_flags"])
            self.assertEqual(
                json.loads(timeline_out.read_text(encoding="utf-8"))["schema"],
                "auditooor.control.deployment_timeline.v1",
            )


if __name__ == "__main__":
    unittest.main()
