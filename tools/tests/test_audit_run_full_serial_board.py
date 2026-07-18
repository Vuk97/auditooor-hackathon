from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "audit-run-full-serial-board.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("audit_run_full_serial_board", TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load audit-run-full-serial-board.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


BOARD = _load_tool()


def _write_manifest(ws: Path, rows: list[dict[str, object]]) -> None:
    path = ws / ".auditooor" / "audit_run_full_manifest.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


class AuditRunFullSerialBoardTest(unittest.TestCase):
    def test_active_process_wins(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "hyperbridge"
            ws.mkdir()
            _write_manifest(
                ws,
                [
                    {"event": "start", "run_id": "run-1", "workspace": str(ws)},
                    {"event": "stage-start", "run_id": "run-1", "stage": "hunt-full"},
                ],
            )
            ps = f"123 00:05 make audit-run-full WS={ws} STRICT=1\n"
            row = BOARD.summarize_workspace(ws, ps_text=ps)
            self.assertEqual(row["state"], "running")
            self.assertEqual(row["next_action"], "wait-active")
            self.assertEqual(row["active_stage"], "hunt-full")
            self.assertEqual(row["active_processes"][0]["pid"], "123")

    def test_process_detection_ignores_workspace_path_prefix_collision(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "foo"
            ws.mkdir()
            ps = f"123 00:05 make audit-run-full WS={ws}-old STRICT=1\n"
            self.assertEqual(BOARD.active_serial_processes_from_ps(ps, ws), [])

    def test_process_detection_ignores_prompt_text_containing_command(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "foo"
            ws.mkdir()
            ps = f"123 00:05 python3 tools/llm-dispatch.py --prompt run make audit-run-full WS={ws}\n"
            self.assertEqual(BOARD.active_serial_processes_from_ps(ps, ws), [])

    def test_process_detection_ignores_search_commands_containing_command(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "foo"
            ws.mkdir()
            ps = f"123 00:05 rg make audit-run-full WS={ws} reports/\n"
            self.assertEqual(BOARD.active_serial_processes_from_ps(ps, ws), [])

    def test_process_detection_ignores_make_dry_run(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "foo"
            ws.mkdir()
            ps = f"123 00:05 make -n audit-run-full WS={ws} STRICT=1\n"
            self.assertEqual(BOARD.active_serial_processes_from_ps(ps, ws), [])

    def test_process_detection_accepts_make_with_cwd_flag(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "foo"
            ws.mkdir()
            ps = f"123 00:05 /usr/bin/make -C /Users/wolf/auditooor-mcp audit-run-full WS={ws}\n"
            self.assertEqual(len(BOARD.active_serial_processes_from_ps(ps, ws)), 1)

    def test_complete_manifest_needs_status_check_without_live_status(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "morpho-midnight"
            ws.mkdir()
            _write_manifest(
                ws,
                [
                    {"event": "start", "run_id": "run-1", "workspace": str(ws)},
                    {
                        "event": "complete",
                        "run_id": "run-1",
                        "deep_engine_freshness_verdict": "pass-fresh-deep-manifest",
                    },
                ],
            )
            row = BOARD.summarize_workspace(ws, ps_text="")
            self.assertEqual(row["state"], "complete")
            self.assertEqual(row["next_action"], "certification-check")
            self.assertIn("audit-run-full-status.py", row["next_command"])

    def test_mcp_failure_points_to_refresh(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "dydx"
            ws.mkdir()
            _write_manifest(
                ws,
                [
                    {"event": "start", "run_id": "run-1", "workspace": str(ws)},
                    {"event": "stage-start", "run_id": "run-1", "stage": "mcp-preflight"},
                    {"event": "stage-fail", "run_id": "run-1", "stage": "mcp-preflight", "rc": 1},
                ],
            )
            row = BOARD.summarize_workspace(ws, ps_text="")
            self.assertEqual(row["state"], "failed")
            self.assertEqual(row["next_action"], "refresh-mcp-preflight")
            self.assertIn("auditooor-session-start.sh", row["next_command"])

    def test_intake_failure_points_to_intake_repair(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "near"
            ws.mkdir()
            _write_manifest(
                ws,
                [
                    {"event": "start", "run_id": "run-1", "workspace": str(ws)},
                    {"event": "stage-fail", "run_id": "run-1", "stage": "intake-truth", "rc": 2},
                ],
            )
            row = BOARD.summarize_workspace(ws, ps_text="")
            self.assertEqual(row["next_action"], "repair-intake")
            self.assertIn("--stage intake-baseline", row["next_command"])

    def test_hunt_full_failure_points_to_hunt_completeness(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "zebra"
            ws.mkdir()
            _write_manifest(
                ws,
                [
                    {"event": "start", "run_id": "run-1", "workspace": str(ws)},
                    {"event": "stage-fail", "run_id": "run-1", "stage": "hunt-full", "rc": 2},
                ],
            )
            row = BOARD.summarize_workspace(ws, ps_text="")
            self.assertEqual(row["next_action"], "recheck-hunt-completeness")
            self.assertIn("hunt-completeness-check.py", row["next_command"])

    def test_hunt_coverage_failure_uses_read_only_status_command(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "zebra"
            ws.mkdir()
            _write_manifest(
                ws,
                [
                    {"event": "start", "run_id": "run-1", "workspace": str(ws)},
                    {"event": "stage-fail", "run_id": "run-1", "stage": "hunt-coverage", "rc": 2},
                ],
            )
            row = BOARD.summarize_workspace(ws, ps_text="")
            self.assertEqual(row["next_action"], "inspect-hunt-coverage")
            self.assertIn("audit-run-full-status.py", row["next_command"])
            self.assertNotIn("hunt-coverage-gate.py", row["next_command"])

    def test_mcp_failure_marks_mutating_command_kind(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "dydx"
            ws.mkdir()
            _write_manifest(
                ws,
                [
                    {"event": "start", "run_id": "run-1", "workspace": str(ws)},
                    {"event": "stage-fail", "run_id": "run-1", "stage": "mcp-preflight", "rc": 1},
                ],
            )
            row = BOARD.summarize_workspace(ws, ps_text="")
            self.assertEqual(row["next_action"], "refresh-mcp-preflight")
            self.assertEqual(row["next_command_kind"], "workspace-mutating")

    def test_operator_repair_sidecars_are_reported_with_provenance(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "dydx"
            auditooor = ws / ".auditooor"
            auditooor.mkdir(parents=True)
            _write_manifest(
                ws,
                [
                    {"event": "start", "run_id": "run-1", "workspace": str(ws)},
                    {"event": "stage-fail", "run_id": "run-1", "stage": "hunt-full", "rc": 2},
                ],
            )
            (auditooor / "dydx_next_audit_run_command_20260601.json").write_text(
                json.dumps({
                    "next_command": "make audit WS=/tmp/dydx",
                    "safe_to_run_without_touching_submissions": True,
                    "blockers": ["hunt-complete is failing"],
                }),
                encoding="utf-8",
            )
            (auditooor / "dydx_repair_command_plan_20260601_agent.json").write_text(
                json.dumps({
                    "minimal_next_command": {
                        "command": "AUDIT_COMMIT_MINING_SKIP=1 make audit WS=/tmp/dydx",
                        "intent": "Refresh baseline audit state",
                        "expected_non_outputs": ["No submission draft edits"],
                    }
                }),
                encoding="utf-8",
            )
            row = BOARD.summarize_workspace(ws, ps_text="")
            repairs = row["operator_repair_commands"]
            self.assertEqual(len(repairs), 2)
            self.assertEqual(repairs[0]["label"], "repair_command")
            self.assertTrue(repairs[0]["safe_to_run_without_touching_submissions"])
            self.assertEqual(repairs[1]["label"], "side_effect_reduced_repair_command")
            rendered = BOARD.render_human([row])
            self.assertIn("Operator repair sidecars:", rendered)
            self.assertIn("make audit WS=/tmp/dydx", rendered)

    def test_live_status_certified_overrides_manifest_action(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "done"
            ws.mkdir()
            action, command, reason = BOARD.classify_next_action(
                ws,
                latest_event="complete",
                latest_stage=None,
                active_stage=None,
                active_processes=[],
                live_status={"certification_complete": True},
            )
            self.assertEqual(action, "certified")
            self.assertIn("audit-run-full-status.py", command)
            self.assertIn("complete", reason)

    def test_live_status_stale_deep_points_to_rerun(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "stale"
            ws.mkdir()
            action, command, reason = BOARD.classify_next_action(
                ws,
                latest_event="stage-pass",
                latest_stage="hunt-full",
                active_stage=None,
                active_processes=[],
                live_status={
                    "certification_complete": False,
                    "live_deep_freshness": {"verdict": "fail-stale-deep-manifest"},
                },
            )
            self.assertEqual(action, "rerun-serial-for-fresh-deep")
            self.assertIn("make audit-run-full", command)
            self.assertIn("stale", reason)

    def test_live_status_bounded_complete_points_to_full_serial_rerun(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "bounded"
            ws.mkdir()
            action, command, reason = BOARD.classify_next_action(
                ws,
                latest_event="bounded-complete",
                latest_stage="deep-freshness",
                active_stage=None,
                active_processes=[],
                live_status={
                    "status": "bounded-complete",
                    "certification_complete": False,
                    "certification_blockers": [
                        "bounded-terminal-not-certifying",
                        "bounded-run",
                    ],
                },
            )
            self.assertEqual(action, "rerun-serial")
            self.assertIn("MAX_FUNCTIONS=0", command)
            self.assertIn("bounded", reason)

    def test_live_status_missing_deep_proof_points_to_fresh_deep_rerun(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "uncertified"
            ws.mkdir()
            action, command, reason = BOARD.classify_next_action(
                ws,
                latest_event="complete",
                latest_stage=None,
                active_stage=None,
                active_processes=[],
                live_status={
                    "status": "uncertified-complete",
                    "certification_complete": False,
                    "certification_blockers": ["missing-current-run-deep-proof"],
                },
            )
            self.assertEqual(action, "rerun-serial-for-fresh-deep")
            self.assertIn("make audit-run-full", command)
            self.assertIn("deep proof", reason)

    def test_stage_warn_without_active_process_is_partial(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "warned"
            ws.mkdir()
            action, command, reason = BOARD.classify_next_action(
                ws,
                latest_event="stage-warn",
                latest_stage="prove-top-leads",
                active_stage=None,
                active_processes=[],
                live_status=None,
            )
            self.assertEqual(action, "inspect-partial-run")
            self.assertIn("audit-run-full-status.py", command)
            self.assertIn("warning", reason)

    def test_discover_workspaces_finds_run_manifests(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "has-run"
            ws.mkdir()
            _write_manifest(ws, [{"event": "start", "run_id": "run-1"}])
            ignored = root / "plain"
            ignored.mkdir()
            found = BOARD.discover_workspaces(root)
            self.assertEqual(found, [ws.resolve()])

    def test_include_no_manifest_discovers_prep_workspace_by_weighted_markers(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "cap-codex95-prep"
            ws.mkdir()
            (ws / "AUDIT_PIN.txt").write_text("abc123\n", encoding="utf-8")
            (ws / "candidate.json").write_text("{}", encoding="utf-8")
            (ws / ".auditooor").mkdir()
            (ws / ".auditooor" / "repo_strategy.json").write_text("{}", encoding="utf-8")
            found = BOARD.discover_workspaces(root, include_no_manifest=True)
            self.assertEqual(found, [ws.resolve()])

    def test_include_no_manifest_excludes_obvious_fixture_names(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            fixture = root / "test-dogfood-r48"
            fixture.mkdir()
            (fixture / "INTAKE_BASELINE.md").write_text("ready\n", encoding="utf-8")
            (fixture / "engage_report.md").write_text("ready\n", encoding="utf-8")
            (fixture / "SEVERITY.md").write_text("ready\n", encoding="utf-8")
            found = BOARD.discover_workspaces(root, include_no_manifest=True)
            self.assertEqual(found, [])

    def test_include_no_manifest_ignores_source_mirror_only_directory(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            mirror = root / "source-mirror"
            mirror.mkdir()
            (mirror / "Cargo.toml").write_text("[workspace]\n", encoding="utf-8")
            found = BOARD.discover_workspaces(root, include_no_manifest=True)
            self.assertEqual(found, [])

    def test_render_human_includes_next_commands(self):
        rows = [
            {
                "name": "zebra",
                "operator_status": "failed",
                "state": "failed",
                "latest_run_id": "run-1",
                "active_stage": None,
                "latest_stage": "hunt-full",
                "next_action": "recheck-hunt-completeness",
                "next_command_kind": "read-only",
                "next_command": "python3 tools/hunt-completeness-check.py /tmp/zebra --json",
            }
        ]
        rendered = BOARD.render_human(rows)
        self.assertIn("workspace", rendered)
        self.assertIn("zebra", rendered)
        self.assertIn("operator_status", rendered)
        self.assertIn("command_kind", rendered)
        self.assertIn("read-only", rendered)
        self.assertIn("next_command", rendered)
        self.assertIn("python3 tools/hunt-completeness-check.py", rendered)

    def test_cli_outputs_json(self):
        with tempfile.TemporaryDirectory(prefix="audit_run_full_serial_board_") as td:
            ws = Path(td) / "cli"
            ws.mkdir()
            _write_manifest(
                ws,
                [{"event": "start", "run_id": "auditrun-cli", "workspace": str(ws)}],
            )
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--json",
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["schema"], "auditooor.audit_run_full_serial_board.v1")
            self.assertEqual(payload["workspaces"][0]["latest_run_id"], "auditrun-cli")

    def test_makefile_wrapper_dry_run_exposes_audits_root_mode(self):
        proc = subprocess.run(
            [
                "make",
                "-n",
                "--no-print-directory",
                "audit-run-full-serial-board",
                "AUDITS_ROOT=/tmp/audits",
                "JSON=1",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        output = proc.stdout + proc.stderr
        self.assertEqual(proc.returncode, 0, output)
        self.assertIn("python3 tools/audit-run-full-serial-board.py", output)
        self.assertIn('--audits-root "/tmp/audits"', output)
        self.assertIn("--json", output)

    def test_makefile_wrapper_dry_run_exposes_workspace_mode(self):
        proc = subprocess.run(
            [
                "make",
                "-n",
                "--no-print-directory",
                "audit-run-full-serial-board",
                "WS=/tmp/a",
                "LIVE_STATUS=1",
                "LIMIT=7",
                "INCLUDE_NO_MANIFEST=1",
                "JSON=1",
            ],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        output = proc.stdout + proc.stderr
        self.assertEqual(proc.returncode, 0, output)
        self.assertIn("python3 tools/audit-run-full-serial-board.py", output)
        self.assertIn('--workspace "/tmp/a"', output)
        self.assertNotIn("--audits-root", output)
        self.assertIn("--live-status", output)
        self.assertIn('--limit "7"', output)
        self.assertIn("--include-no-manifest", output)
        self.assertIn("--json", output)


if __name__ == "__main__":
    unittest.main()
