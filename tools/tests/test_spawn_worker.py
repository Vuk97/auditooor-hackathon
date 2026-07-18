"""test_spawn_worker.py - unit tests for tools/spawn-worker.sh.

iter18 Phase -1 C (WF-7 #2). Closes the Agent-tool spawn surface META-1
gap. Mirrors the structure of test_dispatch_agent_with_prebriefing.py.

Covers:
  1. --help prints usage and exits 0.
  2. Missing required args (--lane-id, --lane-type, --severity,
     --workspace, --prompt-file) each exit 1.
  3. Non-existent prompt-file exits 1.
  4. Invalid severity (e.g. "FOO") exits 1.
  5. Successful run with valid inputs prints enriched-prompt path,
     exit 0; --no-register + --no-prebriefing (with bypass reason).
  6. --no-prebriefing without SPAWN_WORKER_BYPASS_REASON exits 1.
  7. Pathspec registration writes a row into .auditooor/agent_pathspec.json.
  8. Log emission: .auditooor/spawn_worker_log.jsonl gets a single JSON
     row with the required keys.
  9. BEGIN/END marker verification: real prebriefing path produces
     markers_ok=1 in the log.
 10. --strict-markers + raw-prompt + --no-prebriefing exits 0 (we
     bypassed prebriefing so the strict check is a no-op).
 11. --dry-run prints [DRY-RUN] line and does NOT print path on stdout.
 12. --json mode emits a JSON row on stdout.
 13. The enriched prompt file contains the BEGIN marker (full path
     verification via SPAWN_WORKER_TMP_DIR override).
 14. Custom SPAWN_WORKER_LOG_PATH respected.
  15. Dry-run default pathspec registration succeeds for a non-
      Hyperbridge lane/workspace without explicit --pathspec-files.
"""

from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SPAWN_TOOL = REPO_ROOT / "tools" / "spawn-worker.sh"
PATHSPEC_TOOL = REPO_ROOT / "tools" / "agent-pathspec-register.py"


def _run(
    args,
    *,
    env_extra=None,
    cwd=None,
    timeout=60,
):
    """Invoke spawn-worker.sh with given args; return CompletedProcess."""
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        ["bash", str(SPAWN_TOOL), *args],
        env=env,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _write_prompt(dir_path: pathlib.Path, text: str = "test prompt body") -> pathlib.Path:
    p = dir_path / "prompt.md"
    p.write_text(text, encoding="utf-8")
    return p


def _latest_log_row(log_path: pathlib.Path) -> dict:
    rows = [
        json.loads(line)
        for line in log_path.read_text().splitlines()
        if line.strip()
    ]
    if not rows:
        raise AssertionError(f"expected at least one log row in {log_path}")
    return rows[-1]


def _remove_worktree(path: str) -> None:
    if not path:
        return
    worktree_path = pathlib.Path(path)
    if not worktree_path.exists():
        return
    subprocess.run(
        [
            "git",
            "-C",
            str(REPO_ROOT),
            "worktree",
            "remove",
            "--force",
            str(worktree_path),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    subprocess.run(
        ["git", "-C", str(REPO_ROOT), "worktree", "prune"],
        capture_output=True,
        text=True,
        check=False,
    )


def _make_temp_worktree(base_dir: pathlib.Path, name: str) -> pathlib.Path:
    worktree_path = base_dir / name
    subprocess.run(
        [
            "git",
            "-C",
            str(REPO_ROOT),
            "worktree",
            "add",
            "--detach",
            str(worktree_path),
            "HEAD",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return worktree_path


class TestSpawnWorker(unittest.TestCase):
    """Test surface for the Agent-tool spawn wrapper."""

    @classmethod
    def setUpClass(cls):
        if not SPAWN_TOOL.is_file():
            raise unittest.SkipTest(f"spawn-worker.sh missing at {SPAWN_TOOL}")

    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="spawn_worker_test_"))
        # Per-test log path so tests don't collide.
        self.log_path = self.tmp / "spawn_log.jsonl"
        self.spawn_tmp = self.tmp / "spawn_tmp"
        self.spawn_tmp.mkdir(parents=True, exist_ok=True)
        # Per-test pathspec to avoid stomping the repo pathspec.
        self.pathspec_file = self.tmp / "agent_pathspec.json"
        # base env every test inherits
        self.base_env = {
            "SPAWN_WORKER_LOG_PATH": str(self.log_path),
            "SPAWN_WORKER_TMP_DIR": str(self.spawn_tmp),
        }

    def tearDown(self):
        if self.log_path.exists():
            try:
                rows = [
                    json.loads(line)
                    for line in self.log_path.read_text().splitlines()
                    if line.strip()
                ]
                for row in rows:
                    _remove_worktree(row.get("worktree_path", ""))
            except Exception:
                pass
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ------------------------------------------------------------------
    # Test 1: --help
    # ------------------------------------------------------------------
    def test_01_help_prints_usage(self):
        proc = _run(["--help"])
        self.assertEqual(proc.returncode, 0)
        self.assertIn("spawn-worker.sh", proc.stdout)
        self.assertIn("Agent-tool spawn wrapper", proc.stdout)

    # ------------------------------------------------------------------
    # Test 2: missing required args
    # ------------------------------------------------------------------
    def test_02_missing_lane_id_exits_1(self):
        prompt = _write_prompt(self.tmp)
        proc = _run([
            "--lane-type", "hunt",
            "--severity", "HIGH",
            "--workspace", str(self.tmp),
            "--prompt-file", str(prompt),
        ], env_extra=self.base_env)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("missing required arg --lane-id", proc.stderr)

    def test_02b_missing_lane_type_exits_1(self):
        prompt = _write_prompt(self.tmp)
        proc = _run([
            "--lane-id", "TEST",
            "--severity", "HIGH",
            "--workspace", str(self.tmp),
            "--prompt-file", str(prompt),
        ], env_extra=self.base_env)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("missing required arg --lane-type", proc.stderr)

    def test_02c_missing_prompt_file_exits_1(self):
        proc = _run([
            "--lane-id", "TEST",
            "--lane-type", "hunt",
            "--severity", "HIGH",
            "--workspace", str(self.tmp),
        ], env_extra=self.base_env)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("missing required arg --prompt-file", proc.stderr)

    # ------------------------------------------------------------------
    # Test 3: non-existent prompt-file
    # ------------------------------------------------------------------
    def test_03_nonexistent_prompt_file_exits_1(self):
        proc = _run([
            "--lane-id", "TEST",
            "--lane-type", "hunt",
            "--severity", "HIGH",
            "--workspace", str(self.tmp),
            "--prompt-file", str(self.tmp / "does-not-exist.md"),
        ], env_extra=self.base_env)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("prompt-file does not exist", proc.stderr)

    # ------------------------------------------------------------------
    # Test 4: invalid severity
    # ------------------------------------------------------------------
    def test_04_invalid_severity_exits_1(self):
        prompt = _write_prompt(self.tmp)
        proc = _run([
            "--lane-id", "TEST",
            "--lane-type", "hunt",
            "--severity", "EXTRA-HIGH",
            "--workspace", str(self.tmp),
            "--prompt-file", str(prompt),
        ], env_extra=self.base_env)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("severity must be", proc.stderr)

    # ------------------------------------------------------------------
    # Test 5: successful run with --no-register + --no-prebriefing
    # ------------------------------------------------------------------
    def test_05_no_register_no_prebriefing_succeeds(self):
        prompt = _write_prompt(self.tmp, "bypass-mode prompt body")
        env = dict(self.base_env)
        env["SPAWN_WORKER_BYPASS_REASON"] = "unit-test"
        proc = _run([
            "--lane-id", "TEST-BYPASS",
            "--lane-type", "hunt",
            "--severity", "LOW",
            "--workspace", str(self.tmp),
            "--prompt-file", str(prompt),
            "--no-register",
            "--no-prebriefing",
        ], env_extra=env)
        self.assertEqual(proc.returncode, 0)
        # stdout should be a path
        path = proc.stdout.strip().splitlines()[0]
        self.assertTrue(pathlib.Path(path).is_file(),
                        f"enriched file not found at {path}")
        # bypassed prebriefing means content is the raw prompt
        self.assertEqual(pathlib.Path(path).read_text(), "bypass-mode prompt body")

    # ------------------------------------------------------------------
    # Test 6: --no-prebriefing without bypass reason exits 1
    # ------------------------------------------------------------------
    def test_06_no_prebriefing_without_reason_exits_1(self):
        prompt = _write_prompt(self.tmp)
        env = dict(self.base_env)
        # Explicitly clear bypass reason
        env.pop("SPAWN_WORKER_BYPASS_REASON", None)
        proc = _run([
            "--lane-id", "TEST",
            "--lane-type", "hunt",
            "--severity", "HIGH",
            "--workspace", str(self.tmp),
            "--prompt-file", str(prompt),
            "--no-prebriefing",
        ], env_extra=env)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("--no-prebriefing requires SPAWN_WORKER_BYPASS_REASON", proc.stderr)

    # ------------------------------------------------------------------
    # Test 7: pathspec registration produces a row
    # ------------------------------------------------------------------
    def test_07_pathspec_registration_writes_row(self):
        prompt = _write_prompt(self.tmp)
        env = dict(self.base_env)
        env["SPAWN_WORKER_BYPASS_REASON"] = "unit-test"
        worktree = _make_temp_worktree(self.tmp, "repo-worktree-pathspec")
        self.addCleanup(_remove_worktree, str(worktree))
        proc = _run([
            "--lane-id", "TEST-PATHSPEC",
            "--lane-type", "hunt",
            "--severity", "LOW",
            "--workspace", str(self.tmp),
            "--prompt-file", str(prompt),
            "--no-prebriefing",
            "--no-use-worktree",
            "--pathspec-files", "tools/foo.py,docs/bar.md",
        ], env_extra=env, cwd=worktree)
        self.assertEqual(proc.returncode, 0, msg=f"stderr={proc.stderr}")
        # Verify pathspec file contains our lane
        pathspec_file = worktree / ".auditooor" / "agent_pathspec.json"
        data = json.loads(pathspec_file.read_text())
        lane_ids = [a.get("agent_id") for a in data.get("agents", [])]
        self.assertIn("TEST-PATHSPEC", lane_ids)
        self.assertEqual(
            next(a for a in data["agents"] if a["agent_id"] == "TEST-PATHSPEC")["files"],
            ["tools/foo.py", "docs/bar.md"],
        )

    # ------------------------------------------------------------------
    # Test 7b: default sentinel pathspec anchor registers in dry-run
    # ------------------------------------------------------------------
    def test_07b_default_pathspec_registration_uses_workspace_anchor(self):
        worktree = _make_temp_worktree(self.tmp, "repo-worktree-default-anchor")
        self.addCleanup(_remove_worktree, str(worktree))

        workspace = self.tmp / "non_hyperbridge_workspace"
        workspace.mkdir(parents=True, exist_ok=True)
        prompt = _write_prompt(self.tmp, "dry-run prompt body")
        env = dict(self.base_env)
        env["SPAWN_WORKER_BYPASS_REASON"] = "dry-run-default-anchor"
        proc = _run([
            "--lane-id", "NEXT7-NON-HYPERBRIDGE",
            "--lane-type", "tool-build",
            "--severity", "LOW",
            "--workspace", str(workspace),
            "--prompt-file", str(prompt),
            "--no-prebriefing",
            "--dry-run",
        ], env_extra=env, cwd=worktree)
        self.assertEqual(proc.returncode, 0, msg=f"stderr={proc.stderr}")
        self.assertIn("[DRY-RUN]", proc.stdout)
        row = _latest_log_row(self.log_path)
        self.assertEqual(row["pathspec_status"], "registered")

        pathspec_file = worktree / ".auditooor" / "agent_pathspec.json"
        self.assertTrue(pathspec_file.exists(), f"missing pathspec at {pathspec_file}")
        data = json.loads(pathspec_file.read_text())
        lane = next(a for a in data.get("agents", []) if a.get("agent_id") == "NEXT7-NON-HYPERBRIDGE")
        self.assertEqual(len(lane["files"]), 1)
        anchor = pathlib.Path(lane["files"][0])
        self.assertFalse(any(ch in anchor.as_posix() for ch in "*?["))
        self.assertTrue(anchor.is_file(), f"anchor file missing at {anchor}")
        self.assertTrue(str(anchor).startswith(str(workspace / ".auditooor" / "spawn-worker-pathspec")))

    # ------------------------------------------------------------------
    # Test 8: log emission contains required keys
    # ------------------------------------------------------------------
    def test_08_log_row_contains_required_keys(self):
        prompt = _write_prompt(self.tmp)
        env = dict(self.base_env)
        env["SPAWN_WORKER_BYPASS_REASON"] = "unit-test-log"
        proc = _run([
            "--lane-id", "TEST-LOG",
            "--lane-type", "filing",
            "--severity", "MEDIUM",
            "--workspace", str(self.tmp),
            "--prompt-file", str(prompt),
            "--no-register",
            "--no-prebriefing",
        ], env_extra=env)
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(self.log_path.exists(),
                        f"log file missing at {self.log_path}")
        rows = [
            json.loads(line)
            for line in self.log_path.read_text().splitlines()
            if line.strip()
        ]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        required = {
            "ts", "tool", "schema", "lane_id", "lane_type", "severity",
            "workspace", "prompt_file", "enriched_file", "prompt_sha256",
            "pathspec_status", "prebriefing_status", "markers_ok",
            "begin_marker_count", "end_marker_count", "dispatch_guard_env",
            "dispatch_guard_provenance",
        }
        missing = required - set(row.keys())
        self.assertFalse(missing, f"log row missing keys: {missing}")
        self.assertEqual(row["schema"], "auditooor.spawn_worker.v1")
        self.assertEqual(row["tool"], "spawn-worker.sh")
        self.assertEqual(row["lane_id"], "TEST-LOG")
        self.assertEqual(row["lane_type"], "filing")
        self.assertEqual(row["severity"], "MEDIUM")
        self.assertTrue(row["prebriefing_status"].startswith("bypassed:"))
        self.assertEqual(row["dispatch_guard_env"], "AUDITOOOR_SPAWN_WORKER_OK")
        self.assertEqual(row["dispatch_guard_provenance"], "spawn-worker.sh")

    # ------------------------------------------------------------------
    # Test 9: BEGIN/END markers verified on real prebriefing run
    # ------------------------------------------------------------------
    def test_09_markers_ok_on_real_prebriefing(self):
        # This test depends on MCP being reachable. If the prebriefing
        # tool degrades to "fallback-degraded" we still expect the stub
        # block to carry BEGIN/END markers.
        prompt = _write_prompt(self.tmp, "real-mode prompt body")
        proc = _run([
            "--lane-id", "TEST-REAL",
            "--lane-type", "hunt",
            "--severity", "HIGH",
            "--workspace", str(self.tmp),
            "--prompt-file", str(prompt),
            "--no-register",
        ], env_extra=self.base_env)
        self.assertEqual(proc.returncode, 0, msg=f"stderr={proc.stderr}")
        rows = [
            json.loads(line)
            for line in self.log_path.read_text().splitlines()
            if line.strip()
        ]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        # Markers should be present whether real or fallback-degraded.
        # The wrapper's format_skeleton_as_markdown always emits both.
        self.assertEqual(row["markers_ok"], 1,
                         f"markers missing in {row}")
        self.assertGreaterEqual(row["begin_marker_count"], 1)
        self.assertGreaterEqual(row["end_marker_count"], 1)

    # ------------------------------------------------------------------
    # Test 10: --strict-markers + --no-prebriefing succeeds
    # ------------------------------------------------------------------
    def test_10_strict_markers_with_bypass_succeeds(self):
        # --strict-markers checks markers ONLY when prebriefing is enabled.
        # With --no-prebriefing the check is a no-op (we bypassed).
        prompt = _write_prompt(self.tmp)
        env = dict(self.base_env)
        env["SPAWN_WORKER_BYPASS_REASON"] = "test-strict-bypass"
        proc = _run([
            "--lane-id", "TEST-STRICT",
            "--lane-type", "hunt",
            "--severity", "LOW",
            "--workspace", str(self.tmp),
            "--prompt-file", str(prompt),
            "--no-register",
            "--no-prebriefing",
            "--no-use-worktree",
            "--strict-markers",
        ], env_extra=env)
        self.assertEqual(proc.returncode, 0)

    # ------------------------------------------------------------------
    # Test 11: --dry-run mode
    # ------------------------------------------------------------------
    def test_11_dry_run_mode(self):
        prompt = _write_prompt(self.tmp)
        env = dict(self.base_env)
        env["SPAWN_WORKER_BYPASS_REASON"] = "test-dry-run"
        proc = _run([
            "--lane-id", "TEST-DRY",
            "--lane-type", "hunt",
            "--severity", "LOW",
            "--workspace", str(self.tmp),
            "--prompt-file", str(prompt),
            "--no-register",
            "--no-prebriefing",
            "--dry-run",
        ], env_extra=env)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("[DRY-RUN]", proc.stdout)
        # In dry-run mode we should NOT print a bare path.
        path_lines = [l for l in proc.stdout.splitlines() if l.startswith("/")]
        self.assertEqual(len(path_lines), 0,
                         f"dry-run should not emit bare paths: {path_lines}")

    # ------------------------------------------------------------------
    # Test 12: --json mode emits JSON on stdout
    # ------------------------------------------------------------------
    def test_12_json_mode_emits_json(self):
        prompt = _write_prompt(self.tmp)
        env = dict(self.base_env)
        env["SPAWN_WORKER_BYPASS_REASON"] = "test-json"
        proc = _run([
            "--lane-id", "TEST-JSON",
            "--lane-type", "hunt",
            "--severity", "LOW",
            "--workspace", str(self.tmp),
            "--prompt-file", str(prompt),
            "--no-register",
            "--no-prebriefing",
            "--json",
        ], env_extra=env)
        self.assertEqual(proc.returncode, 0)
        # stdout should parse as JSON
        out = proc.stdout.strip()
        self.assertTrue(out)
        data = json.loads(out)
        self.assertEqual(data["lane_id"], "TEST-JSON")
        self.assertEqual(data["schema"], "auditooor.spawn_worker.v1")

    # ------------------------------------------------------------------
    # Test 13: enriched prompt file contains BEGIN marker (full path)
    # ------------------------------------------------------------------
    def test_13_enriched_file_path_correct(self):
        prompt = _write_prompt(self.tmp, "marker-check prompt")
        proc = _run([
            "--lane-id", "TEST-PATH",
            "--lane-type", "hunt",
            "--severity", "HIGH",
            "--workspace", str(self.tmp),
            "--prompt-file", str(prompt),
            "--no-register",
        ], env_extra=self.base_env)
        self.assertEqual(proc.returncode, 0)
        # First stdout line is the path
        path = pathlib.Path(proc.stdout.strip().splitlines()[0])
        self.assertTrue(path.exists(), f"enriched file missing at {path}")
        # Path should be under SPAWN_WORKER_TMP_DIR
        self.assertTrue(str(path).startswith(str(self.spawn_tmp)),
                        f"enriched file {path} not under {self.spawn_tmp}")
        body = path.read_text()
        # BEGIN marker present
        self.assertIn("BEGIN dispatch-agent-with-prebriefing META-1 block", body)
        self.assertIn("END dispatch-agent-with-prebriefing META-1 block", body)
        # Original prompt preserved
        self.assertIn("marker-check prompt", body)

    # ------------------------------------------------------------------
    # Test 14: custom SPAWN_WORKER_LOG_PATH respected
    # ------------------------------------------------------------------
    def test_14_custom_log_path_respected(self):
        prompt = _write_prompt(self.tmp)
        custom_log = self.tmp / "subdir" / "custom_log.jsonl"
        env = dict(self.base_env)
        env["SPAWN_WORKER_LOG_PATH"] = str(custom_log)
        env["SPAWN_WORKER_BYPASS_REASON"] = "custom-log-test"
        proc = _run([
            "--lane-id", "TEST-LOG-CUSTOM",
            "--lane-type", "hunt",
            "--severity", "LOW",
            "--workspace", str(self.tmp),
            "--prompt-file", str(prompt),
            "--no-register",
            "--no-prebriefing",
        ], env_extra=env)
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(custom_log.exists(),
                        f"custom log not at {custom_log}")
        rows = [
            json.loads(line)
            for line in custom_log.read_text().splitlines()
            if line.strip()
        ]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["lane_id"], "TEST-LOG-CUSTOM")

    # ------------------------------------------------------------------
    # Test 15: worktree defaults ON for hunt/drill/comp lane types
    # ------------------------------------------------------------------
    def test_15_use_worktree_defaults_on_for_hunt_drill_comp(self):
        env = dict(self.base_env)
        env["SPAWN_WORKER_BYPASS_REASON"] = "default-on-test"

        for lane_type in ("hunt", "drill", "comp"):
            with self.subTest(lane_type=lane_type):
                prompt = _write_prompt(self.tmp, f"{lane_type} prompt")
                proc = _run([
                    "--lane-id", f"TEST-WT-ON-{lane_type.upper()}",
                    "--lane-type", lane_type,
                    "--severity", "LOW",
                    "--workspace", str(self.tmp),
                    "--prompt-file", str(prompt),
                    "--no-register",
                    "--no-prebriefing",
                ], env_extra=env)
                self.assertEqual(proc.returncode, 0, msg=f"stderr={proc.stderr}")
                row = _latest_log_row(self.log_path)
                self.assertEqual(row["lane_type"], lane_type)
                self.assertEqual(row["use_worktree"], 1)
                self.assertIn(
                    row["worktree_status"],
                    {"provisioned", "tool-missing", "provision-failed"},
                )
                if row.get("worktree_path"):
                    _remove_worktree(row["worktree_path"])
                    row["worktree_path"] = ""

    # ------------------------------------------------------------------
    # Test 16: worktree defaults OFF for tool-build lanes
    # ------------------------------------------------------------------
    def test_16_use_worktree_defaults_off_for_tool_build(self):
        prompt = _write_prompt(self.tmp, "tool-build prompt")
        env = dict(self.base_env)
        env["SPAWN_WORKER_BYPASS_REASON"] = "default-off-test"
        proc = _run([
            "--lane-id", "TEST-WT-OFF-TOOLBUILD",
            "--lane-type", "tool-build",
            "--severity", "LOW",
            "--workspace", str(self.tmp),
            "--prompt-file", str(prompt),
            "--no-register",
            "--no-prebriefing",
        ], env_extra=env)
        self.assertEqual(proc.returncode, 0, msg=f"stderr={proc.stderr}")
        row = _latest_log_row(self.log_path)
        self.assertEqual(row["lane_type"], "tool-build")
        self.assertEqual(row["use_worktree"], 0)
        self.assertEqual(row["worktree_status"], "not-requested")
        self.assertEqual(row.get("worktree_path", ""), "")

    # ------------------------------------------------------------------
    # Test 17: --no-use-worktree overrides the default-on lane types
    # ------------------------------------------------------------------
    def test_17_no_use_worktree_overrides_default_on(self):
        prompt = _write_prompt(self.tmp, "override-off prompt")
        env = dict(self.base_env)
        env["SPAWN_WORKER_BYPASS_REASON"] = "override-off-test"
        proc = _run([
            "--lane-id", "TEST-WT-OFF-OVERRIDE",
            "--lane-type", "drill",
            "--severity", "LOW",
            "--workspace", str(self.tmp),
            "--prompt-file", str(prompt),
            "--no-register",
            "--no-prebriefing",
            "--no-use-worktree",
        ], env_extra=env)
        self.assertEqual(proc.returncode, 0, msg=f"stderr={proc.stderr}")
        row = _latest_log_row(self.log_path)
        self.assertEqual(row["lane_type"], "drill")
        self.assertEqual(row["use_worktree"], 0)
        self.assertEqual(row["worktree_status"], "not-requested")
        self.assertEqual(row.get("worktree_path", ""), "")

    # ------------------------------------------------------------------
    # Test 18: --use-worktree overrides the default-off tool-build lane
    # ------------------------------------------------------------------
    def test_18_use_worktree_overrides_default_off(self):
        prompt = _write_prompt(self.tmp, "override-on prompt")
        env = dict(self.base_env)
        env["SPAWN_WORKER_BYPASS_REASON"] = "override-on-test"
        proc = _run([
            "--lane-id", "TEST-WT-ON-OVERRIDE",
            "--lane-type", "tool-build",
            "--severity", "LOW",
            "--workspace", str(self.tmp),
            "--prompt-file", str(prompt),
            "--no-register",
            "--no-prebriefing",
            "--use-worktree",
        ], env_extra=env)
        self.assertEqual(proc.returncode, 0, msg=f"stderr={proc.stderr}")
        row = _latest_log_row(self.log_path)
        self.assertEqual(row["lane_type"], "tool-build")
        self.assertEqual(row["use_worktree"], 1)
        self.assertIn(
            row["worktree_status"],
            {"provisioned", "tool-missing", "provision-failed"},
        )
        if row.get("worktree_path"):
            _remove_worktree(row["worktree_path"])

    # ------------------------------------------------------------------
    # Test 19: durable enriched-brief copy (prebriefing-durability fix)
    # ------------------------------------------------------------------
    # PROBLEM (operator-caught, strata MIN_SHARES): the enriched brief lived
    # ONLY at the ephemeral /tmp path; /tmp reaping between spawn and Agent-run
    # left workers running DEGRADED. The fix ADDITIVELY writes a durable copy to
    # <ws>/.auditooor/dispatch_briefs/<lane>_enriched.md. This test asserts:
    #   (a) after a run, the durable copy exists AND byte-matches the /tmp file;
    #   (b) the existing stdout contract (the /tmp path line + the OK line) is
    #       unchanged (the /tmp path is still stdout line 1; OK line on stderr).
    def test_19_durable_brief_copy_matches_and_stdout_unchanged(self):
        prompt = _write_prompt(self.tmp, "durable-brief prompt body")
        env = dict(self.base_env)
        env["SPAWN_WORKER_BYPASS_REASON"] = "durable-brief-test"
        proc = _run([
            "--lane-id", "TEST-DURABLE-BRIEF",
            "--lane-type", "hunt",
            "--severity", "LOW",
            "--workspace", str(self.tmp),
            "--prompt-file", str(prompt),
            "--no-register",
            "--no-prebriefing",
        ], env_extra=env)
        self.assertEqual(proc.returncode, 0, msg=f"stderr={proc.stderr}")

        # (b) stdout contract unchanged: first stdout line is the /tmp path,
        # still under SPAWN_WORKER_TMP_DIR.
        stdout_lines = proc.stdout.strip().splitlines()
        self.assertTrue(stdout_lines, "no stdout produced")
        tmp_path = pathlib.Path(stdout_lines[0])
        self.assertTrue(
            str(tmp_path).startswith(str(self.spawn_tmp)),
            f"stdout /tmp path {tmp_path} not under {self.spawn_tmp}",
        )
        self.assertTrue(tmp_path.exists(), f"/tmp enriched file missing at {tmp_path}")
        # The OK line is on stderr and its format is unchanged (starts with
        # "[spawn-worker] OK lane=..." and carries the log= field).
        self.assertIn("[spawn-worker] OK lane=TEST-DURABLE-BRIEF", proc.stderr)
        self.assertIn(f"log={self.log_path}", proc.stderr)
        # The new durable_brief= advisory line is emitted (additive, stderr).
        self.assertIn("[spawn-worker] durable_brief=", proc.stderr)

        # (a) durable copy exists under .auditooor/dispatch_briefs/ and matches.
        db_dir = self.tmp / ".auditooor" / "dispatch_briefs"
        db_path = db_dir / "TEST-DURABLE-BRIEF_enriched.md"
        self.assertTrue(
            db_path.exists(), f"durable brief missing at {db_path}"
        )
        self.assertEqual(
            db_path.read_bytes(),
            tmp_path.read_bytes(),
            "durable brief content does not match the /tmp enriched file",
        )
        # Log row records the durable-brief path + status.
        row = _latest_log_row(self.log_path)
        self.assertEqual(row.get("durable_brief_status"), "written")
        self.assertEqual(row.get("durable_brief_path"), str(db_path))

    # ------------------------------------------------------------------
    # Test 20: durable brief gracefully skipped when workspace unavailable
    # ------------------------------------------------------------------
    def test_20_durable_brief_skipped_when_ws_missing(self):
        prompt = _write_prompt(self.tmp, "no-ws-dir prompt")
        missing_ws = self.tmp / "does_not_exist_ws"
        env = dict(self.base_env)
        env["SPAWN_WORKER_BYPASS_REASON"] = "no-ws-test"
        proc = _run([
            "--lane-id", "TEST-NO-WS",
            "--lane-type", "hunt",
            "--severity", "LOW",
            "--workspace", str(missing_ws),
            "--prompt-file", str(prompt),
            "--no-register",
            "--no-prebriefing",
        ], env_extra=env)
        # Behaves exactly as before: exit 0, /tmp path on stdout, no durable line.
        self.assertEqual(proc.returncode, 0, msg=f"stderr={proc.stderr}")
        self.assertTrue(proc.stdout.strip().splitlines())
        self.assertNotIn("[spawn-worker] durable_brief=", proc.stderr)
        row = _latest_log_row(self.log_path)
        self.assertEqual(row.get("durable_brief_status"), "ws-unavailable")
        self.assertEqual(row.get("durable_brief_path"), "")


if __name__ == "__main__":
    unittest.main()
