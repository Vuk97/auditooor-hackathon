"""Tests for tools/audit-completion-marker.py — V5-P0-05 / Gap 45.

Stdlib-only, hermetic via ``tempfile.TemporaryDirectory``. Each test
scaffolds a workspace tree, exercises one decision rule, and asserts on
the public ``check_marker`` / ``write_marker`` API plus the CLI.

The tool is loaded via ``importlib`` because the script name contains a
hyphen (``audit-completion-marker.py``).
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO / "tools" / "audit-completion-marker.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "audit_completion_marker", TOOL_PATH
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["audit_completion_marker"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()
_ORIGINAL_TOOLCHAIN_HASH = MOD._audit_toolchain_hash
MOD._audit_toolchain_hash = lambda repo: ("test-toolchain", [])


# ---------------------------------------------------------------------------
# Workspace scaffolding helpers
# ---------------------------------------------------------------------------
def _scaffold_workspace(root: Path, *, sols: dict[str, str] | None = None) -> Path:
    ws = root / "ws"
    ws.mkdir()
    (ws / ".audit_logs").mkdir()
    (ws / "src").mkdir()
    sols = sols or {"src/Foo.sol": "contract Foo {}\n"}
    for rel, body in sols.items():
        p = ws / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return ws


# ---------------------------------------------------------------------------
# write_marker / load_marker
# ---------------------------------------------------------------------------
class WriteMarkerTest(unittest.TestCase):

    def test_write_creates_v1_marker(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            out = MOD.write_marker(
                ws, commit_sha="abc1234", stages_completed=["scan", "track"]
            )
            self.assertTrue(out.exists())
            payload = json.loads(out.read_text())
            self.assertEqual(payload["schema"], MOD.SCHEMA)
            self.assertEqual(payload["commit_sha"], "abc1234")
            self.assertEqual(payload["stages_completed"], ["scan", "track"])
            self.assertIn("workspace_state_hash", payload)
            self.assertIn("workspace_state_inventory", payload)
            self.assertGreater(len(payload["workspace_state_inventory"]), 0)
            gap29 = MOD.gap29_marker_path(ws)
            self.assertTrue(gap29.is_file())
            self.assertIn(
                "audit-complete-marker-written-by-audit-completion-marker",
                gap29.read_text(encoding="utf-8"),
            )

    def test_write_overwrites_existing(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            MOD.write_marker(ws, commit_sha="aaa")
            MOD.write_marker(ws, commit_sha="bbb")
            payload = json.loads(MOD.marker_path(ws).read_text())
            self.assertEqual(payload["commit_sha"], "bbb")

    def test_load_returns_none_on_corrupt(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            MOD.marker_path(ws).write_text("{not valid json")
            self.assertIsNone(MOD.load_marker(ws))

    def test_load_returns_none_on_wrong_schema(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            MOD.marker_path(ws).write_text(json.dumps(
                {"schema": "something.else.v9", "completed_at": 0}
            ))
            self.assertIsNone(MOD.load_marker(ws))


# ---------------------------------------------------------------------------
# check_marker decision rules
# ---------------------------------------------------------------------------
class CheckMarkerTest(unittest.TestCase):

    def test_no_marker_runs(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            res = MOD.check_marker(ws, env={})
            self.assertFalse(res.fresh)
            self.assertEqual(res.reason, "no-marker")

    def test_fresh_marker_skips(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            MOD.write_marker(ws, commit_sha="unknown")
            res = MOD.check_marker(ws, env={})
            self.assertTrue(res.fresh, msg=res.reason)
            self.assertEqual(res.reason, "fresh")

    def test_stale_marker_runs(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            MOD.write_marker(ws, commit_sha="unknown")
            # Pretend we are 2h in the future; default window is 30m.
            future = time.time() + (2 * 60 * 60)
            res = MOD.check_marker(ws, env={}, now=future)
            self.assertFalse(res.fresh)
            self.assertTrue(res.reason.startswith("marker-stale"))

    def test_workspace_dirty_runs(self):
        """Modifying a tracked .sol file invalidates the marker."""
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            MOD.write_marker(ws, commit_sha="unknown")
            sol = ws / "src" / "Foo.sol"
            # Bump mtime AND content so the size component also changes.
            sol.write_text("contract Foo { uint x; }\n")
            os.utime(sol, (time.time() + 5, time.time() + 5))
            res = MOD.check_marker(ws, env={})
            self.assertFalse(res.fresh)
            self.assertEqual(res.reason, "workspace-dirty")

    def test_rust_source_change_invalidates_marker(self):
        """Rust workspaces must not be skipped by the freshness guard."""
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(
                Path(td),
                sols={"contracts/router/src/lib.rs": "pub fn route() {}\n"},
            )
            MOD.write_marker(ws, commit_sha="unknown")
            src = ws / "contracts" / "router" / "src" / "lib.rs"
            src.write_text("pub fn route() -> bool { true }\n")
            os.utime(src, (time.time() + 5, time.time() + 5))
            res = MOD.check_marker(ws, env={})
            self.assertFalse(res.fresh)
            self.assertEqual(res.reason, "workspace-dirty")

    def test_go_source_change_invalidates_marker(self):
        """Go workspaces must not be skipped by the freshness guard."""
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(
                Path(td),
                sols={"spark/watcher/watcher.go": "package watcher\n"},
            )
            MOD.write_marker(ws, commit_sha="unknown")
            src = ws / "spark" / "watcher" / "watcher.go"
            src.write_text("package watcher\n\nfunc Live() bool { return true }\n")
            os.utime(src, (time.time() + 5, time.time() + 5))
            res = MOD.check_marker(ws, env={})
            self.assertFalse(res.fresh)
            self.assertEqual(res.reason, "workspace-dirty")

    def test_force_cli_flag_runs(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            MOD.write_marker(ws, commit_sha="unknown")
            res = MOD.check_marker(ws, force=True, env={})
            self.assertFalse(res.fresh)
            self.assertEqual(res.reason, "force-override")
            self.assertTrue(res.forced)

    def test_force_env_var_runs(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            MOD.write_marker(ws, commit_sha="unknown")
            res = MOD.check_marker(ws, env={"FORCE": "1"})
            self.assertFalse(res.fresh)
            self.assertEqual(res.reason, "force-override")

    def test_force_env_zero_does_not_force(self):
        """``FORCE=0`` is the documented opt-out shape."""
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            MOD.write_marker(ws, commit_sha="unknown")
            res = MOD.check_marker(ws, env={"FORCE": "0"})
            self.assertTrue(res.fresh, msg=res.reason)

    def test_force_env_empty_does_not_force(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            MOD.write_marker(ws, commit_sha="unknown")
            res = MOD.check_marker(ws, env={"FORCE": ""})
            self.assertTrue(res.fresh, msg=res.reason)

    def test_commit_sha_change_with_toolchain_hash_skips(self):
        """Docs-only HEAD movement must not rerun when toolchain is unchanged."""
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            MOD.write_marker(ws, commit_sha="aaaaaaa")

            original = MOD._current_commit_sha
            try:
                MOD._current_commit_sha = lambda repo: "bbbbbbb"
                res = MOD.check_marker(ws, env={})
            finally:
                MOD._current_commit_sha = original
            self.assertTrue(res.fresh, msg=res.reason)

    def test_legacy_commit_sha_change_runs(self):
        """Legacy markers without toolchain hash stay conservative."""
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            MOD.write_marker(ws, commit_sha="aaaaaaa")
            payload = json.loads(MOD.marker_path(ws).read_text())
            payload.pop("audit_toolchain_hash", None)
            payload.pop("audit_toolchain_inventory", None)
            MOD.marker_path(ws).write_text(json.dumps(payload))

            original = MOD._current_commit_sha
            try:
                MOD._current_commit_sha = lambda repo: "bbbbbbb"
                res = MOD.check_marker(ws, env={})
            finally:
                MOD._current_commit_sha = original
            self.assertFalse(res.fresh)
            self.assertTrue(res.reason.startswith("commit-changed"))

    def test_toolchain_hash_change_runs(self):
        """Detector / harness changes still bust the marker."""
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            original = MOD._audit_toolchain_hash
            try:
                MOD._audit_toolchain_hash = lambda repo: ("toolchain-a", [])
                MOD.write_marker(ws, commit_sha="aaaaaaa")
                MOD._audit_toolchain_hash = lambda repo: ("toolchain-b", [])
                res = MOD.check_marker(ws, env={})
            finally:
                MOD._audit_toolchain_hash = original
            self.assertFalse(res.fresh)
            self.assertEqual(res.reason, "toolchain-changed")

    def test_commit_sha_unknown_either_side_does_not_block(self):
        """If either recorded or current SHA is 'unknown', skip the gate."""
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            MOD.write_marker(ws, commit_sha="unknown")
            original = MOD._current_commit_sha
            try:
                MOD._current_commit_sha = lambda repo: "ccccccc"
                res = MOD.check_marker(ws, env={})
            finally:
                MOD._current_commit_sha = original
            self.assertTrue(res.fresh, msg=res.reason)

    def test_corrupt_marker_treated_as_no_marker(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            MOD.marker_path(ws).write_text("{not valid")
            res = MOD.check_marker(ws, env={})
            self.assertFalse(res.fresh)
            self.assertEqual(res.reason, "no-marker")

    def test_future_timestamp_marker_runs(self):
        """Clock skew or tampering must not freeze the marker forever."""
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            MOD.write_marker(ws, commit_sha="unknown")
            payload = json.loads(MOD.marker_path(ws).read_text())
            # Bump completed_at into the far future.
            payload["completed_at"] = time.time() + (24 * 60 * 60)
            MOD.marker_path(ws).write_text(json.dumps(payload))
            res = MOD.check_marker(ws, env={})
            self.assertFalse(res.fresh)
            self.assertEqual(res.reason, "marker-future-timestamp")


# ---------------------------------------------------------------------------
# Edge cases Kimi pre-review flagged
# ---------------------------------------------------------------------------
class KimiPrereviewEdgeCasesTest(unittest.TestCase):

    def test_toolchain_hash_uses_content_not_mtime(self):
        """Equivalent tool files keep the same hash across mtime changes."""
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "repo"
            (repo / "tools").mkdir(parents=True)
            tool = repo / "tools" / "engage.py"
            tool.write_text("print('same')\n")
            h1, inv1 = _ORIGINAL_TOOLCHAIN_HASH(repo)
            os.utime(tool, (time.time() + 10, time.time() + 10))
            h2, inv2 = _ORIGINAL_TOOLCHAIN_HASH(repo)
            self.assertEqual(h1, h2)
            self.assertEqual(inv1[0]["sha256"], inv2[0]["sha256"])

    def test_toolchain_hash_detects_content_change(self):
        with tempfile.TemporaryDirectory() as td:
            repo = Path(td) / "repo"
            (repo / "tools").mkdir(parents=True)
            tool = repo / "tools" / "engage.py"
            tool.write_text("print('a')\n")
            h1, _inv1 = _ORIGINAL_TOOLCHAIN_HASH(repo)
            tool.write_text("print('b')\n")
            h2, _inv2 = _ORIGINAL_TOOLCHAIN_HASH(repo)
            self.assertNotEqual(h1, h2)

    def test_scope_json_change_invalidates_marker(self):
        """scope.json edits must invalidate the marker even with no .sol change."""
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            (ws / "scope.json").write_text(json.dumps({"in": ["src/Foo.sol"]}))
            MOD.write_marker(ws, commit_sha="unknown")
            # Operator narrows scope.
            (ws / "scope.json").write_text(
                json.dumps({"in": ["src/Bar.sol"]}, indent=2)
            )
            res = MOD.check_marker(ws, env={})
            self.assertFalse(res.fresh)
            self.assertEqual(res.reason, "workspace-dirty")

    def test_generated_intake_baseline_change_does_not_invalidate_marker(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            (ws / "INTAKE_BASELINE.json").write_text(
                json.dumps({"assets_in_scope": ["src"]})
            )
            MOD.write_marker(ws, commit_sha="unknown")
            (ws / "INTAKE_BASELINE.json").write_text(
                json.dumps({"assets_in_scope": ["src", "lib2"]}, indent=2)
            )
            res = MOD.check_marker(ws, env={})
            # Strict preflight regenerates this derived file immediately
            # before the freshness check; hashing it would self-invalidate
            # every retry without changing audited source or scope.
            self.assertTrue(res.fresh)
            self.assertEqual(res.reason, "fresh")

    def test_foundry_toml_change_invalidates_marker(self):
        """Minimax M1 — foundry.toml remapping change must invalidate."""
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            (ws / "foundry.toml").write_text(
                '[profile.default]\nsrc = "src"\n'
            )
            MOD.write_marker(ws, commit_sha="unknown")
            (ws / "foundry.toml").write_text(
                '[profile.default]\nsrc = "contracts"\n'
            )
            res = MOD.check_marker(ws, env={})
            self.assertFalse(res.fresh)
            self.assertEqual(res.reason, "workspace-dirty")

    def test_remappings_txt_change_invalidates_marker(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            (ws / "remappings.txt").write_text("@oz/=lib/openzeppelin/\n")
            MOD.write_marker(ws, commit_sha="unknown")
            (ws / "remappings.txt").write_text(
                "@oz/=lib/openzeppelin-v5/\n"
            )
            res = MOD.check_marker(ws, env={})
            self.assertFalse(res.fresh)
            self.assertEqual(res.reason, "workspace-dirty")

    def test_hardhat_config_change_invalidates_marker(self):
        """Minimax M1 — hardhat.config swap must invalidate."""
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            (ws / "hardhat.config.ts").write_text(
                "export default { paths: { sources: 'src' } };\n"
            )
            MOD.write_marker(ws, commit_sha="unknown")
            (ws / "hardhat.config.ts").write_text(
                "export default { paths: { sources: 'alt' } };\n"
            )
            res = MOD.check_marker(ws, env={})
            self.assertFalse(res.fresh)
            self.assertEqual(res.reason, "workspace-dirty")

    def test_gitmodules_change_invalidates_marker(self):
        """Minimax M1 — submodule pin change must invalidate."""
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            (ws / ".gitmodules").write_text(
                '[submodule "lib/oz"]\n  path = lib/oz\n  url = ...\n'
            )
            MOD.write_marker(ws, commit_sha="unknown")
            (ws / ".gitmodules").write_text(
                '[submodule "lib/oz"]\n  path = lib/oz\n  url = ...\n'
                '[submodule "lib/foo"]\n  path = lib/foo\n  url = ...\n'
            )
            res = MOD.check_marker(ws, env={})
            self.assertFalse(res.fresh)
            self.assertEqual(res.reason, "workspace-dirty")

    def test_node_modules_change_does_not_invalidate(self):
        """Vendor installs must not bust the marker."""
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            (ws / "node_modules").mkdir()
            (ws / "node_modules" / "junk.sol").write_text("// vendor\n")
            MOD.write_marker(ws, commit_sha="unknown")
            (ws / "node_modules" / "junk.sol").write_text(
                "// vendor changed\n"
            )
            res = MOD.check_marker(ws, env={})
            self.assertTrue(res.fresh, msg=res.reason)

    def test_lib_change_does_not_invalidate(self):
        """foundry-style ``lib/`` is vendored and must be ignored."""
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            (ws / "lib" / "forge-std").mkdir(parents=True)
            (ws / "lib" / "forge-std" / "Test.sol").write_text("contract T {}\n")
            MOD.write_marker(ws, commit_sha="unknown")
            (ws / "lib" / "forge-std" / "Test.sol").write_text(
                "contract T { uint x; }\n"
            )
            res = MOD.check_marker(ws, env={})
            self.assertTrue(res.fresh, msg=res.reason)

    def test_audit_logs_change_does_not_invalidate(self):
        """Writing the marker itself must not bust the next check."""
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            MOD.write_marker(ws, commit_sha="unknown")
            # Simulate a downstream tool dropping a log file.
            (ws / ".audit_logs" / "stage_log.txt").write_text("...")
            res = MOD.check_marker(ws, env={})
            self.assertTrue(res.fresh, msg=res.reason)

    def test_thirty_minute_threshold(self):
        """Marker stays fresh just under the window, stale just over."""
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            MOD.write_marker(ws, commit_sha="unknown")
            payload = json.loads(MOD.marker_path(ws).read_text())
            base = payload["completed_at"]
            # 29 minutes in the future -> fresh
            res = MOD.check_marker(ws, env={}, now=base + 29 * 60)
            self.assertTrue(res.fresh, msg=res.reason)
            # 31 minutes in the future -> stale
            res = MOD.check_marker(ws, env={}, now=base + 31 * 60)
            self.assertFalse(res.fresh)
            self.assertTrue(res.reason.startswith("marker-stale"))


# ---------------------------------------------------------------------------
# CLI plumbing
# ---------------------------------------------------------------------------
class CLITest(unittest.TestCase):

    def test_cli_check_no_marker_exits_1(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = MOD.main(["check", "--workspace", str(ws)])
            self.assertEqual(rc, 1)
            self.assertIn("run", buf.getvalue())
            self.assertIn("no-marker", buf.getvalue())

    def test_cli_check_fresh_exits_0_with_skip_message(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            MOD.write_marker(ws, commit_sha="unknown")
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = MOD.main(["check", "--workspace", str(ws)])
            self.assertEqual(rc, 0)
            out = buf.getvalue()
            self.assertIn("skip-fresh", out)
            self.assertIn("FORCE=1", out)

    def test_cli_check_force_flag_exits_1(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            MOD.write_marker(ws, commit_sha="unknown")
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = MOD.main([
                    "check", "--workspace", str(ws), "--force",
                ])
            self.assertEqual(rc, 1)
            self.assertIn("force-override", buf.getvalue())

    def test_cli_check_json_output(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            MOD.write_marker(ws, commit_sha="unknown")
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = MOD.main([
                    "check", "--workspace", str(ws), "--json",
                ])
            self.assertEqual(rc, 0)
            payload = json.loads(buf.getvalue())
            self.assertTrue(payload["fresh"])
            self.assertEqual(
                payload["schema"], "auditooor.audit_completion_check.v1"
            )
            self.assertEqual(payload["reason"], "fresh")

    def test_cli_check_missing_workspace_exits_2(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "nope"
            buf = io.StringIO()
            err = io.StringIO()
            with redirect_stdout(buf), redirect_stderr(err):
                rc = MOD.main(["check", "--workspace", str(ws)])
            self.assertEqual(rc, 2)
            self.assertIn("workspace not found", err.getvalue())

    def test_cli_write_creates_marker(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = MOD.main([
                    "write", "--workspace", str(ws),
                    "--commit-sha", "deadbeef",
                    "--stages", "scan", "track",
                ])
            self.assertEqual(rc, 0)
            payload = json.loads(MOD.marker_path(ws).read_text())
            self.assertEqual(payload["commit_sha"], "deadbeef")
            self.assertEqual(payload["stages_completed"], ["scan", "track"])

    def test_cli_max_age_seconds_flag(self):
        """``--max-age-seconds`` shrinks the freshness window."""
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            MOD.write_marker(ws, commit_sha="unknown")
            # Backdate the marker by 5s; 1s window -> stale.
            payload = json.loads(MOD.marker_path(ws).read_text())
            payload["completed_at"] = payload["completed_at"] - 5
            MOD.marker_path(ws).write_text(json.dumps(payload))
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = MOD.main([
                    "check", "--workspace", str(ws),
                    "--max-age-seconds", "1",
                ])
            self.assertEqual(rc, 1)
            self.assertIn("marker-stale", buf.getvalue())

    def test_negative_max_age_disables_time_expiry(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            MOD.write_marker(ws, commit_sha="unknown")
            payload = json.loads(MOD.marker_path(ws).read_text())
            payload["completed_at"] -= 10_000
            MOD.marker_path(ws).write_text(json.dumps(payload))
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = MOD.main([
                    "check", "--workspace", str(ws),
                    "--max-age-seconds", "-1",
                ])
            self.assertEqual(rc, 0)
            self.assertIn("skip-fresh", buf.getvalue())

    def test_write_if_core_complete_writes_after_report_success(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            progress = Path(td) / "audit_progress.csv"
            progress.write_text(
                "stage,status,elapsed_secs,started_at_epoch\n"
                "intake-baseline,ok,1.0,1.0\n"
                "orient,ok,1.0,2.0\n"
                "scan,ok,1.0,3.0\n"
                "report,ok,1.0,4.0\n"
                "engagement-retro,failed,1.0,5.0\n",
                encoding="utf-8",
            )
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = MOD.main([
                    "write-if-core-complete",
                    "--workspace", str(ws),
                    "--progress-csv", str(progress),
                    "--commit-sha", "abc1234",
                ])
            self.assertEqual(rc, 0)
            self.assertTrue(MOD.marker_path(ws).is_file())
            self.assertTrue(MOD.gap29_marker_path(ws).is_file())
            payload = json.loads(MOD.marker_path(ws).read_text())
            self.assertEqual(payload["stages_completed"][-1], "report")

    def test_write_if_core_complete_refuses_pre_report_failure(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            progress = Path(td) / "audit_progress.csv"
            progress.write_text(
                "stage,status,elapsed_secs,started_at_epoch\n"
                "intake-baseline,ok,1.0,1.0\n"
                "orient,failed,1.0,2.0\n",
                encoding="utf-8",
            )
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = MOD.main([
                    "write-if-core-complete",
                    "--workspace", str(ws),
                    "--progress-csv", str(progress),
                ])
            self.assertEqual(rc, 1)
            self.assertFalse(MOD.marker_path(ws).exists())
            self.assertFalse(MOD.gap29_marker_path(ws).exists())

    def test_write_if_core_complete_artifact_fallback_when_csv_missing(self):
        """CAP-GAP-88 (2026-05-27): degrade-permissive when CSV missing.

        When audit-progress.py did not write the CSV but engage_report.{json,md}
        exist (the canonical core-complete signal), the marker should still be
        written so Gap #29 hunt-phase-ordering proceeds.
        # r36-rebuttal: build lane (CAP-GAP-88 test coverage)
        """
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            (ws / "engage_report.json").write_text('{"ok": true}', encoding="utf-8")
            (ws / "engage_report.md").write_text("# report\n", encoding="utf-8")
            progress = Path(td) / "nonexistent_audit_progress.csv"
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = MOD.main([
                    "write-if-core-complete",
                    "--workspace", str(ws),
                    "--progress-csv", str(progress),
                    "--commit-sha", "fb01234",
                ])
            self.assertEqual(rc, 0, buf.getvalue())
            self.assertTrue(MOD.marker_path(ws).is_file())
            self.assertTrue(MOD.gap29_marker_path(ws).is_file())
            self.assertIn("degrade-permissive", buf.getvalue())

    def test_write_if_core_complete_no_artifact_fallback_flag_disables(self):
        """CAP-GAP-88 --no-artifact-fallback: opt back into strict CSV-only.
        # r36-rebuttal: build lane (CAP-GAP-88 test coverage)
        """
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            (ws / "engage_report.json").write_text('{"ok": true}', encoding="utf-8")
            (ws / "engage_report.md").write_text("# report\n", encoding="utf-8")
            progress = Path(td) / "nonexistent_audit_progress.csv"
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = MOD.main([
                    "write-if-core-complete",
                    "--workspace", str(ws),
                    "--progress-csv", str(progress),
                    "--no-artifact-fallback",
                ])
            self.assertEqual(rc, 1, buf.getvalue())
            self.assertFalse(MOD.marker_path(ws).exists())
            self.assertFalse(MOD.gap29_marker_path(ws).exists())

    def test_write_if_core_complete_artifact_fallback_skipped_when_missing(self):
        """CAP-GAP-88: fallback only fires when engage_report.{json,md} exist.
        # r36-rebuttal: build lane (CAP-GAP-88 test coverage)
        """
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            # No engage_report.* artifacts -> fallback can't confirm core complete
            progress = Path(td) / "nonexistent_audit_progress.csv"
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = MOD.main([
                    "write-if-core-complete",
                    "--workspace", str(ws),
                    "--progress-csv", str(progress),
                ])
            self.assertEqual(rc, 1, buf.getvalue())
            self.assertFalse(MOD.marker_path(ws).exists())


# ---------------------------------------------------------------------------
# Acceptance: fixture workspace test (Codex spec)
# "no silent duplicate heavy run when fresh artifacts exist"
# ---------------------------------------------------------------------------
class AcceptanceFreshRerunTest(unittest.TestCase):
    """End-to-end behavioural test: write -> check -> dirty -> check -> force.

    Mirrors what `make audit && make audit` and `make audit-deep FORCE=1`
    will hit in real ops.
    """

    def test_back_to_back_audits_short_circuit(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            # Pin both sides of the SHA gate so the test is hermetic
            # regardless of where the repo is checked out.
            original = MOD._current_commit_sha
            MOD._current_commit_sha = lambda repo: "abc1234"
            try:
                # Run 1: no marker -> should run
                r1 = MOD.check_marker(ws, env={})
                self.assertFalse(r1.fresh)
                # First-run engagement completes; write the marker
                MOD.write_marker(ws, commit_sha="abc1234")
                # Run 2 immediately after -> should skip
                r2 = MOD.check_marker(ws, env={})
                self.assertTrue(r2.fresh, msg=r2.reason)
                # Operator edits a .sol file -> rerun
                sol = ws / "src" / "Foo.sol"
                sol.write_text("contract Foo { event E(); }\n")
                os.utime(sol, (time.time() + 5, time.time() + 5))
                r3 = MOD.check_marker(ws, env={})
                self.assertFalse(r3.fresh)
                self.assertEqual(r3.reason, "workspace-dirty")
                # Re-record marker; operator runs FORCE=1 -> rerun
                MOD.write_marker(ws, commit_sha="abc1234")
                r4 = MOD.check_marker(ws, env={"FORCE": "1"})
                self.assertFalse(r4.fresh)
                self.assertEqual(r4.reason, "force-override")
            finally:
                MOD._current_commit_sha = original


# ---------------------------------------------------------------------------
# P52: tamper-evident signature / hash chain
# ---------------------------------------------------------------------------
class TamperSignatureTest(unittest.TestCase):

    def _legit_sig(self, verdict="pass-audit-complete", nonce="n1"):
        inv = [{"path": rel, "size": 1, "sha256": "0" * 64}
               for rel in MOD._SELF_DEF_FILES]
        return MOD.compute_marker_signature(
            verdict=verdict,
            repo_root=Path("/nonexistent-repo"),
            toolchain_hash="tc-hash-abc",
            toolchain_inventory=inv,
            workspace_state_hash="ws-hash-def",
            nonce=nonce,
        )

    def test_legit_signature_verifies_ok(self):
        sig = self._legit_sig()
        v = MOD.verify_marker_signature(sig)
        self.assertTrue(v["ok"], msg=v["reasons"])
        self.assertTrue(v["self_coverage_ok"])
        self.assertEqual(v["verdict"], "pass-audit-complete")

    def test_forged_verdict_fires(self):
        """Hand-write a forged-but-plausible marker: edit a bound field without
        recomputing the chain digest -> verify FAILS (FORGED_VERDICT)."""
        sig = self._legit_sig(verdict="pass-audit-complete")
        forged = dict(sig)
        # Flip the verdict field but keep the (now stale) chain_digest.
        forged["verdict"] = "pass-audit-complete-DEFINITELY"
        v = MOD.verify_marker_signature(forged)
        self.assertFalse(v["ok"])
        self.assertIn("chain-digest-mismatch", v["reasons"])

    def test_forged_enforcer_hash_fires(self):
        sig = self._legit_sig()
        forged = dict(sig)
        forged["enforcer_hash"] = "swapped-enforcer"
        v = MOD.verify_marker_signature(forged)
        self.assertFalse(v["ok"])
        self.assertIn("chain-digest-mismatch", v["reasons"])

    def test_enforcer_mismatch_under_frozen_verdict_fires(self):
        """A block whose chain is internally consistent but whose enforcer_hash
        no longer matches the CURRENT enforcer is flagged (enforcer swapped)."""
        sig = self._legit_sig()  # enforcer_hash = "tc-hash-abc"
        v = MOD.verify_marker_signature(sig, current_enforcer_hash="tc-hash-DIFFERENT")
        self.assertFalse(v["ok"])
        self.assertIn("enforcer-hash-mismatch", v["reasons"])

    def test_enforcer_unknown_tolerated(self):
        """enforcer_hash='unknown' on either side is NOT a mismatch."""
        inv = [{"path": rel, "size": 1, "sha256": "0" * 64}
               for rel in MOD._SELF_DEF_FILES]
        sig = MOD.compute_marker_signature(
            verdict="pass-audit-complete", repo_root=Path("/nope"),
            toolchain_hash="unknown", toolchain_inventory=inv,
            workspace_state_hash="w", nonce="n",
        )
        v = MOD.verify_marker_signature(sig, current_enforcer_hash="real-hash")
        self.assertTrue(v["ok"], msg=v["reasons"])
        v2 = MOD.verify_marker_signature(sig, current_enforcer_hash="unknown")
        self.assertTrue(v2["ok"], msg=v2["reasons"])

    def test_self_coverage_incomplete_when_own_defs_absent(self):
        """If the toolchain inventory did NOT include the gate's own def files,
        self_coverage is flagged (the 'gate checked its own def' claim is
        vacuous)."""
        sig = MOD.compute_marker_signature(
            verdict="pass-audit-complete", repo_root=Path("/nope"),
            toolchain_hash="tc", toolchain_inventory=[{"path": "tools/other.py"}],
            workspace_state_hash="w", nonce="n",
        )
        self.assertFalse(sig["self_coverage"]["all_covered"])
        v = MOD.verify_marker_signature(sig)
        self.assertFalse(v["self_coverage_ok"])
        self.assertIn("self-coverage-incomplete", v["reasons"])

    def test_no_signature_block_returns_not_ok(self):
        v = MOD.verify_marker_signature(None)
        self.assertFalse(v["ok"])
        self.assertIn("no-signature-block", v["reasons"])

    def test_nonce_makes_identical_inputs_distinct(self):
        s1 = self._legit_sig(nonce=None)
        # compute_marker_signature mints a fresh nonce when None
        inv = [{"path": rel, "size": 1, "sha256": "0" * 64}
               for rel in MOD._SELF_DEF_FILES]
        s2 = MOD.compute_marker_signature(
            verdict="pass-audit-complete", repo_root=Path("/nope"),
            toolchain_hash="tc-hash-abc", toolchain_inventory=inv,
            workspace_state_hash="ws-hash-def", nonce=None,
        )
        self.assertNotEqual(s1["nonce"], s2["nonce"])
        self.assertNotEqual(s1["chain_digest"], s2["chain_digest"])

    def test_write_marker_embeds_signature_block(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            MOD.write_marker(ws, commit_sha="abc1234")
            payload = json.loads(MOD.marker_path(ws).read_text())
            self.assertIn("tamper_signature", payload)
            sig = payload["tamper_signature"]
            self.assertEqual(sig["schema"], MOD.SIGNATURE_SCHEMA)
            # No authoritative last_result present -> verdict is HONEST 'unknown'.
            self.assertEqual(sig["verdict"], "unknown")
            v = MOD.verify_marker_signature(sig)
            self.assertTrue(v["ok"], msg=v["reasons"])

    def test_write_marker_signature_reads_authoritative_verdict(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _scaffold_workspace(Path(td))
            (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
            (ws / ".auditooor" / "audit_complete_last_result.json").write_text(
                json.dumps({"verdict": "pass-audit-complete", "strict": True})
            )
            MOD.write_marker(ws, commit_sha="abc1234")
            payload = json.loads(MOD.marker_path(ws).read_text())
            self.assertEqual(
                payload["tamper_signature"]["verdict"], "pass-audit-complete"
            )


if __name__ == "__main__":
    unittest.main()
