"""Unit tests for the Rule 36 pre-commit-pathspec-discipline git hook.

Each test builds a throwaway git repo, installs the hook, stages files, and
invokes the hook the way `git commit` would (with the commit message written
to .git/COMMIT_EDITMSG). The hook's exit code is the assertion target:

  no-declaration            -> pass (exit 0)
  staged within declaration -> pass (exit 0)
  staged exceeds declaration -> fail (exit 1)
  expired declaration       -> pass (exit 0)
  rebuttal marker present   -> pass (exit 0)
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HOOK = ROOT / "tools" / "git-hooks" / "pre-commit-pathspec-discipline.sh"

# Use the real git binary directly. The auditooor environment ships a `git`
# wrapper on PATH that rejects `commit` without a workspace MCP-recall file;
# the throwaway test repo has no such file, so the test invokes git through
# its canonical path and hands the hook a PATH whose `git` is the real binary.
_GIT = next(
    (c for c in ("/usr/bin/git", "/opt/homebrew/bin/git", shutil.which("git"))
     if c and Path(c).exists()),
    "git",
)
_GIT_DIR = str(Path(_GIT).parent)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class PathspecHookTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Path(tempfile.mkdtemp(prefix="r36_pathspec_"))
        self._git("init", "-q")
        self._git("config", "user.email", "test@example.com")
        self._git("config", "user.name", "Test")
        # Seed an initial commit so `git diff --staged` has a base.
        (self.repo / "seed.txt").write_text("seed\n", encoding="utf-8")
        self._git("add", "seed.txt")
        self._git("commit", "-q", "-m", "seed")

    def tearDown(self) -> None:
        shutil.rmtree(self.repo, ignore_errors=True)

    def _git(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [_GIT, *args],
            cwd=self.repo,
            capture_output=True,
            text=True,
            check=False,
        )

    def _write(self, rel: str, content: str = "x\n") -> None:
        path = self.repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def _declare(self, agents: list[dict]) -> None:
        target = self.repo / ".auditooor" / "agent_pathspec.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps({"agents": agents}, indent=2), encoding="utf-8")

    def _commit_msg(self, msg: str) -> None:
        (self.repo / ".git" / "COMMIT_EDITMSG").write_text(msg, encoding="utf-8")

    def _run_hook(self, *, env_overrides: dict | None = None) -> subprocess.CompletedProcess:
        # Hand the hook a PATH whose first `git` is the real binary, so its
        # internal `git rev-parse` / `git diff --staged` calls do not hit the
        # auditooor commit-gating wrapper.
        env = dict(os.environ)
        env["PATH"] = _GIT_DIR + os.pathsep + env.get("PATH", "")
        # Strip R36_CURRENT_AGENT_ID / R55_CURRENT_AGENT_ID from the inherited
        # env so legacy-mode tests do not inherit an orchestrator-set id.
        for var in ("R36_CURRENT_AGENT_ID", "R55_CURRENT_AGENT_ID",
                    "R36_SYSTEM_WIDE_PATTERNS", "R36_STRICT_NO_LANE_ID"):
            env.pop(var, None)
        if env_overrides:
            env.update(env_overrides)
        return subprocess.run(
            ["bash", str(HOOK)],
            cwd=self.repo,
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )

    # 1. no declaration file -> no-op pass.
    def test_no_declaration_passes(self) -> None:
        self._write("tools/foo.py")
        self._git("add", "tools/foo.py")
        self._commit_msg("add foo")
        result = self._run_hook()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    # 2. staged set within the declared pathspec -> pass.
    def test_staged_within_declaration_passes(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "agent-A", "files": ["tools/foo.py", "tools/bar.py"],
             "expires_at": future},
        ])
        self._write("tools/foo.py")
        self._git("add", "tools/foo.py")
        self._commit_msg("update foo")
        result = self._run_hook()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("OK", result.stdout)

    # 3. staged set exceeds the declared pathspec -> fail.
    def test_staged_exceeds_declaration_fails(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "agent-A", "files": ["tools/foo.py"],
             "expires_at": future},
        ])
        self._write("tools/foo.py")
        self._write("tools/sibling.py")  # not declared by agent-A
        self._git("add", "tools/foo.py", "tools/sibling.py")
        self._commit_msg("update foo")
        result = self._run_hook()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("REFUSED", result.stdout)
        self.assertIn("tools/sibling.py", result.stdout)

    # 3b. declarations are literal path matches; globs do not expand.
    def test_declared_glob_is_literal_and_refused(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "agent-A", "files": ["tools/*.py"],
             "expires_at": future},
        ])
        self._write("tools/foo.py")
        self._git("add", "tools/foo.py")
        self._commit_msg("update foo")
        result = self._run_hook()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("REFUSED", result.stdout)
        self.assertIn("tools/foo.py", result.stdout)

    # 4. all declarations expired -> no-op pass.
    def test_expired_declaration_passes(self) -> None:
        past = _iso(datetime.now(timezone.utc) - timedelta(hours=3))
        self._declare([
            {"agent_id": "agent-A", "files": ["tools/foo.py"],
             "expires_at": past},
        ])
        self._write("tools/foo.py")
        self._write("tools/sibling.py")
        self._git("add", "tools/foo.py", "tools/sibling.py")
        self._commit_msg("sweep after expiry")
        result = self._run_hook()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    # 5. r36-rebuttal marker with a non-empty reason -> pass even on excess.
    def test_rebuttal_marker_passes(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "agent-A", "files": ["tools/foo.py"],
             "expires_at": future},
        ])
        self._write("tools/foo.py")
        self._write("tools/sibling.py")
        self._git("add", "tools/foo.py", "tools/sibling.py")
        self._commit_msg(
            "mass rename sweep\n\n"
            "<!-- r36-rebuttal: operator-driven repo-wide rename, sweep intended -->\n"
        )
        result = self._run_hook()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("rebuttal accepted", result.stdout)

    # 6. empty rebuttal reason does NOT silence the gate.
    def test_empty_rebuttal_does_not_pass(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "agent-A", "files": ["tools/foo.py"],
             "expires_at": future},
        ])
        self._write("tools/foo.py")
        self._write("tools/sibling.py")
        self._git("add", "tools/foo.py", "tools/sibling.py")
        self._commit_msg("sweep\n\n<!-- r36-rebuttal:  -->\n")
        result = self._run_hook()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    # 7. union of multiple live agents covers their combined files.
    def test_multi_agent_union(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "agent-A", "files": ["tools/foo.py"],
             "expires_at": future},
            {"agent_id": "agent-B", "files": ["tools/bar.py"],
             "expires_at": future},
        ])
        self._write("tools/foo.py")
        self._write("tools/bar.py")
        self._git("add", "tools/foo.py", "tools/bar.py")
        self._commit_msg("integrate A and B")
        result = self._run_hook()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    # 8. no files staged -> pass (nothing to police).
    def test_nothing_staged_passes(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "agent-A", "files": ["tools/foo.py"],
             "expires_at": future},
        ])
        self._commit_msg("empty")
        result = self._run_hook()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    # ------------------------------------------------------------------
    # FIX-C cases: per-lane staged_set ⊆ registered_pathspec assertion
    # (closes the sweep-add absorption gap surfaced by FIX-B audit).
    # ------------------------------------------------------------------

    # 9. CURRENT-LANE MODE: lane stages only its declared files -> pass.
    def test_current_lane_only_own_files_passes(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": future},
            {"agent_id": "lane-B", "files": ["tools/bar.py"],
             "expires_at": future},
        ])
        self._write("tools/foo.py")
        self._git("add", "tools/foo.py")
        self._commit_msg("lane-A: foo update")
        result = self._run_hook(env_overrides={"R36_CURRENT_AGENT_ID": "lane-A"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("current lane 'lane-A' pathspec", result.stdout)

    # 10. CURRENT-LANE MODE: lane absorbs sibling-lane file -> REFUSE.
    # This is the FIX-C anchor case: pre-FIX-C, the staged set landed in the
    # UNION of lane-A and lane-B, so the union-only check passed even though
    # lane-A absorbed lane-B's work.
    def test_current_lane_absorbs_sibling_refused(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": future},
            {"agent_id": "lane-B", "files": ["tools/bar.py"],
             "expires_at": future},
        ])
        self._write("tools/foo.py")
        self._write("tools/bar.py")
        self._git("add", "tools/foo.py", "tools/bar.py")
        self._commit_msg("lane-A: foo update")
        result = self._run_hook(env_overrides={"R36_CURRENT_AGENT_ID": "lane-A"})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("REFUSED", result.stdout)
        self.assertIn("sibling-lane files", result.stdout)
        self.assertIn("tools/bar.py", result.stdout)
        self.assertIn("lane-B", result.stdout)

    # 11. CURRENT-LANE MODE: lane stages phase_state.json (system-wide path) -> pass.
    def test_current_lane_phase_state_is_system_wide(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": future},
        ])
        self._write("tools/foo.py")
        self._write("reports/v3_iter_2026-05-23_iter18/phase_state.json", "{}\n")
        self._git("add", "tools/foo.py",
                  "reports/v3_iter_2026-05-23_iter18/phase_state.json")
        self._commit_msg("lane-A: foo + phase_state update")
        result = self._run_hook(env_overrides={"R36_CURRENT_AGENT_ID": "lane-A"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    # 12. CURRENT-LANE MODE: lane stages .auditooor/agent_pathspec.json -> pass.
    def test_current_lane_pathspec_file_is_system_wide(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": future},
        ])
        self._write("tools/foo.py")
        # Re-declare to mutate timestamps - simulates a register() during the lane.
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": future},
        ])
        self._git("add", "tools/foo.py", ".auditooor/agent_pathspec.json")
        self._commit_msg("lane-A: foo + register pathspec")
        result = self._run_hook(env_overrides={"R36_CURRENT_AGENT_ID": "lane-A"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    # 13. CURRENT-LANE MODE: lane stages its own results.md under its lane dir -> pass.
    # Tests both `lane_<id_underscored>/` and bare-stem directory conventions.
    def test_current_lane_own_results_md_passes(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-FIX-C-r36-staged-set", "files": ["tools/foo.py"],
             "expires_at": future},
        ])
        self._write("tools/foo.py")
        # Note: results.md is NOT in lane's declared `files`, but lives under
        # the lane's own lane_FIX_C_r36_staged_set/ directory.
        self._write("reports/v3_iter_2026-05-23_iter18/lane_FIX_C_r36_staged_set/results.md")
        self._git("add", "tools/foo.py",
                  "reports/v3_iter_2026-05-23_iter18/lane_FIX_C_r36_staged_set/results.md")
        self._commit_msg("FIX-C: foo + results.md")
        result = self._run_hook(env_overrides={
            "R36_CURRENT_AGENT_ID": "lane-FIX-C-r36-staged-set"
        })
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    # 14. CURRENT-LANE MODE: lane stages undeclared OOS file (no lane owns it) -> REFUSE.
    def test_current_lane_undeclared_file_refused(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": future},
        ])
        self._write("tools/foo.py")
        self._write("tools/random_undeclared.py")
        self._git("add", "tools/foo.py", "tools/random_undeclared.py")
        self._commit_msg("lane-A: foo + accidentally-staged scratch file")
        result = self._run_hook(env_overrides={"R36_CURRENT_AGENT_ID": "lane-A"})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("undeclared staged file(s)", result.stdout)
        self.assertIn("tools/random_undeclared.py", result.stdout)

    # 15. CURRENT-LANE MODE: rebuttal marker silences sibling-absorption REFUSE.
    def test_current_lane_sibling_absorption_rebuttal_passes(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": future},
            {"agent_id": "lane-B", "files": ["tools/bar.py"],
             "expires_at": future},
        ])
        self._write("tools/foo.py")
        self._write("tools/bar.py")
        self._git("add", "tools/foo.py", "tools/bar.py")
        self._commit_msg(
            "lane-A: integration sweep\n\n"
            "<!-- r36-rebuttal: operator-driven cross-lane integration commit; "
            "lane-B handed off to lane-A per phase_state.json -->\n"
        )
        result = self._run_hook(env_overrides={"R36_CURRENT_AGENT_ID": "lane-A"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("rebuttal accepted", result.stdout)

    # 16. CURRENT-LANE MODE: oversized rebuttal (>200 chars) -> still REFUSED.
    def test_current_lane_oversized_rebuttal_refused(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": future},
            {"agent_id": "lane-B", "files": ["tools/bar.py"],
             "expires_at": future},
        ])
        self._write("tools/foo.py")
        self._write("tools/bar.py")
        self._git("add", "tools/foo.py", "tools/bar.py")
        oversized = "a" * 300
        self._commit_msg(
            f"lane-A: absorb sibling\n\n<!-- r36-rebuttal: {oversized} -->\n"
        )
        result = self._run_hook(env_overrides={"R36_CURRENT_AGENT_ID": "lane-A"})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("REFUSED", result.stdout)

    # 17. ENV FALLBACK: R36 honours R55_CURRENT_AGENT_ID if R36 var is absent.
    def test_r55_env_fallback_works(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": future},
            {"agent_id": "lane-B", "files": ["tools/bar.py"],
             "expires_at": future},
        ])
        self._write("tools/foo.py")
        self._write("tools/bar.py")
        self._git("add", "tools/foo.py", "tools/bar.py")
        self._commit_msg("lane-A: foo + absorbed bar")
        # Set only R55_CURRENT_AGENT_ID; R36 should fall back to it.
        result = self._run_hook(env_overrides={"R55_CURRENT_AGENT_ID": "lane-A"})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("REFUSED", result.stdout)
        self.assertIn("lane-A", result.stdout)

    # 18. LEGACY MODE: no current-agent-id env var -> falls back to union.
    # This preserves backward compatibility for operator-driven commits.
    def test_legacy_union_mode_when_no_env(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": future},
            {"agent_id": "lane-B", "files": ["tools/bar.py"],
             "expires_at": future},
        ])
        self._write("tools/foo.py")
        self._write("tools/bar.py")
        self._git("add", "tools/foo.py", "tools/bar.py")
        self._commit_msg("operator: cross-lane integration (no lane env)")
        result = self._run_hook()  # No env_overrides
        # Both files are in the union, so legacy mode passes.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("legacy union mode", result.stdout)

    # 19. STRICT-NO-LANE-ID: opt-in env hook hard-fails on missing lane env.
    def test_strict_no_lane_id_refuses(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": future},
        ])
        self._write("tools/foo.py")
        self._git("add", "tools/foo.py")
        self._commit_msg("no lane env + strict")
        result = self._run_hook(env_overrides={"R36_STRICT_NO_LANE_ID": "1"})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("R36_STRICT_NO_LANE_ID", result.stdout)

    # 20. CURRENT-LANE MODE with unknown env id -> falls back to legacy union
    # and emits a WARNING line so operators notice the misconfiguration.
    def test_current_lane_unknown_id_falls_back_with_warning(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": future},
        ])
        self._write("tools/foo.py")
        self._git("add", "tools/foo.py")
        self._commit_msg("typo'd lane id")
        result = self._run_hook(env_overrides={"R36_CURRENT_AGENT_ID": "lane-TYPO"})
        # File IS in lane-A's union so legacy fallback passes.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("WARNING", result.stdout)
        self.assertIn("lane-TYPO", result.stdout)

    # 21. R36_SYSTEM_WIDE_PATTERNS env hook extends the allowlist.
    def test_env_system_wide_patterns_hook(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": future},
            {"agent_id": "lane-B", "files": ["tools/bar.py"],
             "expires_at": future},
        ])
        self._write("tools/foo.py")
        # operator-declared additional system-wide path that lane-A may stage
        self._write("OPERATOR_NOTES.md", "note\n")
        self._git("add", "tools/foo.py", "OPERATOR_NOTES.md")
        self._commit_msg("lane-A: foo + operator notes")
        result = self._run_hook(env_overrides={
            "R36_CURRENT_AGENT_ID": "lane-A",
            "R36_SYSTEM_WIDE_PATTERNS": r"^OPERATOR_NOTES\.md$",
        })
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    # 22. Hacker_brain_phase_state.json (older iter convention) is system-wide.
    def test_hacker_brain_phase_state_is_system_wide(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": future},
        ])
        self._write("tools/foo.py")
        self._write("reports/v3_iter_2026-05-23_iter17/hacker_brain_phase_state.json",
                    "{}\n")
        self._git("add", "tools/foo.py",
                  "reports/v3_iter_2026-05-23_iter17/hacker_brain_phase_state.json")
        self._commit_msg("lane-A: foo + brain state")
        result = self._run_hook(env_overrides={"R36_CURRENT_AGENT_ID": "lane-A"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    # ------------------------------------------------------------------
    # Gap #41 cases: per-file CROSS-LANE pollution detection
    # ------------------------------------------------------------------

    # 23. Gap #41 baseline: same-lane subset still passes (no cross-claim).
    # Regression-locks that adding the Gap #41 check did not break the
    # legitimate single-lane subset case.
    def test_gap41_same_lane_subset_passes(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py", "tools/bar.py"],
             "expires_at": future},
            {"agent_id": "lane-B", "files": ["tools/baz.py"],
             "expires_at": future},
        ])
        self._write("tools/foo.py")
        self._write("tools/bar.py")
        self._git("add", "tools/foo.py", "tools/bar.py")
        self._commit_msg("lane-A: foo + bar (no cross-claim)")
        result = self._run_hook(env_overrides={"R36_CURRENT_AGENT_ID": "lane-A"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("OK", result.stdout)

    # 24. Gap #41 anchor: file cross-claimed by current and sibling lane -> REFUSE.
    # This is the Gap #41 anchor: pre-Gap-41, the staged file appeared in the
    # current lane's pathspec so the subset check passed even though the same
    # file also appeared in a sibling lane's intent.
    def test_gap41_cross_claim_refuses(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A",
             "files": ["tools/shared.py", "tools/foo.py"],
             "expires_at": future},
            {"agent_id": "lane-B",
             "files": ["tools/shared.py", "tools/bar.py"],
             "expires_at": future},
        ])
        self._write("tools/shared.py")
        self._git("add", "tools/shared.py")
        self._commit_msg("lane-A: shared.py edit (cross-claimed with lane-B)")
        result = self._run_hook(env_overrides={"R36_CURRENT_AGENT_ID": "lane-A"})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("REFUSED", result.stdout)
        self.assertIn("fail-cross-lane-file-pollution", result.stdout)
        self.assertIn("tools/shared.py", result.stdout)
        self.assertIn("lane-B", result.stdout)

    # 25. Gap #41 rebuttal: gap41-rebuttal marker silences cross-claim only.
    def test_gap41_rebuttal_marker_passes(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A",
             "files": ["tools/shared.py"],
             "expires_at": future},
            {"agent_id": "lane-B",
             "files": ["tools/shared.py"],
             "expires_at": future},
        ])
        self._write("tools/shared.py")
        self._git("add", "tools/shared.py")
        self._commit_msg(
            "lane-A: shared.py edit (operator-confirmed cross-claim)\n\n"
            "<!-- gap41-rebuttal: operator-approved integration commit; "
            "lane-B sibling has handed off shared.py per coordination plan -->\n"
        )
        result = self._run_hook(env_overrides={"R36_CURRENT_AGENT_ID": "lane-A"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("cross-claim rebuttal accepted", result.stdout)

    # 26. Gap #41: r36-rebuttal also silences cross-claim (broader umbrella).
    # The r36-rebuttal marker silences the entire gate, including Gap #41.
    def test_gap41_r36_rebuttal_also_silences_cross_claim(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A",
             "files": ["tools/shared.py"],
             "expires_at": future},
            {"agent_id": "lane-B",
             "files": ["tools/shared.py"],
             "expires_at": future},
        ])
        self._write("tools/shared.py")
        self._git("add", "tools/shared.py")
        self._commit_msg(
            "lane-A: shared.py edit\n\n"
            "<!-- r36-rebuttal: operator-approved integration sweep -->\n"
        )
        result = self._run_hook(env_overrides={"R36_CURRENT_AGENT_ID": "lane-A"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("rebuttal accepted", result.stdout)

    # 27. Gap #41: empty gap41-rebuttal does NOT silence the gate.
    def test_gap41_empty_rebuttal_does_not_pass(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A",
             "files": ["tools/shared.py"],
             "expires_at": future},
            {"agent_id": "lane-B",
             "files": ["tools/shared.py"],
             "expires_at": future},
        ])
        self._write("tools/shared.py")
        self._git("add", "tools/shared.py")
        self._commit_msg("lane-A: shared.py\n\n<!-- gap41-rebuttal:  -->\n")
        result = self._run_hook(env_overrides={"R36_CURRENT_AGENT_ID": "lane-A"})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("fail-cross-lane-file-pollution", result.stdout)

    # 28. Gap #41: oversized gap41-rebuttal (>200 chars) is ignored.
    def test_gap41_oversized_rebuttal_refused(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A",
             "files": ["tools/shared.py"],
             "expires_at": future},
            {"agent_id": "lane-B",
             "files": ["tools/shared.py"],
             "expires_at": future},
        ])
        self._write("tools/shared.py")
        self._git("add", "tools/shared.py")
        oversized = "x" * 300
        self._commit_msg(
            f"lane-A: shared.py\n\n<!-- gap41-rebuttal: {oversized} -->\n"
        )
        result = self._run_hook(env_overrides={"R36_CURRENT_AGENT_ID": "lane-A"})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    # 29. Gap #41: EXPIRED sibling intent does NOT count as a live cross-claim.
    # The expired sibling's pathspec is dropped at parse time, so the file
    # is effectively single-claimed by the current lane.
    def test_gap41_expired_sibling_intent_no_cross_claim(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        past = _iso(datetime.now(timezone.utc) - timedelta(hours=3))
        self._declare([
            {"agent_id": "lane-A",
             "files": ["tools/shared.py"],
             "expires_at": future},
            {"agent_id": "lane-B",
             "files": ["tools/shared.py"],
             "expires_at": past},   # EXPIRED
        ])
        self._write("tools/shared.py")
        self._git("add", "tools/shared.py")
        self._commit_msg("lane-A: shared.py (sibling intent expired)")
        result = self._run_hook(env_overrides={"R36_CURRENT_AGENT_ID": "lane-A"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("OK", result.stdout)

    # 30. Gap #41: 3-way cross-claim diagnostic enumerates all owners.
    def test_gap41_three_way_cross_claim_diagnostic(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A",
             "files": ["tools/shared.py"],
             "expires_at": future},
            {"agent_id": "lane-B",
             "files": ["tools/shared.py"],
             "expires_at": future},
            {"agent_id": "lane-C",
             "files": ["tools/shared.py"],
             "expires_at": future},
        ])
        self._write("tools/shared.py")
        self._git("add", "tools/shared.py")
        self._commit_msg("lane-A: shared.py (3-way cross-claim)")
        result = self._run_hook(env_overrides={"R36_CURRENT_AGENT_ID": "lane-A"})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("REFUSED", result.stdout)
        self.assertIn("fail-cross-lane-file-pollution", result.stdout)
        self.assertIn("lane-B", result.stdout)
        self.assertIn("lane-C", result.stdout)

    # 31. Gap #41: missing R36/R55 env var -> falls back to legacy union
    # mode and emits a warning. Cross-claim check is NOT applied because
    # there is no "current lane" to compare against (warn-only fallback
    # is the deliverable spec).
    def test_gap41_no_lane_id_env_falls_back_warn_only(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A",
             "files": ["tools/shared.py"],
             "expires_at": future},
            {"agent_id": "lane-B",
             "files": ["tools/shared.py"],
             "expires_at": future},
        ])
        self._write("tools/shared.py")
        self._git("add", "tools/shared.py")
        self._commit_msg("operator: shared.py (no lane env)")
        result = self._run_hook()  # no env_overrides
        # No current lane -> legacy union mode. The file IS in the union of
        # all declared lanes, so legacy mode passes.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("legacy union mode", result.stdout)

    # 32. Gap #41: GAP41_DISABLE env hook reverts to pre-Gap-41 behaviour.
    # When the kill-switch is set, cross-claim is NOT a refuse condition.
    def test_gap41_disable_env_hook(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A",
             "files": ["tools/shared.py"],
             "expires_at": future},
            {"agent_id": "lane-B",
             "files": ["tools/shared.py"],
             "expires_at": future},
        ])
        self._write("tools/shared.py")
        self._git("add", "tools/shared.py")
        self._commit_msg("lane-A: shared.py (Gap #41 disabled)")
        result = self._run_hook(env_overrides={
            "R36_CURRENT_AGENT_ID": "lane-A",
            "GAP41_DISABLE": "1",
        })
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("OK", result.stdout)
        self.assertNotIn("fail-cross-lane-file-pollution", result.stdout)

    # 33. Gap #41: ownership diagnostic emitted on every per-lane mode check.
    # The diagnostic is part of the visibility deliverable - operator should
    # see per-file ownership without grepping the pathspec JSON.
    def test_gap41_ownership_diagnostic_emitted(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": future},
        ])
        self._write("tools/foo.py")
        self._git("add", "tools/foo.py")
        self._commit_msg("lane-A: foo")
        result = self._run_hook(env_overrides={"R36_CURRENT_AGENT_ID": "lane-A"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("per-file ownership diagnostic", result.stdout)
        self.assertIn("owned-by: lane-A (current)", result.stdout)

    # 34. Gap #41: GIT_AUTHOR_NAME fallback applies when no R36/R55 env and
    # the git author name matches a live lane id exactly. This is the soft
    # fallback per deliverable spec - normally a no-op since author names
    # are not lane ids.
    def test_gap41_git_author_name_fallback_matches(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A",
             "files": ["tools/shared.py"],
             "expires_at": future},
            {"agent_id": "lane-B",
             "files": ["tools/shared.py"],
             "expires_at": future},
        ])
        self._write("tools/shared.py")
        self._git("add", "tools/shared.py")
        self._commit_msg("git-author-as-lane-id")
        result = self._run_hook(env_overrides={"GIT_AUTHOR_NAME": "lane-A"})
        # Falls back to lane-A as current lane via author name, then refuses
        # on Gap #41 cross-claim.
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("GIT_AUTHOR_NAME='lane-A'", result.stdout)
        self.assertIn("fail-cross-lane-file-pollution", result.stdout)

    # 35. Gap #41: GIT_AUTHOR_NAME fallback IGNORED when it does not match
    # any live lane id (the common case - author names are not lane ids).
    def test_gap41_git_author_name_fallback_no_match(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A",
             "files": ["tools/shared.py"],
             "expires_at": future},
            {"agent_id": "lane-B",
             "files": ["tools/shared.py"],
             "expires_at": future},
        ])
        self._write("tools/shared.py")
        self._git("add", "tools/shared.py")
        self._commit_msg("operator commit")
        result = self._run_hook(env_overrides={
            "GIT_AUTHOR_NAME": "Vuk Tanaskovic",  # not a lane id
        })
        # Falls back to legacy union mode; passes because file is in union.
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("legacy union mode", result.stdout)

    # 36. Gap #41: cross-claim combined with sibling-absorption emits BOTH
    # diagnostic sections in the same REFUSED output.
    def test_gap41_cross_claim_plus_sibling_absorption(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A",
             "files": ["tools/shared.py"],
             "expires_at": future},
            {"agent_id": "lane-B",
             "files": ["tools/shared.py", "tools/bar.py"],
             "expires_at": future},
        ])
        self._write("tools/shared.py")
        self._write("tools/bar.py")
        self._git("add", "tools/shared.py", "tools/bar.py")
        self._commit_msg("lane-A: shared.py + absorbed bar.py")
        result = self._run_hook(env_overrides={"R36_CURRENT_AGENT_ID": "lane-A"})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("REFUSED", result.stdout)
        # The combined diagnostic should call out both classes.
        self.assertIn("sibling-lane files", result.stdout)
        self.assertIn("cross-claimed file(s)", result.stdout)
        self.assertIn("tools/bar.py", result.stdout)
        self.assertIn("tools/shared.py", result.stdout)

    # ------------------------------------------------------------------
    # Gap #55 cases: undeclared (orphan) file refusal + dedicated verdict
    # + gap55-rebuttal marker.
    # ------------------------------------------------------------------

    # 37. Gap #55 baseline: staged file is in current lane's pathspec -> PASS.
    # Regression-locks that Gap #55 did not break the legitimate single-lane
    # subset case.
    def test_gap55_staged_in_current_lane_pathspec_passes(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": future},
        ])
        self._write("tools/foo.py")
        self._git("add", "tools/foo.py")
        self._commit_msg("lane-A: foo (declared)")
        result = self._run_hook(env_overrides={"R36_CURRENT_AGENT_ID": "lane-A"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("OK", result.stdout)

    # 38. Gap #55 anchor: staged file not in ANY pathspec -> REFUSE with the
    # dedicated `fail-undeclared-file-staged` verdict tag. This is the Gap
    # #55 anchor: pre-Gap-55 the refusal happened too, but without a
    # dedicated verdict tag operators could not distinguish orphan-staging
    # from cross-claim or sibling-absorption.
    def test_gap55_staged_file_not_in_any_pathspec_refused(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": future},
        ])
        self._write("tools/orphan.py")
        self._git("add", "tools/orphan.py")
        self._commit_msg("lane-A: accidentally staged orphan file")
        result = self._run_hook(env_overrides={"R36_CURRENT_AGENT_ID": "lane-A"})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("REFUSED", result.stdout)
        self.assertIn("fail-undeclared-file-staged", result.stdout)
        self.assertIn("tools/orphan.py", result.stdout)
        self.assertIn("NO live agent's pathspec", result.stdout)

    # 39. Gap #55 anchor: staged file only in EXPIRED pathspec -> REFUSE.
    # Expired entries are dropped at parse time, so the file is effectively
    # an orphan even though the JSON declaration mentioned it.
    def test_gap55_staged_file_only_in_expired_pathspec_refused(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        past = _iso(datetime.now(timezone.utc) - timedelta(hours=3))
        self._declare([
            {"agent_id": "lane-LIVE", "files": ["tools/live.py"],
             "expires_at": future},
            {"agent_id": "lane-EXPIRED", "files": ["tools/expired_only.py"],
             "expires_at": past},
        ])
        self._write("tools/expired_only.py")
        self._git("add", "tools/expired_only.py")
        self._commit_msg("staging file owned only by expired lane")
        result = self._run_hook(env_overrides={"R36_CURRENT_AGENT_ID": "lane-LIVE"})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("REFUSED", result.stdout)
        self.assertIn("fail-undeclared-file-staged", result.stdout)
        self.assertIn("tools/expired_only.py", result.stdout)

    # 40. Gap #55: gap55-rebuttal marker silences the orphan-file refusal.
    def test_gap55_rebuttal_marker_passes(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": future},
        ])
        self._write("tools/orphan.py")
        self._git("add", "tools/orphan.py")
        self._commit_msg(
            "lane-A: scratch cleanup\n\n"
            "<!-- gap55-rebuttal: operator-approved scratch-file removal; "
            "no lane intent warranted -->\n"
        )
        result = self._run_hook(env_overrides={"R36_CURRENT_AGENT_ID": "lane-A"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("orphan-file rebuttal accepted", result.stdout)

    # 41. Gap #55: r36-rebuttal also silences orphan-file refusal (broader
    # umbrella - same as for Gap #41 cross-claim).
    def test_gap55_r36_rebuttal_also_silences_orphan(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": future},
        ])
        self._write("tools/orphan.py")
        self._git("add", "tools/orphan.py")
        self._commit_msg(
            "lane-A: scratch cleanup\n\n"
            "<!-- r36-rebuttal: operator-driven cleanup sweep -->\n"
        )
        result = self._run_hook(env_overrides={"R36_CURRENT_AGENT_ID": "lane-A"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("rebuttal accepted", result.stdout)

    # 42. Gap #55: empty gap55-rebuttal does NOT silence the gate.
    def test_gap55_empty_rebuttal_does_not_pass(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": future},
        ])
        self._write("tools/orphan.py")
        self._git("add", "tools/orphan.py")
        self._commit_msg("orphan\n\n<!-- gap55-rebuttal:  -->\n")
        result = self._run_hook(env_overrides={"R36_CURRENT_AGENT_ID": "lane-A"})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("fail-undeclared-file-staged", result.stdout)

    # 43. Gap #55: oversized gap55-rebuttal (>200 chars) is ignored.
    def test_gap55_oversized_rebuttal_refused(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": future},
        ])
        self._write("tools/orphan.py")
        self._git("add", "tools/orphan.py")
        oversized = "z" * 300
        self._commit_msg(
            f"orphan\n\n<!-- gap55-rebuttal: {oversized} -->\n"
        )
        result = self._run_hook(env_overrides={"R36_CURRENT_AGENT_ID": "lane-A"})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("fail-undeclared-file-staged", result.stdout)

    # 44. Gap #55: legacy mode (no current lane env) also emits the dedicated
    # verdict tag on orphan-file refusal.
    def test_gap55_legacy_mode_orphan_file_refused(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": future},
        ])
        self._write("tools/orphan.py")
        self._git("add", "tools/orphan.py")
        self._commit_msg("operator: orphan file (no lane env)")
        result = self._run_hook()  # no env_overrides -> legacy mode
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("REFUSED", result.stdout)
        self.assertIn("fail-undeclared-file-staged", result.stdout)
        self.assertIn("tools/orphan.py", result.stdout)

    # 45. Gap #55: legacy mode honours gap55-rebuttal.
    def test_gap55_legacy_mode_rebuttal_passes(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": future},
        ])
        self._write("tools/orphan.py")
        self._git("add", "tools/orphan.py")
        self._commit_msg(
            "operator: orphan cleanup\n\n"
            "<!-- gap55-rebuttal: operator legacy-mode scratch cleanup -->\n"
        )
        result = self._run_hook()  # no env_overrides -> legacy mode
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("orphan-file rebuttal accepted", result.stdout)

    # 46. Gap #55: GAP55_DISABLE env hook reverts to pre-Gap-55 behaviour
    # (the refusal still happens but without the dedicated verdict tag).
    def test_gap55_disable_env_hook(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": future},
        ])
        self._write("tools/orphan.py")
        self._git("add", "tools/orphan.py")
        self._commit_msg("orphan (gap55 disabled)")
        result = self._run_hook(env_overrides={
            "R36_CURRENT_AGENT_ID": "lane-A",
            "GAP55_DISABLE": "1",
        })
        # Still refused (the underlying file isn't in any lane's pathspec)
        # but without the dedicated Gap #55 verdict.
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn("fail-undeclared-file-staged", result.stdout)

    # ------------------------------------------------------------------
    # Gap #50 cases: auto-prune stale-expired entries at hook entry
    # ------------------------------------------------------------------

    def _install_register_tool(self) -> None:
        """Install the real agent-pathspec-register.py into the test repo so
        the Gap #50 auto-prune step finds it at <REPO_ROOT>/tools/.
        """
        real = ROOT / "tools" / "agent-pathspec-register.py"
        dst = self.repo / "tools" / "agent-pathspec-register.py"
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(real, dst)

    # 47. Gap #50 anchor: expired entries are pruned at hook entry. After
    # the hook runs, the pathspec file no longer contains the expired
    # entries. The hook itself still passes for the legitimate staged file.
    def test_gap50_expired_entries_pruned_at_hook_entry(self) -> None:
        self._install_register_tool()
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        past = _iso(datetime.now(timezone.utc) - timedelta(hours=3))
        self._declare([
            {"agent_id": "lane-LIVE", "files": ["tools/live.py"],
             "expires_at": future},
            {"agent_id": "lane-EXPIRED-1", "files": ["tools/expired1.py"],
             "expires_at": past},
            {"agent_id": "lane-EXPIRED-2", "files": ["tools/expired2.py"],
             "expires_at": past},
        ])
        self._write("tools/live.py")
        self._git("add", "tools/live.py")
        self._commit_msg("lane-LIVE: live file (with expired siblings)")
        result = self._run_hook(env_overrides={"R36_CURRENT_AGENT_ID": "lane-LIVE"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        # After the hook ran, the pathspec file should NO LONGER contain
        # the expired entries (Gap #50 auto-prune side-effect).
        pathspec_after = json.loads(
            (self.repo / ".auditooor" / "agent_pathspec.json").read_text()
        )
        live_ids = {a["agent_id"] for a in pathspec_after.get("agents", [])}
        self.assertIn("lane-LIVE", live_ids)
        self.assertNotIn("lane-EXPIRED-1", live_ids)
        self.assertNotIn("lane-EXPIRED-2", live_ids)

    # 48. Gap #50: GAP50_DISABLE env hook skips the auto-prune. After the
    # hook runs the pathspec file STILL contains the expired entries.
    def test_gap50_disable_skips_prune(self) -> None:
        self._install_register_tool()
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        past = _iso(datetime.now(timezone.utc) - timedelta(hours=3))
        self._declare([
            {"agent_id": "lane-LIVE", "files": ["tools/live.py"],
             "expires_at": future},
            {"agent_id": "lane-EXPIRED", "files": ["tools/expired.py"],
             "expires_at": past},
        ])
        self._write("tools/live.py")
        self._git("add", "tools/live.py")
        self._commit_msg("lane-LIVE: live file (Gap #50 disabled)")
        result = self._run_hook(env_overrides={
            "R36_CURRENT_AGENT_ID": "lane-LIVE",
            "GAP50_DISABLE": "1",
        })
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

        # Pathspec should STILL contain the expired entry because prune
        # was skipped.
        pathspec_after = json.loads(
            (self.repo / ".auditooor" / "agent_pathspec.json").read_text()
        )
        live_ids = {a["agent_id"] for a in pathspec_after.get("agents", [])}
        self.assertIn("lane-LIVE", live_ids)
        self.assertIn("lane-EXPIRED", live_ids)

    # 49. Gap #50: auto-prune does NOT block the commit when the register
    # tool is missing or fails. The hook tolerates a missing prune helper.
    # We simulate this by pointing the hook at a temp repo where the
    # register tool path does not exist (the test repo does not have
    # tools/agent-pathspec-register.py).
    def test_gap50_missing_register_tool_no_op(self) -> None:
        future = _iso(datetime.now(timezone.utc) + timedelta(hours=2))
        self._declare([
            {"agent_id": "lane-A", "files": ["tools/foo.py"],
             "expires_at": future},
        ])
        self._write("tools/foo.py")
        self._git("add", "tools/foo.py")
        self._commit_msg("lane-A: foo (no register tool in test repo)")
        # The test repo does not have tools/agent-pathspec-register.py;
        # the auto-prune should silently no-op and the hook should still
        # pass for the legitimate staged file.
        result = self._run_hook(env_overrides={"R36_CURRENT_AGENT_ID": "lane-A"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("OK", result.stdout)


if __name__ == "__main__":
    unittest.main()
