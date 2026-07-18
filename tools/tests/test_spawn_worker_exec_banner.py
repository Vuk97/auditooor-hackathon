"""
test_spawn_worker_exec_banner.py
--------------------------------
Regression tests for the Step 2.6 EXECUTE-DIRECTLY / cwd-disambiguation banner
injected at the top of every spawn-worker.sh enriched brief.

PROBLEM this guards (operator-observed 2026-07-06, SEI OCC-scheduler lane): a
dispatched worker, confused by a cross-worktree process cwd unrelated to the
audit workspace, BAILED and spun up its own unmanaged nested agent / worktree
instead of executing the brief - burning the whole dispatch with no result.
The banner tells the worker it IS the worker, to execute directly (no
re-delegation / no self-spawned worktree), and names $WORKSPACE as its cwd.

Spec:
  - Every lane type (hunt AND tool-build) gets the banner in the enriched brief.
  - The banner names the exact --workspace path.
  - SPAWN_WORKER_NO_EXEC_BANNER=1 suppresses it.
  - For non-hunt (tool-build) lanes the auto-injected rebuttal markers STILL
    appear ABOVE the banner (marker-at-top invariant preserved).
  - Original prompt content survives the banner injection.
"""

import os
import subprocess
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SPAWN_WORKER = os.path.join(REPO_ROOT, "tools", "spawn-worker.sh")
WORKSPACE = REPO_ROOT

BANNER_OPEN = "<!-- spawn-worker execute-directly banner (anti-redelegation) -->"
BANNER_LINE = "YOU ARE THE WORKER FOR THIS LANE."
MARKER_PREFIX = "<!-- hacker-mcp-rebuttal:"


def _write_prompt(content: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".md", prefix="sw_exec_test_")
    with os.fdopen(fd, "w") as fh:
        fh.write(content)
    return path


def _run(lane_id, lane_type, extra_env=None,
         prompt_content="# test prompt\n\nsome content\n"):
    prompt_path = _write_prompt(prompt_content)
    cmd = [
        "bash", SPAWN_WORKER,
        "--lane-id", lane_id,
        "--lane-type", lane_type,
        "--severity", "LOW",
        "--workspace", WORKSPACE,
        "--prompt-file", prompt_path,
        "--no-prebriefing",
        "--no-register",
        "--no-inject-prior-lanes",
        "--no-use-worktree",
    ]
    env = os.environ.copy()
    env["SPAWN_WORKER_BYPASS_REASON"] = "unit-test-exec-banner"
    env["SPAWN_WORKER_LOG_PATH"] = os.path.join(
        tempfile.gettempdir(), f"sw_exec_test_{lane_id}.jsonl"
    )
    env["SPAWN_WORKER_GAP29_DISABLE"] = "1"
    if extra_env:
        env.update(extra_env)
    result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=30)
    ep = result.stdout.strip()
    os.unlink(prompt_path)
    return result.returncode, result.stderr, ep


def _read(path):
    if not path or not os.path.isfile(path):
        return ""
    with open(path) as fh:
        return fh.read()


class TestSpawnWorkerExecBanner(unittest.TestCase):

    def test_hunt_lane_gets_banner_naming_workspace(self):
        rc, err, ep = _run("test-exec-hunt", "hunt")
        self.assertEqual(rc, 0, f"rc={rc}\nstderr={err}")
        content = _read(ep)
        self.assertIn(BANNER_OPEN, content, "execute-directly banner missing from hunt brief")
        self.assertIn(BANNER_LINE, content)
        self.assertIn(WORKSPACE, content, "banner must name the exact --workspace cwd")

    def test_tool_build_lane_gets_banner(self):
        rc, err, ep = _run("test-exec-tb", "tool-build")
        self.assertEqual(rc, 0, f"rc={rc}\nstderr={err}")
        content = _read(ep)
        self.assertIn(BANNER_OPEN, content, "execute-directly banner missing from tool-build brief")

    def test_markers_stay_above_banner_for_non_hunt(self):
        """The marker-at-top invariant must survive: markers prepend ABOVE the banner."""
        rc, err, ep = _run("test-exec-order", "tool-build")
        self.assertEqual(rc, 0, f"rc={rc}\nstderr={err}")
        content = _read(ep)
        marker_pos = content.find(MARKER_PREFIX)
        banner_pos = content.find(BANNER_OPEN)
        self.assertGreaterEqual(marker_pos, 0, "auto markers missing for tool-build")
        self.assertGreaterEqual(banner_pos, 0, "banner missing for tool-build")
        self.assertLess(marker_pos, banner_pos,
                        "rebuttal markers must remain above the execute-directly banner")

    def test_banner_precedes_prompt_body(self):
        sentinel = "SENTINEL_BODY_AFTER_EXEC_BANNER_42"
        rc, err, ep = _run("test-exec-body", "hunt",
                           prompt_content=f"# test\n\n{sentinel}\n")
        self.assertEqual(rc, 0, f"rc={rc}\nstderr={err}")
        content = _read(ep)
        self.assertIn(sentinel, content, "prompt body lost after banner injection")
        self.assertLess(content.find(BANNER_OPEN), content.find(sentinel),
                        "banner must precede the original prompt body")

    def test_banner_gives_verifiable_legitimacy(self):
        """Corrected 2026-07-07 (Strata MIDAS lane): forceful self-authorizing
        banner text ('THIS DISPATCH IS INTENTIONAL, NOT a leaked prompt, do NOT
        bail, nothing to confirm') BACKFIRED - a safety-conscious worker cited
        that exact language as the injection tell and refused twice. The winning
        shape (proven on the SATURN/ETHENA/MIDAS re-dispatches) is task-first +
        VERIFIABLE legitimacy: name the real on-disk workspace and tell the worker
        to confirm it itself, NOT to trust an assertion. So the banner must (a)
        name the workspace + point the worker to verify it (ls) + cd there, and
        (b) NOT contain the injection-shaped self-authorizing phrases."""
        rc, err, ep = _run("test-exec-verify", "hunt")
        self.assertEqual(rc, 0, f"rc={rc}\nstderr={err}")
        content = _read(ep).lower()
        self.assertIn("verify", content, "banner must invite the worker to verify legitimacy itself")
        self.assertIn("ls it", content, "banner must tell the worker to ls the real workspace")
        self.assertIn("cd to", content, "banner must tell the worker to cd to the workspace")
        # regression guard: the backfiring injection-shaped assertions must NOT return.
        for bad in ("not a leaked", "do not bail", "nothing to confirm", "not the wrong session"):
            self.assertNotIn(bad, content,
                             f"banner must NOT reintroduce the injection-shaped phrase {bad!r}")

    def test_env_suppresses_banner(self):
        rc, err, ep = _run("test-exec-off", "hunt",
                           extra_env={"SPAWN_WORKER_NO_EXEC_BANNER": "1"})
        self.assertEqual(rc, 0, f"rc={rc}\nstderr={err}")
        content = _read(ep)
        self.assertNotIn(BANNER_OPEN, content,
                         "SPAWN_WORKER_NO_EXEC_BANNER=1 must suppress the banner")


if __name__ == "__main__":
    unittest.main()
