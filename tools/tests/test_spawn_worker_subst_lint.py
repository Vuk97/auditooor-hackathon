#!/usr/bin/env python3
"""Regression: spawn-worker flags a prompt-file containing an UNEXPANDED command-
substitution ($(cat ...)).

Strata 2026-07-07 (Midas cascade): an agent authored a sub-dispatch that tried to
inline a brief via $(cat /tmp/....md) inside an Agent prompt string. Agent prompts
are NOT shell-evaluated, so the sub-agent received the LITERAL "$(cat ...)" text
and got stuck asking for the real content. This lint catches that foot-gun at
dispatch time."""
import os
import subprocess
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SPAWN_WORKER = os.path.join(REPO_ROOT, "tools", "spawn-worker.sh")


def _run(prompt_body, extra_env=None):
    fd, path = tempfile.mkstemp(suffix=".md", prefix="sw_subst_")
    with os.fdopen(fd, "w") as fh:
        fh.write(prompt_body)
    cmd = ["bash", SPAWN_WORKER, "--lane-id", "subst-test", "--lane-type", "hunt",
           "--severity", "LOW", "--workspace", REPO_ROOT, "--prompt-file", path,
           "--no-prebriefing", "--no-register", "--no-inject-prior-lanes",
           "--no-use-worktree"]
    env = os.environ.copy()
    env["SPAWN_WORKER_BYPASS_REASON"] = "unit-test-subst-lint"
    env["SPAWN_WORKER_LOG_PATH"] = os.path.join(tempfile.gettempdir(), "sw_subst_test.jsonl")
    env["SPAWN_WORKER_GAP29_DISABLE"] = "1"
    if extra_env:
        env.update(extra_env)
    r = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=30)
    os.unlink(path)
    return r.returncode, r.stderr


class T(unittest.TestCase):
    def test_cat_substitution_warns(self):
        rc, err = _run("Execute the brief: $(cat /tmp/spawn_worker_x_enriched.md)\n")
        self.assertEqual(rc, 0, err)  # advisory by default
        self.assertIn("command-substitution", err.lower())

    def test_cat_substitution_strict_fails(self):
        rc, err = _run("Do this: $(cat /tmp/brief.md)\n",
                       extra_env={"AUDITOOOR_SPAWN_SUBST_STRICT": "1"})
        self.assertEqual(rc, 1, err)
        self.assertIn("command-substitution", err.lower())

    def test_backtick_cat_warns(self):
        rc, err = _run("Content: `cat /tmp/brief.md`\n")
        self.assertIn("command-substitution", err.lower())

    def test_clean_prompt_no_warning(self):
        rc, err = _run("Read the brief at /tmp/brief.md and execute it.\n")
        self.assertEqual(rc, 0, err)
        self.assertNotIn("command-substitution", err.lower())


if __name__ == "__main__":
    unittest.main()
