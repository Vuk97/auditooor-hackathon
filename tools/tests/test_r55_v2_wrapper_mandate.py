"""Tests for the R55 v2 mandatory PATH-override shim at .auditooor/bin/git.

Three test cases:
  1. test_destructive_reset_triggers_gate: `git reset --hard HEAD` routes to gate
  2. test_non_destructive_passthrough: `git status` passes directly to real git
  3. test_exit_code_preserved: non-zero gate exit propagates correctly
"""

import os
import stat
import subprocess
import tempfile
import textwrap
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SHIM = os.path.join(REPO_ROOT, ".auditooor", "bin", "git")


def _write_exec(path: str, content: str) -> None:
    with open(path, "w") as f:
        f.write(content)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class TestR55V2WrapperMandate(unittest.TestCase):

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="r55_v2_test_")
        hooks_dir = os.path.join(self.tmpdir, "tools", "git-hooks")
        os.makedirs(hooks_dir, exist_ok=True)
        self.gate_script = os.path.join(hooks_dir, "pre-destructive-op-sibling-check.sh")
        bin_dir = os.path.join(self.tmpdir, "fakebin")
        os.makedirs(bin_dir, exist_ok=True)
        self.fake_git = os.path.join(bin_dir, "git")
        self.gate_sentinel = os.path.join(self.tmpdir, "gate_called")
        self.real_git_sentinel = os.path.join(self.tmpdir, "real_git_called")

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _run_shim(self, shim_args, gate_exit_code=0, extra_env=None):
        _write_exec(
            self.gate_script,
            textwrap.dedent(f"""\
                #!/usr/bin/env bash
                touch "{self.gate_sentinel}"
                exit {gate_exit_code}
            """),
        )
        _write_exec(
            self.fake_git,
            textwrap.dedent(f"""\
                #!/usr/bin/env bash
                if [ "$1" = "rev-parse" ] && [ "$2" = "--show-toplevel" ]; then
                  echo "{self.tmpdir}"
                  exit 0
                fi
                touch "{self.real_git_sentinel}"
                exit 0
            """),
        )
        env = os.environ.copy()
        env["PATH"] = os.path.join(self.tmpdir, "fakebin") + ":" + env.get("PATH", "")
        if extra_env:
            env.update(extra_env)
        return subprocess.run(
            ["bash", SHIM] + shim_args,
            env=env,
            capture_output=True,
            text=True,
        )

    def test_destructive_reset_triggers_gate(self):
        """reset --hard routes through pre-destructive-op-sibling-check.sh."""
        result = self._run_shim(["reset", "--hard", "HEAD"], gate_exit_code=0)
        self.assertTrue(
            os.path.exists(self.gate_sentinel),
            f"Gate NOT invoked for `git reset --hard HEAD`\nstderr: {result.stderr}",
        )
        self.assertEqual(result.returncode, 0, f"Shim should exit 0 when gate passes; stderr: {result.stderr}")
        self.assertTrue(os.path.exists(self.real_git_sentinel), "Real git NOT called after gate passed")

    def test_non_destructive_passthrough(self):
        """status, log, diff pass directly to real git without touching gate."""
        for subcmd in ["status", "log", "diff"]:
            for s in (self.gate_sentinel, self.real_git_sentinel):
                if os.path.exists(s):
                    os.remove(s)
            result = self._run_shim([subcmd])
            self.assertFalse(
                os.path.exists(self.gate_sentinel),
                f"Gate WRONGLY invoked for non-destructive `git {subcmd}`",
            )
            self.assertTrue(os.path.exists(self.real_git_sentinel), f"Real git NOT called for `git {subcmd}`")
            self.assertEqual(result.returncode, 0)

    def test_exit_code_preserved(self):
        """Gate non-zero exit propagates; real git is not called."""
        result = self._run_shim(["reset", "--hard", "HEAD"], gate_exit_code=1)
        self.assertTrue(os.path.exists(self.gate_sentinel), "Gate NOT invoked")
        self.assertNotEqual(result.returncode, 0, "Shim should propagate gate refusal exit code")
        self.assertFalse(os.path.exists(self.real_git_sentinel), "Real git WRONGLY called after gate refused")


if __name__ == "__main__":
    unittest.main()
