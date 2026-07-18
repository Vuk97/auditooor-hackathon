# <!-- r36-rebuttal: registered lane reweighter-persist-fix in .auditooor/agent_pathspec.json -->
#!/usr/bin/env python3
"""Tests for the learning-closeout audit-run-full wiring (FIX 2).

The self-learning loop (agent-learning-compiler per-workspace +
hacker-q-reweight corpus-refresh) must run automatically at audit closeout,
not only via the manual `mimo-learning-loop` target. These tests lock in:

  * a `learning-closeout` make target exists and chains
    agent-learning-compiler + hacker-q-reweight;
  * the `learning-closeout` stage is present in `make -n audit-run-full`;
  * it is advisory (G9-parity) - a failure WARNs and continues rather than
    blocking the downstream production-pipeline-check / deep-freshness gates.
"""
import subprocess
import tempfile
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent.parent


def _make_n(target: str, ws: str) -> str:
    proc = subprocess.run(
        ["make", "-n", target, f"WS={ws}"],
        cwd=str(_REPO),
        capture_output=True,
        text=True,
    )
    # `make -n` may exit non-zero only on a hard parse error; capture both.
    return proc.stdout + proc.stderr


class LearningCloseoutStageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        ws = Path(cls._tmp.name) / "ws"
        (ws / ".auditooor").mkdir(parents=True)
        cls.ws = str(ws)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def test_learning_closeout_target_chains_both_steps(self):
        out = _make_n("learning-closeout", self.ws)
        self.assertIn("agent-learning-compiler", out,
                      "learning-closeout must run agent-learning-compiler")
        self.assertIn("hacker-q-reweight", out,
                      "learning-closeout must run hacker-q-reweight")

    def test_audit_run_full_includes_learning_closeout_stage(self):
        out = _make_n("audit-run-full", self.ws)
        self.assertIn('"stage":"learning-closeout"', out,
                      "audit-run-full must emit the learning-closeout stage to the manifest")
        self.assertIn("learning-closeout WS=", out,
                      "audit-run-full must invoke the learning-closeout sub-make")

    def test_learning_closeout_stage_is_advisory(self):
        out = _make_n("audit-run-full", self.ws)
        # The advisory WARN-and-continue branch must be present (G9-parity):
        # a learning-closeout failure must not exit/abort the run.
        self.assertIn("WARN learning-closeout failed", out,
                      "learning-closeout must WARN and continue on failure (advisory)")
        self.assertIn('"event":"stage-warn"', out,
                      "learning-closeout must record a stage-warn (not stage-fail) on failure")


if __name__ == "__main__":
    unittest.main()
