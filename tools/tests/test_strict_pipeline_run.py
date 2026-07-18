import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "strict-pipeline-run.py"


class StrictPipelineRunTests(unittest.TestCase):
    def run_tool(self, body):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "run.log"
            return subprocess.run(
                [sys.executable, str(TOOL), "--log", str(log), "--", sys.executable, "-c", body],
                cwd=ROOT,
                text=True,
                capture_output=True,
            )

    def test_soft_failure_output_blocks_zero_exit(self):
        result = self.run_tool("print('WARN continuing');")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("HARD-BLOCK", result.stderr)

    def test_clean_output_passes(self):
        result = self.run_tool("print('pass-step-integrity');")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_real_child_failure_remains_failure(self):
        result = self.run_tool("raise SystemExit(7)")
        self.assertEqual(result.returncode, 7)

    def test_evidence_prose_does_not_look_like_control_status(self):
        result = self.run_tool("print('agent_rationale: reliability warning in historical code');")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_timeout_budget_banner_is_not_a_timeout_failure(self):
        result = self.run_tool("print('[stage] running check (timeout 120s)');")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_timeout_status_is_a_hard_failure(self):
        result = self.run_tool("print('[stage] status=timeout');")
        self.assertNotEqual(result.returncode, 0)

    def test_informational_continuation_is_not_a_failure(self):
        result = self.run_tool("print('[stage] continuing with partial evidence');")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_shell_comment_timeout_invariant_is_not_a_failure(self):
        result = self.run_tool("print('# The OUTER wrapper timeout MUST exceed the INTERNAL run ceiling');")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_dot_go_language_conditional_skip_is_allowed(self):
        result = self.run_tool("print('[stage] SKIPPED - no .go files in workspace');")
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
