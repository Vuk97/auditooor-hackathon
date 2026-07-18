"""Tests for ``tools/hackerman-pre-merge.py``.

Wave-1 hackerman capability lift (PR #726) - composite pre-merge runner.

Cases (>=6):

1.  compute_overall: every step PASS -> PASS.
2.  compute_overall: one critical step FAIL -> FAIL.
3.  compute_overall: only non-critical step FAIL (criticals PASS) -> NEEDS-CHANGES.
4.  compute_overall: every step SKIPPED -> PASS (vacuous-true).
5.  run_pre_merge: --dry-run marks every step SKIPPED with no subprocess work.
6.  run_pre_merge: --skip-step honoured, target step verdict is SKIPPED with
    reason mentioning ``--skip-step``.
7.  CLI: --json emits a parseable envelope on stdout with schema
    ``auditooor.hackerman_pre_merge.v1``.
8.  CLI: --strict makes NEEDS-CHANGES exit non-zero (simulated by injecting
    a synthetic results list via the public API).
9.  STEPS shape: every step has the canonical keys (step_id, label, argv,
    critical), step ids are unique, and the canonical six steps are present
    in the expected order.
"""
from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-pre-merge.py"


def _load_tool() -> Any:
    name = "_hackerman_pre_merge_test_mod"
    spec = importlib.util.spec_from_file_location(name, str(TOOL_PATH))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


class ComputeOverallTests(unittest.TestCase):
    def test_all_pass_is_pass(self) -> None:
        steps = [
            {"step_id": "a", "verdict": tool.PASS, "critical": True},
            {"step_id": "b", "verdict": tool.PASS, "critical": False},
        ]
        self.assertEqual(tool.compute_overall(steps), tool.OVERALL_PASS)

    def test_one_critical_fail_is_fail(self) -> None:
        steps = [
            {"step_id": "a", "verdict": tool.PASS, "critical": True},
            {"step_id": "b", "verdict": tool.FAIL, "critical": True},
        ]
        self.assertEqual(tool.compute_overall(steps), tool.OVERALL_FAIL)

    def test_non_critical_fail_is_needs_changes(self) -> None:
        steps = [
            {"step_id": "a", "verdict": tool.PASS, "critical": True},
            {"step_id": "b", "verdict": tool.FAIL, "critical": False},
            {"step_id": "c", "verdict": tool.PASS, "critical": True},
        ]
        self.assertEqual(tool.compute_overall(steps), tool.OVERALL_NEEDS_CHANGES)

    def test_all_skipped_is_pass(self) -> None:
        steps = [
            {"step_id": "a", "verdict": tool.SKIPPED, "critical": True},
            {"step_id": "b", "verdict": tool.SKIPPED, "critical": False},
        ]
        self.assertEqual(tool.compute_overall(steps), tool.OVERALL_PASS)

    def test_critical_fail_overrides_non_critical_fail(self) -> None:
        # If both a critical and a non-critical step fail, overall must be FAIL
        # (the critical failure dominates).
        steps = [
            {"step_id": "a", "verdict": tool.FAIL, "critical": False},
            {"step_id": "b", "verdict": tool.FAIL, "critical": True},
        ]
        self.assertEqual(tool.compute_overall(steps), tool.OVERALL_FAIL)


class RunPreMergeTests(unittest.TestCase):
    def test_dry_run_marks_every_step_skipped(self) -> None:
        results, overall = tool.run_pre_merge(dry_run=True)
        self.assertEqual(len(results), len(tool.STEPS))
        for r in results:
            self.assertEqual(r["verdict"], tool.SKIPPED)
            self.assertIsNone(r["returncode"])
        self.assertEqual(overall, tool.OVERALL_PASS)

    def test_skip_step_honoured(self) -> None:
        results, overall = tool.run_pre_merge(
            dry_run=True,
            skip_steps=["docs-check"],
        )
        by_id = {r["step_id"]: r for r in results}
        self.assertEqual(by_id["docs-check"]["verdict"], tool.SKIPPED)
        self.assertIn("--skip-step", by_id["docs-check"]["reason"])
        # Overall is still PASS (everything skipped one way or another via dry-run).
        self.assertEqual(overall, tool.OVERALL_PASS)


class StepsShapeTests(unittest.TestCase):
    def test_canonical_steps_present_in_order(self) -> None:
        expected_ids = [
            "hackerman-all",
            "docs-check",
            "hackerman-docs-cross-link-audit",
            "hackerman-pr726-merge-checklist",
            "hackerman-mcp-smoke-test",
            "hackerman-unit-tests",
        ]
        actual_ids = [s["step_id"] for s in tool.STEPS]
        self.assertEqual(actual_ids, expected_ids)

    def test_every_step_has_required_keys(self) -> None:
        for step in tool.STEPS:
            for key in ("step_id", "label", "argv", "critical"):
                self.assertIn(key, step, f"step missing key: {key}")
            self.assertIsInstance(step["argv"], list)
            self.assertTrue(len(step["argv"]) > 0)
            self.assertIsInstance(step["critical"], bool)

    def test_step_ids_unique(self) -> None:
        ids = [s["step_id"] for s in tool.STEPS]
        self.assertEqual(len(ids), len(set(ids)))


class CLITests(unittest.TestCase):
    def test_dry_run_json_envelope_parses(self) -> None:
        # Run the CLI as a subprocess in --dry-run --json mode and verify the
        # envelope is well-formed.
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL_PATH),
                "--dry-run",
                "--json",
                "--generated-at",
                "2026-05-16T00:00:00Z",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        envelope = json.loads(proc.stdout)
        self.assertEqual(envelope["schema"], "auditooor.hackerman_pre_merge.v1")
        self.assertEqual(envelope["overall"], tool.OVERALL_PASS)
        self.assertEqual(envelope["generated_at"], "2026-05-16T00:00:00Z")
        self.assertEqual(len(envelope["steps"]), len(tool.STEPS))

    def test_dry_run_text_report_smoke(self) -> None:
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL_PATH),
                "--dry-run",
                "--generated-at",
                "2026-05-16T00:00:00Z",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("hackerman-pre-merge composite report", proc.stdout)
        self.assertIn("OVERALL VERDICT: PASS", proc.stdout)

    def test_strict_exit_code_on_needs_changes(self) -> None:
        # Simulate NEEDS-CHANGES by constructing a synthetic step list and
        # round-tripping through the formatter; the CLI behavior is covered
        # via main() with mocked run_pre_merge.
        with mock.patch.object(
            tool,
            "run_pre_merge",
            return_value=(
                [
                    {
                        "step_id": "hackerman-all",
                        "label": "make hackerman-all",
                        "critical": True,
                        "verdict": tool.PASS,
                        "returncode": 0,
                        "duration_s": 0.1,
                        "reason": "",
                    },
                    {
                        "step_id": "docs-check",
                        "label": "make docs-check",
                        "critical": False,
                        "verdict": tool.FAIL,
                        "returncode": 2,
                        "duration_s": 0.2,
                        "reason": "exit=2",
                    },
                ],
                tool.OVERALL_NEEDS_CHANGES,
            ),
        ):
            # Without --strict: NEEDS-CHANGES exits 0.
            rc_default = tool.main(["--dry-run"])
            self.assertEqual(rc_default, 0)
            # With --strict: NEEDS-CHANGES exits 1.
            rc_strict = tool.main(["--dry-run", "--strict"])
            self.assertEqual(rc_strict, 1)

    def test_out_json_writes_file(self) -> None:
        with tempfile.TemporaryDirectory() as tdir:
            out_path = Path(tdir) / "envelope.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL_PATH),
                    "--dry-run",
                    "--out-json",
                    str(out_path),
                    "--generated-at",
                    "2026-05-16T00:00:00Z",
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(out_path.exists())
            envelope = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertEqual(envelope["schema"], "auditooor.hackerman_pre_merge.v1")
            self.assertEqual(envelope["overall"], tool.OVERALL_PASS)


if __name__ == "__main__":
    unittest.main()
