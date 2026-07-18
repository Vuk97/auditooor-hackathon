#!/usr/bin/env python3
"""Tests for tools/forever-loop-budget.py — V5-P0-21 / Gap 38.

Hermetic via ``tempfile.TemporaryDirectory`` and signal injection.

Coverage map:

  Codex test #6 — exits near budget with a resumable state file
    test_max_calls_budget_exit_writes_resumable_manifest
    test_max_minutes_budget_exit_writes_manifest

  Codex test #7 — writes manifest on SIGTERM (mock signal)
    test_sigterm_handler_writes_manifest_with_external_termination_reason
"""
from __future__ import annotations

import importlib.util
import json
import os
import signal
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "forever-loop-budget.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "forever_loop_budget", TOOL_PATH
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["forever_loop_budget"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


def _read_manifest(state_dir: Path, name: str) -> dict:
    matches = sorted(state_dir.glob(f"{name}_manifest_*.json"))
    assert matches, f"no manifest under {state_dir} for {name}"
    return json.loads(matches[-1].read_text(encoding="utf-8"))


class MaxCallsBudgetTest(unittest.TestCase):
    """Codex test #6: budget exhaust writes a resumable manifest."""

    def test_max_calls_budget_exit_writes_resumable_manifest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="flb-") as tmp:
            state_dir = Path(tmp)
            with MOD.ForeverLoopBudget(
                name="demo-loop",
                max_calls=3,
                state_dir=state_dir,
                install_signal_handlers=False,
            ) as loop:
                while loop.should_continue():
                    loop.tick(
                        state={"i": loop.iters_completed},
                        resume={"next_id": loop.iters_completed + 1},
                    )
            self.assertEqual(loop.iters_completed, 3)
            self.assertEqual(loop.exit_reason, MOD.EXIT_MAX_CALLS)

            doc = _read_manifest(state_dir, "demo-loop")
            self.assertEqual(doc["schema"], "auditooor.forever_loop_budget.v1")
            self.assertEqual(doc["name"], "demo-loop")
            self.assertEqual(doc["iters_completed"], 3)
            self.assertEqual(doc["max_calls"], 3)
            self.assertEqual(doc["exit_reason"], "max_calls_reached")
            self.assertEqual(doc["resume_info"], {"next_id": 3})
            # Final state captured at last tick.
            self.assertEqual(doc["final_state"], {"i": 2})


class MaxMinutesBudgetTest(unittest.TestCase):
    def test_max_minutes_budget_exit_writes_manifest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="flb-") as tmp:
            state_dir = Path(tmp)
            # Tiny budget: 0.001 minutes ~= 60ms. Run 1 tick then bail.
            with MOD.ForeverLoopBudget(
                name="tiny-loop",
                max_minutes=0.001,
                state_dir=state_dir,
                install_signal_handlers=False,
            ) as loop:
                # First tick must run.
                self.assertTrue(loop.should_continue())
                loop.tick(state={"i": 0})
                # Sleep past the budget.
                time.sleep(0.2)
                # Second check must reject.
                self.assertFalse(loop.should_continue())
            self.assertEqual(loop.exit_reason, MOD.EXIT_MAX_MINUTES)
            doc = _read_manifest(state_dir, "tiny-loop")
            self.assertEqual(doc["exit_reason"], "max_minutes_reached")
            self.assertEqual(doc["iters_completed"], 1)


class SigtermHandlerTest(unittest.TestCase):
    """Codex test #7: SIGTERM produces a manifest with
    ``external_termination`` reason. We invoke the signal handler
    directly (no real subprocess) to keep the test hermetic.
    """

    def test_sigterm_handler_writes_manifest_with_external_termination_reason(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="flb-") as tmp:
            state_dir = Path(tmp)
            with MOD.ForeverLoopBudget(
                name="sig-loop",
                max_calls=10000,
                state_dir=state_dir,
                # Don't actually install handlers — we'll call _on_signal.
                install_signal_handlers=False,
            ) as loop:
                # Two normal iters.
                for _ in range(2):
                    self.assertTrue(loop.should_continue())
                    loop.tick(state={"phase": "running"})
                # Inject SIGTERM via the handler directly.
                loop._on_signal(signal.SIGTERM, None)
                # Next call must report should_continue == False.
                self.assertFalse(loop.should_continue())
            self.assertEqual(loop.exit_reason, MOD.EXIT_EXTERNAL)

            doc = _read_manifest(state_dir, "sig-loop")
            self.assertEqual(doc["exit_reason"], "external_termination")
            self.assertEqual(doc["iters_completed"], 2)
            self.assertEqual(doc["final_state"], {"phase": "running"})


class ManifestAtomicityTest(unittest.TestCase):
    """A truncated tmp file should never be visible at the manifest path."""

    def test_only_one_manifest_file_visible(self) -> None:
        with tempfile.TemporaryDirectory(prefix="flb-") as tmp:
            state_dir = Path(tmp)
            with MOD.ForeverLoopBudget(
                name="atom-loop",
                max_calls=1,
                state_dir=state_dir,
                install_signal_handlers=False,
            ) as loop:
                while loop.should_continue():
                    loop.tick()
            visible = list(state_dir.glob("*manifest*.json"))
            self.assertEqual(len(visible), 1, f"got {visible!r}")
            # And no .tmp leftovers.
            tmpfiles = list(state_dir.glob("*.tmp"))
            self.assertEqual(tmpfiles, [], f"tmp leftovers: {tmpfiles!r}")


class NameValidationTest(unittest.TestCase):
    def test_empty_name_rejected(self) -> None:
        with self.assertRaises(ValueError):
            MOD.ForeverLoopBudget(name="")


if __name__ == "__main__":
    unittest.main()
