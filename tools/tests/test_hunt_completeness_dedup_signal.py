#!/usr/bin/env python3
# r36-rebuttal: lane-HUNT-DEDUP-FIRST-ORCH registered in .auditooor/agent_pathspec.json
"""Tests for the L36 dedup-first signal added to hunt-completeness-check.py."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "hunt-completeness-check.py"
_spec = importlib.util.spec_from_file_location("hunt_completeness_check", _TOOL)
mod = importlib.util.module_from_spec(_spec)
sys.modules["hunt_completeness_check"] = mod
_spec.loader.exec_module(mod)


class TestDedupFirstSignal(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name) / "ws"
        (self.ws / ".auditooor").mkdir(parents=True)

    def tearDown(self):
        self._tmp.cleanup()

    def _write_skip_set(self, schema="auditooor.l36_hunt_skip_set.v1", entries=3):
        (self.ws / ".auditooor" / "hunt_skip_set.json").write_text(json.dumps({
            "schema": schema,
            "source_counts": {"total_after_dedup": entries},
            "entries": [{"slug": f"e{i}"} for i in range(entries)],
        }))

    def test_dedup_first_is_first_in_signal_order(self):
        self.assertEqual(mod._SIGNAL_ORDER[0][0], "dedup-first")
        self.assertEqual(mod._SIGNAL_ORDER[0][1], "fail-no-dedup-skip-set")

    def test_missing_skip_set_fails_signal(self):
        r = mod.check_dedup_first(self.ws)
        self.assertFalse(r.ok)
        self.assertIn("hunt_skip_set.json", r.reason)

    def test_present_skip_set_passes_signal(self):
        self._write_skip_set()
        r = mod.check_dedup_first(self.ws)
        self.assertTrue(r.ok)
        self.assertEqual(r.detail["entries"], 3)

    def test_wrong_schema_fails_signal(self):
        self._write_skip_set(schema="some.other.schema.v9")
        r = mod.check_dedup_first(self.ws)
        self.assertFalse(r.ok)
        self.assertIn("not a valid L36 skip-set", r.reason)

    def test_empty_skip_set_still_passes(self):
        self._write_skip_set(entries=0)
        r = mod.check_dedup_first(self.ws)
        self.assertTrue(r.ok)

    def test_evaluate_reports_dedup_first_as_first_failure(self):
        # No skip-set + nothing else => dedup-first is the top-level verdict.
        result = mod.evaluate(self.ws)
        self.assertEqual(result["verdict"], "fail-no-dedup-skip-set")
        # dedup-first appears as a signal with raw_ok False.
        df = next(s for s in result["signals"] if s["signal"] == "dedup-first")
        self.assertFalse(df["ok"])

    def test_evaluate_dedup_first_passes_when_skip_set_present(self):
        self._write_skip_set()
        result = mod.evaluate(self.ws)
        df = next(s for s in result["signals"] if s["signal"] == "dedup-first")
        self.assertTrue(df["ok"])
        # Some other signal still fails (no audit-deep etc.) so verdict is not pass.
        self.assertNotEqual(result["verdict"], "fail-no-dedup-skip-set")

    def test_dedup_first_rebuttal_flips_signal(self):
        # Named-signal rebuttal flips dedup-first to ok-rebuttal.
        (self.ws / ".auditooor" / "hunt_completeness_rebuttal.txt").write_text(
            "l35-rebuttal: dedup-first: release-tarball target, no prior corpus\n"
        )
        result = mod.evaluate(self.ws)
        df = next(s for s in result["signals"] if s["signal"] == "dedup-first")
        self.assertEqual(df["verdict"], "ok-rebuttal")


if __name__ == "__main__":
    unittest.main()
