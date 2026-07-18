#!/usr/bin/env python3
"""Tests for tools/ranker-apply-weights.py (Wave-6 Phase E)."""
from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MOD_PATH = REPO_ROOT / "tools" / "ranker-apply-weights.py"


def _load():
    spec = importlib.util.spec_from_file_location("ranker_apply_for_test", MOD_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ranker_apply_for_test"] = mod
    spec.loader.exec_module(mod)
    return mod


RA = _load()


class TestApplyWeights(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ranker_apply_"))
        self.weights = self.tmp / "ranker_weights.yaml"
        self.weights.write_text("# initial\nweights:\n  w1: 0.45\n")
        self.diff = self.tmp / "ranker_weight_diff.md"
        self.diff.write_text("# diff\n")
        self.apply_log = self.tmp / "ranker_weight_apply_log.jsonl"
        # Snapshot
        self.sha = "abc12345"
        self.snap = self.tmp / f"ranker_weights.{self.sha}.yaml"
        self.snap.write_text("# proposed\nweights:\n  w1: 0.46\n")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_missing_snapshot_returns_3(self):
        rc = RA.apply_snapshot(
            sha="ffffffff",
            force=True,
            weights_path=self.weights,
            diff_path=self.diff,
            apply_log=self.apply_log,
        )
        self.assertEqual(rc, 3)

    def test_missing_diff_returns_4(self):
        self.diff.unlink()
        rc = RA.apply_snapshot(
            sha=self.sha,
            force=True,
            weights_path=self.weights,
            diff_path=self.diff,
            apply_log=self.apply_log,
        )
        self.assertEqual(rc, 4)

    def test_force_bypasses_prompt_and_applies(self):
        rc = RA.apply_snapshot(
            sha=self.sha,
            force=True,
            weights_path=self.weights,
            diff_path=self.diff,
            apply_log=self.apply_log,
        )
        self.assertEqual(rc, 0)
        # weights file replaced with snapshot content
        self.assertIn("w1: 0.46", self.weights.read_text())

    def test_apply_log_written(self):
        RA.apply_snapshot(
            sha=self.sha,
            force=True,
            weights_path=self.weights,
            diff_path=self.diff,
            apply_log=self.apply_log,
        )
        self.assertTrue(self.apply_log.exists())
        rows = [json.loads(l) for l in self.apply_log.read_text().splitlines() if l.strip()]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["sha8"], self.sha)
        self.assertIn("prev_sha8", rows[0])
        self.assertIn("ts", rows[0])

    def test_no_y_input_aborts(self):
        rc = RA.apply_snapshot(
            sha=self.sha,
            force=False,
            weights_path=self.weights,
            diff_path=self.diff,
            apply_log=self.apply_log,
            confirm_input="n",
        )
        self.assertEqual(rc, 5)
        # weights file NOT replaced
        self.assertIn("w1: 0.45", self.weights.read_text())


if __name__ == "__main__":
    unittest.main()
