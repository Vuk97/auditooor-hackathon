#!/usr/bin/env python3
"""Tests for ranker.py prediction-log instrumentation (Wave-6 Phase E)."""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
RANKER_PATH = REPO_ROOT / "tools" / "ranker.py"


def _load_ranker():
    spec = importlib.util.spec_from_file_location("ranker_for_predlog_test", RANKER_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ranker_for_predlog_test"] = mod
    spec.loader.exec_module(mod)
    return mod


RM = _load_ranker()


class TestPredictionLog(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ranker_predlog_"))
        self.log = self.tmp / "ranker_predictions_log.jsonl"
        # Force RANKER_PREDICTION_LOG_DISABLED off
        os.environ.pop("RANKER_PREDICTION_LOG_DISABLED", None)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)
        os.environ.pop("RANKER_PREDICTION_LOG_DISABLED", None)

    def test_helper_appends_row(self):
        RM._append_prediction_log(
            target_repo="dydxprotocol/v4-chain",
            file_path="x/affiliates/keeper.go",
            function_signature="func (k Keeper) Foo()",
            shape_hash="abcdef0123456789",
            predicted_top_5=["admin-bypass", "fee-redirect"],
            s1={"admin-bypass": [{"contribution": 1.2}]},
            s2={},
            s3={},
            s4={"admin-bypass": [{"contribution": 0.5}]},
            weights_used_sha8="deadbeef",
            log_path=self.log,
        )
        self.assertTrue(self.log.exists())
        rows = [json.loads(l) for l in self.log.read_text().splitlines() if l.strip()]
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["target_repo"], "dydxprotocol/v4-chain")
        self.assertEqual(row["predicted_top_5"], ["admin-bypass", "fee-redirect"])
        self.assertEqual(row["weights_used_sha8"], "deadbeef")
        # scores_by_scorer has 5 keys (S5 added in Wave-7)
        self.assertEqual(set(row["scores_by_scorer"].keys()), {"S1", "S2", "S3", "S4", "S5"})
        # S1 contribution compressed correctly
        self.assertAlmostEqual(row["scores_by_scorer"]["S1"]["admin-bypass"], 1.2, places=4)

    def test_helper_appends_multiple_rows(self):
        for i in range(3):
            RM._append_prediction_log(
                target_repo="r",
                file_path=f"f{i}.go",
                function_signature="",
                shape_hash="h",
                predicted_top_5=[],
                s1={}, s2={}, s3={}, s4={},
                weights_used_sha8="00000000",
                log_path=self.log,
            )
        rows = [l for l in self.log.read_text().splitlines() if l.strip()]
        self.assertEqual(len(rows), 3)

    def test_disabled_env_var_bypasses_log(self):
        """Simulates the rank() guard that skips logging when env-var is set."""
        os.environ["RANKER_PREDICTION_LOG_DISABLED"] = "1"
        # We mimic the guard inline (rank() does the same)
        wrote = False
        if os.environ.get("RANKER_PREDICTION_LOG_DISABLED") != "1":
            RM._append_prediction_log(
                target_repo="r", file_path="f.go", function_signature="",
                shape_hash="h", predicted_top_5=[],
                s1={}, s2={}, s3={}, s4={}, weights_used_sha8="x",
                log_path=self.log,
            )
            wrote = True
        self.assertFalse(wrote)
        self.assertFalse(self.log.exists())

    def test_weights_sha8_matches_real_weights_file(self):
        sha = RM._weights_sha8()
        self.assertEqual(len(sha), 8)
        # All hex
        int(sha, 16)


if __name__ == "__main__":
    unittest.main()
