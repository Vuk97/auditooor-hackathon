#!/usr/bin/env python3
"""Tests for tools/ranker-learn.py (Wave-6 Phase E)."""
from __future__ import annotations

import datetime
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MOD_PATH = REPO_ROOT / "tools" / "ranker-learn.py"


def _load():
    spec = importlib.util.spec_from_file_location("ranker_learn_for_test", MOD_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ranker_learn_for_test"] = mod
    spec.loader.exec_module(mod)
    return mod


RL = _load()


class TestUpdateTagOutcome(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ranker_learn_"))
        self.tag = self.tmp / "sample.md.yaml"
        self.tag.write_text(
            "verdict_id: sample-verdict\n"
            "target_repo: dydxprotocol/v4-chain\n"
            "language: go\n"
            "filing_id: cantina-test-001\n"
            "severity_claimed: HIGH\n"
            "triager_outcome: PENDING\n"
            "bug_class: fee-redirect\n"
            "attack_classes_to_try: [admin-bypass, fee-redirect]\n",
            encoding="utf-8",
        )

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_set_triager_outcome_updates_existing_key(self):
        RL.set_yaml_key(self.tag, "triager_outcome", "ACCEPTED")
        text = self.tag.read_text()
        self.assertIn("triager_outcome: ACCEPTED", text)
        self.assertNotIn("triager_outcome: PENDING", text)

    def test_set_severity_final_appends_when_missing(self):
        RL.set_yaml_key(self.tag, "severity_final", "CRITICAL")
        text = self.tag.read_text()
        self.assertIn("severity_final: CRITICAL", text)

    def test_realized_ac_for_tag_inline_list(self):
        ac = RL.realized_ac_for_tag(self.tag)
        self.assertEqual(ac, "admin-bypass")

    def test_target_repo_for_tag(self):
        repo = RL.target_repo_for_tag(self.tag)
        self.assertEqual(repo, "dydxprotocol/v4-chain")


class TestResolveFilingId(unittest.TestCase):
    """resolve_tag_for_filing matches the repo's real corpus_tags layout."""

    def test_resolves_cantina_192(self):
        p = RL.resolve_tag_for_filing("cantina-192")
        self.assertIsNotNone(p, "cantina-192 must resolve via repo corpus_tags")
        self.assertTrue(p.exists())
        self.assertIn("cantina-192", p.name)

    def test_no_match_returns_none(self):
        p = RL.resolve_tag_for_filing("cantina-99999999")
        self.assertIsNone(p)


class TestGradient(unittest.TestCase):

    def _pred(self, top5, scores):
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return {
            "ts": ts,
            "target_repo": "dydxprotocol/v4-chain",
            "predicted_top_5": top5,
            "scores_by_scorer": scores,
            "weights_used_sha8": "deadbeef",
        }

    def test_reward_applied_when_prediction_matches(self):
        # admin-bypass realized, in top-5 with S1 dominant
        preds = [self._pred(
            top5=["admin-bypass", "fee-redirect"],
            scores={"S1": {"admin-bypass": 1.0}, "S2": {}, "S3": {}, "S4": {}},
        )]
        grad, counts = RL.compute_gradient(preds, "admin-bypass")
        self.assertEqual(counts["hits"], 1)
        self.assertEqual(counts["misses"], 0)
        # Reward: S1 should get +REWARD * 1.0
        self.assertAlmostEqual(grad["w1"], RL.REWARD, places=4)
        self.assertAlmostEqual(grad["w2"], 0.0)

    def test_penalty_applied_when_prediction_misses(self):
        # admin-bypass realized but NOT in top-5; top-1 was fee-redirect via S2
        preds = [self._pred(
            top5=["fee-redirect"],
            scores={"S1": {}, "S2": {"fee-redirect": 2.0}, "S3": {}, "S4": {}},
        )]
        grad, counts = RL.compute_gradient(preds, "admin-bypass")
        self.assertEqual(counts["misses"], 1)
        self.assertAlmostEqual(grad["w2"], -RL.PENALTY, places=4)

    def test_weight_cap_enforced_low(self):
        current = {"w1": 0.06, "w2": 0.20, "w3": 0.20, "w4": 0.15}
        # Huge negative gradient — should clamp at WEIGHT_FLOOR (0.05)
        grad = {"w1": -1000.0, "w2": 0.0, "w3": 0.0, "w4": 0.0}
        out = RL.apply_gradient(current, grad, lr=RL.LR)
        self.assertAlmostEqual(out["w1"], RL.WEIGHT_FLOOR, places=2)

    def test_weight_cap_enforced_high(self):
        current = {"w1": 0.55, "w2": 0.20, "w3": 0.20, "w4": 0.15}
        # Huge positive gradient — should clamp at WEIGHT_CEIL (0.6)
        grad = {"w1": 1000.0, "w2": 0.0, "w3": 0.0, "w4": 0.0}
        out = RL.apply_gradient(current, grad, lr=RL.LR)
        self.assertAlmostEqual(out["w1"], RL.WEIGHT_CEIL, places=2)


class TestSnapshotAndDiff(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ranker_learn_snap_"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_snapshot_written(self):
        proposed = {"w1": 0.46, "w2": 0.20, "w3": 0.19, "w4": 0.15}
        path, sha8 = RL.write_weights_snapshot(
            proposed, snapshot_dir=self.tmp, provenance="unit test"
        )
        self.assertTrue(path.exists())
        self.assertEqual(len(sha8), 8)
        body = path.read_text()
        self.assertIn("w1: 0.46", body)
        self.assertIn("provenance:", body)

    def test_diff_written(self):
        snap, sha8 = RL.write_weights_snapshot(
            {"w1": 0.46, "w2": 0.20, "w3": 0.19, "w4": 0.15},
            snapshot_dir=self.tmp, provenance="unit test",
        )
        diff_out = self.tmp / "ranker_weight_diff.md"
        path = RL.write_diff(
            current={"w1": 0.45, "w2": 0.20, "w3": 0.20, "w4": 0.15},
            proposed={"w1": 0.46, "w2": 0.20, "w3": 0.19, "w4": 0.15},
            sha8=sha8, snapshot_path=snap,
            counts={"hits": 3, "misses": 1, "rows": 4},
            realized_ac="admin-bypass",
            filing_id="cantina-192",
            out_path=diff_out,
        )
        body = path.read_text()
        self.assertIn("cantina-192", body)
        self.assertIn("admin-bypass", body)
        self.assertIn(f"make ranker-apply-weights SHA={sha8}", body)
        # Delta column populated
        self.assertIn("+0.01", body)
        self.assertIn("-0.01", body)


class TestBatchMode(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="ranker_learn_batch_"))
        self.tags = self.tmp / "tags"
        self.tags.mkdir()
        old = self.tags / "old.md.yaml"
        old.write_text(
            "verdict_id: old\nfiling_id: cantina-999\n"
            "triager_outcome: ACCEPTED\nattack_classes_to_try: [foo]\n"
        )
        # Backdate to outside 24h window
        st = old.stat()
        backdate = st.st_mtime - (48 * 3600)
        os.utime(old, (backdate, backdate))
        new = self.tags / "new.md.yaml"
        new.write_text(
            "verdict_id: new\nfiling_id: cantina-1000\n"
            "triager_outcome: ACCEPTED\nattack_classes_to_try: [bar]\n"
        )

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_since_24h_filters_old_tags(self):
        recent = RL.collect_batch_tags(
            since=datetime.timedelta(hours=24),
            tags_dir=self.tags,
        )
        names = [p.name for p in recent]
        self.assertIn("new.md.yaml", names)
        self.assertNotIn("old.md.yaml", names)


class TestReindex(unittest.TestCase):
    """Smoke that reindex produces by_attack_class.jsonl."""

    def test_reindex_regenerates_indexes(self):
        # Reindex against the live repo (rc=0 enough; we don't mutate)
        rc = RL.reindex_corpus_tags()
        self.assertEqual(rc, 0)
        out = REPO_ROOT / "audit" / "corpus_tags" / "index" / "by_attack_class.jsonl"
        self.assertTrue(out.exists())


if __name__ == "__main__":
    unittest.main()
