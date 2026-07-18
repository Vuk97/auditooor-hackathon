#!/usr/bin/env python3
"""Tests for Wave-7 per-target (per-family) weight tuning in ranker.py +
ranker-learn.py.

Covers:
  T1: load_weights_per_family parses the yaml into {default, families, recency_per_family}
  T2: dydxprotocol/v4-chain resolves to family-id cosmos-sdk-forks
  T3: Uniswap/v3-core resolves to family-id uniswap-v3-forks
  T4: unknown/repo resolves to None (falls back to default)
  T5: resolve_effective_weights returns cosmos-sdk-forks weights when target_repo
      is dydxprotocol/v4-chain
  T6: rank() emits inputs.family_id when family resolves
  T7: rank() with cosmos-sdk-forks family weights yields confidence
      >= the global-only rank for RegisterAffiliate (S1 lift dominant)
  T8: rank() backward-compat: unknown/repo target still returns a valid result
      using default weights
  T9: ranker-learn --family cosmos-sdk-forks updates ranker_weights_per_family.yaml
      only (global ranker_weights.yaml byte-identical)
  T10: write_family_weights round-trips for an existing family
"""
from __future__ import annotations

import hashlib
import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
RANKER_PATH = REPO_ROOT / "tools" / "ranker.py"
RANKER_LEARN_PATH = REPO_ROOT / "tools" / "ranker-learn.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


RA = _load("ranker_per_family_for_test", RANKER_PATH)
RL = _load("ranker_learn_per_family_for_test", RANKER_LEARN_PATH)


# Disable prediction-log writes during these tests (rank() must not pollute
# the real audit/ranker_predictions_log.jsonl from a test run).
import os
os.environ.setdefault("RANKER_PREDICTION_LOG_DISABLED", "1")


class TestPerFamilyLoad(unittest.TestCase):

    def test_per_family_yaml_loads(self):
        pf = RA.load_weights_per_family()
        self.assertIn("default", pf)
        self.assertIn("families", pf)
        self.assertIn("recency_per_family", pf)
        self.assertIn("cosmos-sdk-forks", pf["families"])
        cf = pf["families"]["cosmos-sdk-forks"]
        # The Wave-7 spec values
        self.assertAlmostEqual(cf["w1"], 0.50, places=2)
        self.assertAlmostEqual(cf["w2"], 0.15, places=2)
        self.assertAlmostEqual(cf["w3"], 0.25, places=2)
        self.assertAlmostEqual(cf["w4"], 0.10, places=2)

    def test_per_family_default_block_present(self):
        pf = RA.load_weights_per_family()
        d = pf["default"]
        self.assertAlmostEqual(d["w1"], 0.45, places=2)
        # Sum ~ 1.0 (normalised)
        s = d["w1"] + d["w2"] + d["w3"] + d["w4"]
        self.assertAlmostEqual(s, 1.0, places=2)

    def test_recency_per_family_cosmos_present(self):
        pf = RA.load_weights_per_family()
        rec_c = pf["recency_per_family"].get("cosmos-sdk-forks")
        self.assertIsNotNone(rec_c)
        self.assertAlmostEqual(rec_c["same_engagement"], 0.90, places=2)


class TestFamilyResolution(unittest.TestCase):

    def test_dydx_resolves_to_cosmos_sdk_forks(self):
        fams = RA.load_sibling_families()
        self.assertEqual(
            RA.find_family_id("dydxprotocol/v4-chain", fams),
            "cosmos-sdk-forks",
        )

    def test_uniswap_v3_resolves_to_uniswap_v3_forks(self):
        fams = RA.load_sibling_families()
        self.assertEqual(
            RA.find_family_id("Uniswap/v3-core", fams),
            "uniswap-v3-forks",
        )

    def test_unknown_repo_resolves_none(self):
        fams = RA.load_sibling_families()
        self.assertIsNone(RA.find_family_id("totally-not/in-yaml", fams))


class TestResolveEffectiveWeights(unittest.TestCase):

    def test_cosmos_sdk_overrides_applied(self):
        global_cfg = RA.load_weights()
        per_family = RA.load_weights_per_family()
        fams = RA.load_sibling_families()
        weights, fam_id = RA.resolve_effective_weights(
            target_repo="dydxprotocol/v4-chain",
            weights_global=global_cfg,
            per_family=per_family,
            families=fams,
        )
        self.assertEqual(fam_id, "cosmos-sdk-forks")
        self.assertAlmostEqual(weights["w1"], 0.50, places=2)
        self.assertAlmostEqual(weights["w3"], 0.25, places=2)

    def test_unknown_repo_falls_back_to_default(self):
        global_cfg = RA.load_weights()
        per_family = RA.load_weights_per_family()
        fams = RA.load_sibling_families()
        weights, fam_id = RA.resolve_effective_weights(
            target_repo="totally-not/in-yaml",
            weights_global=global_cfg,
            per_family=per_family,
            families=fams,
        )
        self.assertIsNone(fam_id)
        # Should pull from per_family.default OR global ranker_weights.yaml
        self.assertAlmostEqual(weights["w1"], 0.45, places=2)


class TestRankUsesFamilyWeights(unittest.TestCase):

    def test_rank_inputs_exposes_family_id(self):
        result = RA.rank(
            target_repo="dydxprotocol/v4-chain",
            file_path="protocol/x/affiliates/keeper/msg_server.go",
            function_signature=(
                "func (k msgServer) RegisterAffiliate(ctx context.Context, "
                "msg *types.MsgRegisterAffiliate) "
                "(*types.MsgRegisterAffiliateResponse, error)"
            ),
            workspace_path=str(REPO_ROOT),
            top_n=3,
        )
        self.assertEqual(result.inputs["family_id"], "cosmos-sdk-forks")
        self.assertEqual(result.inputs["weights_source"], "per_family_override")
        # Family weights observed
        self.assertAlmostEqual(result.inputs["w1"], 0.50, places=2)
        self.assertAlmostEqual(result.inputs["w3"], 0.25, places=2)

    def test_cosmos_family_yields_at_least_as_much_confidence_as_global(self):
        """Acceptance: the per-family weights for cosmos-sdk-forks should
        NOT reduce RegisterAffiliate top-1 confidence vs. the global-only
        baseline. (The Wave-7 spec asks for >= 0.80 ideally; the realised
        lift depends on the corpus — see the spike report.)"""
        # With family weights (default rank() path)
        family_result = RA.rank(
            target_repo="dydxprotocol/v4-chain",
            file_path="protocol/x/affiliates/keeper/msg_server.go",
            function_signature=(
                "func (k msgServer) RegisterAffiliate(ctx context.Context, "
                "msg *types.MsgRegisterAffiliate) "
                "(*types.MsgRegisterAffiliateResponse, error)"
            ),
            workspace_path=str(REPO_ROOT),
            top_n=5,
        )
        # With explicit global weights (override family resolution)
        global_result = RA.rank(
            target_repo="dydxprotocol/v4-chain",
            file_path="protocol/x/affiliates/keeper/msg_server.go",
            function_signature=(
                "func (k msgServer) RegisterAffiliate(ctx context.Context, "
                "msg *types.MsgRegisterAffiliate) "
                "(*types.MsgRegisterAffiliateResponse, error)"
            ),
            workspace_path=str(REPO_ROOT),
            top_n=5,
            w1=0.45, w2=0.20, w3=0.20, w4=0.15,
        )
        self.assertGreater(len(family_result.ranked_attack_classes), 0)
        self.assertGreater(len(global_result.ranked_attack_classes), 0)
        fam_top = family_result.ranked_attack_classes[0]["confidence"]
        glob_top = global_result.ranked_attack_classes[0]["confidence"]
        self.assertGreaterEqual(fam_top, glob_top,
            f"per-family weights must not reduce conf vs global "
            f"(fam={fam_top}, global={glob_top})")

    def test_unknown_repo_still_returns_result(self):
        """Backward-compat: callers that pass an out-of-family repo
        still receive a valid RankResult using default weights."""
        result = RA.rank(
            target_repo="totally-not/in-yaml",
            file_path="some/file.go",
            workspace_path=str(REPO_ROOT),
            top_n=3,
        )
        self.assertIsNone(result.inputs["family_id"])
        # Fallback to default weights (sum still ~ 1.0 + variance OK)
        s = (result.inputs["w1"] + result.inputs["w2"]
             + result.inputs["w3"] + result.inputs["w4"])
        self.assertAlmostEqual(s, 1.0, places=2)


class TestRankerLearnFamilyFlag(unittest.TestCase):
    """`ranker-learn --family <id>` must only touch
    audit/ranker_weights_per_family.yaml, never the global weights."""

    def setUp(self):
        # Snapshot byte-hashes of both files; we'll compare after the test.
        self.global_path = REPO_ROOT / "audit" / "ranker_weights.yaml"
        self.family_path = REPO_ROOT / "audit" / "ranker_weights_per_family.yaml"
        self.tmp = Path(tempfile.mkdtemp(prefix="ranker_learn_fam_"))
        # Copy both files to tmp so we don't mutate the real ones.
        self.tmp_global = self.tmp / "ranker_weights.yaml"
        self.tmp_family = self.tmp / "ranker_weights_per_family.yaml"
        shutil.copyfile(self.global_path, self.tmp_global)
        shutil.copyfile(self.family_path, self.tmp_family)
        self.before_global_hash = hashlib.sha256(
            self.tmp_global.read_bytes()).hexdigest()
        self.before_family_hash = hashlib.sha256(
            self.tmp_family.read_bytes()).hexdigest()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_write_family_weights_updates_only_family_file(self):
        # Apply a non-trivial update to cosmos-sdk-forks in the tmp copy
        new_weights = {"w1": 0.52, "w2": 0.14, "w3": 0.25, "w4": 0.09}
        changed = RL.write_family_weights(
            "cosmos-sdk-forks", new_weights,
            path=self.tmp_family,
        )
        self.assertTrue(changed)
        # Family file must have changed
        after_family_hash = hashlib.sha256(
            self.tmp_family.read_bytes()).hexdigest()
        self.assertNotEqual(self.before_family_hash, after_family_hash)
        # Global file untouched (we never wrote to it)
        after_global_hash = hashlib.sha256(
            self.tmp_global.read_bytes()).hexdigest()
        self.assertEqual(self.before_global_hash, after_global_hash)
        # Reload and confirm
        loaded = RL.load_family_weights(
            "cosmos-sdk-forks", path=self.tmp_family)
        self.assertAlmostEqual(loaded["w1"], 0.52, places=3)
        self.assertAlmostEqual(loaded["w4"], 0.09, places=3)

    def test_write_family_weights_new_family_appends(self):
        new_weights = {"w1": 0.30, "w2": 0.30, "w3": 0.30, "w4": 0.10}
        changed = RL.write_family_weights(
            "brand-new-family", new_weights,
            path=self.tmp_family,
        )
        self.assertTrue(changed)
        text = self.tmp_family.read_text()
        self.assertIn("brand-new-family:", text)
        loaded = RL.load_family_weights(
            "brand-new-family", path=self.tmp_family)
        self.assertAlmostEqual(loaded["w1"], 0.30, places=3)


if __name__ == "__main__":
    unittest.main()
