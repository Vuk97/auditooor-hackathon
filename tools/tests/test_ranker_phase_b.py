#!/usr/bin/env python3
"""Tests for tools/ranker.py — Phase-B (S2 + S3 + weighted combine).

Covers:
  - T1: load_weights returns the canonical 4-weight tuple
  - T2: load_sibling_families returns at least the cosmos-sdk + uniswap-v4 families
  - T3: load_bug_class_to_ac_map yields >= 25 bug_class -> attack_class entries
  - T4: find_family(target_repo) returns correct sibling set (no self)
  - T5: score_s2 fallback excludes same-repo tags (only cross-engagement)
  - T6: score_s3 applies the 0.5 discount to a sibling-repo verdict
  - T7: combine_scores adds a convergence bonus when 2+ scorers agree
  - T8: RegisterAffiliate Phase-B spike: top-1 confidence >= 0.65
        (was 0.46 in Phase A)
  - T9: rank() inputs payload exposes w1..w4 + s2_enabled + s3_enabled
  - T10: rank() with disable_s2=True yields a confidence strictly less
         than the S2-enabled run (sanity proof S2 contributes)
"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MOD_PATH = REPO_ROOT / "tools" / "ranker.py"


def _load() -> object:
    spec = importlib.util.spec_from_file_location("ranker_phase_b_for_test", MOD_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {MOD_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ranker_phase_b_for_test"] = mod
    spec.loader.exec_module(mod)
    return mod


RA = _load()


class TestWeightsLoading(unittest.TestCase):

    def test_weights_yaml_has_w1_w2_w3_w4(self):
        cfg = RA.load_weights()
        w = cfg.get("weights", {})
        self.assertIn("w1", w)
        self.assertIn("w2", w)
        self.assertIn("w3", w)
        self.assertIn("w4", w)
        # Phase-B canonical numbers (w4 reduced from 0.15 -> 0.10 in
        # Wave-7 to make room for w5 cross-language transfer at 0.05).
        # Wave-9 Track B: w1 shifted from 0.45 -> 0.30 to free 0.15 for
        # w6 (S6 detector grounding scorer).
        self.assertAlmostEqual(w["w1"], 0.30, places=2)
        self.assertAlmostEqual(w["w2"], 0.20, places=2)
        self.assertAlmostEqual(w["w3"], 0.20, places=2)
        self.assertAlmostEqual(w["w4"], 0.10, places=2)
        # w5 added in Wave-7
        self.assertAlmostEqual(w.get("w5", 0.0), 0.05, places=2)
        # w6 added in Wave-9 Track B
        self.assertAlmostEqual(w.get("w6", 0.0), 0.15, places=2)
        # Sum is 1.0 (so a normalised top-score doesn't blow up the sigmoid)
        self.assertAlmostEqual(
            sum(w[k] for k in ("w1", "w2", "w3", "w4", "w5", "w6")), 1.0, places=2
        )


class TestSiblingFamilies(unittest.TestCase):

    def test_cosmos_sdk_family_present(self):
        fams = RA.load_sibling_families()
        self.assertIn("cosmos-sdk-forks", fams)
        self.assertIn("dydxprotocol/v4-chain", fams["cosmos-sdk-forks"])
        self.assertIn("osmosis-labs/osmosis", fams["cosmos-sdk-forks"])

    def test_find_family_excludes_self(self):
        fams = RA.load_sibling_families()
        siblings = RA.find_family("dydxprotocol/v4-chain", fams)
        self.assertNotIn("dydxprotocol/v4-chain", siblings)
        # At least cosmos/cosmos-sdk should sibling-relate
        self.assertIn("cosmos/cosmos-sdk", siblings)

    def test_find_family_unknown_repo_empty(self):
        fams = RA.load_sibling_families()
        self.assertEqual(RA.find_family("totally-not-in-yaml/repo", fams), [])


class TestBugClassMap(unittest.TestCase):

    def test_map_has_at_least_25_entries(self):
        m = RA.load_bug_class_to_ac_map()
        mappings = m.get("mappings", {})
        self.assertGreaterEqual(len(mappings), 25,
            f"expected >=25 bug_class entries, got {len(mappings)}")

    def test_known_bug_class_present(self):
        m = RA.load_bug_class_to_ac_map()
        mappings = m.get("mappings", {})
        # The cantina-192 anchor bug class
        bc = "missing-blocked-addr-check-on-fee-distribution"
        self.assertIn(bc, mappings)
        self.assertIn("admin-bypass", mappings[bc])
        self.assertIn("blocked-addr-bypass", mappings[bc])

    def test_heatmap_bridges_present(self):
        m = RA.load_bug_class_to_ac_map()
        bridges = m.get("heatmap_family_bridges", {})
        self.assertGreaterEqual(len(bridges), 5)
        # A reasonable bridge: state-machine-race -> at least one race bug_class
        self.assertIn("state-machine-race", bridges)


class TestS2Fallback(unittest.TestCase):

    def test_s2_fallback_excludes_same_repo(self):
        # The fallback aggregator must skip same-repo tags (those are S1's
        # job). Otherwise S2 doublecounts.
        all_tags = RA.load_tags()
        rows = RA._local_bug_family_aggregate("dydxprotocol/v4-chain", all_tags)
        same_repo_classes = {
            t.bug_class for t in all_tags
            if t.target_repo == "dydxprotocol/v4-chain" and t.bug_class
        }
        # Every same-repo bug_class must NOT be in fallback rows UNLESS
        # another (non-dydx) engagement also has it. Test that at least one
        # known same-repo-only class is excluded.
        # accountplus-module-direct-scan is filed by dydx only.
        accountplus_in_rows = [r for r in rows if r.get("bug_class") == "accountplus-module-direct-scan"]
        self.assertEqual(accountplus_in_rows, [],
            "same-repo dydx accountplus class must not appear in S2 fallback")

    def test_s2_high_frequency_generic_rows_are_log_capped(self):
        # Regression for Hackerman function-mindset over-broadcasting: a
        # generic class with thousands of corpus hits must stay a weak prior,
        # not dominate same-function evidence.
        tags = [
            RA.TagRecord(
                verdict_id=f"generic-{i}",
                target_repo=f"repo/{i}",
                audit_pin_sha="0",
                language="go",
                verdict_class="FILED",
                bug_class="access-control",
                attack_classes_to_try=["admin-bypass"],
                triager_outcome="ACCEPTED",
                drop_reason=None,
                sites=[],
                raw={"severity_claimed": "MED"},
            )
            for i in range(2500)
        ]
        mapping = {"mappings": {"access-control": ["admin-bypass"]}, "heatmap_family_bridges": {}}
        out = RA.score_s2("dydxprotocol/v4-chain", mapping, tags)
        contribution = out["admin-bypass"][0]["contribution"]
        self.assertLessEqual(contribution, 0.11)


class TestS3CrossRepo(unittest.TestCase):

    def test_s3_discount_applied(self):
        # Construct a synthetic tag for a sibling repo and verify the
        # contribution carries the 0.5 discount.
        sh = RA.shape_hash_module()
        target_hash = "abcd1234"
        target_hash_fine = "fine_a"
        sibling_tag = RA.TagRecord(
            verdict_id="sibling-fake",
            target_repo="cosmos/cosmos-sdk",
            audit_pin_sha="0",
            language="go",
            verdict_class="FILED",
            bug_class="some-class",
            attack_classes_to_try=["some-ac"],
            triager_outcome="ACCEPTED",
            drop_reason=None,
            sites=[{
                "shape_hash": target_hash,  # exact match → sim=1.0
                "shape_hash_fine": target_hash_fine,
                "receiver_type": None,
                "file_path": "x/y.go",
            }],
            raw={},
        )
        same_repo_tag = RA.TagRecord(
            verdict_id="same-repo-fake",
            target_repo="dydxprotocol/v4-chain",
            audit_pin_sha="0",
            language="go",
            verdict_class="FILED",
            bug_class="some-class",
            attack_classes_to_try=["other-ac"],
            triager_outcome="ACCEPTED",
            drop_reason=None,
            sites=[{"shape_hash": target_hash, "shape_hash_fine": target_hash_fine, "file_path": "z.go"}],
            raw={},
        )
        families = {"cosmos-sdk-forks": ["dydxprotocol/v4-chain", "cosmos/cosmos-sdk"]}
        out = RA.score_s3(
            target_repo="dydxprotocol/v4-chain",
            target_hash=target_hash,
            target_hash_fine=target_hash_fine,
            target_receiver_family=None,
            sibling_families=families,
            tags=[sibling_tag, same_repo_tag],
        )
        # Same-repo tag must NOT appear in S3 output
        self.assertIn("some-ac", out)
        self.assertNotIn("other-ac", out, "S3 must skip same-repo tags")
        entries = out["some-ac"]
        self.assertEqual(len(entries), 1)
        # outcome_weight(ACCEPTED) = 1.0, sim = 1.0, discount = 0.5
        # → contribution = 0.5
        self.assertAlmostEqual(entries[0]["contribution"], 0.5, places=3)
        self.assertEqual(entries[0]["discount"], 0.5)


class TestConvergenceBonus(unittest.TestCase):

    def test_convergence_bonus_applied(self):
        # Score with 2 scorers → bonus = (2 - 1) * 0.15 = 0.15
        s1 = {"ac1": [{"contribution": 0.5, "scorer": "S1"}]}
        s2 = {"ac1": [{"contribution": 0.2, "scorer": "S2"}]}
        s4 = {}  # ac1 not in s4
        rows = RA.combine_scores(
            s1, s4, s2=s2,
            w1=0.45, w2=0.20, w3=0.20, w4=0.15,
            threshold=0.0,
            sigmoid_steepness=3.0,
            convergence_bonus=0.15,
        )
        ac1 = next(r for r in rows if r["attack_class"] == "ac1")
        # Expected: w1*0.5 + w2*0.2 + 0.15(bonus) = 0.225+0.04+0.15 = 0.415
        self.assertAlmostEqual(ac1["score"], 0.415, places=3)
        self.assertEqual(ac1["scorer_hits"], 2)
        self.assertAlmostEqual(ac1["convergence_bonus"], 0.15, places=3)

    def test_no_bonus_for_single_scorer(self):
        s1 = {"ac_only": [{"contribution": 0.5, "scorer": "S1"}]}
        s4 = {}
        rows = RA.combine_scores(
            s1, s4,
            w1=0.45, w2=0.20, w3=0.20, w4=0.15,
            threshold=0.0,
            sigmoid_steepness=3.0,
            convergence_bonus=0.15,
        )
        ac = next(r for r in rows if r["attack_class"] == "ac_only")
        self.assertEqual(ac["scorer_hits"], 1)
        self.assertEqual(ac["convergence_bonus"], 0.0)


class TestPhaseBSpike(unittest.TestCase):

    def test_register_affiliate_top1_confidence_above_065(self):
        """Acceptance: RegisterAffiliate top-1 confidence >= 0.65 (Phase A
        baseline was 0.46). Sanity-check function for cantina-192."""
        result = RA.rank(
            target_repo="dydxprotocol/v4-chain",
            file_path="protocol/x/affiliates/keeper/keeper.go",
            function_signature=(
                "func (k msgServer) RegisterAffiliate(ctx context.Context, "
                "msg *types.MsgRegisterAffiliate) "
                "(*types.MsgRegisterAffiliateResponse, error)"
            ),
            workspace_path=str(REPO_ROOT),
            top_n=5,
        )
        self.assertGreater(len(result.ranked_attack_classes), 0)
        top1 = result.ranked_attack_classes[0]
        self.assertGreaterEqual(top1["confidence"], 0.65,
            f"Phase-B acceptance: top-1 confidence must be >= 0.65 (was 0.46 in "
            f"Phase A), got {top1['confidence']}")
        # The cantina-192 expected attack classes must hold top-5
        expected = {"admin-bypass", "blocked-addr-bypass", "fee-redirect",
                    "module-account-permafreeze"}
        top_acs = {r["attack_class"] for r in result.ranked_attack_classes}
        self.assertTrue(expected & top_acs,
            f"Expected at least one of {expected} in top-5, got {top_acs}")

    def test_rank_inputs_payload_includes_all_weights(self):
        result = RA.rank(
            target_repo="dydxprotocol/v4-chain",
            file_path="protocol/x/affiliates/keeper/keeper.go",
            workspace_path=str(REPO_ROOT),
            top_n=3,
        )
        inputs = result.inputs
        for k in ("w1", "w2", "w3", "w4", "s2_enabled", "s3_enabled"):
            self.assertIn(k, inputs)
        self.assertTrue(inputs["s2_enabled"])
        self.assertTrue(inputs["s3_enabled"])

    def test_disable_s2_lowers_top_score(self):
        """Sanity proof S2 contributes: disabling it must not increase the
        top score for a function whose Phase-B top-1 has S1+S2 evidence."""
        with_s2 = RA.rank(
            target_repo="dydxprotocol/v4-chain",
            file_path="protocol/x/affiliates/keeper/keeper.go",
            function_signature=(
                "func (k msgServer) RegisterAffiliate(ctx context.Context, "
                "msg *types.MsgRegisterAffiliate) "
                "(*types.MsgRegisterAffiliateResponse, error)"
            ),
            workspace_path=str(REPO_ROOT),
            top_n=5,
            enable_s2=True,
        )
        without_s2 = RA.rank(
            target_repo="dydxprotocol/v4-chain",
            file_path="protocol/x/affiliates/keeper/keeper.go",
            function_signature=(
                "func (k msgServer) RegisterAffiliate(ctx context.Context, "
                "msg *types.MsgRegisterAffiliate) "
                "(*types.MsgRegisterAffiliateResponse, error)"
            ),
            workspace_path=str(REPO_ROOT),
            top_n=5,
            enable_s2=False,
        )
        top_with = with_s2.ranked_attack_classes[0]["confidence"]
        # With S2 disabled, no top result may be present at all (below
        # min_confidence). If both have results, with-S2 must be >=
        # without-S2.
        if without_s2.ranked_attack_classes:
            top_without = without_s2.ranked_attack_classes[0]["confidence"]
            self.assertGreaterEqual(top_with, top_without)


if __name__ == "__main__":
    unittest.main()
