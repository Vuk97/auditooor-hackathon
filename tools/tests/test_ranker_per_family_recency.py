#!/usr/bin/env python3
"""Tests for Wave-8 per-family recency wiring in ranker.py.

Covers:
  T1: score_s1 uses family-specific recency when recency_triple is supplied
  T2: score_s1 falls back to legacy recency_weight() when recency_triple is None
  T3: score_s3 uses recency_triple["cross_engagement"] when supplied
  T4: cosmos-sdk-forks recency triple takes effect end-to-end through rank()
  T5: rank() backward compat -- unknown repo gets default recency triple
  T6: _classify_recency classifies same_engagement / old_pin / cross_engagement
  T7: score_s1 evidence items carry recency_class when recency_triple provided
  T8: score_s3 evidence items carry the per-family discount value (not 0.5)
"""
from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional

# Disable prediction log writes during tests.
os.environ.setdefault("RANKER_PREDICTION_LOG_DISABLED", "1")
os.environ.setdefault("RANKER_CACHE_DISABLED", "1")

REPO_ROOT = Path(__file__).resolve().parents[2]
RANKER_PATH = REPO_ROOT / "tools" / "ranker.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


RA = _load("ranker_w8_recency", RANKER_PATH)


def _make_tag(
    verdict_id: str = "test-v1",
    target_repo: str = "dydxprotocol/v4-chain",
    audit_pin_sha: str = "abc1234def",
    attack_classes: Optional[List[str]] = None,
    outcome: str = "ACCEPTED",
) -> RA.TagRecord:
    return RA.TagRecord(
        verdict_id=verdict_id,
        target_repo=target_repo,
        audit_pin_sha=audit_pin_sha,
        language="go",
        verdict_class="FILED",
        bug_class="access-control",
        attack_classes_to_try=attack_classes or ["admin-bypass"],
        triager_outcome=outcome,
        drop_reason=None,
        sites=[{
            "file_path": "some/file.go",
            "shape_hash": "HASH001",
            "shape_hash_fine": "FINE001",
            "receiver_type": "msgServer",
        }],
        raw={"severity_claimed": "HIGH"},
    )


class TestClassifyRecency(unittest.TestCase):
    """T6: _classify_recency correctly buckets verdicts."""

    def test_same_repo_same_pin_is_same_engagement(self):
        tag = _make_tag(target_repo="dydxprotocol/v4-chain", audit_pin_sha="abc1234def")
        cls = RA._classify_recency(tag, "dydxprotocol/v4-chain", "abc1234def")
        self.assertEqual(cls, "same_engagement")

    def test_same_repo_prefix_match_is_same_engagement(self):
        # Short 7-char prefix match (common for git SHAs).
        tag = _make_tag(target_repo="dydxprotocol/v4-chain", audit_pin_sha="abc1234")
        cls = RA._classify_recency(tag, "dydxprotocol/v4-chain", "abc1234def")
        self.assertEqual(cls, "same_engagement")

    def test_same_repo_different_pin_is_old_pin(self):
        tag = _make_tag(target_repo="dydxprotocol/v4-chain", audit_pin_sha="zzz9999")
        cls = RA._classify_recency(tag, "dydxprotocol/v4-chain", "abc1234def")
        self.assertEqual(cls, "old_pin")

    def test_different_repo_is_cross_engagement(self):
        tag = _make_tag(target_repo="cosmos/cosmos-sdk", audit_pin_sha="abc1234def")
        cls = RA._classify_recency(tag, "dydxprotocol/v4-chain", "abc1234def")
        self.assertEqual(cls, "cross_engagement")

    def test_missing_pin_same_repo_treated_as_same_engagement(self):
        tag = _make_tag(target_repo="dydxprotocol/v4-chain", audit_pin_sha="")
        cls = RA._classify_recency(tag, "dydxprotocol/v4-chain", None)
        self.assertEqual(cls, "same_engagement")


class TestScoreS1RecencyWiring(unittest.TestCase):
    """T1 + T2 + T7: score_s1 uses recency_triple when supplied."""

    def _target_record(self):
        return {
            "file_path": "protocol/x/affiliates/keeper/msg_server.go",
            "language": "go",
            "function_name": "RegisterAffiliate",
            "params": [],
            "return_types": [],
            "guards_detected": [],
            "visibility": "public",
            "receiver_type": "msgServer",
        }

    def test_s1_uses_same_engagement_weight_when_triple_given(self):
        """T1: contributions use recency_triple["same_engagement"] (0.90) not default (1.0)."""
        tag = _make_tag(
            verdict_id="dydx-v1",
            target_repo="dydxprotocol/v4-chain",
            audit_pin_sha="SAMEP",
            attack_classes=["admin-bypass"],
        )
        # Force shape hash to match via minimal HASH override
        # We need the target hash to match the site hash. Use the actual shape_hash module.
        sh = RA.shape_hash_module()
        rec = self._target_record()
        target_hash = sh.compute_shape_hash(
            language=rec["language"],
            params=rec["params"],
            return_types=rec["return_types"],
            visibility=rec["visibility"],
            guards_detected=rec["guards_detected"],
            receiver_type=rec["receiver_type"],
            fine=False,
        )
        target_hash_fine = sh.compute_shape_hash(
            language=rec["language"],
            params=rec["params"],
            return_types=rec["return_types"],
            visibility=rec["visibility"],
            guards_detected=rec["guards_detected"],
            receiver_type=rec["receiver_type"],
            fine=True,
        )
        # Override tag site to match target hash exactly.
        tag.sites = [{
            "file_path": "some/file.go",
            "shape_hash": target_hash,
            "shape_hash_fine": target_hash_fine,
            "receiver_type": rec["receiver_type"],
        }]

        recency_triple = {"same_engagement": 0.90, "old_pin": 0.65, "cross_engagement": 0.50}
        result = RA.score_s1(
            rec, target_hash, target_hash_fine,
            [tag], "SAMEP",
            target_repo="dydxprotocol/v4-chain",
            recency_triple=recency_triple,
        )
        self.assertIn("admin-bypass", result)
        ev = result["admin-bypass"][0]
        # ow=1.0 (ACCEPTED), shape_sim=1.0, rw should be 0.90
        self.assertAlmostEqual(ev["recency_weight"], 0.90, places=3)
        self.assertAlmostEqual(ev["contribution"], 1.0 * 1.0 * 0.90, places=3)

    def test_s1_falls_back_to_legacy_when_no_triple(self):
        """T2: without recency_triple, legacy recency_weight() is used."""
        tag = _make_tag(
            verdict_id="dydx-v2",
            target_repo="dydxprotocol/v4-chain",
            audit_pin_sha="SAMEP",
            attack_classes=["admin-bypass"],
        )
        sh = RA.shape_hash_module()
        rec = self._target_record()
        target_hash = sh.compute_shape_hash(
            language=rec["language"], params=rec["params"],
            return_types=rec["return_types"], visibility=rec["visibility"],
            guards_detected=rec["guards_detected"], receiver_type=rec["receiver_type"],
            fine=False,
        )
        target_hash_fine = sh.compute_shape_hash(
            language=rec["language"], params=rec["params"],
            return_types=rec["return_types"], visibility=rec["visibility"],
            guards_detected=rec["guards_detected"], receiver_type=rec["receiver_type"],
            fine=True,
        )
        tag.sites = [{
            "file_path": "some/file.go",
            "shape_hash": target_hash,
            "shape_hash_fine": target_hash_fine,
            "receiver_type": rec["receiver_type"],
        }]
        # No recency_triple -- backward compat path
        result = RA.score_s1(
            rec, target_hash, target_hash_fine,
            [tag], "SAMEP",
        )
        self.assertIn("admin-bypass", result)
        ev = result["admin-bypass"][0]
        # Legacy recency_weight returns 1.0 for same-pin match
        self.assertAlmostEqual(ev["recency_weight"], 1.0, places=3)
        # No recency_class key in legacy mode
        self.assertNotIn("recency_class", ev)

    def test_s1_evidence_carries_recency_class_when_triple_given(self):
        """T7: evidence items include recency_class when recency_triple supplied."""
        tag = _make_tag(
            verdict_id="dydx-v3",
            target_repo="cosmos/cosmos-sdk",   # different repo -> cross_engagement
            audit_pin_sha="DIFFP",
            attack_classes=["admin-bypass"],
        )
        sh = RA.shape_hash_module()
        rec = self._target_record()
        target_hash = sh.compute_shape_hash(
            language=rec["language"], params=rec["params"],
            return_types=rec["return_types"], visibility=rec["visibility"],
            guards_detected=rec["guards_detected"], receiver_type=rec["receiver_type"],
            fine=False,
        )
        target_hash_fine = sh.compute_shape_hash(
            language=rec["language"], params=rec["params"],
            return_types=rec["return_types"], visibility=rec["visibility"],
            guards_detected=rec["guards_detected"], receiver_type=rec["receiver_type"],
            fine=True,
        )
        tag.sites = [{
            "file_path": "x/auth/keeper.go",
            "shape_hash": target_hash,
            "shape_hash_fine": target_hash_fine,
            "receiver_type": rec["receiver_type"],
        }]
        recency_triple = {"same_engagement": 0.90, "old_pin": 0.65, "cross_engagement": 0.50}
        result = RA.score_s1(
            rec, target_hash, target_hash_fine,
            [tag], "SAMEP",
            target_repo="dydxprotocol/v4-chain",
            recency_triple=recency_triple,
        )
        self.assertIn("admin-bypass", result)
        ev = result["admin-bypass"][0]
        self.assertEqual(ev["recency_class"], "cross_engagement")
        self.assertAlmostEqual(ev["recency_weight"], 0.50, places=3)


class TestScoreS3RecencyWiring(unittest.TestCase):
    """T3 + T8: score_s3 uses cross_engagement from recency_triple."""

    def test_s3_uses_cross_engagement_from_triple(self):
        """T3: score_s3 discount = recency_triple["cross_engagement"] not 0.5."""
        # Build two repos in the same family
        sibling_families: Dict[str, List[str]] = {
            "cosmos-sdk-forks": ["dydxprotocol/v4-chain", "cosmos/cosmos-sdk"]
        }
        tag = _make_tag(
            verdict_id="cosmos-v1",
            target_repo="cosmos/cosmos-sdk",
            audit_pin_sha="cosmospin",
            attack_classes=["admin-bypass"],
        )
        sh = RA.shape_hash_module()
        rec = {
            "file_path": "some/file.go", "language": "go",
            "function_name": "Foo", "params": [], "return_types": [],
            "guards_detected": [], "visibility": "public", "receiver_type": "msgServer",
        }
        target_hash = sh.compute_shape_hash(
            language="go", params=[], return_types=[],
            visibility="public", guards_detected=[], receiver_type="msgServer",
            fine=False,
        )
        target_hash_fine = sh.compute_shape_hash(
            language="go", params=[], return_types=[],
            visibility="public", guards_detected=[], receiver_type="msgServer",
            fine=True,
        )
        tag.sites = [{
            "file_path": "some/cosmos.go",
            "shape_hash": target_hash,
            "shape_hash_fine": target_hash_fine,
            "receiver_type": "msgServer",
        }]
        recency_triple = {"same_engagement": 0.90, "old_pin": 0.65, "cross_engagement": 0.50}
        result = RA.score_s3(
            target_repo="dydxprotocol/v4-chain",
            target_hash=target_hash,
            target_hash_fine=target_hash_fine,
            target_receiver_family=sh.receiver_family("msgServer"),
            sibling_families=sibling_families,
            tags=[tag],
            recency_triple=recency_triple,
        )
        self.assertIn("admin-bypass", result)
        ev = result["admin-bypass"][0]
        # ow=1.0 (ACCEPTED triager_outcome), sim=1.0, discount=0.50
        self.assertAlmostEqual(ev["discount"], 0.50, places=3)
        self.assertAlmostEqual(ev["contribution"], 1.0 * 1.0 * 0.50, places=3)

    def test_s3_uses_per_family_higher_cross_engagement(self):
        """T8: when recency_triple["cross_engagement"]=0.55 (frost-clients),
        discount and contribution reflect the override (not the 0.5 default)."""
        sibling_families: Dict[str, List[str]] = {
            "frost-clients": ["buildonspark/spark", "ZcashFoundation/frost"]
        }
        tag = _make_tag(
            verdict_id="frost-v1",
            target_repo="ZcashFoundation/frost",
            audit_pin_sha="frostpin",
            attack_classes=["crypto-misuse"],
        )
        sh = RA.shape_hash_module()
        target_hash = sh.compute_shape_hash(
            language="rust", params=[], return_types=[],
            visibility="public", guards_detected=[], receiver_type=None,
            fine=False,
        )
        target_hash_fine = sh.compute_shape_hash(
            language="rust", params=[], return_types=[],
            visibility="public", guards_detected=[], receiver_type=None,
            fine=True,
        )
        tag.sites = [{
            "file_path": "src/lib.rs",
            "shape_hash": target_hash,
            "shape_hash_fine": target_hash_fine,
            "receiver_type": None,
        }]
        recency_triple = {"same_engagement": 0.85, "old_pin": 0.70, "cross_engagement": 0.55}
        result = RA.score_s3(
            target_repo="buildonspark/spark",
            target_hash=target_hash,
            target_hash_fine=target_hash_fine,
            target_receiver_family=sh.receiver_family(None),
            sibling_families=sibling_families,
            tags=[tag],
            recency_triple=recency_triple,
        )
        self.assertIn("crypto-misuse", result)
        ev = result["crypto-misuse"][0]
        self.assertAlmostEqual(ev["discount"], 0.55, places=3)
        self.assertAlmostEqual(ev["contribution"], 1.0 * 1.0 * 0.55, places=3)

    def test_s3_backward_compat_no_triple_uses_0_5(self):
        """Backward compat: without recency_triple, discount stays 0.5."""
        sibling_families: Dict[str, List[str]] = {
            "cosmos-sdk-forks": ["dydxprotocol/v4-chain", "cosmos/cosmos-sdk"]
        }
        tag = _make_tag(
            verdict_id="cosmos-v2",
            target_repo="cosmos/cosmos-sdk",
            audit_pin_sha="cosmospin",
            attack_classes=["admin-bypass"],
        )
        sh = RA.shape_hash_module()
        target_hash = sh.compute_shape_hash(
            language="go", params=[], return_types=[],
            visibility="public", guards_detected=[], receiver_type="msgServer",
            fine=False,
        )
        target_hash_fine = sh.compute_shape_hash(
            language="go", params=[], return_types=[],
            visibility="public", guards_detected=[], receiver_type="msgServer",
            fine=True,
        )
        tag.sites = [{
            "file_path": "some/cosmos.go",
            "shape_hash": target_hash,
            "shape_hash_fine": target_hash_fine,
            "receiver_type": "msgServer",
        }]
        result = RA.score_s3(
            target_repo="dydxprotocol/v4-chain",
            target_hash=target_hash,
            target_hash_fine=target_hash_fine,
            target_receiver_family=sh.receiver_family("msgServer"),
            sibling_families=sibling_families,
            tags=[tag],
            # No recency_triple -- legacy path
        )
        if "admin-bypass" in result:
            ev = result["admin-bypass"][0]
            self.assertAlmostEqual(ev["discount"], 0.50, places=3)


class TestCosmosRecencyEndToEnd(unittest.TestCase):
    """T4: cosmos-sdk-forks recency triple takes effect via rank().

    RegisterAffiliate with per-family recency should show same-engagement
    weight of 0.90 in any S1 hit from the same dydx corpus, yielding
    a slightly lower raw score than the legacy same-pin weight of 1.0
    but the correct recency_triple is resolved and exposed in inputs.
    """

    def test_rank_exposes_recency_triple_in_inputs(self):
        result = RA.rank(
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
        self.assertIn("recency_triple", result.inputs)
        triple = result.inputs["recency_triple"]
        self.assertIn("same_engagement", triple)
        self.assertIn("old_pin", triple)
        self.assertIn("cross_engagement", triple)
        # cosmos-sdk-forks same_engagement = 0.90 (from YAML)
        self.assertAlmostEqual(triple["same_engagement"], 0.90, places=2)
        self.assertAlmostEqual(triple["old_pin"], 0.65, places=2)
        self.assertAlmostEqual(triple["cross_engagement"], 0.50, places=2)

    def test_rank_recency_triple_applied_to_s1_evidence(self):
        """Any S1 hits for the dydx target carry recency_class in evidence."""
        result = RA.rank(
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
        s1_evidence = [
            ev
            for ac_row in result.ranked_attack_classes
            for ev in ac_row.get("evidence", [])
            if ev.get("scorer") == "S1"
        ]
        # If there are any S1 hits, they must carry recency_class
        for ev in s1_evidence:
            self.assertIn(
                "recency_class", ev,
                f"S1 evidence missing recency_class: {ev}",
            )
            self.assertIn(
                ev["recency_class"],
                ("same_engagement", "old_pin", "cross_engagement"),
            )


class TestUnknownRepoRecencyFallback(unittest.TestCase):
    """T5: rank() backward compat -- unknown repo uses default recency triple."""

    def test_unknown_repo_default_recency_triple(self):
        result = RA.rank(
            target_repo="totally-not/in-yaml",
            file_path="some/file.go",
            workspace_path=str(REPO_ROOT),
            top_n=3,
        )
        self.assertIn("recency_triple", result.inputs)
        triple = result.inputs["recency_triple"]
        # Default triple from YAML: same=0.85, old=0.60, cross=0.40
        self.assertAlmostEqual(triple["same_engagement"], 0.85, places=2)
        self.assertAlmostEqual(triple["old_pin"], 0.60, places=2)
        self.assertAlmostEqual(triple["cross_engagement"], 0.40, places=2)


if __name__ == "__main__":
    unittest.main()
