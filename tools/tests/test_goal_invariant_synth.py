"""
tools/tests/test_goal_invariant_synth.py

FIX-3 guard tests for the adversary-GOAL invariant synthesizer.

Proves BOTH directions:
  - a GENUINE function (writes rewardDebt, reads accReward*) GOAL-binds the
    theft-unclaimed-yield templates -> credited (is_goal_template True);
  - a pure-math helper (no balance/accrual/withdraw symbols) -> every goal
    UNBOUND, goal_bound_count 0 -> NEVER credited (never-false-pass);
  - a missing corpus -> {} and goal_invariants_for -> [] (zero false credit);
  - a getter matching NO playbook -> [] (no spray);
  - additive: process_sol_file still emits the original invariant_candidates key
    unchanged AND the new goal_invariants key.

Lane: FIX-3 adversary-goal-invariant-generation.
"""
from __future__ import annotations

import importlib.util as _ilu
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_LIB = _REPO_ROOT / "tools" / "lib" / "goal_invariant_synth.py"
_IAS = _REPO_ROOT / "tools" / "invariant-auto-synth.py"


def _load(name: str, path: Path):
    spec = _ilu.spec_from_file_location(name, str(path))
    mod = _ilu.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


gis = _load("goal_invariant_synth", _LIB)
ias = _load("invariant_auto_synth", _IAS)


# A genuine MasterChef-style claim(): writes rewardDebt, reads accRewardPerShare,
# mutates a reward-bearing balance. Binds the theft-unclaimed-yield roles.
_GENUINE_BODY = """{
    uint256 acc = accRewardPerShare;
    uint256 pending = user.amount * acc - rewardDebt[msg.sender];
    rewardDebt[msg.sender] = user.amount * acc;
    balanceOf[msg.sender] += pending;
    reward.transfer(msg.sender, pending);
}"""

# A pure-math helper: no accrual/balance/withdraw/auth symbols at all.
_PURE_MATH_BODY = """{
    uint256 r = a + b;
    return r * c;
}"""

# SSV-style settle/claim: the accrual vocab is operator.snapshot.balance and the
# settle marker is the snapshot.block reset - NONE of which match the v1 default
# claimed_marker regex (rewardDebt|claimed|lastClaim|nullifier). The curated
# match_any in the template is what binds these. Real source shape:
# contracts/modules/SSVOperators.sol _withdrawOperatorEarnings (snapshot.block /
# snapshot.balance) + SSVStaking.sol claimEthRewards (_settle / s.accrued).
_SSV_SNAPSHOT_BODY = """{
    if (operator.snapshot.block == 0) revert InsufficientBalance();
    OperatorLib.updateSnapshotStSSV(operator);
    PackedSSV balance = operator.snapshot.balance;
    operator.snapshot.balance = balance.sub(shrunkWithdrawn);
    _transferOperatorTokenBalanceUnsafe(operatorId, PackedSSVLib.unpack(shrunkWithdrawn));
}"""

# A plain admin setter that contains block.number but NO accrual/claim/snapshot
# vocab. Proves the curated theft-unclaimed-yield anchors (snapshot\\w*\\.block,
# settle*, withdrawn*, lastSettle*) did NOT degrade to matching bare block.number.
_ADMIN_SETTER_BLOCKNUMBER_BODY = """{
    require(msg.sender == owner);
    lastUpdatedBlock = block.number;
    feeRate = newRate;
}"""

# A liquidation entrypoint mirroring SSVClusters.sol liquidate(): named liquidate,
# reads the isLiquidatableWithEB health gate. The collateral-liquidation-fn shape
# the classifier emits is NOT in the liquidation-abuse playbook's
# applies_to_shape_classes, so this only routes via the liquidate-name rescue.
_SSV_LIQUIDATE_BODY = """{
    cluster.validateClusterIsNotLiquidated();
    if (
        clusterOwner != msg.sender &&
        !cluster.isLiquidatableWithEB(hashedCluster, burnRate, fee, minBlocks, minColl)
    ) {
        revert ClusterNotLiquidatable();
    }
    _executeLiquidation(clusterOwner, msg.sender, hashedCluster, operatorIds, cluster, s, sp, seb);
}"""


class GoalBindingDirectionTest(unittest.TestCase):
    def test_genuine_goal_binds_and_is_credited(self):
        recs = gis.goal_invariants_for(
            "claim", "() external",
            language="solidity", contract_kind="staking",
            source_body=_GENUINE_BODY, file_line="Gauge.sol:42",
        )
        yield_bound = [
            r for r in recs
            if r["impact_id"] == "theft-unclaimed-yield"
            and r["status"] == "goal-bound"
        ]
        self.assertTrue(
            yield_bound,
            "genuine claim() must GOAL-bind >=1 theft-unclaimed-yield template",
        )
        for r in yield_bound:
            self.assertTrue(r["is_goal_template"])
            self.assertEqual(r["status"], "goal-bound")
            self.assertEqual(r["unbound_roles"], [])
        # the claimable-bounded template must bind BOTH accrual + claimed marker.
        cb = [r for r in yield_bound
              if r["goal_template_id"] == "GINV-yield-claimable-bounded"]
        self.assertTrue(cb, "GINV-yield-claimable-bounded must be present + bound")
        self.assertIn("accrual_accumulator", cb[0]["bound_symbols"])
        self.assertIn("claimed_marker", cb[0]["bound_symbols"])
        # BACKWARD-COMPAT: the MasterChef `rewardDebt` token is NOT in any curated
        # match_any list, so it must bind via the built-in DEFAULT regex fallback.
        self.assertEqual(cb[0]["bound_symbols"]["claimed_marker"], "rewardDebt")

    def test_unbound_goal_fails_closed(self):
        recs = gis.goal_invariants_for(
            "compute", "(uint256 a, uint256 b, uint256 c)",
            language="solidity", contract_kind="staking",
            source_body=_PURE_MATH_BODY, file_line="Math.sol:1",
        )
        # Any record that DOES surface (impact may still match by kind-rescue or
        # shape) must be UNBOUND and uncredited; bound count must be 0.
        for r in recs:
            self.assertEqual(r["status"], "goal-unbound", r)
            self.assertFalse(r["is_goal_template"], r)
        bound = sum(1 for r in recs if r["status"] == "goal-bound")
        self.assertEqual(bound, 0, "pure-math helper must credit ZERO goals")

    def test_missing_corpus_returns_empty(self):
        self.assertEqual(gis.load_goal_templates(Path("/nonexistent/x.yaml")), {})
        # With an explicitly-empty corpus, goal_invariants_for returns [].
        self.assertEqual(
            gis.goal_invariants_for(
                "claim", "() external", language="solidity",
                source_body=_GENUINE_BODY, templates={},
            ),
            [],
        )

    def test_auth_guard_does_not_falsebind_from_params(self):
        # A claim() with NO modifier and NO require(msg.sender) must NOT bind the
        # caller_auth_guard role from param identifiers (uint256/amount). The
        # direct-theft goal therefore stays UNBOUND (never-false-pass).
        recs = gis.goal_invariants_for(
            "claim", "uint256 amount",
            language="solidity", contract_kind="staking",
            source_body=_GENUINE_BODY, auth_sig_tail="external",
        )
        dt = [r for r in recs if r["impact_id"] == "direct-theft-funds"]
        self.assertTrue(dt, "direct-theft template should surface for a value-mover")
        for r in dt:
            self.assertEqual(r["status"], "goal-unbound", r)
            self.assertIn("caller_auth_guard", r["unbound_roles"])

    def test_auth_guard_binds_with_real_modifier(self):
        # The SAME function WITH an onlyOwner modifier in its signature tail binds
        # caller_auth_guard -> direct-theft becomes goal-bound (real credit).
        recs = gis.goal_invariants_for(
            "claim", "uint256 amount",
            language="solidity", contract_kind="staking",
            source_body=_GENUINE_BODY, auth_sig_tail="external onlyOwner",
        )
        dt_bound = [
            r for r in recs
            if r["impact_id"] == "direct-theft-funds" and r["status"] == "goal-bound"
        ]
        self.assertTrue(dt_bound, "direct-theft must bind with a real modifier")
        self.assertIn("caller_auth_guard", dt_bound[0]["bound_symbols"])

    def test_ssv_snapshot_accounting_goal_binds_from_curated(self):
        # The curated match_any patterns must bind BOTH theft-unclaimed-yield
        # roles on SSV's snapshot accounting (operator.snapshot.balance accrual +
        # snapshot.block settle marker) even though NONE match the v1 defaults.
        recs = gis.goal_invariants_for(
            "withdrawOperatorEarnings",
            "(uint64 operatorId, uint256 amount) external override nonReentrant",
            language="solidity", contract_kind="staking",
            source_body=_SSV_SNAPSHOT_BODY, file_line="SSVOperators.sol:237",
        )
        yb = [
            r for r in recs
            if r["impact_id"] == "theft-unclaimed-yield"
            and r["status"] == "goal-bound"
        ]
        self.assertTrue(
            yb,
            "SSV snapshot accounting must GOAL-bind theft-unclaimed-yield via "
            "curated match_any (defaults do not match snapshot.balance/.block)",
        )
        cb = [r for r in yb
              if r["goal_template_id"] == "GINV-yield-claimable-bounded"]
        self.assertTrue(cb, "claimable-bounded must bind from curated synonyms")
        self.assertIn("accrual_accumulator", cb[0]["bound_symbols"])
        self.assertIn("claimed_marker", cb[0]["bound_symbols"])
        # The curated tokens must come from SSV vocab, not the default regex.
        self.assertIn("snapshot", cb[0]["bound_symbols"]["accrual_accumulator"])
        self.assertIn("snapshot", cb[0]["bound_symbols"]["claimed_marker"])

    def test_curated_block_anchor_does_not_overbind_on_block_number(self):
        # A plain admin setter containing block.number (but no accrual/claim/
        # snapshot vocab) must NOT GOAL-bind theft-unclaimed-yield. Proves the
        # curated 'snapshot\\w*\\.block' anchor did not collapse to bare 'block'.
        recs = gis.goal_invariants_for(
            "setFeeRate", "(uint256 newRate) external onlyOwner",
            language="solidity", contract_kind="staking",
            source_body=_ADMIN_SETTER_BLOCKNUMBER_BODY,
            auth_sig_tail="external onlyOwner",
            file_line="Admin.sol:10",
        )
        ty_bound = [
            r for r in recs
            if r["impact_id"] == "theft-unclaimed-yield"
            and r["status"] == "goal-bound"
        ]
        self.assertEqual(
            ty_bound, [],
            "block.number alone must NOT bind theft-unclaimed-yield (no over-bind)",
        )

    def test_liquidate_routes_to_liquidation_abuse(self):
        # A function NAMED liquidate must admit + GOAL-bind the liquidation-abuse
        # goal (rescue route: collateral-liquidation-fn shape is not in the
        # playbook's applies_to_shape_classes, so the name rescue is what admits).
        recs = gis.goal_invariants_for(
            "liquidate",
            "(address clusterOwner, uint64[] calldata operatorIds, Cluster memory cluster)"
            " external override nonReentrant",
            language="solidity", contract_kind="",
            source_body=_SSV_LIQUIDATE_BODY, file_line="SSVClusters.sol:31",
        )
        lb = [
            r for r in recs
            if r["impact_id"] == "liquidation-abuse"
            and r["status"] == "goal-bound"
        ]
        self.assertTrue(
            lb, "liquidate must GOAL-bind liquidation-abuse via the name rescue",
        )
        self.assertIn("health_factor_read", lb[0]["bound_symbols"])
        self.assertIn("liquidate_entrypoint", lb[0]["bound_symbols"])

    def test_no_impact_match_no_goal(self):
        # A pure view getter on no DeFi kind matches no playbook -> no spray.
        recs = gis.goal_invariants_for(
            "getDecimals", "() external view returns (uint8)",
            language="solidity", contract_kind="",
            source_body="{ return 18; }",
        )
        self.assertEqual(recs, [], "a plain getter must produce no goal records")


class AdditiveWiringTest(unittest.TestCase):
    def test_process_sol_file_is_additive(self):
        sol = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Gauge {
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public rewardDebt;
    uint256 public accRewardPerShare;
    function claim(uint256 amount) external {
        uint256 acc = accRewardPerShare;
        rewardDebt[msg.sender] = amount * acc;
        balanceOf[msg.sender] += amount;
    }
}
"""
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "Gauge.sol"
            p.write_text(sol, encoding="utf-8")
            recs = ias.process_sol_file(p, {})
        self.assertTrue(recs, "process_sol_file must emit >=1 record")
        rec = next(r for r in recs if r["function"] == "claim")
        # ADDITIVE: the original shape-axis key is present + unchanged in shape.
        self.assertIn("invariant_candidates", rec)
        self.assertIsInstance(rec["invariant_candidates"], list)
        self.assertTrue(rec["invariant_candidates"])
        # NEW goal-axis keys exist alongside it.
        self.assertIn("goal_invariants", rec)
        self.assertIn("goal_invariant_count_bound", rec)
        self.assertIsInstance(rec["goal_invariants"], list)
        # The genuine claim() binds at least one goal.
        self.assertGreaterEqual(rec["goal_invariant_count_bound"], 1)
        # count_bound counts ONLY goal-bound records (never-false-pass).
        actual_bound = sum(
            1 for g in rec["goal_invariants"] if g.get("status") == "goal-bound"
        )
        self.assertEqual(actual_bound, rec["goal_invariant_count_bound"])


class TestAccrualComparatorNotAWrite(unittest.TestCase):
    """The accrual_accumulator default regex must treat a `==` comparator as NOT
    an accrual write (`if (blockIndex == 3)`) while still binding plain/compound
    assignment. A comparator false-bind is harmless (the AND-over-roles gate keeps
    the goal unbound) but imprecise; `=(?!=)` keeps the default great."""

    def test_comparator_does_not_bind_accrual(self):
        self.assertEqual(
            gis._resolve_role(
                "accrual_accumulator", function_name="f",
                function_signature="", source_body="if (blockIndex == 3) {}",
            ),
            "",
        )

    def test_plain_assignment_binds_accrual(self):
        self.assertEqual(
            gis._resolve_role(
                "accrual_accumulator", function_name="f",
                function_signature="", source_body="clusterIndex = 5;",
            ),
            "clusterIndex",
        )

    def test_compound_assignment_binds_accrual(self):
        self.assertEqual(
            gis._resolve_role(
                "accrual_accumulator", function_name="f",
                function_signature="", source_body="rewardIndex += x;",
            ),
            "rewardIndex",
        )


if __name__ == "__main__":
    unittest.main()
