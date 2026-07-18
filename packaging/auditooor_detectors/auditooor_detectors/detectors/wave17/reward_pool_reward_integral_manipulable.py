"""
reward-pool-reward-integral-manipulable — generated from reference/patterns.dsl/reward-pool-reward-integral-manipulable.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py reward-pool-reward-integral-manipulable.yaml
Source: solodit/C0308
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RewardPoolRewardIntegralManipulable(AbstractDetector):
    ARGUMENT = "reward-pool-reward-integral-manipulable"
    HELP = "Reward-integral update divides newly-accrued rewards by live totalSupply()/totalStaked/totalShares — donor of reward tokens (or flashloan that inflates supply for one block) can skew the index for every other staker, stealing or bricking rewards (Convex/Synthetix/MasterChef class)."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/reward-pool-reward-integral-manipulable.yaml"
    WIKI_TITLE = "Reward-pool reward integral manipulable via donation or live totalSupply"
    WIKI_DESCRIPTION = "The reward-accrual function (Convex ConvexStakingWrapper._calcRewardIntegral / Synthetix rewardPerToken / MasterChef pending) computes the per-share reward index as (newRewards * SCALE) / totalSupply(). Because both inputs can be manipulated in the same block — an attacker can donate reward tokens directly to the pool's token balance (inflating the numerator) or take a flashloaned mint/stake to in"
    WIKI_EXPLOIT_SCENARIO = "ConvexStakingWrapper tracks `integral` per reward token. Attacker observes that `_calcRewardIntegral` reads `rewardToken.balanceOf(address(this)) - lastIntegralClaim` as the numerator and `totalSupply()` as the denominator. Attacker flashloans a large CVX mint into the wrapper, calls any state-updating entry point to trigger `_calcRewardIntegral`, causing integral to be diluted by the inflated tot"
    WIKI_RECOMMENDATION = "Maintain a snapshotted `trackedBalance` / `lastBalance` of both staked supply and reward tokens, updated only via state-mutating flows (stake / unstake / claim). Compute the integral from the delta between `currentBalance` and `trackedBalance` and only against the snapshotted supply. Reject direct d"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(integral|rewardPerShare|accRewardPerShare|rewardIndex|cumulativeReward)'}]
    _MATCH = [{'function.name_matches': '_calcRewardIntegral|_updateReward|updateRewardIntegral|_updateIntegral|_updateRewardPerShare|earned|rewardPerToken'}, {'function.body_contains_regex': {'regex': 'totalSupply\\s*\\(\\s*\\)|totalStaked|\\.totalShares\\('}}, {'function.body_not_contains_regex': 'trackedBalance|lastBalance|snapshottedSupply|virtualSupply'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = False
    _INVERSE_CEI = False

    def _detect(self):
        results = []
        for c in self.contracts:
            if is_vendored_or_test_contract(c):
                continue
            if not eval_preconditions(c, self._PRECONDITIONS):
                continue
            for f in c.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(f):
                    continue
                if not eval_function_match(f, self._MATCH):
                    continue
                info = [f, f" — reward-pool-reward-integral-manipulable: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
