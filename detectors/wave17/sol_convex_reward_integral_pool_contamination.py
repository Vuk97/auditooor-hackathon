"""
sol-convex-reward-integral-pool-contamination — generated from reference/patterns.dsl/sol-convex-reward-integral-pool-contamination.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py sol-convex-reward-integral-pool-contamination.yaml
Source: solodit-cluster-C0345-Convex
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class SolConvexRewardIntegralPoolContamination(AbstractDetector):
    ARGUMENT = "sol-convex-reward-integral-pool-contamination"
    HELP = "Reward integral uses contract-wide balance of reward token — reward flows from another pool contaminate the integral."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/sol-convex-reward-integral-pool-contamination.yaml"
    WIKI_TITLE = "Reward integral contaminated by other-pool balance"
    WIKI_DESCRIPTION = "A reward-per-share integral that reads `IERC20(reward).balanceOf(address(this))` attributes ALL reward balance to the current pool, even when the contract hosts multiple pools/wrappers. Attacker transfers reward tokens into the wrapper to inflate one pool's integral at another pool's expense."
    WIKI_EXPLOIT_SCENARIO = "ConvexStakingWrapper C0345 H-11: wrapper hosted multiple reward streams; attacker minted CVX rewards for Pool A by calling claim paths; that increased `balanceOf(this)` and on next `_calcRewardIntegral` invocation, Pool B's integral also stepped up, letting attacker withdraw CVX earmarked for A."
    WIKI_RECOMMENDATION = "Maintain a per-pool `rewardsOwed[token]` accumulator incremented only when that pool's deposit path triggered the reward. Never conflate with raw `balanceOf(this)`."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'rewardIntegral|_calcRewardIntegral|BaseRewardPool|rewardPerTokenStored|StakingWrapper'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': '_calcRewardIntegral|rewardPerTokenStored|rewardIntegral'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.has_high_level_call_named': 'balanceOf'}, {'function.body_contains_regex': 'balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)|IERC20\\s*\\([^)]+\\)\\.balanceOf'}, {'function.body_not_contains_regex': 'rewardToken\\[|poolRewards\\[|_pool\\[|rewardsOwedToPool'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — sol-convex-reward-integral-pool-contamination: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
