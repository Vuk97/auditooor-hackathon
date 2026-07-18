"""
reward-index-div-zero-on-full-unlock — generated from reference/patterns.dsl/reward-index-div-zero-on-full-unlock.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py reward-index-div-zero-on-full-unlock.yaml
Source: code4arena/slice_ac-GTE-Launchpad-H07
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RewardIndexDivZeroOnFullUnlock(AbstractDetector):
    ARGUMENT = "reward-index-div-zero-on-full-unlock"
    HELP = "Reward-per-share accumulator divides by totalStaked/totalShares without a zero-guard. When all stakers exit mid-epoch totalStaked == 0 and the next interaction panics with div-by-zero, permanently bricking the pool."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/reward-index-div-zero-on-full-unlock.yaml"
    WIKI_TITLE = "Reward index divides by totalStaked without zero-guard"
    WIKI_DESCRIPTION = "A MasterChef-style accumulator updates `accRewardPerShare += rewards * PRECISION / totalStaked` on each stake/unstake/claim. In the edge case where all stakers unwind mid-epoch, `totalStaked == 0` and the next accrual calculates `rewards / 0`, which panics and reverts. Because every subsequent stake-path hits the same accrual, the pool becomes permanently unusable."
    WIKI_EXPLOIT_SCENARIO = "Pool has one staker; attacker baits them to unstake (or waits). `totalStaked` reaches 0. Attacker calls `stake(1)`; the pre-stake accrual reads `rewardRate * elapsed / 0` and reverts. Nobody can stake, unstake, or claim — all three paths enter the same `_updatePool` helper. Unlocking requires an admin override, which the contract typically does not expose."
    WIKI_RECOMMENDATION = "Before the division, short-circuit on empty pool: `if (totalStaked == 0) { lastRewardBlock = block.number; return; }`. Alternatively, bank the elapsed rewards to a pending bucket and fold them into the accumulator on the next non-zero-supply interaction."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(totalStaked|totalShares|totalSupply|totalLocked)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.body_contains_regex': '(accRewardPerShare|rewardPerShare|rewardIndex|rewardsPerToken)'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.has_high_level_call_named': 'totalSupply'}, {'function.body_contains_regex': '/\\s*(totalStaked|totalShares|totalSupply|totalLocked)'}, {'function.body_not_contains_regex': 'if\\s*\\(\\s*total\\w*\\s*==\\s*0\\s*\\)|total\\w*\\s*>\\s*0\\s*\\?|require\\s*\\(\\s*total\\w*\\s*>\\s*0'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — reward-index-div-zero-on-full-unlock: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
