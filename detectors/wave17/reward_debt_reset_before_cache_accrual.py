"""
reward-debt-reset-before-cache-accrual — generated from reference/patterns.dsl/reward-debt-reset-before-cache-accrual.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py reward-debt-reset-before-cache-accrual.yaml
Source: solodit/sherlock/olympus-H4-6676
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RewardDebtResetBeforeCacheAccrual(AbstractDetector):
    ARGUMENT = "reward-debt-reset-before-cache-accrual"
    HELP = "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: reward-debt storage is zeroed BEFORE being used in the pending/cached-reward computation on a later line. The subtraction reads the post-zeroed value, over-crediting the user on their next claim. Swap the two assignments."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/reward-debt-reset-before-cache-accrual.yaml"
    WIKI_TITLE = "Reward-debt zeroed before cached-reward subtraction: double-credit on next claim"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only. NOT_SUBMIT_READY. A MasterChef-style vault uses `userRewardDebts[user][token]` to track what the user has already been paid. On withdraw, the contract must (a) compute `cached += rewardDebtDiff - userRewardDebts[user][token]` and (b) reset `userRewardDebts[user][token] = 0`. If (b) is executed BEFORE (a), the subtraction reads zero instead of the true paid-ou"
    WIKI_EXPLOIT_SCENARIO = "Alice deposits, claims 1e17 rewards (userRewardDebts = 1e17, paidOut = 1e17). Time passes, accumulatedRewardsPerShare grows; partial withdraw of 50% triggers `_withdrawUpdateRewardState`. `rewardDebtDiff = 5e17 * 0.5 = 3e17`. Code runs `userRewardDebts[Alice][tok] = 0;` then `cachedUserRewards += rewardDebtDiff - userRewardDebts[...]` = 3e17 - 0 = 3e17. But only 2e17 of that is new (1e17 was alrea"
    WIKI_RECOMMENDATION = "Compute `cachedUserRewards` FIRST (using the current userRewardDebts), then zero out: `cachedUserRewards[user][tok] += rewardDebtDiff - userRewardDebts[user][tok]; userRewardDebts[user][tok] = 0;`. Add an invariant test that asserts total lifetime payout matches total lifetime accrued rewards within"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(rewardDebt|userRewardDebts|userInfo|pendingReward|cachedUserRewards)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.body_ordered_regex': {'first': '((?:\\w+\\.)?rewardDebt|userRewardDebts\\s*\\[[^\\]]+\\]\\s*\\[[^\\]]+\\])\\s*=\\s*(?:0|uint256\\s*\\(\\s*0\\s*\\))', 'second': '(cached\\w+|pending\\w*|accrued\\w*)\\s*(?:\\[[^\\]]+\\]\\s*)*\\+?=\\s*[^;]*(rewardDebt|userRewardDebts)', 'ignore_comments_and_strings': True}}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — reward-debt-reset-before-cache-accrual: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
