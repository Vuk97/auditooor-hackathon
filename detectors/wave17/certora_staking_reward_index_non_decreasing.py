"""
certora-staking-reward-index-non-decreasing — generated from reference/patterns.dsl/certora-staking-reward-index-non-decreasing.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py certora-staking-reward-index-non-decreasing.yaml
Source: certora-examples/RewardIndex/rewardPerTokenMonotonic
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CertoraStakingRewardIndexNonDecreasing(AbstractDetector):
    ARGUMENT = "certora-staking-reward-index-non-decreasing"
    HELP = "Reward-index mutator can write a lower value — Certora `rewardPerTokenMonotonic` invariant violated, double-pay possible."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/certora-staking-reward-index-non-decreasing.yaml"
    WIKI_TITLE = "Reward index written without monotone-increase guard (re-pay exploit)"
    WIKI_DESCRIPTION = "Certora's rewards spec proves `rewardPerTokenStored` is non-decreasing: once issued, rewards can be paid at most once per user. A mutator that writes the index to a lower value (admin reset, snapshot-restore, bad migration) makes a user's `userRewardPerTokenPaid` temporarily greater than the stored index. The canonical reward math is `rewardsOwed = balance * (stored - paid)`. Normally non-negative"
    WIKI_EXPLOIT_SCENARIO = "An admin reset `rewardPerTokenStored = 0` intending to start a new epoch. Stakers who had already claimed have `userRewardPerTokenPaid = X > 0`. Next `_earned()` call computes `balance * (0 - X)` — in unchecked, this is `balance * type(uint256).max`, returning 2^256 as owed. If the reward token is minted on demand, attacker claims an astronomical reward, drains the emission schedule and possibly t"
    WIKI_RECOMMENDATION = "Reward indices can only go up. The only legitimate path is the `+= (elapsed * rewardRate) / totalSupply` accumulator. Reset logic must be a new-epoch bumped-up index or a full per-user migration that zeroes both sides. Prove Certora's `rewardPerTokenMonotonic` rule."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(?i)(rewardPerToken|rewardIndex|rewardPerTokenStored|userRewardPerTokenPaid|cumulativeReward|rewardDebt)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.is_mutating': True}, {'function.writes_storage_matching': '(?i)(rewardPerToken|rewardIndex|rewardPerTokenStored|cumulativeReward)'}, {'function.body_contains_regex': '(?i)(rewardPerToken|rewardIndex|rewardPerTokenStored|cumulativeReward)\\s*='}, {'function.body_not_contains_regex': '(?i)(>=\\s*.*(rewardPerToken|rewardIndex|rewardPerTokenStored)|(rewardPerToken|rewardIndex|rewardPerTokenStored)\\s*\\+=|\\+\\s*rewardPerToken|require[^;]*rewardPerToken)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — certora-staking-reward-index-non-decreasing: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
