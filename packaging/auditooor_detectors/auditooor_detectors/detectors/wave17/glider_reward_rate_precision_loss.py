"""
glider-reward-rate-precision-loss — generated from reference/patterns.dsl/glider-reward-rate-precision-loss.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-reward-rate-precision-loss.yaml
Source: hexens-glider/reward-rate-precision-loss
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderRewardRatePrecisionLoss(AbstractDetector):
    ARGUMENT = "glider-reward-rate-precision-loss"
    HELP = "`rewardRate = amount / duration` truncates to zero when `amount < duration` (e.g. 100 wei reward over 1 week of seconds). Stakers see zero emissions despite non-zero funded rewards; admin must re-fund with large enough amounts — and any dust is permanently stranded."
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-reward-rate-precision-loss.yaml"
    WIKI_TITLE = "Reward rate integer-division precision loss: rewardRate rounds to zero for small amounts"
    WIKI_DESCRIPTION = "Synthetix-style reward distributors compute the per-second emission rate as `rewardRate = rewardAmount / duration`. With `duration = 604_800` (one week in seconds), any reward amount less than 604_800 base units produces `rewardRate == 0`. The stored `rewardPerTokenStored` integral never increments, stakers earn nothing, and the funded tokens sit idle in the contract. The correct pattern scales by"
    WIKI_EXPLOIT_SCENARIO = "Admin calls `notifyRewardAmount(500_000)` with a 1-week duration (`604_800s`). `rewardRate = 500_000 / 604_800 = 0`. For the full week, `rewardPerTokenStored` is incremented by `0 * elapsed / totalStaked = 0`. Stakers claim — receive zero. The 500_000 tokens are marooned in the contract with no automatic rollover. Admin must top up above the precision threshold and restart the period. Repeatedly h"
    WIKI_RECOMMENDATION = "Scale the rate upward: `rewardRate = rewardAmount * PRECISION / duration` with `PRECISION = 1e18`, and divide back out in the accrual formula. Alternatively, revert if `rewardRate == 0` — fails loudly instead of silently zeroing emissions. Both fixes are small; the choice depends on whether the accr"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'rewardRate|rewardsRate|emissionRate|rate'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '(?i)^(notifyReward|notifyRewardAmount|notifyRewards|setRewardRate|setRate|startRewards|startReward|updateRate|updateRewardRate|fund|fundRewards|_fund|_notifyReward|_setRewardRate)$'}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.reads_block_timestamp': True}, {'function.body_contains_regex': '\\w+\\s*=\\s*\\w+\\s*/\\s*(?:duration|period|DURATION|PERIOD|rewardsDuration|rewardDuration|periodFinish\\s*-\\s*block\\.timestamp)'}, {'function.body_not_contains_regex': '\\*\\s*(?:1e18|PRECISION|SCALE|1_000_000|1e12|MULTIPLIER)\\s*/|require\\s*\\(\\s*\\w+\\s*!=\\s*0|require\\s*\\(\\s*\\w+\\s*>\\s*0'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-reward-rate-precision-loss: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
