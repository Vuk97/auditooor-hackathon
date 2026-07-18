"""
rebalance-rewards-accounting-gap — generated from reference/patterns.dsl/rebalance-rewards-accounting-gap.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py rebalance-rewards-accounting-gap.yaml
Source: solodit/C0168
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RebalanceRewardsAccountingGap(AbstractDetector):
    ARGUMENT = "rebalance-rewards-accounting-gap"
    HELP = "rebalance()/poke() mutates totalSupply / locked / balances without calling the reward accrual hook first — rewardPerToken is computed with the post-rebalance denominator and users lose or double-count rewards for the elapsed period."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/rebalance-rewards-accounting-gap.yaml"
    WIKI_TITLE = "Rebalance without reward accrual: reward index misaligned against totalSupply"
    WIKI_DESCRIPTION = "Staking/vault contracts expose a rebalance path that writes to totals (totalSupply, totalLocked, balances). If the reward accrual hook (updateReward / accrue / checkpoint) is not invoked FIRST, the period between the previous accrual and this rebalance is accounted against the NEW totals, so users are credited or debited rewards they should not have received."
    WIKI_EXPLOIT_SCENARIO = "Protocol earned $100 yield over the last epoch for 100 shares (→1 per share). rebalance() doubles the share count BEFORE accruing, so 200 shares divide the $100 — honest stakers see their rewards halved, griefers who deposit late capture half the accrued yield."
    WIKI_RECOMMENDATION = "Call the rewards accrual hook as the FIRST statement of every rebalance / poke / sync path that mutates totals. Use a `updateReward(address(0))` or global checkpoint to settle before writing supply/balance."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '(?i)rebalance'}, {'contract.has_state_var_matching': '(?i)(rewardPerToken|accReward|rewardIndex|rewardDebt|lastUpdateTime)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(rebalance|poke|syncPool|_rebalance|rebalancePool|rebalanceAll|syncRewards|_poke)$'}, {'function.writes_storage_matching': '(?i)(total|balance|locked|supply|shares)'}, {'function.body_not_contains_regex': '(?i)(updateReward|_updateReward|accrue|_accrue|checkpoint|_checkpoint|harvest|claimPending|updateIndex)\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — rebalance-rewards-accounting-gap: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
