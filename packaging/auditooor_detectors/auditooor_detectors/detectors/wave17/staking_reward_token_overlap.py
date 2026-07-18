"""
staking-reward-token-overlap — generated from reference/patterns.dsl/staking-reward-token-overlap.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py staking-reward-token-overlap.yaml
Source: solodit/C0342
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class StakingRewardTokenOverlap(AbstractDetector):
    ARGUMENT = "staking-reward-token-overlap"
    HELP = "Reward claim path transfers out the same token variable used for stake deposits — rewards are paid from pooled stake principal, enabling drain."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/staking-reward-token-overlap.yaml"
    WIKI_TITLE = "Staking/reward token overlap: claim drains staked principal"
    WIKI_DESCRIPTION = "The contract uses one ERC20 as both the staked asset and the reward asset. The reward-payout function transfers the stake token directly from the contract's own balance, which also holds every user's deposited principal. Reward payouts reduce the pool available for unstakers, and sufficiently large accrued rewards let a user claim more than the protocol's dedicated reward budget — i.e. withdraw ot"
    WIKI_EXPLOIT_SCENARIO = "Alice and Bob each stake 100 STK. The contract's STK balance is 200. Rewards accrue and the claim logic says Alice is owed 50 STK. claimReward() calls stakeToken.transfer(alice, 50). The contract now holds 150 STK, but both users still have 100 STK of principal on the books. When Bob unstakes, he receives his 100 STK. When Alice unstakes, there are only 50 STK left — 50 of Bob's principal was paid"
    WIKI_RECOMMENDATION = "Use a separate reward token, OR segregate reward accounting (e.g. track rewardReserve separately from stake principal and refuse to pay rewards that would dip into stake balance). Never pay rewards from the same ERC20 balance that holds user deposits."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'stake|staking|stakedToken|stakeToken'}, {'contract.has_function_matching': 'stake|deposit|unstake|withdraw'}, {'contract.has_function_matching': 'claim|claimReward|harvest|getReward'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'claim|reward|harvest|getReward'}, {'function.body_contains_regex': '(?:^|[^a-zA-Z0-9_])(stakeToken|stakedToken|stakingToken|_token)\\s*\\.\\s*(transfer|safeTransfer)\\s*\\('}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — staking-reward-token-overlap: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
