"""
rewards-distribution-skew-live-denominator - generated from reference/patterns.dsl/rewards-distribution-skew-live-denominator.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py rewards-distribution-skew-live-denominator.yaml
Source: p1-10-capability-lift-rewards-distribution-skew
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RewardsDistributionSkewLiveDenominator(AbstractDetector):
    ARGUMENT = "rewards-distribution-skew-live-denominator"
    HELP = "Reward distribution divides by the live stake/share denominator without an eligibility snapshot or cooldown, so last-minute stake can dilute prior participants."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/rewards-distribution-skew-live-denominator.yaml"
    WIKI_TITLE = "Reward distribution skew from live denominator without eligibility snapshot"
    WIKI_DESCRIPTION = "Reward and yield distributors often translate a funded reward amount into a global per-share index. If that index divides by the live stake/share/supply denominator, and users can still deposit or mint immediately before the distribution, a last-minute participant can join the denominator and receive rewards that were intended for the prior eligible set. The same class appears in staking, gauges, "
    WIKI_EXPLOIT_SCENARIO = "Alice and Bob have been staked for the whole reward period with totalStaked = 100. An attacker stakes 900 in the same block as `distributeRewards(1000)`. The function computes `rewardPerShare = 1000 / totalStaked`, now using 1000 instead of the eligible 100. The attacker claims most of the distribution despite not being eligible for the period."
    WIKI_RECOMMENDATION = "Bind each distribution to an eligibility snapshot or checkpointed supply, or require a cooldown/epoch boundary between stake changes and reward distribution. Distribution math should divide by the snapshotted eligible supply, not the live stake/share denominator."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(reward|rewards|yield|emission|distribut|incentive)'}, {'contract.source_matches_regex': '(?i)(totalStaked|totalStake|totalShares|totalSupply|totalDeposits|totalWeight|stakeWeight|shareSupply)'}, {'contract.has_function_matching': '(?i)^(deposit|stake|mint|join|increaseStake|addLiquidity|enter)$'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(distribute|distributeRewards|notifyRewardAmount|immediateDistribution|instantDistribution|oneTimeDistribution|startDistribution|fundRewards|addRewards|queueRewards|allocateRewards|checkpointRewards|updateRewardIndex)$'}, {'function.body_contains_regex': '(?i)(reward|rewards|yield|emission|amount|tokens|index|perShare|rewardPerToken)'}, {'function.body_contains_regex': '(?i)(totalStaked|totalStake|totalShares|totalSupply|totalDeposits|totalWeight|stakeWeight|shareSupply)'}, {'function.body_contains_regex': '(?i)(rewardPerToken|rewardPerShare|accRewardPerShare|index|globalIndex|rewardIndex|accumulator|perShare)\\s*=?\\s*[^;]*\\/\\s*(totalStaked|totalStake|totalShares|totalSupply|totalDeposits|totalWeight|stakeWeight|shareSupply)'}, {'function.body_not_contains_regex': '(?i)(snapshotSupply|supplySnapshot|snapshotTotal|distributionSnapshot|checkpointSupply|eligibleSupply|qualifiedSupply|distributionSupply|supplyAt|sharesAt|stakeAt|cooldown|lastStake|lastDeposit|lockUntil|distributionUnlock|TWAP|timeWeighted|epochStart)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)\\b'}]

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
                info = [f, f" - rewards-distribution-skew-live-denominator: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
