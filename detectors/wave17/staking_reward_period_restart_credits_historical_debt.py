"""
staking-reward-period-restart-credits-historical-debt — generated from reference/patterns.dsl/staking-reward-period-restart-credits-historical-debt.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py staking-reward-period-restart-credits-historical-debt.yaml
Source: defimon-2026-04/inugami-staking-8K
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class StakingRewardPeriodRestartCreditsHistoricalDebt(AbstractDetector):
    ARGUMENT = "staking-reward-period-restart-credits-historical-debt"
    HELP = "Reward period restart (notifyRewardAmount / fund / reactivate) advances periodFinish and rewardPerShare without resetting the rewardDebt of users who staked during the previous inactive window."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/staking-reward-period-restart-credits-historical-debt.yaml"
    WIKI_TITLE = "Reward period restart back-credits historical reward-debt to between-periods stakers"
    WIKI_DESCRIPTION = "MasterChef-style staking: when a reward period ends (`block.timestamp > periodFinish`), the per-share reward index `S` stops accumulating but is not zeroed. Users who deposit during the inactive window have `userInfo[user].rewardDebt = amount * S_frozen` recorded against the still-stale `S_frozen`. When the operator calls `notifyRewardAmount(extraReward)` (or any equivalent fund / refill / reactiv"
    WIKI_EXPLOIT_SCENARIO = "Inugami staking, March 2026: previous reward period had ended. Attacker `stake(1e18)`. Their `rewardDebt = 1e18 * S_frozen`. Attacker then sent 1 wei of WBNB to trigger / fund the contract (or another holder did so on schedule), making `notifyRewardAmount` reactivate emissions. `S_now` grew. Attacker called `claim()`: `pending = 1e18 * S_now - 1e18 * S_frozen ≈ 13.9 WBNB`. Total drain ≈ $8,750."
    WIKI_RECOMMENDATION = "On any function that restarts/refills the reward period, snapshot or refresh the rewardDebt of every staker (e.g., emit a checkpoint event, increment a `rewardEpoch` counter, store per-epoch indexes and redeem off `userInfo.epoch`). At minimum, force `rewardDebt = balance * rewardPerShare` for the c"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(rewardPerShare|rewardPerToken|rewardDebt|periodFinish|notifyRewardAmount|MasterChef|StakingRewards|Gauge|FarmRewards|RewardPool)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(notifyRewardAmount|fund|refill|reactivate|setRewardRate|extendRewards|setPeriod|addRewards|topUp|seedRewards|startEpoch)\\w*$'}, {'function.body_contains_regex': '(periodFinish|lastUpdateTime|lastRewardBlock|lastRewardTime|nextEpoch)\\s*='}, {'function.body_contains_regex': '(rewardPerShare|rewardPerToken|accReward|rewardIndex)\\s*[+]?='}, {'function.body_not_contains_regex': 'userInfo\\s*\\[[^\\]]+\\]\\s*\\.rewardDebt\\s*=|users\\s*\\[[^\\]]+\\]\\.rewardDebt\\s*=|_rewardDebt\\s*\\[[^\\]]+\\]\\s*=|accountRewardDebt\\s*\\[[^\\]]+\\]\\s*=|rewardDebtSnapshotAll|_resetAllRewardDebt|rewardPerShareAtEpoch\\s*\\[[^\\]]+\\]\\s*=|epochRewardPerShare\\s*\\[[^\\]]+\\]\\s*=|rewardIndexAtEpoch\\s*\\[[^\\]]+\\]\\s*=|currentEpoch\\s*\\+=\\s*1|currentEpoch\\+\\+|epochCounter\\s*\\+=\\s*1|periodIndex\\s*\\+=\\s*1|onlyOwner'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — staking-reward-period-restart-credits-historical-debt: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
