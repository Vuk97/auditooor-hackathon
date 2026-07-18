"""
staking-claim-pays-from-accumulated-not-funded-balance — generated from reference/patterns.dsl/staking-claim-pays-from-accumulated-not-funded-balance.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py staking-claim-pays-from-accumulated-not-funded-balance.yaml
Source: defimon-deep-mine/JFIN_Bridge_2024-12-24_post-2465 ($13.4K)
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class StakingClaimPaysFromAccumulatedNotFundedBalance(AbstractDetector):
    ARGUMENT = "staking-claim-pays-from-accumulated-not-funded-balance"
    HELP = "Reward / vesting claim transfers the full accumulator amount without checking the contract holds enough reward token. The first late claim drains the contract; later claimants revert. Drains depositor principal when reward token == staked token."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/staking-claim-pays-from-accumulated-not-funded-balance.yaml"
    WIKI_TITLE = "Reward claim pays from internal accumulator with no balance/budget cap"
    WIKI_DESCRIPTION = "Staking and vesting contracts often accumulate `pendingReward[user] += staked * rewardPerSecond * dt` as an unrestricted internal counter. The claim path then `IERC20(reward).transfer(user, pendingReward[user])` without ever checking the contract is solvent for that payout. When the reward budget was funded for N tokens but the accumulator has grown past N, the first late claimant gets the full N "
    WIKI_EXPLOIT_SCENARIO = "JFIN Bridge LCBridgev2Token staking, BSC, 2024-12-24 (post-2465, $13.4K). The `claimReward` path computed payouts from an accumulated `totalReward` per stake without bounding by the contract's actual JFIN balance. Once `totalReward > balanceOf(staking)`, the first claim drained all staked JFIN. Tx: 0xf867d1d7164ac9178d81696c989f65e817b8cab14850345ab3a1f99bbe547210 — the attacker minted high `total"
    WIKI_RECOMMENDATION = "Cap every reward transfer by the contract's actual reward-token balance: `uint payout = Math.min(pendingReward[user], IERC20(rewardToken).balanceOf(address(this)));`. If the reward and staked tokens are the same, track them in separate accumulators (or compute `available = balanceOf(this) - totalSta"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(reward|vesting|payout|claim|distribute)'}, {'contract.has_function_matching': '(?i)(claim|getReward|withdraw[A-Z]?[Rr]eward|harvest)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(claim|claimReward|claimRewards|getReward|withdrawReward|harvestReward|withdrawAccumulated)$'}, {'function.body_contains_regex': '(?i)(totalReward|accumulatedReward|accruedReward|pendingReward|userReward|userPending|reward[A-Z]?[Bb]alance)\\s*[\\[]?'}, {'function.body_contains_regex': '(?i)(safeTransfer|transfer|safeTransferFrom)\\s*\\(.*(totalReward|accumulatedReward|accruedReward|pendingReward|userReward|userPending|amountToClaim|reward(s)?Amount|claimable)'}, {'function.body_not_contains_regex': '(?i)(require\\s*\\([^)]*(balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)|rewardBudget|fundedAmount|rewardPool[Bb]alance)\\s*>=|min\\s*\\([^)]*balanceOf\\s*\\(\\s*address\\s*\\(\\s*this|amount\\s*=\\s*Math\\.min|amount\\s*=\\s*\\w+\\s*<\\s*balanceOf|if\\s*\\(\\s*\\w+\\s*>\\s*balanceOf\\s*\\(\\s*address\\s*\\(\\s*this\\s*\\)\\s*\\)\\s*\\)\\s*\\w+\\s*=)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — staking-claim-pays-from-accumulated-not-funded-balance: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
