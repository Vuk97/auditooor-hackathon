"""
r94-reverse-rewards-claim-all-missing-per-pool-settle — generated from reference/patterns.dsl/r94-reverse-rewards-claim-all-missing-per-pool-settle.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-reverse-rewards-claim-all-missing-per-pool-settle.yaml
Source: reverse-port-from-rust_wave1
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94ReverseRewardsClaimAllMissingPerPoolSettle(AbstractDetector):
    ARGUMENT = "r94-reverse-rewards-claim-all-missing-per-pool-settle"
    HELP = "claimAll() / claimAllRewards() transfers accrued rewards across pools but never zeros the per-pool bookkeeping; attacker can claim a single pool (zeroing that slot) then call claimAll (which still reads the cached accrual) and be paid twice."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-reverse-rewards-claim-all-missing-per-pool-settle.yaml"
    WIKI_TITLE = "claimAll() does not settle per-pool accrual — rewards paid twice via claim + claimAll sequence"
    WIKI_DESCRIPTION = "A rewards contract that exposes both a narrow per-pool claim(id) and a broad claimAll() must keep both settle paths in sync. The narrow path typically resets userAccrued[user][pool] = 0 or bumps userRewardPerTokenPaid. If the broad claimAll() path loops through pools, sums accrued, and transfers without ALSO calling the same _updateReward / checkpoint helper that the narrow path uses, an attacker "
    WIKI_EXPLOIT_SCENARIO = "Staking contract stores `userAccrued[user][pool]` and exposes `claim(uint pid)` which does `token.safeTransfer(msg.sender, userAccrued[msg.sender][pid]); userAccrued[msg.sender][pid] = 0;`. A later release adds `claimAllRewards()` that does `for (uint i; i < pools.length; ++i) { token.safeTransfer(msg.sender, userAccrued[msg.sender][i]); }` — shipping a bug that re-reads the same mapping without z"
    WIKI_RECOMMENDATION = "Route both claim() and claimAll() through a single internal `_settleReward(user, pool)` helper that transfers AND zeros the slot. Audit any public reward-path for each mutation or read of `userAccrued`, `userRewardPerTokenPaid`, `rewardDebt` — every transfer MUST be preceded by a checkpoint write. A"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(reward|Reward|accrued|claim|incentive|Incentive)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(claimAll|claimAllRewards|claimRewardsAll|harvestAll|claimMultiple|claimAllFor)$'}, {'function.body_contains_regex': '(safeTransfer|\\.transfer\\(|_transfer\\(|_safeTransfer|pendingReward|accruedReward|earned\\()'}, {'function.body_contains_regex': '(for\\s*\\(.*?(pool|asset|token|index|reward|i\\s*<).*?\\)|for\\s*\\(uint)'}, {'function.body_not_contains_regex': '(userAccrued\\[[^\\]]+\\]\\s*=\\s*0|delete\\s+user|_updateReward|checkpoint\\(|accrued\\[[^\\]]+\\]\\s*=\\s*0|_userState|claimed\\[[^\\]]+\\]\\s*=|rewardDebt\\[[^\\]]+\\]\\s*=\\s*user|userRewardPerTokenPaid\\[[^\\]]+\\]\\s*=)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r94-reverse-rewards-claim-all-missing-per-pool-settle: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
