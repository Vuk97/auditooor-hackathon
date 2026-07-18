"""
reward-debt-updated-on-failed-claim — generated from reference/patterns.dsl/reward-debt-updated-on-failed-claim.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py reward-debt-updated-on-failed-claim.yaml
Source: solodit/C0373
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RewardDebtUpdatedOnFailedClaim(AbstractDetector):
    ARGUMENT = "reward-debt-updated-on-failed-claim"
    HELP = "Staking claim/harvest path updates accountRewardDebt / lastReward before the reward transfer is confirmed. When the transfer silently fails (try/catch, unchecked .call, raw .transfer, custom _send) the debt write is not rolled back, permanently burning the user's future reward entitlement."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/reward-debt-updated-on-failed-claim.yaml"
    WIKI_TITLE = "Reward debt updated on failed claim: unchecked transfer leaves accountRewardDebt corrupted"
    WIKI_DESCRIPTION = "MasterChef / synthetix-style staking contracts compute a user's owed rewards as `pending = balance * rewardPerShare - accountRewardDebt`. A correct claim path must commit the debt update only if the reward actually left the contract. This pattern fires when the claim / harvest function writes to rewardDebt / accountRewardDebt / lastReward bookkeeping and the reward payout is performed via a try / "
    WIKI_EXPLOIT_SCENARIO = "User U calls claimReward. Internally the contract executes `user.accountRewardDebt = user.balance * rewardPerShare`, then does `try rewardToken.transfer(U, pending) { } catch { }`. The reward token is, for example, a fee-on-transfer token, a paused token, a token that blacklists U, or a token whose transfer runs out of gas. The transfer reverts, the catch swallows the error, the function returns s"
    WIKI_RECOMMENDATION = "Perform the reward transfer first, require(success) on the return value, and only update rewardDebt / accountRewardDebt / lastReward after the transfer is confirmed. Alternatively, use SafeERC20.safeTransfer so a silent failure bubbles up as a revert that rolls back the debt write. Never swallow tra"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': 'rewardDebt|accountRewardDebt|rewardPerShare|userReward'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': 'claim|_claim|claimReward|_claimReward|_claimRewardToken|harvest'}, {'function.writes_storage_matching': 'rewardDebt|accountReward|lastReward'}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.has_low_level_call': True}, {'function.body_contains_regex': 'try\\s+|catch\\s*\\{|\\.call\\s*\\{|\\.transfer\\s*\\(|_send\\s*\\('}, {'function.body_not_contains_regex': 'require\\s*\\(.*success\\s*(==|!=|,)|require\\s*\\(\\s*ok\\s*(==|!=|,)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — reward-debt-updated-on-failed-claim: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
