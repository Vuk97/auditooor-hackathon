"""
reward-distribution-missing-update — generated from reference/patterns.dsl/reward-distribution-missing-update.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py reward-distribution-missing-update.yaml
Source: solodit/C0307+C0339
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RewardDistributionMissingUpdate(AbstractDetector):
    ARGUMENT = "reward-distribution-missing-update"
    HELP = "Deposit/withdraw/stake/transfer function in a rewards/staking contract mutates user balance or shares without first invoking the reward-update hook (updateReward / accrueRewards / harvest). MasterChef-class accounting bug."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/reward-distribution-missing-update.yaml"
    WIKI_TITLE = "Reward distribution: state-mutating entry point does not call updateReward first"
    WIKI_DESCRIPTION = "Rewards/gauge contracts that track per-user balances or shares must invariant-maintain the per-share reward index by calling an updateReward-style hook BEFORE any mutation of the user's balance. Entry points (deposit, stake, withdraw, unstake, transfer, mint, burn) that mutate the balance/shares/stake state without first invoking the update function cause users to lose accrued rewards or, in Maste"
    WIKI_EXPLOIT_SCENARIO = "User A has accrued rewards proportional to their shares since the last checkpoint. User A (or another user via `transfer`) invokes an entry point that mutates shares without first accruing. The reward index advances implicitly using the NEW share count, so User A's accrued rewards are computed against the wrong snapshot and either (a) are lost, (b) are paid to the wrong user, or (c) an attacker de"
    WIKI_RECOMMENDATION = "Require every external balance-mutating entry point to invoke updateReward(account) (or an equivalent accrual hook) as its first action. In Solidity, encode this as an `updateReward` modifier applied to deposit/withdraw/transfer/stake/mint/burn."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^(updateReward|_updateReward|accrueRewards?|_accrueRewards?|harvest|_harvest|checkpoint|_checkpoint)$'}, {'contract.has_state_var_matching': '(balance|shares|stake|deposit)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(deposit|stake|withdraw|unstake|transfer|mint|burn)'}, {'function.writes_storage_matching': '(balance|shares|stake|deposit)'}, {'function.has_modifier': {'includes': ['updateReward', 'updatesReward', 'updateRewards', 'withReward', 'accrueReward', 'accrueRewards'], 'negate': True}}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — reward-distribution-missing-update: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
