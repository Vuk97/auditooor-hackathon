"""
r94-reverse-rewards-accrual-double-count-self-transfer — generated from reference/patterns.dsl/r94-reverse-rewards-accrual-double-count-self-transfer.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-reverse-rewards-accrual-double-count-self-transfer.yaml
Source: reverse-port-from-rust_wave1
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94ReverseRewardsAccrualDoubleCountSelfTransfer(AbstractDetector):
    ARGUMENT = "r94-reverse-rewards-accrual-double-count-self-transfer"
    HELP = "ERC-20 transfer override invokes reward accrual for both `from` and `to` without a `from != to` self-transfer guard; self-transfer double-counts accrual for the same account in one tx."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-reverse-rewards-accrual-double-count-self-transfer.yaml"
    WIKI_TITLE = "ERC-20 transfer hook accrues rewards twice on self-transfer"
    WIKI_DESCRIPTION = "Incentivized ERC-20s (aTokens, scaled-balance shares, gauge LP, veToken) override `_transfer` / `_beforeTokenTransfer` / `_update` to checkpoint reward accrual for both sender and recipient. If the override unconditionally calls the accrual hook for both `from` and `to`, a self-transfer (user sends tokens to themselves) runs the hook twice against the same user in a single block. For indexes that "
    WIKI_EXPLOIT_SCENARIO = "An ERC-20 aToken uses `_transfer(from, to, amount)` with hooks: `_handleAction(from); _handleAction(to);` each of which accrues the user's incentive. User A with balance 100 calls `transfer(A, 100)` → hook runs `_handleAction(A)` TWICE, ticking their index twice as fast as an honest holder. The second call is pure arbitrage — no transfer cost, no price risk — and the attacker repeats every block t"
    WIKI_RECOMMENDATION = "Add an explicit `if (from == to) return;` at the top of the transfer body, OR run the accrual hook only ONCE with both participants in a single call: `_handleAction(from, to, amount)`. Unit-test: balance before and after a self-transfer should match, and the reward index delta should match an idle a"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(IncentivizedERC20|RewardsDistribution|scaledBalance|scaledTotalSupply|rewardIndex|userIndex)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(?i)^(_transfer|_update|transfer|transferFrom|_beforeTokenTransfer|_afterTokenTransfer)$'}, {'function.body_contains_regex': '(_handleAction|handleAction|_updateUserRewardIndex|_updateRewards|accrueFor|_updateUserState|_accruedRewards|_updateState|_updateIndex|_userRewardIndex|_checkpoint|updateUser|accrueRewards)'}, {'function.body_not_contains_regex': '(from\\s*==\\s*to|to\\s*==\\s*from|if\\s*\\(from\\s*!=\\s*to|if\\s*\\(to\\s*!=\\s*from|if\\s*\\(sender\\s*==\\s*recipient|sender\\s*!=\\s*recipient)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r94-reverse-rewards-accrual-double-count-self-transfer: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
