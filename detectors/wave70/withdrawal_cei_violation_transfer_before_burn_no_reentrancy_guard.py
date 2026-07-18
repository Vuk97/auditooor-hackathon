"""
withdrawal-cei-violation-transfer-before-burn-no-reentrancy-guard - narrow Solidity detector
Source anchor: hackerman-v2-slice2-batch2-minimax-state-change-weaken-narrowed
"""

import sys
from pathlib import Path as _Path

sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))

from _predicate_engine import eval_function_match, eval_preconditions
from _template_utils import is_leaf_helper, is_vendored_or_test_contract
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class WithdrawalCeiViolationTransferBeforeBurnNoReentrancyGuard(AbstractDetector):
    ARGUMENT = "withdrawal-cei-violation-transfer-before-burn-no-reentrancy-guard"
    HELP = "Withdraw or redeem transfers value before burning shares or decrementing balances, with no reentrancy guard."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/withdrawal-cei-violation-transfer-before-burn-no-reentrancy-guard.yaml"
    WIKI_TITLE = "Withdrawal transfer before burn without reentrancy guard"
    WIKI_DESCRIPTION = (
        "External-facing withdraw, redeem, claim, or unstake paths that "
        "transfer tokens before they burn shares or decrement user balances "
        "expose stale accounting to hook-based reentry."
    )
    WIKI_EXPLOIT_SCENARIO = (
        "An ERC777-style token transfer fires a receiver callback while the "
        "user's balance and share state are still unchanged. The attacker "
        "reenters withdraw or a sibling exit path against the stale balance."
    )
    WIKI_RECOMMENDATION = (
        "Apply checks-effects-interactions: burn shares or decrement "
        "balances before the transfer, and add a reentrancy guard on the "
        "external withdraw-facing entrypoints."
    )

    _PRECONDITIONS = [
        {
            "contract.source_matches_regex": (
                "(?i)(withdraw|redeem|claim|exit|harvest|unstake|unbond)"
            )
        },
        {
            "contract.has_state_var_matching": (
                "shares|balances|staked|deposited|positions|locked|totalAssets|totalSupply"
            )
        },
    ]
    _MATCH = [
        {"function.kind": "external_or_public"},
        {
            "function.name_matches": (
                "(?i)^(withdraw|redeem|exit|claim|harvest|collectRewards|"
                "claimRewards|unstake|unbond|emergencyWithdraw)\\d*$"
            )
        },
        {
            "function.body_ordered_regex": {
                "first": (
                    "(?i)(\\.transfer\\s*\\(|\\.safeTransfer\\s*\\(|_transfer\\s*\\(|"
                    "\\.safeTransferFrom\\s*\\(|call\\s*\\{\\s*value\\s*:)"
                ),
                "second": (
                    "(?i)(burn\\s*\\(|_burn\\s*\\(|balances?\\s*\\[[^\\]]+\\]\\s*-=|"
                    "shares\\s*\\[[^\\]]+\\]\\s*-=|staked\\s*\\[[^\\]]+\\]\\s*-=|"
                    "totalAssets\\s*-=|totalDeposited\\s*-=|userShares\\s*-=)"
                ),
                "ignore_comments_and_strings": True,
            }
        },
        {
            "function.body_not_contains_regex": (
                "(?i)(nonReentrant|ReentrancyGuard|reentrancyLock|"
                "_nonReentrantBefore|mutex|locked\\s*=\\s*true)"
            )
        },
        {
            "function.body_not_contains_regex": (
                "(?i)_withdraw\\s*\\(|_redeem\\s*\\(|_exit\\s*\\(|_harvest\\s*\\(|"
                "_claimRewards\\s*\\(|_emergencyWithdraw\\s*\\("
            )
        },
        {"function.not_in_skip_list": True},
    ]

    _INCLUDE_LEAF_HELPERS = True

    def _detect(self):
        results = []
        for contract in self.contracts:
            if is_vendored_or_test_contract(contract):
                continue
            if not eval_preconditions(contract, self._PRECONDITIONS):
                continue
            for function in contract.functions_and_modifiers_declared:
                if not self._INCLUDE_LEAF_HELPERS and is_leaf_helper(function):
                    continue
                if not eval_function_match(function, self._MATCH):
                    continue
                info = [
                    function,
                    " - withdrawal-cei-violation-transfer-before-burn-no-reentrancy-guard: pattern matched. See WIKI for details.",
                ]
                results.append(self.generate_result(info))
        return results
