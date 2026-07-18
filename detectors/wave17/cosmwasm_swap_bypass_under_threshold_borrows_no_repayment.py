"""
cosmwasm-swap-bypass-under-threshold-borrows-no-repayment — generated from reference/patterns.dsl/cosmwasm-swap-bypass-under-threshold-borrows-no-repayment.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py cosmwasm-swap-bypass-under-threshold-borrows-no-repayment.yaml
Source: auditooor-R76-c4-rujira-bug-bounty-41
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CosmwasmSwapBypassUnderThresholdBorrowsNoRepayment(AbstractDetector):
    ARGUMENT = "cosmwasm-swap-bypass-under-threshold-borrows-no-repayment"
    HELP = "Small-amount fast-path borrows from vault and sends tokens to user but never emits the hedge swap message or charges the reserve fee — each call creates permanent bad debt."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/cosmwasm-swap-bypass-under-threshold-borrows-no-repayment.yaml"
    WIKI_TITLE = "Small-amount bypass in virtualization strategy borrows from vault without generating repayment"
    WIKI_DESCRIPTION = "A swap router that virtualises small output via an intermediate vault (borrow → swap → repay) has an early-return fast-path for `min_return < N` that skips both the external swap message (no repayment source) and the reserve-fee charge. Tokens leave the vault, the repayment handler has a `> 1000` minimum threshold, and the debt is never retired. An attacker (or even normal market-maker activity) a"
    WIKI_EXPLOIT_SCENARIO = "Authorised market (e.g. FIN) calls `ExecuteMsg::Swap { min_return: coin(9, 'rune'), offer: coin(1, 'btc') }`. Handler takes the < 10 branch: adds `vault.borrow_msg(9, user)` and `execute_repayments` (which has nothing new to repay with). No `swap_msg` is attached. 9 RUNE leaves the vault, contract has no incoming swap to cover it. Loop this with every small market trade → Ghost Vault depositors' a"
    WIKI_RECOMMENDATION = "In the small-amount path, EITHER (a) still append the swap_msg and charge the reserve_fee, OR (b) remove the bypass and let the normal path handle small amounts. Also raise the repayment handler's minimum threshold only after adding a sweep that retires small debts from accumulated reserve fees. Add"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)\\.rs$'}, {'contract.has_function_matching': '(?i)swap|virtualize|hedge|borrow_from_vault'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)execute|swap|do_swap|virtualize_swap'}, {'function.body_contains_regex': '(?i)if\\s+[\\w\\.]*\\.(amount|u128|value)\\s*<\\s*Uint128::new\\s*\\(\\s*\\d+|amount\\s*<\\s*1[0-9]?\\b|<\\s*MIN_(SWAP|AMOUNT|RETURN)'}, {'function.body_contains_regex': '(?i)vault\\.borrow_msg|borrow_msg\\b|BankMsg::Send'}, {'function.body_not_contains_regex': '(?i)swap_msg|add_message\\(.*Swap|reserve_fee|multiply_ratio\\(.*reserve'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — cosmwasm-swap-bypass-under-threshold-borrows-no-repayment: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
