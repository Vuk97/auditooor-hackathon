"""
r94-reverse-flashloan-callback-state-mutation-before-repay — generated from reference/patterns.dsl/r94-reverse-flashloan-callback-state-mutation-before-repay.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-reverse-flashloan-callback-state-mutation-before-repay.yaml
Source: reverse-port-from-rust_wave1
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94ReverseFlashloanCallbackStateMutationBeforeRepay(AbstractDetector):
    ARGUMENT = "r94-reverse-flashloan-callback-state-mutation-before-repay"
    HELP = "Flash-loan entry runs the borrower callback before protocol state is finalized; callback-initiated reentrant calls observe mid-update state or mutate state in ways the post-repay check cannot detect."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-reverse-flashloan-callback-state-mutation-before-repay.yaml"
    WIKI_TITLE = "Flashloan lender mutates state AFTER borrower callback without reentrancy lock"
    WIKI_DESCRIPTION = "A lender's flashLoan() implementation performs four logical steps: (1) transfer principal to receiver, (2) invoke receiver's onFlashLoan / executeOperation / receiveFlashLoan callback, (3) update protocol interest indexes and user-configuration state, (4) verify that the principal plus premium was repaid. If step 3 happens after step 2 and the function lacks a nonReentrant modifier, the callback i"
    WIKI_EXPLOIT_SCENARIO = "Aave-style pool's flashLoan() transfers the principal, invokes `IFlashLoanReceiver(receiver).executeOperation(...)`, then calls `_updateIndexes(asset)` to accrue interest at the post-loan utilization, then checks that `balanceOf(this) >= preBalance + premium`. Inside executeOperation, the attacker reenters the same pool to `deposit` or `borrow` while `_updateIndexes` has not yet run for this trans"
    WIKI_RECOMMENDATION = "Apply `nonReentrant` to every public `flashLoan` variant. Run all state updates (interest indexes, user configuration, reserve configuration, scaled supply adjustments) BEFORE invoking the receiver callback. Treat the receiver call as purely external: verify `balanceOf(this)` delta afterwards but do"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(flashLoan|FlashLoan|flash)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(flashLoan|flashLoanSimple|_flashLoan|executeFlashLoan|flash|_flash)$'}, {'function.body_contains_regex': '(IFlashLoanReceiver|IERC3156FlashBorrower|executeOperation|onFlashLoan|receiveFlashLoan|receiver\\.\\w+\\(|IFlashLoanSimpleReceiver)'}, {'function.body_contains_regex': '(updateState|_updateState|_accrueInterest|_updateInterestRates|setUserConfiguration|scaledTotalSupply|mintToTreasury|_updateIndexes|updateInterestRatesAndVirtualBalance)'}, {'function.has_modifier': {'includes': ['nonReentrant', 'reentrancyGuard', 'lock', 'globalLock'], 'negate': True}}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r94-reverse-flashloan-callback-state-mutation-before-repay: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
