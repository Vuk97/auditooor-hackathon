"""
loan-collateral-steal-owner-frontrun — generated from reference/patterns.dsl/loan-collateral-steal-owner-frontrun.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py loan-collateral-steal-owner-frontrun.yaml
Source: solodit/C0369
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LoanCollateralStealOwnerFrontrun(AbstractDetector):
    ARGUMENT = "loan-collateral-steal-owner-frontrun"
    HELP = "Loan buyout/refinance/takeover entry reads loanInfo without nonReentrant; current owner can mutate the loan state after a challenger commits and steal collateral."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/loan-collateral-steal-owner-frontrun.yaml"
    WIKI_TITLE = "Loan buyout: current owner can frontrun challenger and steal collateral"
    WIKI_DESCRIPTION = "A loan / position manager exposes a buyout, refinance, takeOver, acceptOffer, or swapCollateral entry point that reads and mutates per-loan state (loanInfo, loanOwner, currentOwner, collateral) without a reentrancy guard. The existing loan owner observes a challenger's pending buyout / refinance transaction in the mempool (or re-enters via a token callback triggered during settlement) and adjusts "
    WIKI_EXPLOIT_SCENARIO = "Lender A advertises a loan with 10 WETH of collateral and 5k USDC debt. Lender B calls buyout(loanId) to refinance it on better terms, signing a transaction that assumes the 10 WETH / 5k USDC snapshot. The current owner watches the mempool, frontruns with swapCollateral(loanId, newToken) that replaces the 10 WETH collateral with a worthless governance token, and Lender B's buyout settles against t"
    WIKI_RECOMMENDATION = "Apply OpenZeppelin ReentrancyGuard (nonReentrant) to every buyout / refinance / takeOver / acceptOffer / swapCollateral entry point AND require challengers to commit to a loanInfo digest (hash of the exact loan parameters) that is verified atomically inside the settlement function — reverting if the"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(loan|loanInfo|position|collateral|currentOwner|loanOwner)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(buyout|refinance|takeOver|acceptOffer|swapCollateral|_buyout)'}, {'function.body_contains_regex': {'regex': '(loanInfo|\\.loan|loanOwner|currentOwner|_loan)'}}, {'function.has_modifier': {'includes': ['nonReentrant', 'reentrancyGuard', 'lock'], 'negate': True}}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — loan-collateral-steal-owner-frontrun: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
