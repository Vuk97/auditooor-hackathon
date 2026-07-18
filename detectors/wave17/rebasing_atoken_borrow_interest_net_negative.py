"""
rebasing-atoken-borrow-interest-net-negative — generated from reference/patterns.dsl/rebasing-atoken-borrow-interest-net-negative.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py rebasing-atoken-borrow-interest-net-negative.yaml
Source: auditooor-R75-c4-lending-wise-lending-285
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RebasingAtokenBorrowInterestNetNegative(AbstractDetector):
    ARGUMENT = "rebasing-atoken-borrow-interest-net-negative"
    HELP = "Pool accrues debt via borrow rate only; rebasing collateral/asset increments are not factored into the borrower's debt. If yield > rate, borrow is net-positive — infinite-leverage farming of rebase yield."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/rebasing-atoken-borrow-interest-net-negative.yaml"
    WIKI_TITLE = "Rebasing asset borrowed without accounting for positive yield"
    WIKI_DESCRIPTION = "Aave aTokens and stETH-style rebasers distribute yield by increasing the token's balanceOf at every interaction. When such a token is borrow-enabled, the borrower's wallet grows every block while their debt grows only at the protocol's borrow rate. The protocol's interest accrual updates `pseudoTotalBorrow` using `rate * dt` but never reconciles against the aToken's actual balanceOf delta. If borr"
    WIKI_EXPLOIT_SCENARIO = "aUSDC supply APY = 5%, Wise Lending borrow APY on aUSDC = 2%. Attacker deposits 1M USDC as collateral, borrows 500k aUSDC. Over a year the aUSDC rebases to 525k (+5% of 500k = 25k) but debt only accrues to 510k (+2%). Attacker repays 510k aUSDC, keeps 15k USDC worth of rebase. Looping with fresh borrows compounds. Protocol's expected-liquidity invariant silently slips."
    WIKI_RECOMMENDATION = "Either (a) disallow positive-rebasing tokens as borrow assets, or (b) on every `syncPool`, measure the actual balanceOf delta of the aToken/rebasing asset since last sync and credit that delta to the borrow side accounting (effectively making the borrower's debt grow with the rebase too), or (c) req"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(aToken|stETH|rebasing|cToken)'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '(?i)(_?updatePseudoTotal|_?accrueInterest|_?updateGlobal(Interest|Debt)|_?syncPool|_?preparePool)'}, {'function.body_contains_regex': '(?i)(borrowRate|borrowInterest|interestFactor|rate\\s*\\*\\s*(dt|timeDelta|elapsed))'}, {'function.body_not_contains_regex': '(?i)(IAToken.*balanceOf|scaledBalance|ATokenHarvest|rebaseAccrued|_cleanUp.*balanceOf|currentBalance\\s*-\\s*stored)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — rebasing-atoken-borrow-interest-net-negative: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
