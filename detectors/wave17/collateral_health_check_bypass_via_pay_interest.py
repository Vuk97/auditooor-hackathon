"""
collateral-health-check-bypass-via-pay-interest — generated from reference/patterns.dsl/collateral-health-check-bypass-via-pay-interest.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py collateral-health-check-bypass-via-pay-interest.yaml
Source: solodit-novel/slice_aa
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CollateralHealthCheckBypassViaPayInterest(AbstractDetector):
    ARGUMENT = "collateral-health-check-bypass-via-pay-interest"
    HELP = "payInterest / accrueInterest mutates debt or collateral balances without invoking the health check. Borrower can decrement collateral below solvency threshold via this path."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/collateral-health-check-bypass-via-pay-interest.yaml"
    WIKI_TITLE = "Interest-settlement path skips health check"
    WIKI_DESCRIPTION = "Borrower-accessible interest-payment paths must run the same solvency / collateral health check as other user flows. When `payInterest` decrements `collateral[borrower]` (or credits debt) without calling `isRedeemAllowed` / `_healthCheck`, the borrower can make their position technically insolvent via this path while avoiding the liquidation trigger."
    WIKI_EXPLOIT_SCENARIO = "Borrower has collateral 1000, debt 800 (80% LTV, threshold 85%). Calling `withdraw(200)` reverts (would exceed LTV). Attacker calls `payInterest` with specific parameters that decrement collateral 200 but credits the pool without touching debt. New state: collateral 800, debt 800 (100% LTV) — position insolvent, but no liquidation has triggered because `payInterest` did not invoke the health check"
    WIKI_RECOMMENDATION = "Every function that mutates collateral or debt must end with `_requireHealthy(borrower)` or equivalent. Central that invariant: add a modifier `afterHealthy` applied to all user-mutating entry-points."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'isRedeemAllowed|checkCollateral|_healthCheck|isHealthy|solvencyCheck|accrueInterest'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': 'payInterest|accrueInterest|settleInterest|pay|repayInterest|harvestInterest'}, {'function.body_contains_regex': 'debt\\s*[-=]|collateral\\s*[-=]|borrow\\w*\\s*[-=]|\\.amount\\s*[-=]'}, {'function.body_not_contains_regex': 'isRedeemAllowed|_healthCheck|isHealthy|solvencyCheck|checkCollateral|_requireSolvent'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — collateral-health-check-bypass-via-pay-interest: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
