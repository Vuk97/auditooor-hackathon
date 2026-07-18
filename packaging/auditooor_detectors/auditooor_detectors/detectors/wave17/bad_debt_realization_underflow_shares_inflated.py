"""
bad-debt-realization-underflow-shares-inflated — generated from reference/patterns.dsl/morpho-bad-debt-realization-underflow.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py morpho-bad-debt-realization-underflow.yaml
Source: auditooor-R71-fixdiff-mined-morpho-e52ab6b
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class BadDebtRealizationUnderflowSharesInflated(AbstractDetector):
    ARGUMENT = "bad-debt-realization-underflow-shares-inflated"
    HELP = "Bad-debt realization subtracts a share-derived asset amount from multiple accumulators with no clamp; inflated borrow-share price can drive the delta above totalBorrowAssets and underflow."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/morpho-bad-debt-realization-underflow.yaml"
    WIKI_TITLE = "Bad-debt write-off underflow: badDebtShares.toAssetsUp can exceed totalBorrowAssets"
    WIKI_DESCRIPTION = "When all collateral has been seized and the borrower retains borrowShares, the protocol mints those shares as bad debt by reducing totalSupplyAssets and totalBorrowAssets by toAssetsUp(badDebtShares). If borrow-share price has been inflated (via virtual-shares mint-inflate, interest accrual, or fee donation), the computed badDebt can exceed totalBorrowAssets. The subsequent subtraction panics on u"
    WIKI_EXPLOIT_SCENARIO = "Morpho Blue cantina-58 (2023): attacker borrows with shares=1 on an empty market to inflate borrow-share price. Then normal borrower defaults, collateral goes to zero. Liquidator calls liquidate — badDebtShares.toAssetsUp overshoots totalBorrowAssets, panic underflow, liquidation DoS'd. Attacker repeats to brick every new market."
    WIKI_RECOMMENDATION = "Clamp bad-debt accumulator subtractions with `badDebt = min(totalBorrowAssets, badDebtShares.toAssetsUp(...))` before applying. Also mint the clamped badDebt to totalSupplyAssets so supply-side accounting stays consistent."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(totalBorrowAssets|totalSupplyAssets|totalDebtAssets)'}, {'contract.has_function_matching': '^(liquidate|closeBadDebt|realizeBadDebt|chargeOff)$'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(liquidate|closeBadDebt|realizeBadDebt|chargeOff)$'}, {'function.body_contains_regex': '(badDebt|writeOff|defaulted).*toAssetsUp|borrowShares.*toAssetsUp'}, {'function.body_contains_regex': 'total(Supply|Borrow|Debt)(Assets|)\\s*-='}, {'function.body_not_contains_regex': 'zeroFloorSub|Math\\.min\\s*\\(\\s*total|UtilsLib\\.min\\s*\\(\\s*total(Borrow|Supply)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — bad-debt-realization-underflow-shares-inflated: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
