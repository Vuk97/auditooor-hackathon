"""
repay-assetsup-exceeds-total-borrow-underflow — generated from reference/patterns.dsl/morpho-repay-assetsup-exceeds-total-borrow-underflow.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py morpho-repay-assetsup-exceeds-total-borrow-underflow.yaml
Source: auditooor-R71-fixdiff-mined-morpho-bdcf70a
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RepayAssetsupExceedsTotalBorrowUnderflow(AbstractDetector):
    ARGUMENT = "repay-assetsup-exceeds-total-borrow-underflow"
    HELP = "Repay/liquidate path subtracts a ceil-rounded asset conversion from a debt accumulator with no saturation — repaying the last share panics on underflow."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/morpho-repay-assetsup-exceeds-total-borrow-underflow.yaml"
    WIKI_TITLE = "Debt accumulator underflow when toAssetsUp(shares) exceeds totalBorrowAssets by 1 wei"
    WIKI_DESCRIPTION = "When a borrower repays or is liquidated for their last outstanding share, the function computes `assets = shares.toAssetsUp(totalBorrowAssets, totalBorrowShares)`. Because toAssetsUp rounds up, assets can equal totalBorrowAssets + 1 for the final share. The subsequent `totalBorrowAssets -= assets.toUint128()` panic-reverts on underflow, permanently blocking close-out of the final position in the m"
    WIKI_EXPLOIT_SCENARIO = "Morpho Blue pre-1.0 fix (cantina-58): borrower holds the last 1-wei of borrowShares. Repay with shares-input converts to assetsUp = totalBorrowAssets + 1. `totalBorrowAssets -= assets` panics. Full repay is impossible and the market's debt side is permanently stuck with 1-wei phantom debt."
    WIKI_RECOMMENDATION = "Wrap every accumulator decrement that consumes a ceil-rounded conversion in a saturating helper: `totalBorrowAssets = zeroFloorSub(totalBorrowAssets, assets).toUint128()` or `totalBorrowAssets -= Math.min(totalBorrowAssets, assets).toUint128()`. Document in the event that assets may exceed totalBorr"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(totalBorrowAssets|totalBorrow|totalDebtAssets|totalLiability)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(repay|liquidate|closePosition|settle|redeemDebt)$'}, {'function.body_contains_regex': '(toAssetsUp|mulDivUp)\\s*\\('}, {'function.body_contains_regex': 'total(Borrow|Debt|Liability)(Assets|)\\s*-='}, {'function.body_not_contains_regex': 'zeroFloorSub|Math\\.min\\s*\\(\\s*total(Borrow|Debt)|UtilsLib\\.min\\s*\\(\\s*total(Borrow|Debt)|saturatingSub'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — repay-assetsup-exceeds-total-borrow-underflow: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
