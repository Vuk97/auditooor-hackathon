"""
r94-loop-swap-amount-not-reduced-after-price-clamp-lock-funds — generated from reference/patterns.dsl/r94-loop-swap-amount-not-reduced-after-price-clamp-lock-funds.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-swap-amount-not-reduced-after-price-clamp-lock-funds.yaml
Source: solodit-40243-cantina-marginal-v1-lb-pool
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopSwapAmountNotReducedAfterPriceClampLockFunds(AbstractDetector):
    ARGUMENT = "r94-loop-swap-amount-not-reduced-after-price-clamp-lock-funds"
    HELP = "r94-loop-swap-amount-not-reduced-after-price-clamp-lock-funds"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-swap-amount-not-reduced-after-price-clamp-lock-funds.yaml"
    WIKI_TITLE = "r94-loop-swap-amount-not-reduced-after-price-clamp-lock-funds"
    WIKI_DESCRIPTION = "r94-loop-swap-amount-not-reduced-after-price-clamp-lock-funds"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-swap-amount-not-reduced-after-price-clamp-lock-funds"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = {'contract.source_matches_regex': '(Pool|Swap|MarginalV1|LbPool|ConcentratedLiquidity)', 'function.name_matches': '(?i)(^swap$|swapPool|swapStep|exactInput|swapWithClamp|limitPriceSwap)', 'function.source_matches_regex': '(sqrtPriceNext\\s*=\\s*sqrtPriceLimit|priceClamped|if\\s*\\(\\s*\\w*sqrtPriceNext\\s*[<>]\\s*\\w*sqrtPriceLimit|clampSqrtPrice)', 'function.not_source_matches_regex': '(amountSpecified\\s*-=|specifiedAmount\\s*=\\s*\\w*specifiedAmount\\s*-|leftoverAmountToUser|refundUnused|\\.\\s*saturatingSub\\s*\\(\\s*\\w*(amountConsumed|usedAmount|executed))'}
    _MATCH = ['function']

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
                info = [f, f" — r94-loop-swap-amount-not-reduced-after-price-clamp-lock-funds: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
