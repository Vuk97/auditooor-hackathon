"""
decimal-truncation-price-check — generated from reference/patterns.dsl/decimal-truncation-price-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py decimal-truncation-price-check.yaml
Source: solodit-novel/slice_aa-SOCKET
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class DecimalTruncationPriceCheck(AbstractDetector):
    ARGUMENT = "decimal-truncation-price-check"
    HELP = "Price ratio computed as `fromPrice / toPrice` via integer division without scaling by precision. Near-equal prices collapse to 0 or 1, rendering `priceChangeLimit` trivially satisfied."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/decimal-truncation-price-check.yaml"
    WIKI_TITLE = "Price ratio integer-division truncation (no 1e18 scaling)"
    WIKI_DESCRIPTION = "Integer division of similar-magnitude prices truncates to 0 or 1. Functions that check `require(ratio <= maxChange)` without pre-scaling (e.g., `fromPrice * 1e18 / toPrice`) are trivially satisfied even when the true ratio differs materially."
    WIKI_EXPLOIT_SCENARIO = "Function checks `require(fromPrice / toPrice <= 105, \"price diverged\")`. fromPrice and toPrice are both 8-decimal oracles. With `fromPrice=1.01e8, toPrice=1e8`, `fromPrice / toPrice == 1`, passing the check. If the check was meant to catch 5% divergence, any divergence short of 4x is now invisible."
    WIKI_RECOMMENDATION = "Scale before dividing: `ratio = fromPrice * PRECISION / toPrice` (or use OpenZeppelin `Math.mulDiv`)."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(PriceOracle|Oracle|Router|Pricing|priceChangeLimit|fromPrice|toPrice|exchangeRate|getPrice|priceFrom)'}, {'contract.has_state_var_matching': 'price|priceFrom|fromPrice|toPrice|exchangeRate'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(_?checkPrice|_?checkRatio|_?checkPriceRatio|_?validatePrice|_?validateRatio|_?validateOracle|_?computePrice|_?computeRatio|_?computeAmount|_?getRatio|_?getPriceRatio|_?priceRatio|_?swap|_?swapExact|_?swapTokens|_?quote|_?quoteExact|_?execute|_?executeSwap|_?settle|_?settleAmount|_?rebalance|_?updatePrice|_?updateOracle|fromPriceToAmount|convertPrice)$'}, {'function.body_contains_regex': '\\w*[pP]rice\\s*/\\s*\\w*[pP]rice|fromPrice\\s*/\\s*toPrice'}, {'function.body_not_contains_regex': 'fromPrice\\s*\\*\\s*1e\\d+|PRECISION\\s*\\*\\s*fromPrice|\\bmulDiv\\b|FullMath'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(Math\\.mulDiv|FullMath\\.mulDiv|TWAP|view\\s+returns|pure\\s+returns|SafeCast|\\*\\s*1e18\\s*/|\\*\\s*PRECISION\\s*/|wadDiv|rayDiv)'}]

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
                info = [f, f" — decimal-truncation-price-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
