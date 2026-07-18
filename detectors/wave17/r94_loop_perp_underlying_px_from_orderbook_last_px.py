"""
r94-loop-perp-underlying-px-from-orderbook-last-px — generated from reference/patterns.dsl/r94-loop-perp-underlying-px-from-orderbook-last-px.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r94-loop-perp-underlying-px-from-orderbook-last-px.yaml
Source: loop-cycle-74-sol-sibling
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R94LoopPerpUnderlyingPxFromOrderbookLastPx(AbstractDetector):
    ARGUMENT = "r94-loop-perp-underlying-px-from-orderbook-last-px"
    HELP = "r94-loop-perp-underlying-px-from-orderbook-last-px"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r94-loop-perp-underlying-px-from-orderbook-last-px.yaml"
    WIKI_TITLE = "r94-loop-perp-underlying-px-from-orderbook-last-px"
    WIKI_DESCRIPTION = "r94-loop-perp-underlying-px-from-orderbook-last-px"
    WIKI_EXPLOIT_SCENARIO = "r94-loop-perp-underlying-px-from-orderbook-last-px"
    WIKI_RECOMMENDATION = "See audit report."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(perpUnderlyingPx|markToMarket|getUnderlyingPrice|lastPx)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)(getUnderlyingPrice|markToMarket|liquidate|computeUnderlyingPx|perpUnderlyingPx|getPerpUnderlying)'}, {'function.source_matches_regex': '(lastPx|lastPrice|lastTradePrice|orderbook\\.lastPx|market\\.lastPx|pair\\.lastPx)'}, {'function.not_source_matches_regex': '(oracleFeed|oracle\\.get|chainlink|markPriceOracle|hasOracle\\s*\\(|priceFeed\\.get|freshTwap|twapPrice)'}]

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
                info = [f, f" — r94-loop-perp-underlying-px-from-orderbook-last-px: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
