"""
reduce-only-inflates-open-interest — generated from reference/patterns.dsl/reduce-only-inflates-open-interest.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py reduce-only-inflates-open-interest.yaml
Source: code4arena/slice_ac-GTE-Perps-M08
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ReduceOnlyInflatesOpenInterest(AbstractDetector):
    ARGUMENT = "reduce-only-inflates-open-interest"
    HELP = "Perps matching engine increments open-interest (quoteOI/baseOI) on every new order without branching on reduce-only. Reduce-only orders push OI up, triggering the max-OI guard and DoS'ing the book."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/reduce-only-inflates-open-interest.yaml"
    WIKI_TITLE = "Perps increments open-interest on reduce-only orders"
    WIKI_DESCRIPTION = "In a perps matching engine, OI should only grow when an order opens or grows a position. Reduce-only orders are explicit guarantees from the caller that the order will never increase position size. When the engine increments a global `quoteOI` counter on every placeOrder — including reduce-only — the counter drifts upward with each cancellation cycle, eventually tripping any max-OI circuit breaker"
    WIKI_EXPLOIT_SCENARIO = "GTE-Perps M-08: attacker repeatedly places-and-cancels reduce-only orders. Every placement increments `quoteOI` but reduce-only cancels don't decrement correctly. `quoteOI` reaches the max-OI guard, and legitimate opens start reverting `MaxOI`. The exchange is DoS'd until admin intervention."
    WIKI_RECOMMENDATION = "Branch on reduce-only at placement: if `order.reduceOnly == true`, skip the OI increment. On cancellation, only decrement OI by the portion that was accounted for on open. Unit-test every order-lifecycle path for OI-neutrality on reduce-only."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(quoteOI|baseOI|openInterest|OI)\\s*[+-]?='}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '(placeOrder|submitOrder|_addOrder|_insertOrder|matchOrder)'}, {'function.body_contains_regex': '(quoteOI|baseOI|openInterest)\\s*\\+=|increaseOI\\s*\\('}, {'function.body_not_contains_regex': 'reduceOnly|isReduceOnly|ReduceOnly|require\\s*\\(\\s*!\\w*reduceOnly'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — reduce-only-inflates-open-interest: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
