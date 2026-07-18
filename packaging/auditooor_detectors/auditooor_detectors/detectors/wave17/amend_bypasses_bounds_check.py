"""
amend-bypasses-bounds-check — generated from reference/patterns.dsl/amend-bypasses-bounds-check.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py amend-bypasses-bounds-check.yaml
Source: solodit-novel/slice_ae-GTE-CLOB
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AmendBypassesBoundsCheck(AbstractDetector):
    ARGUMENT = "amend-bypasses-bounds-check"
    HELP = "Order `amend*` function modifies price without invoking the bounds validator (e.g. `assertLimitPriceInBounds`) that the initial `place*` path uses. Users can amend orders outside the allowed price range."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/amend-bypasses-bounds-check.yaml"
    WIKI_TITLE = "Order amend bypasses limit-price bounds check"
    WIKI_DESCRIPTION = "A CLOB/DEX defines `assertLimitPriceInBounds(price)` used by `placeOrder`. The corresponding `amendOrder` forgets to call it, so the user can reprice an active order outside the bounds (e.g. far below floor to front-run a taker)."
    WIKI_EXPLOIT_SCENARIO = "Attacker places a normal limit buy. After a whale sell hits the book, attacker amends price to an out-of-bounds value that `placeOrder` would reject, picking up the fill at a price no legitimate placer could have quoted."
    WIKI_RECOMMENDATION = "Factor bounds check into an internal helper that both placeOrder and amendOrder (and any future path) invoke unconditionally."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_body_matching': 'assertLimitPriceInBounds|_checkPriceBounds|_validatePrice|assertBounds'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(amend|modifyOrder|updateOrder|editOrder|reprice)'}, {'function.has_param_name_matching': 'price|newPrice|limitPrice'}, {'function.writes_storage_matching': '.*'}, {'function.body_not_contains_regex': 'assertLimitPriceInBounds|_checkPriceBounds|_validatePrice|assertBounds'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — amend-bypasses-bounds-check: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
