"""
a-non-zero-discount-prevents-all-purchases-of-cards — generated from reference/patterns.dsl/a-non-zero-discount-prevents-all-purchases-of-cards.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py a-non-zero-discount-prevents-all-purchases-of-cards.yaml
Source: Solodit
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ANonZeroDiscountPreventsAllPurchasesOfCards(AbstractDetector):
    ARGUMENT = "a-non-zero-discount-prevents-all-purchases-of-cards"
    HELP = "A Non-Zero Discount Prevents All Purchases Of Cards"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/a-non-zero-discount-prevents-all-purchases-of-cards.yaml"
    WIKI_TITLE = "A Non-Zero Discount Prevents All Purchases Of Cards"
    WIKI_DESCRIPTION = "The `getAllocations()` function on line [60] calculates the allocation percentage of the vault and referrer. On line [66] of the Processor, the `vaultPercentage` variable is calculated using both `discount` and `refer`. However, `discount` is not factored into the require statement o"
    WIKI_EXPLOIT_SCENARIO = "Per Solodit #19402: ## Description\n\nThe `getAllocations()` function on line [60] calculates the allocation percentage of the vault and referrer. On line [66] of the Processor, the `vaultPercentage` variable is calculated"
    WIKI_RECOMMENDATION = "See source audit report for recommended fix."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.name_matches': '.*(getAllocations|vaultPercentage|discount|refer).*'}, {'function.writes_state_var_matching_regex': '.*(discount|discountedTotal|getAllocations).*'}, {'function.body_contains_regex': '.*'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*.*(discount|discountedTotal|getAllocations).*'}, {'function.not_in_skip_list': True}]

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
                info = [f, f" — a-non-zero-discount-prevents-all-purchases-of-cards: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
