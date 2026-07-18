"""
in-stable2lut1-getratiosfrompriceliquidity-in-extreme-cases-x — generated from reference/patterns.dsl/in-stable2lut1-getratiosfrompriceliquidity-in-extreme-cases-x.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py in-stable2lut1-getratiosfrompriceliquidity-in-extreme-cases-x.yaml
Source: code4arena audit 2024-07-basin
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class InStable2lut1GetratiosfrompriceliquidityInExtremeCasesX(AbstractDetector):
    ARGUMENT = "in-stable2lut1-getratiosfrompriceliquidity-in-extreme-cases-x"
    HELP = "Stable2LUT1 getRatiosFromPriceLiquidity contains the documented extreme-price literal branch that can make updateReserve fail."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/in-stable2lut1-getratiosfrompriceliquidity-in-extreme-cases-x.yaml"
    WIKI_TITLE = "In Stable2LUT1::getRatiosFromPriceLiquidity, extreme cases can break updateReserve"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof for the direct Basin Stable2LUT1 getRatiosFromPriceLiquidity branch containing the low-price guard and PriceData tuple from the audit text. NOT_SUBMIT_READY."
    WIKI_EXPLOIT_SCENARIO = "Stable2LUT1 getRatiosFromPriceLiquidity contains the documented extreme-price literal branch that can make updateReserve fail."
    WIKI_RECOMMENDATION = "Do not promote from this fixture smoke alone. Validate the full reserve convergence invariant before submission."

    _PRECONDITIONS = []
    _MATCH = [{'function.name': 'getRatiosFromPriceLiquidity'}, {'function.source_contains_all': ['if (price < 0.001083e6)', 'revert("LUT: Invalid price")', 'PriceData(', '0.27702e6', '9.646293093274934449e18', '2000e18']}]

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
                info = [f, f" — in-stable2lut1-getratiosfrompriceliquidity-in-extreme-cases-x: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
