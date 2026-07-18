"""
fx-euler-max-liq-discount-full-scale — generated from reference/patterns.dsl/fx-euler-max-liq-discount-full-scale.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py fx-euler-max-liq-discount-full-scale.yaml
Source: github:euler-xyz/euler-vault-kit@3f9468d
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class FxEulerMaxLiqDiscountFullScale(AbstractDetector):
    ARGUMENT = "fx-euler-max-liq-discount-full-scale"
    HELP = "setMaxLiquidationDiscount() does not reject the value CONFIG_SCALE (1e4 = 100%). A 100% discount causes division by zero in the liquidation discount calculation: denominator = CONFIG_SCALE - discount = 0."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/fx-euler-max-liq-discount-full-scale.yaml"
    WIKI_TITLE = "setMaxLiquidationDiscount allows 100% discount — governance-triggered division-by-zero in liquidation"
    WIKI_DESCRIPTION = "Liquidation modules that compute bonus collateral as `collateral * discount / (CONFIG_SCALE - discount)` will divide by zero if maxLiquidationDiscount equals CONFIG_SCALE (10000 = 100%). A governance or admin call to setMaxLiquidationDiscount(10000) permanently bricks all liquidations until the parameter is changed back."
    WIKI_EXPLOIT_SCENARIO = "Euler Cantina-520 (2024): governance sets maxLiquidationDiscount = CONFIG_SCALE. All subsequent liquidation calls compute denominator = 1e4 - 1e4 = 0 and revert with a division-by-zero panic, preventing bad-debt resolution."
    WIKI_RECOMMENDATION = "Add `if (newDiscount == CONFIG_SCALE) revert E_BadMaxLiquidationDiscount()` at the start of setMaxLiquidationDiscount. Optionally also enforce newDiscount < CONFIG_SCALE as a strict upper bound."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_function_matching': '^setMaxLiquidationDiscount$'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^setMaxLiquidationDiscount$'}, {'function.body_not_contains_regex': '== CONFIG_SCALE|== 1e4|== 10000|maxLiquidationDiscount.*revert'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — fx-euler-max-liq-discount-full-scale: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
