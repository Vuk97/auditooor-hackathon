"""
c4-lambo-hardcoded-sqrt-price-limit — generated from reference/patterns.dsl/c4-lambo-hardcoded-sqrt-price-limit.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py c4-lambo-hardcoded-sqrt-price-limit.yaml
Source: code4arena/2024-12-lambowin-M05
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class C4LamboHardcodedSqrtPriceLimit(AbstractDetector):
    ARGUMENT = "c4-lambo-hardcoded-sqrt-price-limit"
    HELP = "Uniswap V3 swap hardcodes sqrtPriceLimitX96 to TickMath bounds — users swept to worst price."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/c4-lambo-hardcoded-sqrt-price-limit.yaml"
    WIKI_TITLE = "Hardcoded sqrtPriceLimitX96 = TickMath bound"
    WIKI_DESCRIPTION = "Passing `sqrtPriceLimitX96 = MIN_SQRT_RATIO + 1` (or `MAX - 1`) disables V3's price-limit slippage protection. A sandwich or thin-pool attack can push price all the way to the tick bound before the swap completes, exacting maximum value from the user."
    WIKI_EXPLOIT_SCENARIO = "Lambo.win C4-2024-12 M-05: `Rebalance` called `swapRouter.exactInputSingle` with `sqrtPriceLimitX96 = 0` (interpreted as no limit). Attacker sandwiched with a flashloan, rebalance paid worst-case price, protocol lost bps-scale value per rebalance."
    WIKI_RECOMMENDATION = "Compute `sqrtPriceLimitX96` from the expected price ± max-slippage tolerance, or pair with a `minOut` check that aborts before reaching tick bounds."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'ISwapRouter|IUniswapV3Pool|sqrtPriceLimitX96|uniswapV3'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'sqrtPriceLimitX96\\s*:\\s*(0|TickMath\\.MIN|TickMath\\.MAX|4295128740|1461446703485210103287273052203988822378723970342)'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — c4-lambo-hardcoded-sqrt-price-limit: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
