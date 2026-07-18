"""
concentrated-liquidity-checked-shlw-overflow-narrow-tick-range — generated from reference/patterns.dsl/concentrated-liquidity-checked-shlw-overflow-narrow-tick-range.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py concentrated-liquidity-checked-shlw-overflow-narrow-tick-range.yaml
Source: auditooor-R76-rekt-cetus-2025
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ConcentratedLiquidityCheckedShlwOverflowNarrowTickRange(AbstractDetector):
    ARGUMENT = "concentrated-liquidity-checked-shlw-overflow-narrow-tick-range"
    HELP = "Concentrated-liquidity math uses a left-shift / fixed-point scaling that overflows for very narrow tick ranges. No explicit minimum-tick-delta guard means a 1-wei input mints 10^34 liquidity."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/concentrated-liquidity-checked-shlw-overflow-narrow-tick-range.yaml"
    WIKI_TITLE = "Liquidity-from-amount math overflows for narrow tick ranges, minting phantom liquidity"
    WIKI_DESCRIPTION = "Concentrated-liquidity protocols (Uniswap V3, Cetus, Balancer CL) compute liquidity as `L = amount0 / (1/sqrtPriceA - 1/sqrtPriceB)` or similar, using fixed-point scaling like Q96. When the tick range is very narrow, the denominator approaches zero; intermediate left-shifts can silently wrap. If the overflow-check helper (e.g. `checked_shlw` in Move / `mulDiv` in Solidity) has edge-case bugs for n"
    WIKI_EXPLOIT_SCENARIO = "Attacker flash-loans 56,700 SUI. Calls `openPosition(tickLower=300000, tickUpper=300200, amount0=1, amount1=0)`. Internal math: `deltaSqrt = sqrtPriceAtTick(300200) - sqrtPriceAtTick(300000)` is tiny. `L = amount0 * sqrtPriceA * sqrtPriceB / deltaSqrt` overflows via intermediate shift. Resulting `L` is 10^34. Protocol records attacker's liquidity as 10^34 units. Attacker withdraws against this, ex"
    WIKI_RECOMMENDATION = "Enforce a minimum tick-range width: `require(tickUpper - tickLower >= MIN_TICK_SPACING, 'range too narrow');` where MIN_TICK_SPACING is large enough that the denominator cannot underflow in any code path. Use 512-bit intermediates (`FullMath.mulDiv`) for all narrow-range fixed-point arithmetic and a"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, 'Concentrated-liquidity math computes liquidity from amount0/amount1 across a tick range using an intermediate scaled / shifted intermediate that can overflow for narrow ranges.']
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)get[Ll]iquidityFrom(A|Amount0|Amount1)|computeLiquidityFrom|mintLiquidity|addLiquidity|openPosition|increaseLiquidity'}, {'function.body_contains_regex': '(?i)shlw|shl\\s*\\(|<<\\s*\\d+|Q96|Q128|mulDiv|sqrtPriceA\\s*-\\s*sqrtPriceB|deltaSqrtPrice'}, {'function.body_not_contains_regex': '(?i)require\\s*\\(\\s*(sqrtPriceAX|sqrtPriceA)\\s*-\\s*(sqrtPriceBX|sqrtPriceB)\\s*>=?\\s*MIN_PRICE_DELTA|require\\s*\\([^;]*tickUpper\\s*-\\s*tickLower\\s*>=?\\s*MIN_TICK_SPACING|narrowRangeGuard|checkMinPriceDelta'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — concentrated-liquidity-checked-shlw-overflow-narrow-tick-range: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
