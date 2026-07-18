"""
uniswap-v3-oracle-negative-tick-rounding — generated from reference/patterns.dsl/uniswap-v3-oracle-negative-tick-rounding.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py uniswap-v3-oracle-negative-tick-rounding.yaml
Source: auditooor-R75-c4-lending-revert-lend-482
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UniswapV3OracleNegativeTickRounding(AbstractDetector):
    ARGUMENT = "uniswap-v3-oracle-negative-tick-rounding"
    HELP = "Uniswap V3 TWAP tick calculated as `delta / secondsAgo` without the Uniswap-reference negative-tick rounding fix (`if (delta < 0 && delta % secondsAgo != 0) tick--`). Price is inflated by ~1 tick for any pool in the negative-tick range, breaking LTV / liquidation math."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/uniswap-v3-oracle-negative-tick-rounding.yaml"
    WIKI_TITLE = "Uniswap V3 TWAP does not round negative ticks down"
    WIKI_DESCRIPTION = "Solidity integer division truncates toward zero. For a negative `tickCumulativesDelta`, division by `secondsAgo` with a non-zero remainder yields a tick larger (less negative) than the true TWAP tick. `sqrtPriceX96 = TickMath.getSqrtRatioAtTick(tick)` then returns a price biased upward by ~1 tick (~0.01%). In Uniswap's own OracleLibrary, the reference code explicitly decrements the tick in that ca"
    WIKI_EXPLOIT_SCENARIO = "Attacker observes protocol uses an in-house Uniswap V3 TWAP for collateral valuation. In a WETH/USDC pool the arithmetic-mean tick is ~-201240 with a non-zero remainder. Protocol's oracle reports tick=-201240 instead of -201241, over-valuing WETH by ~1 bp. Attacker repeatedly borrows up to the inflated LTV; across many positions the protocol accrues bad debt equal to the cumulative bias."
    WIKI_RECOMMENDATION = "Copy Uniswap's reference implementation exactly: `int24 tick = int24(tickCumulativesDelta / int56(uint56(secondsAgo))); if (tickCumulativesDelta < 0 && (tickCumulativesDelta % int56(uint56(secondsAgo)) != 0)) tick--;`. Or just use `OracleLibrary.consult` / `getQuoteAtTick` from uniswap-v3-periphery "

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(TickMath\\.getSqrtRatioAtTick|tickCumulatives|IUniswapV3Pool.*observe)'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '(?i)(twap|_?getReferencePool|_?getTwap|consult|getQuoteAtTick|_?getPoolPrice|getSqrtPrice)'}, {'function.body_contains_regex': '(?i)tickCumulatives\\s*\\[\\s*0\\s*\\]\\s*-\\s*tickCumulatives\\s*\\[\\s*1\\s*\\]|tickCumulatives\\s*\\[\\s*1\\s*\\]\\s*-\\s*tickCumulatives\\s*\\[\\s*0\\s*\\]'}, {'function.body_contains_regex': '(?i)int24\\s*\\(\\s*.*?\\s*/\\s*int(56|32)\\s*\\('}, {'function.body_not_contains_regex': '(?i)%\\s*int(56|32)?\\s*\\([^)]*\\)\\s*!=\\s*0|tickCumulativesDelta\\s*<\\s*0\\s*&&.*%.*!=\\s*0|if\\s*\\(.*tickCumulativesDelta\\s*<\\s*0.*\\)\\s*\\{?\\s*(arithmeticMeanTick|tick)\\s*--'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — uniswap-v3-oracle-negative-tick-rounding: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
