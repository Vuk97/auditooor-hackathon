"""
univ4-hook-midpoint-average-not-time-weighted-integral — generated from reference/patterns.dsl/univ4-hook-midpoint-average-not-time-weighted-integral.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py univ4-hook-midpoint-average-not-time-weighted-integral.yaml
Source: defimon-2026-04/zoo-finance-univ4-hook-27K
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class Univ4HookMidpointAverageNotTimeWeightedIntegral(AbstractDetector):
    ARGUMENT = "univ4-hook-midpoint-average-not-time-weighted-integral"
    HELP = "UniswapV4 hook aggregates a price-derived quantity over the swap's traversed range using arithmetic mean of two endpoints rather than the curve's integral. Systematic bias is harvestable by chained small swaps."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/univ4-hook-midpoint-average-not-time-weighted-integral.yaml"
    WIKI_TITLE = "UniV4 hook uses (start+end)/2 endpoint-average instead of integrating sqrt-price curve"
    WIKI_DESCRIPTION = "UniswapV4 hooks frequently need to aggregate a fee-growth, accrual, or price-tracking quantity over the price range a swap traversed. Because the v4 swap curve is `liquidity / sqrt(P)`, NOT linear in P, the arithmetic mean of two endpoints diverges systematically from the true integral; the gap grows quadratically with the range width and accumulates over many swaps. An attacker who can split a sw"
    WIKI_EXPLOIT_SCENARIO = "Zoo Finance March 2026: hook's `_calcFee` averaged `sqrtPriceBefore` and `sqrtPriceAfter` to produce a per-swap fee bucket, then split that bucket among LPs. Attacker chained 20+ near-zero-impact swaps; on each, the (start+end)/2 average produced a fee-owed quote slightly higher than the true integral. Repeated harvest accumulated 17,560 REPPO + 17,681 vREPPO before detection."
    WIKI_RECOMMENDATION = "Use Uniswap's `SwapMath.computeSwapStep` or `SqrtPriceMath` library to walk the actual price curve, OR use a known closed-form for the integral over the swap range (for v3-style fee growth this is `liquidity * (sqrt_end - sqrt_start)`). Property test: for any swap that crosses N ticks, the hook's fe"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(IHooks|UniswapV4|v4|PoolKey|BalanceDelta|beforeSwap|afterSwap|hook|sqrtPriceX96)'}]
    _MATCH = [{'function.kind': 'any'}, {'function.name_matches': '(?i)^(beforeSwap|afterSwap|_beforeSwap|_afterSwap|_swapHook|_accrueFee|_accrueGrowth|_settleFee|_calcFee|_priceAccumulator|_avgPrice|_quotePrice)\\w*$'}, {'function.body_contains_regex': '(sqrtPriceX96Before|sqrtPriceX96After|priceBefore|priceAfter|sqrtBefore|sqrtAfter|p0|p1|start|end)'}, {'function.body_contains_regex': '\\(\\s*\\w+\\s*\\+\\s*\\w+\\s*\\)\\s*[/]\\s*2|\\(\\s*\\w+\\s*\\+\\s*\\w+\\s*\\)\\s*>>\\s*1|Math\\.average\\s*\\(|FixedPointMathLib\\.average\\s*\\(|_avg\\s*\\(|geometricMean\\s*\\('}, {'function.body_not_contains_regex': 'SwapMath\\.computeSwapStep|SqrtPriceMath\\.getAmount|FullMath\\.mulDiv\\s*\\([^)]*sqrt|integratePriceCurve|_iterateTicks|while\\s*\\([^)]*tick'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

    _INCLUDE_LEAF_HELPERS = True
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
                info = [f, f" — univ4-hook-midpoint-average-not-time-weighted-integral: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
