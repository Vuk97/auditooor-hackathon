"""
concentrated-liquidity-cross-tick-double-counts-liquidity-at-boundary — generated from reference/patterns.dsl/concentrated-liquidity-cross-tick-double-counts-liquidity-at-boundary.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py concentrated-liquidity-cross-tick-double-counts-liquidity-at-boundary.yaml
Source: auditooor-R76-rekt-kyberswap-2023
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ConcentratedLiquidityCrossTickDoubleCountsLiquidityAtBoundary(AbstractDetector):
    ARGUMENT = "concentrated-liquidity-cross-tick-double-counts-liquidity-at-boundary"
    HELP = "Concentrated-liquidity swap step applies tick-cross `liquidityNet` without verifying that the step actually crossed the boundary strictly. A swap that ends exactly at the boundary can trigger the cross twice, double-counting the tick's liquidity."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/concentrated-liquidity-cross-tick-double-counts-liquidity-at-boundary.yaml"
    WIKI_TITLE = "Concentrated-liquidity swap double-counts cross-tick liquidity at exact sqrtPrice boundary"
    WIKI_DESCRIPTION = "Uniswap-V3-style concentrated liquidity pools advance `sqrtPrice` through a swap loop, calling `crossTick(tickNext)` to add/subtract `liquidityNet` each time the price crosses a tick boundary. If the swap step produces a `sqrtPriceAfter` equal to `sqrtPriceAtTick(tickNext)` (edge case), and the loop then begins a new iteration that re-targets the same tick, `crossTick` can be invoked twice for the"
    WIKI_EXPLOIT_SCENARIO = "Attacker takes a flash loan, computes the exact input amount required to end the swap step at `sqrtPriceAfter == sqrtPriceAtTick(tickNext)`. Calls `swap(..., amountSpecified, sqrtPriceLimit)`. First loop iteration crosses tickNext and applies `liquidityNet[tickNext]`. The `sqrtPriceAfter == target` state, combined with a stale `computedTarget`, causes the NEXT iteration to treat tickNext as yet-to"
    WIKI_RECOMMENDATION = "Add an explicit guard in the swap loop: track `alreadyCrossedAtPrice[tickNext]` and require it is only crossed once per swap. Alternatively, ensure `state.sqrtPrice` is strictly less/greater than `sqrtPriceAtTick(tickNext)` (never equal) when registering a cross — round the step result away from the"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, 'Concentrated-liquidity AMM swap function crosses ticks in a loop, applying `liquidityNet` deltas as it moves.']
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)^swap$|computeSwapStep|_swap$|swapQty|exactInput|exactOutput'}, {'function.body_contains_regex': '(?i)liquidityNet|crossTick|tickList\\[tickNext\\]|sqrtPriceTargetQ|nextTickCross|liquidityDelta'}, {'function.body_not_contains_regex': '(?i)require\\s*\\(\\s*sqrtPriceAfter\\s*!=\\s*sqrtPriceAtTick|alreadyCrossed\\[tickNext\\]|require\\s*\\([^;]*state\\.sqrtPrice\\s*!=\\s*sqrtPriceTarget|uniqueCrossGuard'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — concentrated-liquidity-cross-tick-double-counts-liquidity-at-boundary: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
