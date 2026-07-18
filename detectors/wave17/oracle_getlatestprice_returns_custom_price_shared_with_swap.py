"""
oracle-getlatestprice-returns-custom-price-shared-with-swap — generated from reference/patterns.dsl/oracle-getlatestprice-returns-custom-price-shared-with-swap.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py oracle-getlatestprice-returns-custom-price-shared-with-swap.yaml
Source: lisa-mine-r99-case-01812-sherlock-gmx-2023-04
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OracleGetlatestpriceReturnsCustomPriceSharedWithSwap(AbstractDetector):
    ARGUMENT = "oracle-getlatestprice-returns-custom-price-shared-with-swap"
    HELP = "Oracle's `getLatestPrice` checks for a custom-price override (triggerPrice / maximizedPrice / orderExecutionPrice) and returns it ahead of the live oracle price. The same `getLatestPrice` is called from the swap path that runs AFTER an order executes — so the swap re-uses the order's bespoke executi"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/oracle-getlatestprice-returns-custom-price-shared-with-swap.yaml"
    WIKI_TITLE = "Oracle `getLatestPrice` returns custom-price override; reused by post-order swap"
    WIKI_DESCRIPTION = "Pattern fires on oracle wrappers whose `getLatestPrice` (or `getPrice`) returns a stored `customPrice` (set via `setCustomPrice` for order execution: trigger price for limit orders, maximized price for market orders) without distinguishing the caller's context. When the same oracle is queried by the post-order swap leg (e.g. `executeOrder` -> `swap output token through swapPath` -> `oracle.getLate"
    WIKI_EXPLOIT_SCENARIO = "User opens a market-increase position with a `swapPath` that converts the position's secondary collateral back to USDC after execution. `getLatestPrice` for the position-sizing leg returns the maximized price (so the user pays the worst price for opening). The post-execution swap calls the same `getLatestPrice`, gets the SAME maximized price, and converts the secondary token at a price more favour"
    WIKI_RECOMMENDATION = "Pass an explicit `Context` enum (or `bool isOrderExecution`) into `getLatestPrice` and only consult `customPrice` when the context is order-execution. Equivalently, scope custom prices via `_customPrices[orderId][token]` and `delete` them at the start of each swap leg; downstream `getLatestPrice` th"

    _PRECONDITIONS = [{'contract.has_function_matching': 'getLatestPrice|getCustomPrice|setCustomPrice'}, {'contract.has_function_matching': 'swap|_swap|executeSwap|executeOrder|fillOrder|positionExecute'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(getLatestPrice|_getLatestPrice|getPrice|_getPrice)$'}, {'function.body_contains_regex': '\\bcustomPrice|triggerPrice|maximizedPrice|orderExecutionPrice'}, {'function.body_contains_regex': '\\bif\\s*\\([^)]*customPrice|if\\s*\\([^)]*triggerPrice|customPrice\\s*\\.\\s*max|customPrice\\s*\\.\\s*min'}, {'function.body_not_contains_regex': 'context\\s*==\\s*Context\\.|isSwapContext|isLiveContext|onlyOrderExecution|delete\\s+customPrices|onlyForOrderExecution'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — oracle-getlatestprice-returns-custom-price-shared-with-swap: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
