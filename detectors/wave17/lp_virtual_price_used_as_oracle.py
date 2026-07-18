"""
lp-virtual-price-used-as-oracle — generated from reference/patterns.dsl/lp-virtual-price-used-as-oracle.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py lp-virtual-price-used-as-oracle.yaml
Source: defihacklabs/Makina-2026-01+Woofi-2024-03+UwuLend-2024-06
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LpVirtualPriceUsedAsOracle(AbstractDetector):
    ARGUMENT = "lp-virtual-price-used-as-oracle"
    HELP = "Oracle reads Curve `get_virtual_price` or Uniswap `getReserves` as spot price with no TWAP. Flashloan-inflated pool lets attacker borrow against inflated collateral."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/lp-virtual-price-used-as-oracle.yaml"
    WIKI_TITLE = "LP virtual price used as oracle without TWAP"
    WIKI_DESCRIPTION = "`get_virtual_price` and `getReserves` reflect the instantaneous invariant of a pool and are cheap to move with a large swap. Using either directly as a collateral price oracle is flashloan-manipulable: attacker takes a flashloan, distorts the pool, borrows against inflated collateral, reverts the pool, repays flashloan, walks with the debt."
    WIKI_EXPLOIT_SCENARIO = "Makina Caliber 2026-01: `Caliber.valueOf(dusdLP)` returned `curvePool.get_virtual_price() * balance / 1e18`. Attacker flashloaned USDC, imbalanced DUSD/USDC 3pool, then borrowed 5.1M worth against inflated DUSD LP value, then reversed the imbalance and repaid flashloan. Similar for Uniswap-reserve pricing: Woofi, UwuLend (via Bunni), Polter, Shezmu, Bedrock."
    WIKI_RECOMMENDATION = "Never price LP tokens at spot. Use a canonical TWAP (Uniswap V3 `observe`, Curve EMA oracle where available) or compute the minimum of (spot, Chainlink aggregate) with a max-deviation cap. For Curve stableswap LPs, prefer a bespoke fair-price formula that derives reserves from external price feeds."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'ICurvePool|get_virtual_price|ISwapRouter|getReserves|IUniV2Pair|IUniswapV2Pair|ICurveStableSwap'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.state_mutability': 'view'}, {'function.name_matches': '^(getPrice|price|latestAnswer|getLatest|fetchPrice|getAssetPrice|getExchangeRate|getValue|valuate|valuationOf|getTokenPrice)[A-Z_]?|^(getPrice|price|latestAnswer|getValue)$'}, {'function.body_contains_regex': 'get_virtual_price|getReserves\\s*\\('}, {'function.body_not_contains_regex': 'twap|TWAP|observe\\s*\\(|priceCumulative|ema|EMA|timeWeighted'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — lp-virtual-price-used-as-oracle: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
