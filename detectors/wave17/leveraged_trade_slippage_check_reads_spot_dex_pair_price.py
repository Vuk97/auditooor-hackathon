"""
leveraged-trade-slippage-check-reads-spot-dex-pair-price — generated from reference/patterns.dsl/leveraged-trade-slippage-check-reads-spot-dex-pair-price.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py leveraged-trade-slippage-check-reads-spot-dex-pair-price.yaml
Source: auditooor-R76-rekt-vee-finance-2021
"""

# NOT_SUBMIT_READY: fixture-smoke/source-shape proof only for this row.

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class LeveragedTradeSlippageCheckReadsSpotDexPairPrice(AbstractDetector):
    ARGUMENT = "leveraged-trade-slippage-check-reads-spot-dex-pair-price"
    HELP = "Leveraged-trade open path sources its slippage-check price from spot AMM reserves on a pool whose identity is not whitelisted. Attackers spin up a fresh pool and feed it any price they want."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/leveraged-trade-slippage-check-reads-spot-dex-pair-price.yaml"
    WIKI_TITLE = "Leverage open uses spot AMM pool price with no whitelist or TWAP; slippage check is toothless"
    WIKI_DESCRIPTION = "In margin / leveraged DEXes, the `open` function must compute a price and verify the user's `minAmountOut` against it. If the price source is a spot Uniswap-V2-style pool whose identity is passed in calldata (or resolved from the asset address via a factory `getPair` that returns ANY pair with the right tokens), an attacker can pre-create a low-liquidity pool for their asset, seed it with a manipu"
    WIKI_EXPLOIT_SCENARIO = "Attacker deploys a fresh Pangolin pair for MANIP/USDC with reserves 1 MANIP + 1000 USDC (price = 1000). Calls `VeeFinance.openLong(MANIP, collateral=10 USDC, leverage=10x, minAmountOut=0)`. VeeFinance reads the pair's spot ratio, sees MANIP = 1000 USDC, borrows 90 USDC against 10 USDC collateral, swaps 100 USDC into 0.1 MANIP at the inflated rate. Position opens. Attacker then dumps their real MAN"
    WIKI_RECOMMENDATION = "Source the open-price from a Chainlink / Pyth / high-liquidity TWAP, never a spot DEX pool. Maintain a registry of allowed trading pairs whose liquidity depth exceeds a minimum. Ensure decimal conversion is consistent between price read and slippage check (a common secondary bug at Vee Finance). Add"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, "Leveraged trade / perp-open function computes `minAmountOut` / slippage bound from a spot AMM pool's reserves at call time."]
    _MATCH = [{'function.kind': 'external'}, {'function.name_matches': '(?i)openLeveragedTrade|openPosition|openLeverage|leverageSwap|marginOpen|openLong|openShort'}, {'function.body_contains_regex': '(?i)IUniswapV2Pair|IPangolinPair|getReserves\\s*\\(\\s*\\)|pair\\.token0|pair\\.token1'}, {'function.body_not_contains_regex': '(?i)chainlink|AggregatorV3|twap|observe\\(|cumulativePrice|deviation|isWhitelistedPair|registry\\.isApprovedPool'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — leveraged-trade-slippage-check-reads-spot-dex-pair-price: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
