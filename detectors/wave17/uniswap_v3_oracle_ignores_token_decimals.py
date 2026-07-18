"""
uniswap-v3-oracle-ignores-token-decimals — generated from reference/patterns.dsl/uniswap-v3-oracle-ignores-token-decimals.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py uniswap-v3-oracle-ignores-token-decimals.yaml
Source: auditooor-R75-c4-lending-revert-lend-490
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UniswapV3OracleIgnoresTokenDecimals(AbstractDetector):
    ARGUMENT = "uniswap-v3-oracle-ignores-token-decimals"
    HELP = "Pool price computed as sqrtPriceX96^2 / Q96 (or via getSqrtRatioAtTick) without normalizing by token0/token1 decimals. Prices between mismatched-decimal pairs are off by 10^(|d1-d0|), breaking LTV, liquidation, and oracle-health checks."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/uniswap-v3-oracle-ignores-token-decimals.yaml"
    WIKI_TITLE = "Uniswap V3 pool-price helper ignores token decimals"
    WIKI_DESCRIPTION = "`sqrtPriceX96` is the square root of the ratio of raw token1 units to raw token0 units. For a WETH/USDC pool at price $3000, that is `sqrt(3000 * 10^6 / 10^18) * 2^96` — the encoded price is ~3e-12, not 3000. A helper that returns `mulDiv(sqrtPriceX96, sqrtPriceX96, Q96)` without multiplying/dividing by `10^(decimals1 - decimals0)` is off by 12 orders of magnitude. Protocols that use this helper f"
    WIKI_EXPLOIT_SCENARIO = "Protocol uses helper P = mulDiv(sqrtPriceX96^2, 1, Q96) as the USD price of WETH in a USDC-quoted pool. Actual price is 3000 but helper returns ~3e-9. Collateral appears worthless → any attempt to deposit is under-valued → users cannot borrow. Reverse: if token0 is USDC and token1 is WETH, helper returns ~3e15, over-valuing USDC deposits by 10^12 and allowing a $1 deposit to back a $10^12 loan."
    WIKI_RECOMMENDATION = "Use Uniswap's `OracleLibrary.getQuoteAtTick(tick, baseAmount, baseToken, quoteToken)` which handles decimals internally. If computing manually, adjust: `price = (sqrtPriceX96^2 * 10^decimals0) / (Q96 * 10^decimals1)` for price-of-token0-in-token1, or vice versa, depending on ordering."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)IUniswapV3Pool|getSqrtRatioAtTick'}]
    _MATCH = [{'function.kind': 'internal_or_external'}, {'function.name_matches': '(?i)(_?getReferencePool|consult|getPoolPrice|getQuote|_?getSpotPrice|latestPrice)'}, {'function.body_contains_regex': '(?i)(FullMath\\.)?mulDiv\\s*\\(\\s*sqrtPriceX96\\s*,\\s*sqrtPriceX96\\s*,\\s*(Q96|uint256\\(2\\)\\*\\*192|1\\s*<<\\s*192|FixedPoint96)'}, {'function.body_not_contains_regex': '(?i)(decimals0|decimals1|token0\\.decimals|token1\\.decimals|10\\s*\\*\\*\\s*(decimals|_dec)|getQuoteAtTick)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — uniswap-v3-oracle-ignores-token-decimals: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
