"""
ec-spot-price-used-as-oracle — generated from reference/patterns.dsl/ec-spot-price-used-as-oracle.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py ec-spot-price-used-as-oracle.yaml
Source: economic-mining-R61
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class EcSpotPriceUsedAsOracle(AbstractDetector):
    ARGUMENT = "ec-spot-price-used-as-oracle"
    HELP = "AMM spot price derived from getReserves() used directly for collateral/loan valuation without TWAP protection — manipulable via flashloan in a single transaction."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/ec-spot-price-used-as-oracle.yaml"
    WIKI_TITLE = "AMM spot price (getReserves) used as valuation oracle — no TWAP"
    WIKI_DESCRIPTION = "The contract reads raw reserve values from a Uniswap V2-compatible AMM pair and computes a price ratio for collateral valuation or liquidation logic. Spot prices from constant-product AMMs can be moved arbitrarily within a single transaction via flashloans. This enables single-block borrow/drain attacks."
    WIKI_EXPLOIT_SCENARIO = "Lending protocol calls IUniswapV2Pair.getReserves() and computes tokenPrice = reserve1/reserve0. Attacker flashloans reserve1, dumps into pool to inflate reserve0, calls borrow() against inflated collateral price, repays flashloan from borrowed funds."
    WIKI_RECOMMENDATION = "Replace spot-price reads with a TWAP oracle (Uniswap V3 observe(), Chainlink, or Pyth). If AMM reserves must be read, apply a minimum-blocks-elapsed guard and take the geometric mean over multiple snapshots. Never use a single getReserves() call for price-sensitive operations."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'getReserves|reserve0|reserve1|token0|token1'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'getReserves\\(\\)|reserve0|reserve1|_reserve0|_reserve1'}, {'function.body_contains_regex': 'reserve[01]\\s*/\\s*reserve[01]|price\\s*=.*reserve|amount.*\\*.*reserve'}, {'function.body_contains_regex': 'collateral|borrow|liquidat|value|worth|price'}, {'function.body_not_contains_regex': 'twap|TWAP|cumulative|observe|consult|timeWeighted'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — ec-spot-price-used-as-oracle: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
