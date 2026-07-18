"""
glider-curve-get-p-spot-price-oracle — generated from reference/patterns.dsl/glider-curve-get-p-spot-price-oracle.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-curve-get-p-spot-price-oracle.yaml
Source: glider-docs/uwulend-curve-get_p-spot-price-oracle
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderCurveGetPSpotPriceOracle(AbstractDetector):
    ARGUMENT = "glider-curve-get-p-spot-price-oracle"
    HELP = "Price oracle reads Curve `get_p()` spot price and returns it (or a median including it) as the asset price. `get_p` is a single-block spot reading and is flash-loan manipulable — UwuLend lost ~$20M via exactly this pattern."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-curve-get-p-spot-price-oracle.yaml"
    WIKI_TITLE = "Curve `get_p()` used as price feed — flash-loan manipulable"
    WIKI_DESCRIPTION = "Curve pools expose a `get_p(uint256)` function returning the instantaneous spot price of a token in the pool. Because the value is a single-block reading of pool reserves, a flash loan can push reserves in either direction within the same tx, shifting `get_p` enough that a lending protocol relying on it will mis-price collateral and let the attacker over-borrow. UwuLend was drained in June 2024 vi"
    WIKI_EXPLOIT_SCENARIO = "Lending market uses `PriceProvider.getPrice()` which returns a median over several feeds, one of which is `FRAX_POOL.get_p(0) * FRAX_USD_PRICE`. Attacker flash-borrows 20M FRAX, dumps it into the Curve USDe/FRAX pool shifting reserves, calls `market.borrow(USDe_collateral=small, debt=huge)` while the median inflates, then unwinds the flash loan and walks with the debt."
    WIKI_RECOMMENDATION = "Never use `get_p()` as an oracle input. Use Curve's `price_oracle()` (the EMA / moving-average variant which Curve specifically built for oracle consumers), pair it with a Chainlink / Pyth sanity feed, and bound the deviation. For lending markets always prefer TWAP of at least 30 minutes over any si"

    _PRECONDITIONS = [{'contract.source_matches_regex': '\\.get_p\\s*\\('}, {'contract.has_function_matching': '(?i)^(getPrice|latestAnswer|peek|price|priceOf|assetPrice|getAssetPrice)$'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)^(getPrice|latestAnswer|peek|price|priceOf|assetPrice|getAssetPrice|_getPrices?|_getUSDe|_getPair)'}, {'function.body_contains_regex': '\\.get_p\\s*\\('}, {'function.body_not_contains_regex': 'latestRoundData|consult\\s*\\(|observe\\s*\\(|TWAP|AggregatorV3Interface'}, {'function.not_leaf_helper': True}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-curve-get-p-spot-price-oracle: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
