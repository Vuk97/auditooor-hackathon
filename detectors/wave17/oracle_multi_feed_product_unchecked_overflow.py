"""
oracle-multi-feed-product-unchecked-overflow — generated from reference/patterns.dsl/oracle-multi-feed-product-unchecked-overflow.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py oracle-multi-feed-product-unchecked-overflow.yaml
Source: auditooor-R110-morpho-MorphoChainlinkOracleV2
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OracleMultiFeedProductUncheckedOverflow(AbstractDetector):
    ARGUMENT = "oracle-multi-feed-product-unchecked-overflow"
    HELP = "Oracle's `price()` view computes a chained product of independent feed prices (`getPrice() * getPrice() * ...`) before the outer `mulDiv`, exposing the inner multiplication to plain Solidity 0.8 checked-arithmetic uint256 overflow. With a legitimate combination of vault-conversion sample, feed decim"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/oracle-multi-feed-product-unchecked-overflow.yaml"
    WIKI_TITLE = "Oracle `price()` chained `getPrice() * getPrice() * ...` overflows on legitimate decimal combinations"
    WIKI_DESCRIPTION = "Morpho-Blue-style oracle adapters report `price()` by combining independent Chainlink-compliant feeds: `SCALE_FACTOR * (sample * basePrice1 * basePrice2) / (sample * quotePrice1 * quotePrice2)`. The outer `SCALE_FACTOR.mulDiv(num, den)` is OZ `Math.mulDiv` and uses a 512-bit intermediate, so it does NOT overflow. But the *inner* numerator and denominator are constructed by plain Solidity 0.8 `*` o"
    WIKI_EXPLOIT_SCENARIO = "WBTC / USDC market deployed on Morpho Blue uses `MorphoChainlinkOracleV2` with `BASE_VAULT = wstETH-vault`, `BASE_VAULT_CONVERSION_SAMPLE = 1e18`, `BASE_FEED_1 = wstETH/ETH (8-decimal)`, `BASE_FEED_2 = ETH/BTC (8-decimal)`. During a temporary feed-aggregator misconfiguration on a layer-2 chain, `BASE_FEED_1.getPrice()` returns `5e29` (mis-scaled). Inner numerator = `1e18 * 5e29 * 2.5e25 = 1.25e73`"
    WIKI_RECOMMENDATION = "Replace each chained `*` in `price()` with `mulDiv` against `1e18` (or the relevant scale): `uint256 baseNum = sample.mulDiv(basePrice1, 1e18).mulDiv(basePrice2, 1e18); uint256 quoteNum = sample.mulDiv(quotePrice1, 1e18).mulDiv(quotePrice2, 1e18); return SCALE_FACTOR.mulDiv(baseNum, quoteNum);`. The"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Oracle|PriceFeed|PriceRouter|ChainlinkOracle|FeedAggregator|MorphoChainlink'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(_?price|_?getPrice|_?latestPrice|_?spotPrice|_?fetchPrice|_?queryPrice)$'}, {'function.state_mutability': 'view'}, {'function.body_contains_regex': '\\.getPrice\\s*\\(\\s*\\)\\s*\\*\\s*\\w+\\.getPrice\\s*\\(\\s*\\)|\\.latestAnswer\\s*\\(\\s*\\)\\s*\\*\\s*\\w+\\.latestAnswer\\s*\\(\\s*\\)|\\bFEED_1\\b\\s*\\*\\s*\\b\\w*FEED_2\\b|getAssets\\s*\\([^)]*\\)\\s*\\*\\s*\\w+\\.getPrice\\s*\\(\\s*\\)'}, {'function.body_not_contains_regex': '\\.getPrice\\s*\\(\\s*\\)\\s*\\)\\s*\\.mulDiv\\s*\\(|\\.mulDiv\\s*\\(\\s*\\w+\\.getPrice\\s*\\(\\s*\\)\\s*,|\\.mulDiv\\s*\\([^()]*\\)\\.mulDiv\\s*\\([^()]*getPrice'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — oracle-multi-feed-product-unchecked-overflow: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
