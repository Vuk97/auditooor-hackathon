"""
multi-oracle-aggregator-reverts-on-divergence-no-fallback — generated from reference/patterns.dsl/multi-oracle-aggregator-reverts-on-divergence-no-fallback.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py multi-oracle-aggregator-reverts-on-divergence-no-fallback.yaml
Source: lisa-mine-r99-case-05242-c4-salty-2024-01
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class MultiOracleAggregatorRevertsOnDivergenceNoFallback(AbstractDetector):
    ARGUMENT = "multi-oracle-aggregator-reverts-on-divergence-no-fallback"
    HELP = "Multi-oracle aggregator (typically Chainlink + Uniswap TWAP + on-chain spot) returns the average of the closest two feeds, but reverts when no two feeds are within `maximumPriceFeedPercentDifference`. During genuine market dislocations (depegs, exchange outages, flash-crashes), real-world prices DO "
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/multi-oracle-aggregator-reverts-on-divergence-no-fallback.yaml"
    WIKI_TITLE = "Multi-feed price aggregator reverts on divergence with no fallback / grace path"
    WIKI_DESCRIPTION = "Pattern fires on price-aggregator entry points that consult three oracles, attempt to find the closest two, and revert when the closest pair's relative difference exceeds a threshold (`maximumPriceFeedPercentDifferenceTimes1000`). The function exposes no `fallbackOracle`, no last-valid-price cache, no grace-period TWAP-widening, and no graceful zero-return — every consumer that calls into it inher"
    WIKI_EXPLOIT_SCENARIO = "Salty's PriceAggregator queries Chainlink ETH/USD, Uni TWAP ETH/USDC, and the Salty BTC/ETH pool's implied USD price. During the May 2024 brief Coinbase outage, Chainlink lagged by 90 seconds, Uni TWAP smoothed an extreme tick, and Salty's pool drifted 4%. All three pairwise diffs exceed the 3% `maximumPriceFeedPercentDifference` threshold; aggregator reverts. Borrow function reverts. Liquidation "
    WIKI_RECOMMENDATION = "Provide a layered fallback: (1) if all three feeds agree within the tight threshold, return the median; (2) if only two agree within a wider threshold (e.g. 5%), return that pair's mean and emit `DegradedPrice`; (3) if no two agree, return the last-valid-price cached in storage along with its timest"

    _PRECONDITIONS = [{'contract.has_function_matching': 'getPrice|fetchPrice|aggregatePrice|priceFor'}, {'contract.source_matches_regex': 'maximumPriceFeedPercentDifference|priceFeedDifference|maxDeviation|maxPriceDelta|closestTwoPrices|threeOracle'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(getPrice|fetchPrice|aggregatePrice|priceFor|getLatestPrice)$'}, {'function.body_contains_regex': 'closestTwoPrices|maximumPriceFeedPercentDifference|priceFeedPercentDifference|threeFeed|aggregate3Feeds|priceDelta\\s*>\\s*max'}, {'function.body_contains_regex': '\\brevert\\b|require\\s*\\(\\s*[^,)]+,\\s*"|\\.revert\\s*\\('}, {'function.body_not_contains_regex': 'fallbackOracle|backupFeed|gracePeriod|emergencyPrice|stalePriceFallback|return\\s+lastValidPrice|return\\s+0\\s*;'}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — multi-oracle-aggregator-reverts-on-divergence-no-fallback: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
