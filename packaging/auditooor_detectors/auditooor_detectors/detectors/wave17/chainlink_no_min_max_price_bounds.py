"""
chainlink-no-min-max-price-bounds — generated from reference/patterns.dsl/chainlink-no-min-max-price-bounds.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py chainlink-no-min-max-price-bounds.yaml
Source: solodit-cluster-CL-MINMAX
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ChainlinkNoMinMaxPriceBounds(AbstractDetector):
    ARGUMENT = "chainlink-no-min-max-price-bounds"
    HELP = "Chainlink price feed consumed without validating the returned value against the aggregator's minAnswer / maxAnswer bounds. During a depeg or extreme market event the feed can stall at its minimum (or maximum), and consumers that do not reject the bounded value will keep transacting against a known-w"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/chainlink-no-min-max-price-bounds.yaml"
    WIKI_TITLE = "Chainlink consumer missing minAnswer / maxAnswer bound check"
    WIKI_DESCRIPTION = "Every Chainlink aggregator encodes a minAnswer and maxAnswer at deployment. When the real market price moves beyond those bounds the feed clamps at the boundary and keeps reporting it as the 'latest' answer. A classic example is LUNA's collapse: the LUNA/USD feed floored at minAnswer while LUNA traded orders of magnitude lower, so any protocol that used the feed without a bound check kept valuing "
    WIKI_EXPLOIT_SCENARIO = "An asset depegs or crashes below the feed's minAnswer. The Chainlink aggregator keeps reporting minAnswer. A lending market that consumes the feed without the bound check continues accepting the asset as full-value collateral; the attacker deposits the worthless asset, borrows against it at the clamped valuation, and walks away with the honest side of the market."
    WIKI_RECOMMENDATION = "After every `latestRoundData()` / `latestAnswer()` read, call the aggregator's `minAnswer()` and `maxAnswer()` (or their cached equivalents) and revert with a dedicated error if the returned price is `<= minAnswer` or `>= maxAnswer`. Pair with staleness checks (`updatedAt` freshness) and — on L2s — "

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': {'regex': 'latestRoundData\\s*\\(\\s*\\)|\\.latestAnswer\\s*\\(\\s*\\)'}}, {'function.body_not_contains_regex': 'minAnswer|maxAnswer|\\.minAnswer|\\.maxAnswer|IAggregator.*\\.min|IAggregator.*\\.max|price\\s*>\\s*\\w+MinPrice|price\\s*<\\s*\\w+MaxPrice'}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — chainlink-no-min-max-price-bounds: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
