"""
oracle-decimal-mis-scaling-hardcoded-scale-without-feed-decimals — generated from reference/patterns.dsl/oracle-decimal-mis-scaling-hardcoded-scale-without-feed-decimals.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py oracle-decimal-mis-scaling-hardcoded-scale-without-feed-decimals.yaml
Source: glider-oracle-prices-with-hardcoded-scales-row-local-repair
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OracleDecimalMisScalingHardcodedScaleWithoutFeedDecimals(AbstractDetector):
    ARGUMENT = "oracle-decimal-mis-scaling-hardcoded-scale-without-feed-decimals"
    HELP = "Oracle price/quote/value function reads a Chainlink-style answer and scales it by a hardcoded decimal factor without reading feed.decimals()."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/oracle-decimal-mis-scaling-hardcoded-scale-without-feed-decimals.yaml"
    WIKI_TITLE = "Oracle decimal mis-scaling: hardcoded scale without feed decimals"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: this row flags a Chainlink-style price/quote/value function that reads an oracle answer and scales it with a fixed decimal literal such as 1e18 or 1e8 while omitting a visible feed `decimals()` read. It does not prove exploitability in a live deployed corpus."
    WIKI_EXPLOIT_SCENARIO = "A collateral quote reads `answer = priceFeed.latestRoundData()` and returns `amount * uint256(answer) / 1e18`. If the configured feed returns 8 decimals, collateral value is under-reported by 10^10; if a non-8-decimal feed is forced through 1e8 math, the error flips accordingly."
    WIKI_RECOMMENDATION = "Read `feed.decimals()` and normalize oracle answers to the protocol's target precision dynamically, or wrap feeds behind an adapter that guarantees a single output precision. Keep this row NOT_SUBMIT_READY until real corpus-backed exploit evidence is added."

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)(AggregatorV3Interface|Chainlink|latestRoundData|latestAnswer|getPrice|getAnswer)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.name_matches': '(?i)(price|quote|value|nav|asset|collateral)'}, {'function.body_contains_regex': '(?i)(latestRoundData|latestAnswer|getPrice|getAnswer)\\s*\\('}, {'function.body_contains_regex': '(?i)\\b(answer|price|oraclePrice|rawPrice|latestPrice)\\b'}, {'function.body_contains_regex': '\\b(1e6|1e8|1e18|1e27|10\\s*\\*\\*\\s*(6|8|18|27)|1000000|100000000|1000000000000000000)\\b'}, {'function.body_not_contains_regex': '(?i)\\.\\s*decimals\\s*\\(\\s*\\)|\\b(feed|priceFeed|oracle)\\s*Decimals\\b|\\b(decimals|feedDecimals|priceDecimals)\\s*=\\s*[^;]*decimals\\s*\\('}]

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
                info = [f, f" — oracle-decimal-mis-scaling-hardcoded-scale-without-feed-decimals: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
