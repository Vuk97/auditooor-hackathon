"""
oracle-wrong-decimals — generated from reference/patterns.dsl/oracle-wrong-decimals.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py oracle-wrong-decimals.yaml
Source: solodit/C0241
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class OracleWrongDecimals(AbstractDetector):
    ARGUMENT = "oracle-wrong-decimals"
    HELP = "Function consumes a Chainlink-style oracle price but hardcodes a decimal scale (e.g., * 1e8 / * 1e18 / 10**8) instead of reading oracle.decimals() — breaks on aggregators with non-default decimals (ETH/USD=8 vs AMPL/USD=18 vs some feeds=6)."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/oracle-wrong-decimals.yaml"
    WIKI_TITLE = "Oracle price consumed with hardcoded decimal scale"
    WIKI_DESCRIPTION = "The function calls latestAnswer / latestRoundData / getPrice / getAnswer on a price feed and then multiplies or divides by a literal 1e8 / 1e18 / 1e6 / 1e10 (or 10**N) without first reading the feed's decimals() getter. Chainlink aggregators publish prices in different decimal bases (ETH/USD=8, AMPL/USD=18, some stables=6). A function that assumes 8 decimals will under- or over-scale by orders of "
    WIKI_EXPLOIT_SCENARIO = "Protocol lists a new collateral with a price feed using 18 decimals (e.g., AMPL/USD). The lending-contract's getCollateralValueUsd function hardcodes `price * amount / 1e8`, expecting the 8-decimal ETH/USD shape. The resulting collateral value is under-stated by 1e10, letting an attacker borrow far beyond their collateral and drain the pool; symmetrically, a protocol that hardcoded 1e18 against an"
    WIKI_RECOMMENDATION = "Always read `feed.decimals()` at construction (or every call, cached) and normalise prices into the protocol's internal precision. Alternatively wrap every feed in an adapter that exposes a fixed-precision `getPrice()` and reject feeds whose decimals() returns an unexpected value."

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.has_state_var_matching': '(oracle|priceFeed|aggregator|priceOracle)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': {'regex': '\\.(latestAnswer|latestRoundData|getPrice|getAnswer)\\s*\\('}}, {'function.body_contains_regex': {'regex': '(\\*\\s*1e(8|18|6|10)\\b|\\/\\s*1e(8|18|6|10)\\b|10\\s*\\*\\*\\s*(8|18|6))'}}, {'function.body_not_contains_regex': '\\.decimals\\s*\\(\\s*\\)|priceFeed\\.decimals|aggregator\\.decimals|scaledBy'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — oracle-wrong-decimals: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
