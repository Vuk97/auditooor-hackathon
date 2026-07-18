"""
glider-oracle-price-denominator-zero — generated from reference/patterns.dsl/glider-oracle-price-denominator-zero.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-oracle-price-denominator-zero.yaml
Source: glider-query-db/oracle-price-used-as-denominator-without-zero-check
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderOraclePriceDenominatorZero(AbstractDetector):
    ARGUMENT = "glider-oracle-price-denominator-zero"
    HELP = "Oracle price fetched and used as divisor without a zero-guard. A malformed or uninitialized feed returns 0, causing division-by-zero revert — permanent DoS on all dependent paths. (refined Phase 40 — requires oracle-ABI body token)"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-oracle-price-denominator-zero.yaml"
    WIKI_TITLE = "Oracle price used as denominator without zero check"
    WIKI_DESCRIPTION = "`latestAnswer()` / `latestRoundData()` may return 0 for un-aggregated feeds, slashed feeds, or pre-initialization states. Using the returned price as denominator without a `require(price > 0)` causes every dependent function to revert."
    WIKI_EXPLOIT_SCENARIO = "New oracle registered but not yet populated; first `deposit()` reads price=0; `amount / price` reverts; deposits permanently blocked until admin manually refreshes."
    WIKI_RECOMMENDATION = "Always `require(price > 0, 'invalid price')` immediately after the feed read, before any division."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'latestRoundData|getPrice|latestAnswer|priceOf'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': '(latestRoundData|latestAnswer|getPrice|priceOf)[^;]*;\\s*[\\s\\S]{0,300}?/\\s*(price|answer|rate|oraclePrice|quote)'}, {'function.body_contains_regex': '(IChainlinkAggregator|latestAnswer|AggregatorV3|IPyth\\.getPrice|priceFeed|getRoundData|consult\\(|observe\\(|getPrice\\(|oracle)'}, {'function.body_not_contains_regex': 'require\\s*\\(\\s*(price|answer|rate|oraclePrice|quote)\\s*>\\s*0'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-oracle-price-denominator-zero: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
