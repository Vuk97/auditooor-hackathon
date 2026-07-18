"""
glider-chainlink-no-error-except — generated from reference/patterns.dsl/glider-chainlink-no-error-except.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py glider-chainlink-no-error-except.yaml
Source: glider-query-db/chainlink-oracle-calls-without-proper-error-except
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class GliderChainlinkNoErrorExcept(AbstractDetector):
    ARGUMENT = "glider-chainlink-no-error-except"
    HELP = "Chainlink `latestRoundData` called without try/catch. If feed is deprecated or sequencer down, the call reverts — every dependent path becomes unusable until admin replaces the feed."
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/glider-chainlink-no-error-except.yaml"
    WIKI_TITLE = "Chainlink oracle call without try/catch fallback"
    WIKI_DESCRIPTION = "Chainlink aggregators can be removed from the `FeedRegistry` or marked deprecated, causing `latestRoundData()` to revert. Without a try/catch or fallback path, the entire contract locks up with no recovery primitive."
    WIKI_EXPLOIT_SCENARIO = "Feed for a rarely-traded asset is deprecated by Chainlink. All `deposit`/`withdraw`/`liquidate` calls that query that feed revert. Users cannot exit positions; liquidators cannot protect the protocol."
    WIKI_RECOMMENDATION = "Wrap `latestRoundData()` in `try/catch` with a fallback (secondary oracle, TWAP, or explicit circuit-breaker pause)."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'latestRoundData|AggregatorV3Interface'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.body_contains_regex': 'latestRoundData\\s*\\(\\s*\\)'}, {'function.body_not_contains_regex': 'try\\s+\\w+\\.latestRoundData|catch\\s*\\{|staticcall'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — glider-chainlink-no-error-except: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
