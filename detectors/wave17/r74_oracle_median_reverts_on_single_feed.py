"""
r74-oracle-median-reverts-on-single-feed — generated from reference/patterns.dsl/r74-oracle-median-reverts-on-single-feed.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py r74-oracle-median-reverts-on-single-feed.yaml
Source: r74b-cross-firm-cs
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class R74OracleMedianRevertsOnSingleFeed(AbstractDetector):
    ARGUMENT = "r74-oracle-median-reverts-on-single-feed"
    HELP = "NOT_SUBMIT_READY fixture-smoke/source-shape proof only: a median/aggregator function reads N price feeds in a loop without try/catch, so any single feed reverting DoS-es the entire oracle output."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/r74-oracle-median-reverts-on-single-feed.yaml"
    WIKI_TITLE = "Median price aggregator reverts when any single feed reverts"
    WIKI_DESCRIPTION = "Fixture-smoke/source-shape proof only: this row targets the owned oracle aggregation shape where a public median/aggregate function iterates `priceFeeds`, calls `latestRoundData()` directly inside the loop, and performs no per-feed `try/catch`. The positive fixture models the revert-amplifying shape; the clean fixture keeps the same loop but isolates individual feed failures and enforces a minimum"
    WIKI_EXPLOIT_SCENARIO = "A deprecated feed in the configured `priceFeeds` array begins reverting. Because the median path calls `latestRoundData()` directly for every feed and never catches failures, the next price read reverts and every downstream liquidation, borrow, or valuation path that depends on the median halts until governance removes the bad feed."
    WIKI_RECOMMENDATION = "Wrap each per-feed read in `try oracle.latestRoundData() returns (...) { ... } catch { continue; }`, compute the aggregate only over successful reads, and enforce a minimum-success threshold before serving a price. Keep submission_posture NOT_SUBMIT_READY until evidence expands beyond the owned fixt"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(median|aggregator|quorum|oracleArray|priceFeeds)'}]
    _MATCH = [{'function.kind': 'external_or_public_or_internal'}, {'function.body_contains_regex': 'for\\s*\\([^)]*(feeds?|oracles?|sources?|aggregators?)[^)]*\\.length|for\\s*\\(.*i\\s*<\\s*.*(length|len)'}, {'function.body_contains_regex': 'latestRoundData\\s*\\(|latestAnswer\\s*\\(|getAnswer\\s*\\('}, {'function.body_not_contains_regex': 'try\\s+\\w+\\.latestRoundData|try\\s+I\\w+Oracle|try\\s+\\w+\\.getAnswer|catch\\s*\\(|catch\\s*\\{'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — r74-oracle-median-reverts-on-single-feed: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
