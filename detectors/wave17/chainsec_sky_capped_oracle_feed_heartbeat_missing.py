"""
chainsec-sky-capped-oracle-feed-heartbeat-missing — generated from reference/patterns.dsl/chainsec-sky-capped-oracle-feed-heartbeat-missing.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py chainsec-sky-capped-oracle-feed-heartbeat-missing.yaml
Source: auditooor-R75-chainsec-Sky-CappedOracleFeed
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ChainsecSkyCappedOracleFeedHeartbeatMissing(AbstractDetector):
    ARGUMENT = "chainsec-sky-capped-oracle-feed-heartbeat-missing"
    HELP = "Capped oracle wrapper applies an upper price cap but does not propagate/verify the upstream feed's `updatedAt` — a stuck feed at the cap silently stays 'fresh' until the cap is raised."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/chainsec-sky-capped-oracle-feed-heartbeat-missing.yaml"
    WIKI_TITLE = "Capped oracle feed omits heartbeat/staleness check (stale high price pinned to cap)"
    WIKI_DESCRIPTION = "Protocols that wrap a price feed with an upper cap (e.g. for LSTs whose exchange rate should not exceed their oracle-projected value) typically do `answer = min(underlying.latestAnswer(), cap)`. If the underlying feed goes stale (stops updating), the cap still produces the capped value so the returned price looks normal — no revert, no alarm. Consumers that don't themselves check `updatedAt` will "
    WIKI_EXPLOIT_SCENARIO = "Sky CappedOracleFeed: underlying LST oracle reports 1.0500, cap=1.0000, output=1.0000. Underlying feed freezes due to an operator outage at 1.0500. True LST price drops to 0.9500 over the next 48h. Capped feed keeps returning 1.0000 the whole time (min(1.0500, 1.0000)). Borrowers collateralize LST at 1.0000, but if mark-to-market were honest they'd be under-collateralized at 0.9500. When the feed "
    WIKI_RECOMMENDATION = "Propagate `updatedAt` from the underlying feed and enforce a heartbeat: `(, int256 ans, , uint256 updatedAt, ) = underlying.latestRoundData(); require(block.timestamp - updatedAt <= HEARTBEAT, 'stale'); return (min(ans, cap), updatedAt);`. Provide separate heartbeats per underlying asset. Emit a met"

    _PRECONDITIONS = [{'contract.source_matches_regex': 'CappedOracle|OracleFeed|PriceCap|CappedAggregator'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': 'latestAnswer|latestRoundData|getPrice|read|price'}, {'function.body_contains_regex': 'upperCap|priceCap|MAX_PRICE|maxPrice|ceiling'}, {'function.body_contains_regex': 'Math\\.min\\s*\\(|_min\\s*\\(|price\\s*>\\s*(upperCap|priceCap|ceiling)'}, {'function.body_not_contains_regex': 'updatedAt|heartbeat|staleAfter|MAX_STALE|block\\.timestamp\\s*-\\s*updatedAt'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — chainsec-sky-capped-oracle-feed-heartbeat-missing: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
