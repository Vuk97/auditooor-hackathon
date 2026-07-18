"""
auction-failure-stalls-period — generated from reference/patterns.dsl/auction-failure-stalls-period.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py auction-failure-stalls-period.yaml
Source: solodit-novel/slice_ag-Auction
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AuctionFailureStallsPeriod(AbstractDetector):
    ARGUMENT = "auction-failure-stalls-period"
    HELP = "Auction finalizer only increments the period counter on SUCCESS paths; a failed/undersold auction leaves the counter unchanged, stalling all future auctions."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/auction-failure-stalls-period.yaml"
    WIKI_TITLE = "Failed auction doesn't advance period — permanent stall"
    WIKI_DESCRIPTION = "Auction-sequenced protocols (gauges, bond markets) require the period counter to advance after each settlement. If `finalize()` returns early on failure without advancing, the protocol is stuck until an admin manually fixes state."
    WIKI_EXPLOIT_SCENARIO = "Market conditions cause auction N to undersell. Finalizer takes the `return` path on fail; period stays at N. Auction N+1 cannot open; all later auctions blocked. Protocol lost weekly emission cycle."
    WIKI_RECOMMENDATION = "Always advance the period counter after finalization, regardless of success. Emit a `AuctionFailed` event and still bump the index."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'Auction|period|epoch'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^(finalize|close|settle|endAuction|_finalize|finalizeAuction)'}, {'function.body_contains_regex': 'FAILED|UNDERSOLD|NOT_FILLED|revert|return\\s*;'}, {'function.body_not_contains_regex': '(period|epoch|auctionId|periodIndex|currentPeriod)\\s*(\\+\\+|\\+=\\s*1|=\\s*\\w+\\s*\\+\\s*1)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — auction-failure-stalls-period: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
