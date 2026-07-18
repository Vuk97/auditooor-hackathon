"""
auction-failure-stalls-period-advance — generated from reference/patterns.dsl/auction-failure-stalls-period-advance.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py auction-failure-stalls-period-advance.yaml
Source: solodit-novel/slice_ag
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class AuctionFailureStallsPeriodAdvance(AbstractDetector):
    ARGUMENT = "auction-failure-stalls-period-advance"
    HELP = "Auction close function advances `currentPeriod` only on success. FAILED/UNDERSOLD branches exit without advancing; protocol deadlocks on the stuck period."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.LOW
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/auction-failure-stalls-period-advance.yaml"
    WIKI_TITLE = "Auction FAILED branch does not advance period counter"
    WIKI_DESCRIPTION = "Periodic auctions rely on a monotonic period/epoch counter. When the close function advances the counter only inside the success branch and returns early on FAILED/UNDERSOLD without incrementing, the protocol can never roll over. All subsequent operations remain bound to the failed period and the auction mechanism is permanently stuck."
    WIKI_EXPLOIT_SCENARIO = "Treasury dutch auction: `closeAuction()` checks `totalRaised >= minRaise`; if true, mint tokens + `currentPeriod++`. Otherwise emits `AuctionFailed` and returns. If the first auction fails (under-subscribed), currentPeriod stays at 0 forever. No one can start period 1, so no treasury emissions, no new auctions. Recovery requires governance upgrade."
    WIKI_RECOMMENDATION = "Always advance the period inside the close function, regardless of success/failure: `finally { currentPeriod++; }`. Treat the period counter as tx-level metadata separate from auction outcome state."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'auction|period|epoch|Auction'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': 'close|finalize|resolveAuction|endAuction|settleAuction'}, {'function.body_contains_regex': '(currentPeriod|epoch|round|period)\\s*\\+\\+|\\1\\s*=\\s*\\1\\s*\\+\\s*1'}, {'function.body_contains_regex': 'UNDERSOLD|FAILED|CANCELLED|Cancelled|Failed|if\\s*\\(\\s*\\w+\\s*<\\s*minRaised'}, {'function.body_not_contains_regex': '(FAILED|UNDERSOLD|CANCELLED)[^{}]*\\{[^}]*(currentPeriod|epoch|round|period)\\s*\\+\\+'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — auction-failure-stalls-period-advance: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
