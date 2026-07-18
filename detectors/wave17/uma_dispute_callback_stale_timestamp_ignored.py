"""
uma-dispute-callback-stale-timestamp-ignored — generated from reference/patterns.dsl/uma-dispute-callback-stale-timestamp-ignored.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py uma-dispute-callback-stale-timestamp-ignored.yaml
Source: auditooor-R77-polymarket-UmaCtfAdapter-priceDisputed
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class UmaDisputeCallbackStaleTimestampIgnored(AbstractDetector):
    ARGUMENT = "uma-dispute-callback-stale-timestamp-ignored"
    HELP = "UMA priceDisputed callback receives a timestamp parameter but does not compare it to the stored questionData.requestTimestamp — stale OO callbacks from orphan/reset requests mutate current state."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/uma-dispute-callback-stale-timestamp-ignored.yaml"
    WIKI_TITLE = "UMA priceDisputed callback ignores timestamp parameter, allowing stale-request state mutation"
    WIKI_DESCRIPTION = "The UMA Optimistic Oracle V2 calls `priceDisputed(bytes32 identifier, uint256 timestamp, bytes ancillaryData, uint256 refund)` on the requester when a dispute fires. The callback typically looks up the question by `keccak256(ancillaryData)`, which returns the CURRENT question state. However, the OO can fire this callback for ANY prior request (including ones orphaned by a `_reset`). Contracts that"
    WIKI_EXPLOIT_SCENARIO = "Creator initializes a question with reward R. Admin flags for manual resolution (paused=true, safety period begins). Attacker (proposer+disputer) disputes request-1 with a throwaway bond. Callback fires, `_reset(adapter, qID, resetRefund=false, …)` opens request-2 consuming R. `refund=false` after reset. Admin later calls `resolveManually`; refund branch is skipped because `refund==false`; creator"
    WIKI_RECOMMENDATION = "Validate the callback's timestamp against the stored request timestamp at the top of the handler: `require(timestamp == questionData.requestTimestamp, StaleDispute());`. Also gate the callback on paused/flagged state: during admin-initiated manual-resolution windows, the callback should either short"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)priceDisputed|IOptimisticRequester|OOV2|optimisticOracle'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)priceDisputed|onPriceDispute'}, {'function.has_modifier': 'onlyOptimisticOracle|onlyOO|onlyOracle'}, {'function.body_not_contains_regex': '(?i)require\\s*\\(\\s*(timestamp|_timestamp)\\s*==\\s*\\w*[Rr]equestTimestamp|\\w*[Rr]equestTimestamp\\s*==\\s*timestamp'}, {'function.body_not_contains_regex': '(?i)if\\s*\\(\\s*(timestamp|_timestamp)\\s*!=\\s*\\w*[Rr]equestTimestamp\\s*\\)\\s*(revert|return)'}, {'function.not_in_slither_synthetic': True}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — uma-dispute-callback-stale-timestamp-ignored: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
