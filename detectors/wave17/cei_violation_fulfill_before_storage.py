"""
cei-violation-fulfill-before-storage — generated from reference/patterns.dsl/cei-violation-fulfill-before-storage.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py cei-violation-fulfill-before-storage.yaml
Source: solodit-novel/slice_aa
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class CeiViolationFulfillBeforeStorage(AbstractDetector):
    ARGUMENT = "cei-violation-fulfill-before-storage"
    HELP = "Fulfillment function invokes an external callback before setting `fulfilledRequests[id] = true`. Callback can re-enter and request same hash again; double-fulfill."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/cei-violation-fulfill-before-storage.yaml"
    WIKI_TITLE = "Fulfill callback fires before fulfilled-flag storage write (CEI violation)"
    WIKI_DESCRIPTION = "Oracle / randomness / relayer fulfillment paths that call `callback.onFulfill(requestId, data)` before setting the `fulfilled[requestId] = true` storage flag expose a cross-function reentrancy window. The callee can invoke the fulfill entry again with the same requestId and get a second fulfillment — doubling payouts, rewards, or callback side-effects."
    WIKI_EXPLOIT_SCENARIO = "VRF / cross-chain relay pattern: `function fulfill(uint256 id, bytes data) { callback.onFulfill(id, data); fulfilledRequests[id] = true; }`. Attacker deploys a receiver whose `onFulfill` calls `fulfill(id, data)` again. The guard has not been set yet, so the second call repeats the payout. If the callback mints NFTs or transfers rewards, attacker mints twice."
    WIKI_RECOMMENDATION = "Strict CEI: write `fulfilledRequests[id] = true` BEFORE the callback. Additionally apply a `nonReentrant` modifier for defense in depth. Consider also `require(!fulfilledRequests[id])` as the first statement."

    _PRECONDITIONS = [{'contract.source_matches_regex': 'fulfill|callback|request|oracle'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.is_mutating': True}, {'function.name_matches': '^(fulfill|deliver|finalize|settle|respond)[A-Z_]?|^(fulfill|deliver|finalize|settle|respond)$'}, {'function.has_external_call': True}, {'function.post_external_call_mutates_state': True}, {'function.has_high_level_call_named': '(?i)^(onFulfill|onCallback|fulfillCallback|callback|onResponse|onSettlement|deliver|onDelivery|notifyConsumer)$'}, {'function.body_contains_regex': 'fulfilledRequests|requestFulfilled|processed|completed|isDone|handled\\s*\\['}, {'function.has_modifier': {'includes': ['nonReentrant', 'reentrancyGuard', 'lock'], 'negate': True}}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — cei-violation-fulfill-before-storage: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
