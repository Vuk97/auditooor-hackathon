"""
polygon-statesync-no-source-replay-guard — generated from reference/patterns.dsl/polygon-statesync-no-source-replay-guard.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py polygon-statesync-no-source-replay-guard.yaml
Source: auditooor-R73-chain-specific-polygon
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class PolygonStatesyncNoSourceReplayGuard(AbstractDetector):
    ARGUMENT = "polygon-statesync-no-source-replay-guard"
    HELP = "Polygon L1->L2 state-sync consumer doesn't check the monotonic stateId, allowing a Heimdall-forwarded message to be replayed on L2."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/polygon-statesync-no-source-replay-guard.yaml"
    WIKI_TITLE = "Polygon state-sync receiver lacks replay guard on stateId"
    WIKI_DESCRIPTION = "Polygon PoS L1->L2 data bridge (StateSender → Heimdall → Bor → FxChild → user contract) hands each message a monotonically-increasing stateId. Heimdall does not enforce one-time delivery; the downstream contract must track `processedStateId[stateId] = true`. Forked fx-portal children that skip this track re-process the same stateId across restarts/forks and across operator-triggered resync events."
    WIKI_EXPLOIT_SCENARIO = "L1 contract sends a `setRole(admin=X)` message with stateId=42 via StateSender. Heimdall signs, Bor relays, FxChild calls `onStateReceive(42, payload)`. User contract grants admin. Later, Heimdall's resync replay (or a malicious block producer's re-import) calls onStateReceive(42, payload) again — with no replay guard, admin is 'granted' again, setting `grants[X] = 2`, which some downstream logic "
    WIKI_RECOMMENDATION = "Maintain `mapping(uint256 => bool) processedStateId` and `require(!processedStateId[stateId], 'replay')` at the top of onStateReceive, setting the flag before external effects. Defense-in-depth: require stateId == lastProcessedId + 1 so operators notice gaps (missing messages) rather than silently a"

    _PRECONDITIONS = [{'contract.source_matches_regex': '(?i)onStateReceive|FxMessageProcessor|stateSender|fxRoot'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '(?i)onStateReceive|processMessageFromRoot'}, {'function.body_not_contains_regex': '(?i)(processedStateId|_processedState|stateId\\s*>\\s*last|nonce\\s*==|require\\s*\\(\\s*stateId\\s*>)'}, {'function.not_in_skip_list': True}, {'function.not_leaf_helper': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — polygon-statesync-no-source-replay-guard: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
