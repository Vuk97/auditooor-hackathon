"""
reentrancy-guard-blocks-required-callback — generated from reference/patterns.dsl/reentrancy-guard-blocks-required-callback.yaml
DO NOT EDIT BY HAND. Regenerate via: python3 tools/pattern-compile.py reentrancy-guard-blocks-required-callback.yaml
Source: auditooor-R75-c4-yield-2024-04-renzo-368
"""

import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from _template_utils import is_vendored_or_test_contract, is_leaf_helper
from _predicate_engine import eval_preconditions, eval_function_match

from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class ReentrancyGuardBlocksRequiredCallback(AbstractDetector):
    ARGUMENT = "reentrancy-guard-blocks-required-callback"
    HELP = "receive()/fallback guarded by nonReentrant while an external completeWithdrawal() is also nonReentrant — breaks the callback chain that returns ETH to the vault."
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM
    WIKI = "https://github.com/Vuk97/auditooor/blob/main/reference/patterns.dsl/reentrancy-guard-blocks-required-callback.yaml"
    WIKI_TITLE = "nonReentrant on receive() blocks EigenLayer/restaking ETH callback from parent withdraw call"
    WIKI_DESCRIPTION = "Restaking / LST wrappers often call `delegationManager.completeQueuedWithdrawal(..., receiveAsTokens=true)` which, internally, routes ETH back into the vault's `receive()`. If both the outer function AND `receive()` carry a `nonReentrant` modifier sharing the same lock, the callback reverts — permanently stranding any ETH-denominated position in the withdrawal queue because the only way to exit it"
    WIKI_EXPLOIT_SCENARIO = "Renzo OperatorDelegator.receive() is nonReentrant and completeQueuedWithdrawal() is also nonReentrant. When an admin completes a native-ETH withdrawal, EigenPod sweeps ETH via the receive() callback inside the outer call; the guard reverts. Every ETH withdrawal ever queued cannot be completed until a contract upgrade."
    WIKI_RECOMMENDATION = "Allow the callback path: either remove `nonReentrant` from `receive()`, or guard it only when the sender is untrusted (`if (msg.sender != trustedCallbackSource) _nonReentrantBefore();`). Write an integration test that actually runs the full withdrawal roundtrip — unit tests of the outer function alo"

    _PRECONDITIONS = [{'contract.source_matches_regex': '.*'}, {'contract.source_matches_regex': '(?i)function\\s+completeQueuedWithdrawal|completeWithdrawal|withdrawETH|claimDelayedWithdrawals'}, {'contract.source_matches_regex': '(?i)(completeQueuedWithdrawal|completeWithdrawal|claimDelayedWithdrawal)[\\s\\S]*(nonReentrant|_locked)'}]
    _MATCH = [{'function.kind': 'external_or_public'}, {'function.name_matches': '^receive$|^fallback$'}, {'function.has_modifier': ['nonReentrant']}, {'function.not_in_skip_list': True}, {'function.not_source_matches_regex': '(?i)\\b(mock|test|fixture)'}]

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
                info = [f, f" — reentrancy-guard-blocks-required-callback: pattern matched. See WIKI for details."]
                results.append(self.generate_result(info))
        return results
